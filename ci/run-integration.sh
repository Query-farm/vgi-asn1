#!/usr/bin/env bash
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Run this repo's sqllogictest suite (test/sql/*.test) against the vgi-asn1
# VGI worker, using a prebuilt standalone `haybarn-unittest` and the signed
# community `vgi` extension — no C++ build from source. See ci/README.md.
#
# Parameterized by TRANSPORT (default: subprocess), exercising the SAME suite
# over each transport the vgi extension supports — the only thing that changes
# is what LOCATION (VGI_ASN1_WORKER) the .test files ATTACH:
#
#   subprocess  VGI_ASN1_WORKER = the stdio worker command (DuckDB spawns it).
#   http        start `asn1-worker --http` (auto port; advertises `PORT:<n>`
#               on stdout), VGI_ASN1_WORKER = http://127.0.0.1:<port>.
#               If VGI_ASN1_WORKER is ALREADY set to an http(s):// URL (e.g. a
#               pre-launched container in the docker image_test), it is used
#               as-is and no local worker is spawned.
#   unix        start `asn1-worker --unix <sock>` (advertises `UNIX:<sock>`
#               on stdout), VGI_ASN1_WORKER = unix://<sock>.
#
# Required environment:
#   HAYBARN_UNITTEST  path to the haybarn-unittest binary
#   WORKER_BIN        path to the compiled asn1-worker binary (used to launch
#                     the http/unix servers, and the stdio LOCATION). Falls back
#                     to VGI_ASN1_WORKER when that is a bare command (subprocess).
# Optional:
#   TRANSPORT         subprocess | http | unix   (default: subprocess)
#   STAGE             scratch dir for the preprocessed test tree (default: mktemp)
#   TEST_PATTERN      runner glob/path under the staged tree to execute
#                     (default: test/sql/*). All files are always staged; this
#                     only narrows what RUNS — e.g. a single-file stdio smoke.
set -euo pipefail

TRANSPORT="${TRANSPORT:-subprocess}"

: "${HAYBARN_UNITTEST:?path to the haybarn-unittest binary}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STAGE="${STAGE:-$(mktemp -d)}"

# For http/unix we must launch the worker binary ourselves; for subprocess the
# binary IS the LOCATION. WORKER_BIN names the compiled binary; default to the
# release build in this repo.
WORKER_BIN="${WORKER_BIN:-$REPO/target/release/asn1-worker}"

SERVER_PID=""
SOCK_PATH=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  [[ -n "$SOCK_PATH" ]] && rm -f "$SOCK_PATH" 2>/dev/null || true
}
trap cleanup EXIT

# Bring up the out-of-band server for http/unix and resolve VGI_ASN1_WORKER.
# Both transports announce their endpoint on stdout (`PORT:<n>` / `UNIX:<path>`),
# which we poll for in the log before running the suite (readiness gate).
start_server_and_set_location() {
  local kind="$1"
  : "${WORKER_BIN:?path to the asn1-worker binary (WORKER_BIN)}"
  [[ -x "$WORKER_BIN" ]] || { echo "ERROR: worker binary not executable: $WORKER_BIN" >&2; exit 1; }

  local log="$STAGE/.worker-$kind.log"
  case "$kind" in
    http)
      "$WORKER_BIN" --http >"$log" 2>&1 &
      SERVER_PID=$!
      local port=""
      for _ in $(seq 1 60); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
          echo "ERROR: worker (--http) exited during startup. Log:" >&2; cat "$log" >&2; exit 1
        fi
        port=$(sed -n 's/.*PORT:\([0-9][0-9]*\).*/\1/p' "$log" 2>/dev/null | head -1)
        [[ -n "$port" ]] && break
        sleep 0.5
      done
      [[ -n "$port" ]] || { echo "ERROR: timed out waiting for PORT:<n>. Log:" >&2; cat "$log" >&2; exit 1; }
      export VGI_ASN1_WORKER="http://127.0.0.1:$port"
      echo "HTTP worker ready on 127.0.0.1:$port (pid $SERVER_PID)"
      ;;
    unix)
      SOCK_PATH="${VGI_ASN1_SOCK:-/tmp/asn1.$$.sock}"
      rm -f "$SOCK_PATH" 2>/dev/null || true
      "$WORKER_BIN" --unix "$SOCK_PATH" >"$log" 2>&1 &
      SERVER_PID=$!
      local ready=""
      for _ in $(seq 1 60); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
          echo "ERROR: worker (--unix) exited during startup. Log:" >&2; cat "$log" >&2; exit 1
        fi
        if grep -q "UNIX:$SOCK_PATH" "$log" 2>/dev/null && [[ -S "$SOCK_PATH" ]]; then
          ready=1; break
        fi
        sleep 0.5
      done
      [[ -n "$ready" ]] || { echo "ERROR: timed out waiting for UNIX socket. Log:" >&2; cat "$log" >&2; exit 1; }
      export VGI_ASN1_WORKER="unix://$SOCK_PATH"
      echo "Unix worker ready on $SOCK_PATH (pid $SERVER_PID)"
      ;;
  esac
}

case "$TRANSPORT" in
  subprocess)
    # The binary itself is the stdio LOCATION DuckDB spawns. Honor an explicit
    # VGI_ASN1_WORKER (e.g. a bare command) if the caller set one.
    export VGI_ASN1_WORKER="${VGI_ASN1_WORKER:-$WORKER_BIN}"
    ;;
  http)
    # Honor a pre-launched HTTP worker (e.g. a running container in the docker
    # image_test): if VGI_ASN1_WORKER already points at an http(s) URL, use it
    # and skip spawning a local binary. The awk preprocessor still injects
    # httpfs because TRANSPORT=http.
    if [[ "${VGI_ASN1_WORKER:-}" =~ ^https?:// ]]; then
      echo "Using pre-launched HTTP worker at $VGI_ASN1_WORKER"
    else
      start_server_and_set_location http
    fi
    ;;
  unix)  start_server_and_set_location unix ;;
  *) echo "ERROR: unknown TRANSPORT '$TRANSPORT' (want subprocess|http|unix)" >&2; exit 1 ;;
esac

: "${VGI_ASN1_WORKER:?worker LOCATION (stdio command, http:// URL, or unix:// socket)}"

echo "Staging preprocessed tests into $STAGE ..."
mkdir -p "$STAGE/test/sql"
# Pass the transport to the preprocessor: the http leg additionally needs DuckDB's
# `httpfs` extension loaded (the vgi extension's HTTP client is built on it), so
# the awk injects a signed INSTALL/LOAD httpfs after each `LOAD vgi;`. Without it
# the http ATTACH fails with a "HTTP"-containing error that the sqllogictest
# runner *silently auto-skips* (default ignore_error_messages), masking the gap.
for f in "$REPO"/test/sql/*.test; do
  awk -v transport="$TRANSPORT" -f "$HERE/preprocess-require.awk" "$f" > "$STAGE/test/sql/$(basename "$f")"
done

cd "$STAGE"

# Warm the extension cache once: vgi from the signed community channel. A miss
# here is only a warning — the per-test LOAD vgi; (the .test files load it
# explicitly) is what actually gates each file, and that LOAD only succeeds once
# vgi has been INSTALLed from community.
echo "Warming the extension cache (vgi from community) ..."
mkdir -p "$STAGE/test"
cat > "$STAGE/test/_warm.test" <<'EOF'
# name: test/_warm.test
# group: [warm]
statement ok
INSTALL vgi FROM community;
EOF
"$HAYBARN_UNITTEST" "test/_warm.test" >/dev/null 2>&1 || echo "::warning::extension warm step did not fully succeed"
rm -f "$STAGE/test/_warm.test"

# Run the whole suite in one invocation, streaming the runner's native
# sqllogictest report. Any failed assertion exits non-zero and fails the job.
#
# Guard against the silent-skip trap: DuckDB's sqllogictest runner auto-skips
# any test whose error message contains "HTTP" (default ignore_error_messages),
# so a broken http leg can report "All tests were skipped" with exit 0 and look
# green. Tee the report and fail if NOTHING actually ran. (For subprocess/unix
# there is no skip path, so this only ever bites a genuinely broken http leg.)
TEST_PATTERN="${TEST_PATTERN:-test/sql/*}"
echo "Running suite (transport: $TRANSPORT, worker: $VGI_ASN1_WORKER, pattern: $TEST_PATTERN) ..."
REPORT="$STAGE/.report.txt"
set +e
"$HAYBARN_UNITTEST" "$TEST_PATTERN" 2>&1 | tee "$REPORT"
status="${PIPESTATUS[0]}"
set -e
if grep -qiE "All tests were skipped|total skipped [1-9]" "$REPORT"; then
  echo "ERROR: tests were SKIPPED — almost certainly an ATTACH/transport error whose" >&2
  echo "       message matched the runner's default ignore list (e.g. \"HTTP\"). A skip" >&2
  echo "       is NOT a pass. Transport=$TRANSPORT worker=$VGI_ASN1_WORKER." >&2
  exit 1
fi
# Surface — but do NOT fail on — a Catch2 fatal-signal block in the report. The
# subprocess transport occasionally logs a "fatal error condition: SIGTERM" when
# DuckDB terminates the spawned worker at end-of-suite; the assertions have
# already passed and `status` is 0, so this is benign teardown noise. We only
# warn (not fail) because it is intermittent — failing would be flaky — but we
# echo it so it is not silently buried under a green "All tests passed".
if [[ "$status" -eq 0 ]] && grep -qiE "fatal error condition|SIG(TERM|SEGV|ABRT|KILL)" "$REPORT"; then
  echo "::warning::haybarn logged a fatal-signal condition during the suite (transport=$TRANSPORT); exit code was 0 so it is treated as benign end-of-suite worker teardown. Review the log if unexpected."
fi
exit "$status"
