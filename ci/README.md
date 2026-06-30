# CI: the vgi-asn1 worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs fmt/clippy/build,
the Rust unit + integration tests, and this repo's sqllogictest suite
(`test/sql/*.test`) against the vgi-asn1 VGI worker through the **real DuckDB
`vgi` extension** on every push / PR.

## Transport matrix

The integration suite runs over **every transport the vgi extension supports**.
The exact same `test/sql/*.test` files run three ways; the only thing that
changes is what LOCATION the `.test` files `ATTACH` (set by
[`run-integration.sh`](run-integration.sh) from the `TRANSPORT` env var):

| `TRANSPORT`  | `VGI_ASN1_WORKER` (the ATTACH LOCATION) | how the worker is launched |
|--------------|------------------------------------------|----------------------------|
| `subprocess` | `…/target/release/asn1-worker`          | DuckDB spawns the stdio binary (default) |
| `http`       | `http://127.0.0.1:<port>`                | `asn1-worker --http` (auto port; prints `PORT:<n>` on stdout, which the script polls for) |
| `unix`       | `unix:///tmp/units.<pid>.sock`           | `asn1-worker --unix <sock>` (prints `UNIX:<sock>` on stdout + creates the socket; the script waits for both) |

CI runs `transport: [subprocess, http, unix]` × `os: [ubuntu, macos]` as a
matrix. Build the worker once with a plain `cargo build --release` — the
workspace already pins `vgi-rpc = { features = ["macros", "http"] }`, so the one
binary serves all three transports; **no extra cargo feature is needed**.

### The `http` leg needs DuckDB's `httpfs` extension

The vgi extension's **HTTP client** is built on DuckDB's `httpfs`. Over `http://`,
`ATTACH` fails without it:

> `Binder Error: VGI HTTP transport requires the httpfs extension. Install it with: INSTALL httpfs; LOAD httpfs;`

Crucially, that message contains the substring **`HTTP`**, and DuckDB's
sqllogictest runner ships a default `ignore_error_messages = {"HTTP", "Unable to
connect"}` that **silently SKIPs** any test whose error matches — so a missing
`httpfs` looks like a (deceptive) pass-by-skip, not a failure. We handle this in
two places:

1. [`preprocess-require.awk`](preprocess-require.awk), invoked with
   `-v transport=http`, injects a signed `INSTALL httpfs FROM core; LOAD httpfs;`
   right after each `LOAD vgi;` so the http leg actually loads the client and runs.
2. [`run-integration.sh`](run-integration.sh) fails the job if the runner reports
   *any* skipped tests (a skip is never a pass) — guarding against this and any
   future silent-skip masking.

The `unix` (AF_UNIX launcher) leg needs no extra extension.

## How it works (no C++ build)

Rather than building the vgi DuckDB extension from source, the integration job
drives a **prebuilt** standalone `haybarn-unittest` (the DuckDB/Haybarn
sqllogictest runner, published in Haybarn's releases) and installs the
**signed** `vgi` extension from the Haybarn community channel:

1. **Build the worker** — `cargo build --release --bin asn1-worker`. The
   compiled `target/release/asn1-worker` is a self-contained stdio worker the
   extension spawns (the `.test` files `ATTACH` it via `${VGI_ASN1_WORKER}`).
2. **Download the runner** — the matching `haybarn_unittest-*` asset per
   platform from the latest Haybarn release.
3. **Preprocess** — the standalone runner links none of the extensions the
   tests gate on, so [`preprocess-require.awk`](preprocess-require.awk) rewrites
   each `require <ext>` into an explicit signed `INSTALL <ext> FROM
   {community,core}; LOAD <ext>;`. `require-env` and everything else pass
   through untouched. (The vgi-asn1 `.test` files already `LOAD vgi;`
   explicitly and use `require-env VGI_ASN1_WORKER`, so the `require`-rewrite is
   a no-op here.) When run with `-v transport=http`, the awk also injects
   `INSTALL httpfs FROM core; LOAD httpfs;` after each `LOAD vgi;` (see the
   transport-matrix section above for why).
4. **Run** — [`run-integration.sh`](run-integration.sh) brings up the worker for
   the selected `TRANSPORT` and sets `VGI_ASN1_WORKER` accordingly, stages the
   preprocessed tree, warms the extension cache once (`INSTALL vgi FROM
   community;` — this is what makes the tests' explicit `LOAD vgi;` succeed),
   then runs the suite in a single `haybarn-unittest` invocation. Any failed
   assertion — or any skipped test — exits non-zero and fails the job.

## Run it locally

```bash
cargo build --release --bin asn1-worker
# point HAYBARN_UNITTEST at a haybarn-unittest binary (or a local DuckDB
# `unittest` built with the vgi extension), and WORKER_BIN at the release binary.
# TRANSPORT defaults to subprocess; set it to http or unix for the other legs.
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
WORKER_BIN="$PWD/target/release/asn1-worker" \
TRANSPORT=subprocess \
  ci/run-integration.sh

# HTTP leg: launches `asn1-worker --http`, reads PORT:<n>, attaches http://…
HAYBARN_UNITTEST=/path/to/haybarn-unittest WORKER_BIN="$PWD/target/release/asn1-worker" \
  TRANSPORT=http ci/run-integration.sh

# Unix leg: launches `asn1-worker --unix /tmp/units.<pid>.sock`, attaches unix://…
HAYBARN_UNITTEST=/path/to/haybarn-unittest WORKER_BIN="$PWD/target/release/asn1-worker" \
  TRANSPORT=unix ci/run-integration.sh
```

Or use the Makefile target `make test-sql`, which builds the release worker and
runs the suite against a `haybarn-unittest` on `PATH` (`uv tool install
haybarn-unittest`).
