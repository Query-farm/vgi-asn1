# CLAUDE.md — vgi-asn1

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker (Rust, compiled binary) that decodes generic
ASN.1 BER/CER/DER and the named security/telecom modules (SNMP, Kerberos, LDAP,
CMS/PKCS#7, PKCS#8/#12, OCSP) to DuckDB over Arrow IPC
(`ATTACH 'asn1' (TYPE vgi, LOCATION '…')`). Functions live under catalog `asn1`,
schema `main`. Built on the published `vgi = "0.9.5"` SDK, arrow 59. Modeled on
`../vgi-units` and `../vgi-fixedformat`.

## Layout

```
Cargo.toml                          workspace; vgi 0.9.5, arrow 59, no path deps to the SDK
crates/asn1-core/                   PURE engine (no Arrow / no VGI)
  src/tlv.rs                        generic BER/CER/DER TLV reader → Tlv tree; bounded recursion/alloc; never panics
  src/value.rs                      integer(bignum→string)/bool/time(→ISO+epoch µs)/string/bitstring interpretation
  src/oid.rs                        OID codec (dotted ⇆ bytes) + curated name registry
  src/json.rs                       Tlv → serde_json (to_json_verbose; decode_value); base64url/OID/time projection
  src/dump.rs                       openssl asn1parse + dumpasn1 style renderers
  src/tlvlist.rs                    flat TLV node list, OID inventory, at_path navigation
  src/validate.rs                   is_valid(rules) + well_formed (classified kind)
  src/reencode.rs                   Tlv → canonical DER (definite minimal lengths, sorted SET OF)
  src/pem.rs                        PEM bundle split + base64 → DER
  src/security/{snmp,kerberos,ldap,cms,pkcs,ocsp}.rs  structural decoders over the Tlv tree
  tests/{vectors,never_panic}.rs    golden DER/BER vectors + proptest zero-panic gate
crates/asn1-worker/                 thin Arrow/VGI adapter
  src/main.rs                       Worker::new(); catalog metadata; registers scalars + tables
  src/arrow_io.rs                   BLOB/VARCHAR reads; LIST<STRUCT>/STRUCT/LIST<BLOB> builders; test harness
  src/meta.rs                       vgi-lint discovery tags (object_tags / keywords_json / agent_test_tasks_json)
  src/scalar/{generic,security}.rs  scalar adapters (+ json_macro.rs for the JSON-returning decoders)
  src/table/*.rs                    producer table functions (pem_decode + the structural fan-outs)
test/sql/*.test                     haybarn sqllogictest E2E (authoritative); fixtures via from_hex()
ci/                                 run-integration.sh + preprocess-require.awk + check-version.sh
```

Pattern: all correctness lives in `asn1-core` (pure, unit-tested); the worker is
a thin Arrow marshaller.

## Design decisions (read before changing behavior)

1. **Own TLV codec, not `rasn`.** The generic reader is hand-written for total
   panic-safety (the zero-panic proptest gate) and full control of the
   error-`kind` taxonomy, bounded recursion/alloc, dump rendering, and BER
   indefinite/constructed-string handling. The structural decoders **navigate the
   same `Tlv` tree** (by tag/index) rather than pulling in the `rasn-*` typed
   crates — uniform, and every access is an explicit `Option`, so a malformed
   module blob degrades to `None`/`{error}` instead of panicking.

2. **`decode` returns JSON, not a dynamic STRUCT.** A VGI `on_bind` must fix the
   output type before seeing any data, so true per-blob STRUCT inference is
   impossible to do stably. JSON is the spec's documented stable-column choice
   (`mode := 'json'` / heterogeneous fallback). `mode='tlv'` returns the flat
   node list as JSON. The `*_decode` structural projections likewise return JSON;
   the fixed-schema functions (`well_formed`, `tlv`, `oids`, `krb_ticket`,
   `pkcs8_info`, `cms_certs`, `cms_content`, table fns) return real types.

3. **Table functions take a LITERAL/scalar blob, not a LATERAL column.** The vgi
   extension's table-function binder rejects correlated `LATERAL f(t.col)`
   columns ("only supports literals as parameters"), and `register_table_in_out`
   delivers the literal via `params.arguments` (not an input column) — reading
   `batch.column(0)` panics for a literal call. So the fan-outs are **producer
   `TableFunction`s** reading `const_blob(&args)` (position 0), exactly like
   `pem_decode`. For bulk per-row work over a column, callers use the scalar
   `*_decode` JSON functions. This is a vgi-extension limitation, documented in
   the README. (A `table_in_out` attempt was reverted for this reason.)

4. **No scan state, no secrets, no network.** Pure scalar/table compute over the
   input. **No crypto verification/decryption** anywhere; PKCS#8/#12 never
   surface plaintext key material. `cms_signers.signer_cert_sha256` /
   `pkcs12_bags.cert_sha256` are the SHA-256 join keys to `vgi-x509`.

## Sharp edges

- **`from_hex()` fixtures.** The `.test` files pass blobs as `from_hex('…')` so
  the suite needs no binary files. `LOAD vgi` (never `require vgi`),
  `require-env VGI_ASN1_WORKER`, `SET search_path='asn1.main'`, then `USE memory`
  + `DETACH asn1` at the end.
- **Optional 2nd scalar arg = an arity overload.** DuckDB scalars are positional
  only, so `decode`/`dump`/`is_valid`/`reencode` register both a 1-arg and a
  2-arg variant (`{ two: bool }`), reading the const at position 1. A `pos = -1`
  named const is silently dropped by the binder.
- **OCTET STRING values are base64url** in the generic `decode_value` (binary-
  safe). SNMP/LDAP text fields are read via `security::as_str`, which falls back
  to UTF-8/Latin-1 for OCTET STRING and context-implicit strings.
- **Logs → stderr** (stdout is the Arrow-IPC channel). Catalog name defaults to
  `asn1` via `VGI_WORKER_CATALOG_NAME`.

## Build & test

```sh
cargo test                                       # unit + vectors + proptest (zero-panic)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
HAYBARN_UNITTEST=$(which haybarn-unittest) WORKER_BIN=$PWD/target/release/asn1-worker \
  TRANSPORT=subprocess ci/run-integration.sh    # E2E (also http / unix)
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/build/test, the `test/sql/*`
suite over the subprocess/http/unix × ubuntu/macos matrix, and the
`Query-farm/vgi-lint-check@v1` metadata gate at `--fail-on info`.
