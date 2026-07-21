<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# ASN.1 BER/DER Decoding & Security-Payload Shredding in DuckDB

> **vgi-asn1** · a [Query.Farm](https://query.farm) VGI worker

A [VGI](https://query.farm) worker that decodes generic **ASN.1** **BER / CER / DER**
blobs into DuckDB JSON / `STRUCT` / `LIST` / table rows, with an **OID → name
registry** and first-class structural decoders for the security/telecom payloads
that ride on ASN.1: **SNMP** PDUs, **Kerberos** tickets, **LDAP** wire messages,
**CMS / PKCS#7**, **PKCS#8 / PKCS#12**, and **OCSP**. Pure in-engine scalar/table
compute over a `BLOB` column — no network, no state, **no crypto verification**
(structural decode only). It is the structural-decode sibling to `vgi-x509`
(certs + TLS) and `vgi-cbor` (CBOR/COSE).

```sql
LOAD vgi;
ATTACH 'asn1' (TYPE vgi, LOCATION './target/release/asn1-worker');
SET search_path = 'asn1.main';

-- Decode any BER/DER blob to JSON, to self-describing JSON, and to a dump.
SELECT decode(from_hex('3003020105'));                 -- '[5]'
SELECT to_json(payload), dump(payload) FROM read_blob('s3://pki/*.der');

-- Resolve OIDs and inventory every OID in a blob.
SELECT oid_name('1.2.840.113549.1.1.11');              -- 'sha256WithRSAEncryption'
SELECT oids(data) FROM blobs;                          -- LIST<STRUCT(oid,name,path)>

-- Robust, verify-free triage: well-formedness with a classified failure kind.
SELECT well_formed(data) FROM unknown_blobs WHERE NOT (well_formed(data)).ok;

-- Shred a CMS SignedData and join embedded signer certs to vgi-x509.
SELECT s.digest_alg, s.sig_alg, s.signing_time, s.signer_cert_sha256
FROM asn1.main.cms_signers(read_blob('codesign.p7s')) s;
```

## What it does

| Area | SQL surface | kind |
| --- | --- | --- |
| Generic decode | `decode(blob[,mode])`, `to_json(blob)`, `dump(blob[,format])` | scalar → JSON / text |
| TLV walk | `tlv(blob)` → `LIST<STRUCT(path,class,tag,tag_name,constructed,header_len,len,value)>`, `at_path(blob,path)` | scalar |
| OIDs | `oids(blob)` → `LIST<STRUCT(oid,name,path)>`, `oid_name(oid)`, `oid(name)` | scalar |
| Validate | `is_valid(blob[,rules])`, `well_formed(blob)` → `STRUCT(ok,error,kind)` | scalar |
| Re-encode | `to_der(blob)`, `reencode(blob[,rules])` (canonical DER) | scalar |
| PEM | `pem_decode(text)` → `TABLE(idx,label,der)`, `pem_label(text)` | table / scalar |
| SNMP | `snmp_decode(blob)`, `snmp_varbinds(blob)` → `TABLE` | scalar / table |
| Kerberos | `krb_decode(blob)`, `krb_ticket(blob)` → `STRUCT` | scalar |
| LDAP | `ldap_decode(blob)`, `ldap_messages(blob)` → `TABLE` | scalar / table |
| CMS / PKCS#7 | `cms_decode(blob)`, `cms_signers(blob)` → `TABLE`, `cms_certs(blob)` → `LIST<BLOB>`, `cms_content(blob)` → `BLOB` | scalar / table |
| PKCS#8/#12 | `pkcs8_info(blob)` → `STRUCT`, `pkcs12_bags(blob)` → `TABLE` | scalar / table |
| OCSP | `ocsp_decode(blob)` | scalar |

The worker build version is published as catalog metadata —
`SELECT implementation_version FROM vgi_catalogs('<location>')` — rather than as a
scalar function.

`decode` returns a stable **JSON** column (the spec's stable-column choice): mode
`auto`/`struct`/`json` give the clean nested typed projection (SEQUENCE→array,
primitives→their scalar value, OID→dotted, time→ISO-8601, OCTET/BIT STRING→
base64url) and mode `tlv` gives the flat TLV-node list. The `*_decode` structural
projections also return JSON; the typed `STRUCT` / `TABLE` / `LIST` functions
(`well_formed`, `tlv`, `oids`, `krb_ticket`, `pkcs8_info`, `cms_certs`,
`cms_content`, and the table functions) return real DuckDB types.

## Robustness

Every decoder is **panic-free on arbitrary input** — bounded recursion
(`max_nesting = 256`) and bounded allocation (a TLV length may never exceed the
bytes actually present), and per-row error capture. A malformed blob yields an
`{error, kind}` JSON value (or `NULL` / `well_formed(ok=false)`), never crashing
the scan. `well_formed().kind` classifies the failure: `truncated`,
`trailing-bytes`, `invalid-tag`, `length-overflow`, `indefinite-in-der`,
`non-canonical`, `bad-time`, `bad-oid`, `bad-utf8`, `nesting-limit`,
`alloc-limit`. A `proptest` gate fuzzes every entry point with random and
truncated bytes and asserts **zero panics**.

**No crypto.** Signatures, MACs, and encrypted parts are surfaced (algorithm OID
+ bytes) but never verified or decrypted; PKCS#8/#12 never surface plaintext key
material. `cms_signers.signer_cert_sha256` and `pkcs12_bags.cert_sha256` are the
join keys to a `vgi-x509` fingerprint.

## Build & run

```sh
cargo build --release --bin asn1-worker
duckdb -c "LOAD vgi;
           ATTACH 'asn1' (TYPE vgi, LOCATION './target/release/asn1-worker');
           SELECT asn1.main.oid_name('2.5.4.3');"     -- id-at-commonName
```

## Test

```sh
cargo test                                  # unit + golden vectors + proptest (zero-panic gate)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
make test-sql                               # DuckDB sqllogictest E2E over all transports
```

The E2E suite (`test/sql/*.test`) runs the worker through the real DuckDB `vgi`
extension over the **subprocess + unix + HTTP** transport matrix via
`haybarn-unittest` (see `ci/`).

## Notes & limitations

- The vgi extension's table-function binder accepts **literal / scalar**
  parameters — it rejects a correlated `LATERAL f(t.col)` column. For bulk
  per-row shredding over a `BLOB` column, use the scalar `*_decode` JSON
  functions (which run per row); the table functions (`snmp_varbinds`,
  `ldap_messages`, `cms_signers`, `pkcs12_bags`, `pem_decode`) shred a single
  literal/scalar blob into typed rows.
- The OID registry is assembled from permissive public sources (RustCrypto /
  IANA-style names); Gutmann's `dumpasn1.cfg` is **not** bundled — the `dumpasn1`
  dump *format* is reproduced, names come from the bundled registry only.

The `asn1` worker is open source (MIT) and part of the
[Query.Farm](https://query.farm) VGI ecosystem — see the
[source repository](https://github.com/Query-farm/vgi-asn1).

## License

MIT — Copyright 2026 Query Farm LLC.
