//! The `asn1` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'asn1' (TYPE vgi, LOCATION '…')`). It decodes generic ASN.1
//! BER/CER/DER and the named security/telecom modules (SNMP, Kerberos, LDAP,
//! CMS/PKCS#7, PKCS#8/#12, OCSP) into DuckDB JSON / STRUCT / LIST / table rows,
//! under the catalog `asn1`, schema `main`:
//!
//! ```sql
//! ATTACH 'asn1' (TYPE vgi, LOCATION './target/release/asn1-worker');
//! SET search_path = 'asn1.main';
//!
//! SELECT decode(from_hex('3003020105'));        -- '[5]'
//! SELECT to_json(payload), dump(payload) FROM read_blob('a.der');
//! SELECT oids(data) FROM blobs;                 -- OID inventory
//! SELECT * FROM cms_blobs b, LATERAL cms_signers(b.data) s;
//! ```
//!
//! The pure codec + structural decoders live in the `asn1-core` crate; the
//! `scalar/`, `table/`, and `table_in_out/` modules are thin Arrow adapters.

mod arrow_io;
mod meta;
mod scalar;
mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `asn1_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata surfaced to DuckDB and the `vgi-lint` linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Generic ASN.1 BER/CER/DER decode plus SNMP/Kerberos/LDAP/CMS/PKCS/OCSP structural \
             decoders for SQL."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "ASN.1 BER/DER Decoder & Security-Payload Shredder".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "asn.1, asn1, ber, cer, der, tlv, object identifier, oid, decode, asn1parse, \
                     dumpasn1, pem, snmp, varbind, kerberos, ldap, cms, pkcs7, pkcs8, pkcs12, \
                     ocsp, x509, signed data, signer, certificate, revocation, security, pki",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Decode generic ASN.1 BER/CER/DER blobs and the named security/telecom modules \
                 directly in SQL. Generic scalars: decode (to JSON), to_json (self-describing \
                 JSON), dump (openssl/dumpasn1-style text), tlv (flat node list), at_path, oids \
                 (OID inventory), oid_name/oid (registry lookup), is_valid / well_formed \
                 (robust validation), to_der / reencode (canonicalize), pem_label. Structural \
                 decoders: snmp_decode + snmp_varbinds, krb_decode + krb_ticket, ldap_decode + \
                 ldap_messages, cms_decode + cms_signers + cms_certs + cms_content, pkcs8_info + \
                 pkcs12_bags, ocsp_decode. cms_signers exposes signer_cert_sha256 to join to \
                 vgi-x509. Every function is robust per row — a malformed blob yields an error \
                 value / NULL, never crashing the scan — and no crypto is verified (structural \
                 decode only). Use it to triage, inventory, and shred PKI/security binary \
                 payloads at scale."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# asn1 — ASN.1 BER/DER Decoding & Security-Payload Shredding in SQL\n\n\
                 **Decode generic ASN.1 (BER/CER/DER) and the security/telecom modules that ride \
                 on it — SNMP, Kerberos, LDAP, CMS/PKCS#7, PKCS#8/#12, OCSP — directly in DuckDB \
                 SQL.** Walk any DER blob into a typed JSON tree (`decode`/`to_json`), dump it \
                 `openssl asn1parse`-style (`dump`), inventory every OBJECT IDENTIFIER (`oids`), \
                 and shred the named modules into joinable rows (`cms_signers`, `snmp_varbinds`, \
                 `ldap_messages`, …). The flagship pairing is **vgi-x509**: `cms_signers` and \
                 `pkcs12_bags` surface `signer_cert_sha256` / `cert_sha256` so you can join \
                 embedded certificates straight to cert metadata and revocation.\n\n\
                 The worker is **structural-decode only** — signatures, MACs, and encrypted parts \
                 are surfaced (algorithm OID + bytes) but never verified or decrypted, and PKCS#8/\
                 #12 never expose plaintext key material. Decoding is robust against hostile input: \
                 bounded recursion and allocation, and per-row error capture (`well_formed` \
                 classifies the failure `kind`) so a malformed blob never aborts a scan.\n\n\
                 Part of the [Query.Farm](https://query.farm) VGI ecosystem — see the \
                 [repository](https://github.com/Query-farm/vgi-asn1) for the full function \
                 catalog and examples."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "resolve_oid_name",
                        "What is the friendly name of the OID 1.2.840.113549.1.1.11? Return a \
                         single column named name.",
                        "SELECT asn1.main.oid_name('1.2.840.113549.1.1.11') AS name",
                    ),
                    (
                        "name_to_oid",
                        "What is the dotted OID for the algorithm name \
                         'sha256WithRSAEncryption'? Return a single column named oid.",
                        "SELECT asn1.main.oid('sha256WithRSAEncryption') AS oid",
                    ),
                    (
                        "decode_small_der",
                        "Decode the DER blob whose hex is '3003020105' to JSON. Return a single \
                         column named j.",
                        "SELECT asn1.main.decode(from_hex('3003020105')) AS j",
                    ),
                    (
                        "validity_check",
                        "Is the DER blob with hex '300502' well-formed? Return a single boolean \
                         column named ok.",
                        "SELECT (asn1.main.well_formed(from_hex('300502'))).ok AS ok",
                    ),
                    (
                        "worker_version",
                        "What version of the asn1 worker is running? Return a single row with one \
                         column named version.",
                        "SELECT asn1.main.asn1_version() AS version",
                    ),
                ]),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-asn1/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-asn1/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-asn1".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "Generic ASN.1 decode + SNMP/Kerberos/LDAP/CMS/PKCS/OCSP structural decoders."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "ASN.1 — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "asn1, ber, der, decode, to_json, dump, tlv, oids, well_formed, snmp, \
                         kerberos, ldap, cms, pkcs, ocsp, security, pki",
                    ),
                ),
                ("domain".to_string(), "security-and-pki".to_string()),
                ("category".to_string(), "binary-decode".to_string()),
                ("topic".to_string(), "asn1".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "Generic ASN.1 BER/DER decode (decode, to_json, dump, tlv, oids, is_valid, \
                     well_formed, to_der, reencode, pem_label) and structural decoders for SNMP, \
                     Kerberos, LDAP, CMS/PKCS#7, PKCS#8/#12, and OCSP."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `asn1` worker: the generic BER/DER codec scalars \
                     plus the SNMP/Kerberos/LDAP/CMS/PKCS/OCSP structural decoders and the \
                     `pem_decode` / `snmp_varbinds` / `ldap_messages` / `cms_signers` / \
                     `pkcs12_bags` table functions."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT asn1.main.decode(from_hex('3003020105'));\n\
                     SELECT asn1.main.to_json(from_hex('3003020105'));\n\
                     SELECT asn1.main.dump(from_hex('3003020105'));\n\
                     SELECT asn1.main.oid_name('1.2.840.113549.1.1.11');\n\
                     SELECT (asn1.main.well_formed(from_hex('300502'))).ok;\n\
                     SELECT asn1.main.is_valid(from_hex('020105'), 'der');"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "asn1");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "asn1".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
