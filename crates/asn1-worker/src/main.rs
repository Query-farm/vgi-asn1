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

use std::sync::Arc;

use vgi::catalog::{CatSchema, CatTable, CatalogModel};
use vgi::constraints::{constraint_record, ConstraintKind, ConstraintRecord};
use vgi::Worker;

/// Worker build version, surfaced as the catalog's `implementation_version`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The catalog-level `vgi.agent_test_tasks` suite exercised by `vgi-lint
/// simulate` / `--ai` (VGI520 coverage + VGI920 pass-rate). Only the prompts
/// are published here; each task's grader (`reference_sql` + `success_criteria`)
/// lives in `vgi-agent-tests.yaml` at the repo root (VGI416). Every worker object
/// is referenced by some task's `reference_sql`, and every `reference_sql` was
/// verified against the live worker so exact-compare grading is sound. Blobs are
/// inlined as `from_hex(...)` so each task is self-contained; JSON-returning
/// decoders are graded on a stable projection (`contains(...)`, `len(...)`, or a
/// single STRUCT field) rather than a formatting-sensitive whole-document match.
fn agent_test_tasks() -> Vec<meta::AgentTask> {
    use meta::AgentTask;

    fn t(name: &'static str, prompt: &'static str) -> AgentTask {
        AgentTask { name, prompt }
    }

    vec![
        t(
            "resolve_oid_name",
            "What is the friendly name of the OBJECT IDENTIFIER 1.2.840.113549.1.1.11? \
             Return a single column named name.",
        ),
        t(
            "name_to_oid",
            "What is the dotted OBJECT IDENTIFIER for the algorithm name \
             'sha256WithRSAEncryption'? Return a single column named oid.",
        ),
        t(
            "decode_small_der",
            "Decode the ASN.1 DER blob whose hex is 3003020105 to its nested typed JSON. \
             Return a single column named j.",
        ),
        t(
            "to_json_shape",
            "Does the self-describing JSON projection of the DER blob \
             301202010506092a864886f70d01010b0c026869 mention the tag name SEQUENCE? \
             Return a single boolean column named ok.",
        ),
        t(
            "dump_has_oid",
            "In the openssl-asn1parse-style text dump of the DER blob \
             301202010506092a864886f70d01010b0c026869, does an OBJECT IDENTIFIER line \
             appear? Return a single boolean column named ok.",
        ),
        t(
            "tlv_node_count",
            "How many TLV nodes does the flat node list of the DER blob \
             301202010506092a864886f70d01010b0c026869 contain? Return a single column \
             named n.",
        ),
        t(
            "oid_inventory_count",
            "How many distinct OBJECT IDENTIFIERs appear in the DER blob \
             301202010506092a864886f70d01010b0c026869? Return a single column named n.",
        ),
        t(
            "value_at_path",
            "What is the value of the node at path '$.0' (the first child) of the DER blob \
             3003020105? Return a single column named v.",
        ),
        t(
            "validity_well_formed",
            "Is the ASN.1 blob with hex 300502 well-formed? Return a single boolean column \
             named ok.",
        ),
        t(
            "is_valid_der",
            "Is the blob with hex 020105 valid under DER encoding rules? Return a single \
             boolean column named ok.",
        ),
        t(
            "canonical_der_to_der",
            "Canonicalize the BER blob 3080040248690000 (indefinite-length) to DER and give \
             the result as a lowercase hex string. Return a single column named der_hex.",
        ),
        t(
            "canonical_der_reencode",
            "Re-encode the BER blob 3080040248690000 to canonical DER and give the result as \
             a lowercase hex string. Return a single column named der_hex.",
        ),
        t(
            "pem_block_label",
            "What is the PEM label of this armored block? Return a single column named label.\n\
             -----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----",
        ),
        t(
            "snmp_community",
            "Does the SNMP message with hex 302e02010104067075626c6963a221020101020100020100\
             3016301406082b060102010101000408526f757465724f53 use the community string \
             'public'? Return a single boolean column named ok.",
        ),
        t(
            "snmp_varbind_oid",
            "For the SNMP message with hex 302e02010104067075626c6963a2210201010201000201003016\
             301406082b060102010101000408526f757465724f53, what OID does its single varbind \
             carry? Return a single column named oid.",
        ),
        t(
            "ldap_filter",
            "Does the LDAP message with hex 3033020102632e040a64633d6578616d706c650a01020a01000\
             20100020100010100a30b040375696404046a646f6530040402636e carry the search filter \
             (uid=jdoe)? Return a single boolean column named ok.",
        ),
        t(
            "ldap_operation",
            "What LDAP operation does the message with hex 3033020102632e040a64633d6578616d706c6\
             50a01020a0100020100020100010100a30b040375696404046a646f6530040402636e contain? \
             Return a single column named op.",
        ),
        t(
            "pem_decode_label",
            "Split this PEM bundle into its blocks and give the label of the block at index 0. \
             Return a single column named label.\n\
             -----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----",
        ),
        t(
            "krb_message_type",
            "Is the Kerberos structure with hex 61073005a003020105 a Ticket? Return a single \
             boolean column named ok.",
        ),
        t(
            "krb_ticket_vno",
            "What is the ticket version number (tkt_vno) of the Kerberos ticket with hex \
             61073005a003020105? Return a single column named vno.",
        ),
        t(
            "cms_content_type",
            "What is the content type of the CMS ContentInfo with hex \
             301106092a864886f70d010701a00404026869? Return a single boolean column named ok \
             that is true when the content type is id-data.",
        ),
        t(
            "cms_signer_digest",
            "For the CMS SignedData with hex 304d0201013100301106092a864886f70d010701a004040268\
             69a0053003020105312c302a020101800401020304300b0609608648016503040201300d06092a86\
             4886f70d01010105000403aabbcc, what named digest algorithm did its signer use? \
             Return a single column named digest_alg.",
        ),
        t(
            "cms_cert_count",
            "How many certificates are embedded in the CMS SignedData with hex \
             304d0201013100301106092a864886f70d010701a00404026869a0053003020105312c302a0201018\
             00401020304300b0609608648016503040201300d06092a864886f70d01010105000403aabbcc? \
             Return a single column named n.",
        ),
        t(
            "cms_econtent_hex",
            "Extract the encapsulated eContent of the CMS SignedData with hex \
             304d0201013100301106092a864886f70d010701a00404026869a0053003020105312c302a0201018\
             00401020304300b0609608648016503040201300d06092a864886f70d01010105000403aabbcc as \
             a lowercase hex string. Return a single column named hexval.",
        ),
        t(
            "pkcs8_algorithm",
            "What named key algorithm does the PKCS#8 PrivateKeyInfo with hex \
             3016020100300d06092a864886f70d010101050004026869 declare? Return a single column \
             named algorithm.",
        ),
        t(
            "ocsp_status",
            "What is the responseStatus of the OCSP response with hex 30030a0100? Return a \
             single boolean column named ok that is true when the status is 'successful'.",
        ),
        t(
            "pkcs12_bag_type",
            "What is the bag type of the single SafeBag in the PKCS#12 PFX with hex \
             3051020103304c06092a864886f70d010701a03f043d303b303906092a864886f70d010701a02c042\
             a30283026060b2a864886f70d010c0a0103a0173015060a2a864886f70d01091601a00704053003020\
             105? Return a single column named bag_type.",
        ),
        t(
            "oid_registry_browse",
            "Browse the OID registry table and give the friendly name the worker assigns to the \
             OBJECT IDENTIFIER 1.2.840.113549.1.1.11. Return a single column named name.",
        ),
    ]
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
                 classifies the failure `kind`) so a malformed blob never aborts a scan."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&agent_test_tasks()),
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
        // The worker build version, surfaced via `catalog_catalogs().implementation_version`
        // (VGI328: publish the version as catalog metadata rather than as a parameterless
        // `asn1_version()` scalar that spends a surface slot duplicating it).
        implementation_version: Some(version().to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            path: Vec::new(),
            comment: Some(
                "Generic ASN.1 decode + SNMP/Kerberos/LDAP/CMS/PKCS/OCSP structural decoders."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "ASN.1 — main".to_string()),
                (
                    "vgi.categories".to_string(),
                    crate::meta::categories_json(),
                ),
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
                    "## The `main` schema\n\n\
                     Everything the `asn1` worker exposes lives here — one place to decode raw \
                     BER/CER/DER bytes and the security and telecom protocols layered on top of \
                     ASN.1.\n\n\
                     **Key concepts**\n\n\
                     - *Generic decode* — walk any DER/BER blob into a typed JSON tree, render it \
                     `openssl asn1parse`-style, flatten it to TLV nodes, or inventory every \
                     OBJECT IDENTIFIER.\n\
                     - *Structural decoders* — shred the named modules (SNMP, Kerberos, LDAP, \
                     CMS/PKCS#7, PKCS#8/#12, OCSP) into joinable rows and JSON projections.\n\
                     - *Validation & canonicalization* — classify malformed input and re-encode \
                     to minimal-length DER, all robust per row: a hostile blob yields an error \
                     value, never a crash.\n\n\
                     **When to use it**\n\n\
                     Reach for this schema to triage, inventory, and join PKI and security binary \
                     payloads at scale — for example lifting embedded certificate hashes so signed \
                     CMS or PKCS#12 material joins straight to [vgi-x509](https://query.farm). No \
                     cryptography is verified or decrypted; this is structural decode only."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    crate::meta::example_queries_json(&[
                        (
                            "Decode a DER `SEQUENCE { INTEGER 5 }` into its nested typed JSON \
                             projection.",
                            "SELECT asn1.main.decode(from_hex('3003020105'));",
                        ),
                        (
                            "Project the same blob into self-describing JSON, one object per TLV \
                             node.",
                            "SELECT asn1.main.to_json(from_hex('3003020105'));",
                        ),
                        (
                            "Render an `openssl asn1parse`-style indented text dump of the blob.",
                            "SELECT asn1.main.dump(from_hex('3003020105'));",
                        ),
                        (
                            "Resolve a dotted OID to its friendly algorithm name \
                             ('sha256WithRSAEncryption').",
                            "SELECT asn1.main.oid_name('1.2.840.113549.1.1.11');",
                        ),
                        (
                            "Triage a truncated blob — `well_formed(...).ok` is false.",
                            "SELECT (asn1.main.well_formed(from_hex('300502'))).ok;",
                        ),
                        (
                            "Validate a bare INTEGER 5 under strict DER encoding rules.",
                            "SELECT asn1.main.is_valid(from_hex('020105'), 'der');",
                        ),
                    ]),
                ),
                (
                    "vgi.executable_examples".to_string(),
                    // Self-contained, must-run walkthrough (verified against the worker).
                    // Blobs are inlined via from_hex() so each statement runs as written.
                    r#"[{"name":"decode_generic","description":"Decode a generic DER SEQUENCE { INTEGER 5 } into its nested typed JSON projection.","sql":"SELECT asn1.main.decode(from_hex('3003020105')) AS decoded"},{"name":"resolve_oid","description":"Resolve a dotted OID to its friendly name from the bundled registry.","sql":"SELECT asn1.main.oid_name('1.2.840.113549.1.1.11') AS name"},{"name":"snmp_to_json","description":"Decode a real SNMP GetResponse (community 'public') into JSON with its resolved varbinds.","sql":"SELECT asn1.main.snmp_decode(from_hex('302e02010104067075626c6963a2210201010201000201003016301406082b060102010101000408526f757465724f53')) AS msg"},{"name":"cms_content_type","description":"Decode a minimal CMS ContentInfo and read its content type.","sql":"SELECT asn1.main.cms_decode(from_hex('301106092a864886f70d010701a00404026869')) AS info"}]"#
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: vec![oid_registry_table()],
        }],
        ..Default::default()
    }
}

/// The browsable `oid_registry` catalog table: the curated OID → name registry,
/// function-backed (no scan arguments) so an agent can `SELECT * FROM
/// asn1.main.oid_registry` without knowing any inputs. Being a real table (not
/// just a table function) it is the worker's directly-scannable entry point
/// (VGI146). Carries its own discovery tags + an analytical example.
fn oid_registry_table() -> CatTable {
    let mut tags = meta::object_tags(
        "ASN.1 OID Name Registry",
        "The complete curated OBJECT IDENTIFIER → friendly-name registry the worker ships, one \
         row per known OID (oid, name). A browsable, no-argument entry point: it lists every OID \
         that oid_name() resolves and oid() looks up, so an agent can learn the vocabulary before \
         decoding any blob.",
        "The curated OID → friendly-name registry as a directly-scannable table (`oid`, `name`). \
         The table form of `oid_name()` / `oid()`.",
        "oid, object identifier, registry, oid name lookup, names, browse, vocabulary, pki",
        "table/oid_registry.rs",
        meta::CAT_GENERIC,
    );
    // Classifying tags, reusing the schema's shared vocabulary (VGI123/VGI132).
    tags.push(("domain".to_string(), "security-and-pki".to_string()));
    tags.push(("topic".to_string(), "asn1".to_string()));
    tags.push((
        "vgi.example_queries".to_string(),
        r#"[{"description":"Resolve one OID to its friendly name by browsing the registry table.","sql":"SELECT name FROM asn1.main.oid_registry WHERE oid = '1.2.840.113549.1.1.11'"},{"description":"Count the digest/signature algorithm OIDs the worker knows whose name mentions 'RSA'.","sql":"SELECT count(*) AS rsa_oids FROM asn1.main.oid_registry WHERE name ILIKE '%rsa%'"}]"#
            .to_string(),
    ));
    let mut t = CatTable::with_function(
        "oid_registry",
        table::oid_registry::schema(),
        Arc::new(table::oid_registry::OidRegistry),
        Some(
            "The curated OBJECT IDENTIFIER → friendly-name registry as a browsable table (oid, \
             name)."
                .to_string(),
        ),
        Some(asn1_core::oid::REGISTRY.len() as i64),
    );
    // Honest constraints: every row has both fields and `oid` is the unique key
    // (the registry resolves each dotted OID to exactly one name).
    t.constraints = [
        ("oid_registry.pk", ConstraintKind::PrimaryKey, "oid"),
        ("oid_registry.oid.not_null", ConstraintKind::NotNull, "oid"),
        (
            "oid_registry.name.not_null",
            ConstraintKind::NotNull,
            "name",
        ),
    ]
    .into_iter()
    .map(|(id, kind, column)| {
        constraint_record(
            &ConstraintRecord::new(&["main"], "oid_registry", id, kind)
                .with_columns(&[&[column]])
                .enforced(),
        )
        .expect("valid constraint record")
    })
    .collect();
    t.tags = tags;
    t
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
