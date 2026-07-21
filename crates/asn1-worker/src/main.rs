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
use vgi::Worker;

/// Worker build version, surfaced as the catalog's `implementation_version`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The catalog-level `vgi.agent_test_tasks` suite exercised by `vgi-lint
/// simulate` / `--ai` (VGI520 coverage + VGI920 pass-rate). Every worker object
/// is referenced by some task's `reference_sql`, and every `reference_sql` was
/// verified against the live worker so exact-compare grading is sound. Blobs are
/// inlined as `from_hex(...)` so each task is self-contained; JSON-returning
/// decoders are graded on a stable projection (`contains(...)`, `len(...)`, or a
/// single STRUCT field) rather than a formatting-sensitive whole-document match.
fn agent_test_tasks() -> Vec<meta::AgentTask> {
    use meta::AgentTask;

    fn t(
        name: &'static str,
        prompt: &'static str,
        reference_sql: &'static str,
        success_criteria: Option<&'static str>,
    ) -> AgentTask {
        AgentTask {
            name,
            prompt,
            reference_sql,
            success_criteria,
            unordered: false,
        }
    }

    vec![
        t(
            "resolve_oid_name",
            "What is the friendly name of the OBJECT IDENTIFIER 1.2.840.113549.1.1.11? \
             Return a single column named name.",
            "SELECT asn1.main.oid_name('1.2.840.113549.1.1.11') AS name",
            Some("The answer is the algorithm name 'sha256WithRSAEncryption'."),
        ),
        t(
            "name_to_oid",
            "What is the dotted OBJECT IDENTIFIER for the algorithm name \
             'sha256WithRSAEncryption'? Return a single column named oid.",
            "SELECT asn1.main.oid('sha256WithRSAEncryption') AS oid",
            Some("The answer is the dotted OID '1.2.840.113549.1.1.11'."),
        ),
        t(
            "decode_small_der",
            "Decode the ASN.1 DER blob whose hex is 3003020105 to its nested typed JSON. \
             Return a single column named j.",
            "SELECT asn1.main.decode(from_hex('3003020105')) AS j",
            Some("The blob is SEQUENCE { INTEGER 5 }; the decoded JSON is the array [5]."),
        ),
        t(
            "to_json_shape",
            "Does the self-describing JSON projection of the DER blob \
             301202010506092a864886f70d01010b0c026869 mention the tag name SEQUENCE? \
             Return a single boolean column named ok.",
            "SELECT contains(asn1.main.to_json(from_hex('301202010506092a864886f70d01010b0c\
             026869')), 'SEQUENCE') AS ok",
            Some("The outermost node is a SEQUENCE, so the answer is true."),
        ),
        t(
            "dump_has_oid",
            "In the openssl-asn1parse-style text dump of the DER blob \
             301202010506092a864886f70d01010b0c026869, does an OBJECT IDENTIFIER line \
             appear? Return a single boolean column named ok.",
            "SELECT contains(asn1.main.dump(from_hex('301202010506092a864886f70d01010b0c026869\
             ')), 'OBJECT IDENTIFIER') AS ok",
            Some(
                "The blob contains an OBJECT IDENTIFIER, so the dump includes one and the \
                  answer is true.",
            ),
        ),
        t(
            "tlv_node_count",
            "How many TLV nodes does the flat node list of the DER blob \
             301202010506092a864886f70d01010b0c026869 contain? Return a single column \
             named n.",
            "SELECT len(asn1.main.tlv(from_hex('301202010506092a864886f70d01010b0c026869'))) \
             AS n",
            Some("The blob is a SEQUENCE with three children, so there are 4 TLV nodes."),
        ),
        t(
            "oid_inventory_count",
            "How many distinct OBJECT IDENTIFIERs appear in the DER blob \
             301202010506092a864886f70d01010b0c026869? Return a single column named n.",
            "SELECT len(asn1.main.oids(from_hex('301202010506092a864886f70d01010b0c026869'))) \
             AS n",
            Some("The blob carries exactly one OID, so the answer is 1."),
        ),
        t(
            "value_at_path",
            "What is the value of the node at path '$.0' (the first child) of the DER blob \
             3003020105? Return a single column named v.",
            "SELECT asn1.main.at_path(from_hex('3003020105'), '$.0') AS v",
            Some("The first child is INTEGER 5, so the value is 5."),
        ),
        t(
            "validity_well_formed",
            "Is the ASN.1 blob with hex 300502 well-formed? Return a single boolean column \
             named ok.",
            "SELECT (asn1.main.well_formed(from_hex('300502'))).ok AS ok",
            Some("The blob is truncated/malformed, so ok is false."),
        ),
        t(
            "is_valid_der",
            "Is the blob with hex 020105 valid under DER encoding rules? Return a single \
             boolean column named ok.",
            "SELECT asn1.main.is_valid(from_hex('020105'), 'der') AS ok",
            Some("It is a well-formed INTEGER 5 in DER, so the answer is true."),
        ),
        t(
            "canonical_der_to_der",
            "Canonicalize the BER blob 3080040248690000 (indefinite-length) to DER and give \
             the result as a lowercase hex string. Return a single column named der_hex.",
            "SELECT lower(hex(asn1.main.to_der(from_hex('3080040248690000')))) AS der_hex",
            Some("Canonical DER of that OCTET STRING 'hi' is 300404024869."),
        ),
        t(
            "canonical_der_reencode",
            "Re-encode the BER blob 3080040248690000 to canonical DER and give the result as \
             a lowercase hex string. Return a single column named der_hex.",
            "SELECT lower(hex(asn1.main.reencode(from_hex('3080040248690000')))) AS der_hex",
            Some("The canonical minimal-length DER re-encoding is 300404024869."),
        ),
        t(
            "pem_block_label",
            "What is the PEM label of this armored block? Return a single column named label.\n\
             -----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----",
            "SELECT asn1.main.pem_label('-----BEGIN CERTIFICATE-----' || chr(10) || 'AQID' || \
             chr(10) || '-----END CERTIFICATE-----') AS label",
            Some("The block label is 'CERTIFICATE'."),
        ),
        t(
            "snmp_community",
            "Does the SNMP message with hex 302e02010104067075626c6963a221020101020100020100\
             3016301406082b060102010101000408526f757465724f53 use the community string \
             'public'? Return a single boolean column named ok.",
            "SELECT contains(asn1.main.snmp_decode(from_hex('302e02010104067075626c6963a221020\
             1010201000201003016301406082b060102010101000408526f757465724f53')), \
             '\"community\":\"public\"') AS ok",
            Some("The community is 'public', so the answer is true."),
        ),
        t(
            "snmp_varbind_oid",
            "For the SNMP message with hex 302e02010104067075626c6963a2210201010201000201003016\
             301406082b060102010101000408526f757465724f53, what OID does its single varbind \
             carry? Return a single column named oid.",
            "SELECT oid FROM asn1.main.snmp_varbinds(from_hex('302e02010104067075626c6963a22102\
             01010201000201003016301406082b060102010101000408526f757465724f53'))",
            Some("The lone varbind is sysDescr.0, OID 1.3.6.1.2.1.1.1.0."),
        ),
        t(
            "ldap_filter",
            "Does the LDAP message with hex 3033020102632e040a64633d6578616d706c650a01020a01000\
             20100020100010100a30b040375696404046a646f6530040402636e carry the search filter \
             (uid=jdoe)? Return a single boolean column named ok.",
            "SELECT contains(asn1.main.ldap_decode(from_hex('3033020102632e040a64633d6578616d70\
             6c650a01020a0100020100020100010100a30b040375696404046a646f6530040402636e')), \
             '(uid=jdoe)') AS ok",
            Some("The filter is (uid=jdoe), so the answer is true."),
        ),
        t(
            "ldap_operation",
            "What LDAP operation does the message with hex 3033020102632e040a64633d6578616d706c6\
             50a01020a0100020100020100010100a30b040375696404046a646f6530040402636e contain? \
             Return a single column named op.",
            "SELECT op FROM asn1.main.ldap_messages(from_hex('3033020102632e040a64633d6578616d70\
             6c650a01020a0100020100020100010100a30b040375696404046a646f6530040402636e'))",
            Some("It is a SearchRequest."),
        ),
        t(
            "pem_decode_label",
            "Split this PEM bundle into its blocks and give the label of the block at index 0. \
             Return a single column named label.\n\
             -----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----",
            "SELECT label FROM asn1.main.pem_decode('-----BEGIN CERTIFICATE-----' || chr(10) || \
             'AQID' || chr(10) || '-----END CERTIFICATE-----')",
            Some("The single block is labelled 'CERTIFICATE'."),
        ),
        t(
            "krb_message_type",
            "Is the Kerberos structure with hex 61073005a003020105 a Ticket? Return a single \
             boolean column named ok.",
            "SELECT contains(asn1.main.krb_decode(from_hex('61073005a003020105')), \
             '\"msg_type\":\"Ticket\"') AS ok",
            Some("The [APPLICATION 1] tag identifies a Ticket, so the answer is true."),
        ),
        t(
            "krb_ticket_vno",
            "What is the ticket version number (tkt_vno) of the Kerberos ticket with hex \
             61073005a003020105? Return a single column named vno.",
            "SELECT (asn1.main.krb_ticket(from_hex('61073005a003020105'))).tkt_vno AS vno",
            Some("The tkt-vno is 5."),
        ),
        t(
            "cms_content_type",
            "What is the content type of the CMS ContentInfo with hex \
             301106092a864886f70d010701a00404026869? Return a single boolean column named ok \
             that is true when the content type is id-data.",
            "SELECT contains(asn1.main.cms_decode(from_hex('301106092a864886f70d010701a004040268\
             69')), '\"content_type\":\"id-data\"') AS ok",
            Some("The content type OID 1.2.840.113549.1.7.1 is id-data, so ok is true."),
        ),
        t(
            "cms_signer_digest",
            "For the CMS SignedData with hex 304d0201013100301106092a864886f70d010701a004040268\
             69a0053003020105312c302a020101800401020304300b0609608648016503040201300d06092a86\
             4886f70d01010105000403aabbcc, what named digest algorithm did its signer use? \
             Return a single column named digest_alg.",
            "SELECT digest_alg FROM asn1.main.cms_signers(from_hex('304d0201013100301106092a8648\
             86f70d010701a00404026869a0053003020105312c302a020101800401020304300b06096086480165\
             03040201300d06092a864886f70d01010105000403aabbcc'))",
            Some("The signer's digest algorithm is sha256."),
        ),
        t(
            "cms_cert_count",
            "How many certificates are embedded in the CMS SignedData with hex \
             304d0201013100301106092a864886f70d010701a00404026869a0053003020105312c302a0201018\
             00401020304300b0609608648016503040201300d06092a864886f70d01010105000403aabbcc? \
             Return a single column named n.",
            "SELECT len(asn1.main.cms_certs(from_hex('304d0201013100301106092a864886f70d010701a0\
             0404026869a0053003020105312c302a020101800401020304300b0609608648016503040201300d06\
             092a864886f70d01010105000403aabbcc'))) AS n",
            Some("Exactly one certificate is embedded, so the answer is 1."),
        ),
        t(
            "cms_econtent_hex",
            "Extract the encapsulated eContent of the CMS SignedData with hex \
             304d0201013100301106092a864886f70d010701a00404026869a0053003020105312c302a0201018\
             00401020304300b0609608648016503040201300d06092a864886f70d01010105000403aabbcc as \
             a lowercase hex string. Return a single column named hexval.",
            "SELECT lower(hex(asn1.main.cms_content(from_hex('304d0201013100301106092a864886f70d\
             010701a00404026869a0053003020105312c302a020101800401020304300b060960864801650304020\
             1300d06092a864886f70d01010105000403aabbcc')))) AS hexval",
            Some("The eContent is the two bytes 'hi' = 6869."),
        ),
        t(
            "pkcs8_algorithm",
            "What named key algorithm does the PKCS#8 PrivateKeyInfo with hex \
             3016020100300d06092a864886f70d010101050004026869 declare? Return a single column \
             named algorithm.",
            "SELECT (asn1.main.pkcs8_info(from_hex('3016020100300d06092a864886f70d0101010500040\
             26869'))).algorithm AS algorithm",
            Some("The key algorithm is rsaEncryption."),
        ),
        t(
            "ocsp_status",
            "What is the responseStatus of the OCSP response with hex 30030a0100? Return a \
             single boolean column named ok that is true when the status is 'successful'.",
            "SELECT contains(asn1.main.ocsp_decode(from_hex('30030a0100')), \
             '\"response_status\":\"successful\"') AS ok",
            Some("responseStatus 0 is 'successful', so ok is true."),
        ),
        t(
            "pkcs12_bag_type",
            "What is the bag type of the single SafeBag in the PKCS#12 PFX with hex \
             3051020103304c06092a864886f70d010701a03f043d303b303906092a864886f70d010701a02c042\
             a30283026060b2a864886f70d010c0a0103a0173015060a2a864886f70d01091601a00704053003020\
             105? Return a single column named bag_type.",
            "SELECT bag_type FROM asn1.main.pkcs12_bags(from_hex('3051020103304c06092a864886f70d\
             010701a03f043d303b303906092a864886f70d010701a02c042a30283026060b2a864886f70d010c0a0\
             103a0173015060a2a864886f70d01091601a00704053003020105'))",
            Some("The lone bag is a certBag."),
        ),
        t(
            "oid_registry_browse",
            "Browse the OID registry table and give the friendly name the worker assigns to the \
             OBJECT IDENTIFIER 1.2.840.113549.1.1.11. Return a single column named name.",
            "SELECT name FROM asn1.main.oid_registry WHERE oid = '1.2.840.113549.1.1.11'",
            Some("The registry maps that OID to 'sha256WithRSAEncryption'."),
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
    t.not_null = vec![0, 1];
    t.primary_key = vec![vec![0]];
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
