//! Composed example queries: each combines two or more of the worker's own
//! objects in one realistic query. Each `(description, sql)` pair is defined
//! once here and referenced from the schema-level `vgi.example_queries` list and
//! from the example list of the object that drives the query (within its first
//! five examples, which is all the `vgi-lint` agent simulator shows).
//!
//! Every query is offline and deterministic (blobs inlined via `from_hex` / PEM
//! literals) and was executed against the worker; `test/sql/composed.test`
//! pins the rows each description claims.

/// A described example: `(description, sql)`.
pub type Example = (&'static str, &'static str);

/// `pem_decode` → `well_formed` + `oids` over each block's DER.
pub const PEM_TRIAGE: Example = (
    "Split a three-block PEM bundle (PRIVATE KEY, PKCS7, CERTIFICATE) and triage each block's \
     DER: well-formedness, the classified failure kind, and how many OIDs it carries. The \
     PRIVATE KEY (1 OID) and PKCS7 (3 OIDs) blocks are well-formed; the CERTIFICATE body is \
     truncated and flagged ok=false with kind 'length-overflow'.",
    "SELECT p.idx, p.label, (asn1.main.well_formed(p.der)).ok AS ok, \
     (asn1.main.well_formed(p.der)).kind AS kind, len(asn1.main.oids(p.der)) AS n_oids \
     FROM asn1.main.pem_decode('-----BEGIN PRIVATE KEY-----' || chr(10) || \
     'MBYCAQAwDQYJKoZIhvcNAQEBBQAEAmhp' || chr(10) || '-----END PRIVATE KEY-----' || chr(10) || \
     '-----BEGIN PKCS7-----' || chr(10) || \
     'ME0CAQExADARBgkqhkiG9w0BBwGgBAQCaGmgBTADAgEFMSwwKgIBAYAEAQIDBDALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEA6q7zA==' \
     || chr(10) || '-----END PKCS7-----' || chr(10) || '-----BEGIN CERTIFICATE-----' || \
     chr(10) || 'MAUC' || chr(10) || '-----END CERTIFICATE-----') AS p ORDER BY p.idx;",
);

/// `pkcs12_bags` joined to the unnested `cms_certs` of a CMS SignedData by SHA-256.
pub const P12_CMS_CERT_MATCH: Example = (
    "Find the certificates a PKCS#12 keystore shares with a CMS SignedData: join the keystore's \
     cert bags (cert_sha256) to the SHA-256 of each certificate embedded in the signed message \
     (cms_certs). Returns the one certBag whose certificate is also embedded in the message.",
    "SELECT b.bag_type, b.cert_sha256 \
     FROM asn1.main.pkcs12_bags(from_hex('3051020103304c06092a864886f70d010701a03f043d303b30390609\
     2a864886f70d010701a02c042a30283026060b2a864886f70d010c0a0103a0173015060a2a864886f70d01091601a0\
     0704053003020105')) AS b \
     JOIN (SELECT unnest(asn1.main.cms_certs(from_hex('304d0201013100301106092a864886f70d010701a004\
     04026869a0053003020105312c302a020101800401020304300b0609608648016503040201300d06092a864886f70d\
     01010105000403aabbcc'))) AS cert) AS c ON sha256(c.cert) = b.cert_sha256 \
     ORDER BY b.cert_sha256;",
);

/// `cms_signers` joined to the `oid_registry` table to recover dotted OIDs.
pub const SIGNER_ALG_OIDS: Example = (
    "Shred a CMS SignedData's signers and join the oid_registry table to recover the dotted OIDs \
     behind the named digest and signature algorithms (sha256 → 2.16.840.1.101.3.4.2.1, \
     rsaEncryption → 1.2.840.113549.1.1.1).",
    "SELECT s.digest_alg, d.oid AS digest_oid, s.sig_alg, g.oid AS sig_oid \
     FROM asn1.main.cms_signers(from_hex('304d0201013100301106092a864886f70d010701a00404026869a005\
     3003020105312c302a020101800401020304300b0609608648016503040201300d06092a864886f70d0101010500\
     0403aabbcc')) AS s \
     LEFT JOIN asn1.main.oid_registry AS d ON d.name = s.digest_alg \
     LEFT JOIN asn1.main.oid_registry AS g ON g.name = s.sig_alg ORDER BY s.signer_sid;",
);

/// `to_der` canonicalization checked with `is_valid` and `decode`.
pub const CANONICALIZE_CHECK: Example = (
    "Canonicalize an indefinite-length BER blob with to_der, then prove the result: is_valid \
     under strict DER is false before and true after, and decode yields the same value for both \
     encodings. The canonical bytes are 300404024869.",
    "SELECT asn1.main.is_valid(b, 'der') AS der_before, hex(asn1.main.to_der(b)) AS der_hex, \
     asn1.main.is_valid(asn1.main.to_der(b), 'der') AS der_after, \
     asn1.main.decode(b) = asn1.main.decode(asn1.main.to_der(b)) AS same_value \
     FROM (SELECT from_hex('3080040248690000') AS b) AS t;",
);

/// All composed examples, in schema-listing order.
pub const ALL: [Example; 4] = [
    PEM_TRIAGE,
    P12_CMS_CERT_MATCH,
    SIGNER_ALG_OIDS,
    CANONICALIZE_CHECK,
];

#[cfg(test)]
mod tests {
    use super::ALL;

    /// Every composed SQL runs verbatim in the haybarn E2E suite, which pins the
    /// rows its description claims; this guards the two against drifting apart.
    #[test]
    fn composed_examples_are_pinned_by_e2e() {
        let suite = include_str!("../../../test/sql/composed.test");
        for (description, sql) in ALL {
            assert!(
                suite.contains(sql),
                "composed example not run verbatim in test/sql/composed.test: {description}"
            );
        }
    }

    /// Each composed SQL is catalog-qualified (VGI505) with no bare `SELECT *` (VGI514).
    #[test]
    fn composed_examples_are_qualified_and_projected() {
        for (_, sql) in ALL {
            assert!(sql.contains("asn1.main."), "{sql}");
            assert!(!sql.contains("SELECT *"), "{sql}");
        }
    }
}
