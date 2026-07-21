//! Structural-decoder scalars: the `*_decode` JSON projections plus the typed
//! `krb_ticket` / `pkcs8_info` structs, `cms_certs` (`LIST<BLOB>`), and
//! `cms_content` (BLOB).

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, BooleanBuilder, Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use asn1_core::security::{cms, kerberos, ldap, ocsp, pkcs, snmp};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{blob_bytes, build_blob_list};

// --- JSON `*_decode` scalars via the shared macro ---

json_blob_scalar!(
    SnmpDecode,
    "snmp_decode",
    "Decode SNMP Message",
    "Decode an SNMP v1/v2c/v3 message to JSON (version, community, PDU, resolved varbinds).",
    "Decode an SNMP v1/v2c/v3 message (RFC 1157/3416) into a JSON `STRUCT`: version, community, \
     pdu_type, request_id, error_status, error_index, trap fields, and a varbinds list (each \
     with oid, resolved oid_name, SMI type, and value). The signature/auth envelope is not \
     verified. Returns {error} on a non-SNMP blob.",
    "Decode an SNMP PDU to JSON, e.g. `snmp_decode(payload)`.",
    "snmp, snmp_decode, varbind, trap, pdu, oid, mib, rfc 1157, rfc 3416, network management",
    "SELECT asn1.main.snmp_decode(from_hex('302e02010104067075626c6963a2210201010201000201003016301406082b060102010101000408526f757465724f53')) AS msg;",
    "Decode a real SNMP GetResponse (community 'public') into JSON with its resolved varbinds.",
    "scalar/security.rs",
    crate::meta::CAT_SECURITY,
    snmp::snmp_decode
);

json_blob_scalar!(
    KrbDecode,
    "krb_decode",
    "Decode Kerberos Message",
    "Decode a Kerberos V5 message to JSON, dispatched on its [APPLICATION n] message tag.",
    "Decode a Kerberos V5 message (RFC 4120) by dispatching on its [APPLICATION n] tag \
     (Ticket, AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP, KRB-ERROR, …) into a JSON projection. \
     Encrypted parts are left as opaque bytes — nothing is decrypted.",
    "Decode a Kerberos message to JSON, e.g. `krb_decode(blob)`.",
    "kerberos, krb5, krb_decode, ticket, AS-REQ, TGS-REP, KRB-ERROR, rfc 4120",
    "SELECT asn1.main.krb_decode(from_hex('61073005a003020105')) AS msg;",
    "Decode an [APPLICATION 1] Kerberos Ticket (tkt-vno 5) into JSON (msg_type 'Ticket').",
    "scalar/security.rs",
    crate::meta::CAT_SECURITY,
    kerberos::krb_decode
);

json_blob_scalar!(
    LdapDecode,
    "ldap_decode",
    "Decode LDAP Message",
    "Decode the first LDAPMessage of a blob to JSON (message_id, protocolOp, dn/filter/…).",
    "Decode the first LDAPMessage of a blob (RFC 4511) into a JSON projection: message_id, the \
     protocolOp name, plus dn / scope / RFC 4515 filter / attributes / result fields as \
     applicable. Use ldap_messages() to fan a multi-message segment into rows.",
    "Decode an LDAP message to JSON, e.g. `ldap_decode(blob)`.",
    "ldap, ldap_decode, bind, search, filter, rfc 4511, rfc 4515, directory",
    "SELECT asn1.main.ldap_decode(from_hex('3033020102632e040a64633d6578616d706c650a01020a0100020100020100010100a30b040375696404046a646f6530040402636e')) AS msg;",
    "Decode a real LDAP searchRequest into JSON (RFC 4515 filter '(uid=jdoe)').",
    "scalar/security.rs",
    crate::meta::CAT_SECURITY,
    ldap::ldap_decode
);

json_blob_scalar!(
    CmsDecode,
    "cms_decode",
    "Decode CMS / PKCS#7",
    "Decode a CMS / PKCS#7 ContentInfo to JSON (named content_type + dispatched content).",
    "Decode a CMS / PKCS#7 ContentInfo (RFC 5652) into a JSON projection: the named content_type \
     (signedData, envelopedData, TSTInfo, …) and the dispatched content tree. Use cms_signers() / \
     cms_certs() / cms_content() to shred a SignedData. Signatures are surfaced, never verified.",
    "Decode a CMS/PKCS#7 blob to JSON, e.g. `cms_decode(data)`.",
    "cms, pkcs7, cms_decode, signedData, envelopedData, content type, rfc 5652, s/mime, timestamp",
    "SELECT asn1.main.cms_decode(from_hex('301106092a864886f70d010701a00404026869')) AS info;",
    "Decode a minimal CMS ContentInfo (content_type 'id-data') into JSON.",
    "scalar/security.rs",
    crate::meta::CAT_SECURITY,
    cms::cms_decode
);

json_blob_scalar!(
    OcspDecode,
    "ocsp_decode",
    "Decode OCSP Message",
    "Decode an OCSP request or response to JSON (status, responder, per-cert responses).",
    "Decode an OCSP request or response (RFC 6960) into a JSON projection: response_status, \
     producedAt, responder_id, and a responses list (per-cert serial, issuer hashes, cert_status \
     good/revoked/unknown, revocation time/reason, this/next update). Signature surfaced, not \
     verified.",
    "Decode an OCSP message to JSON, e.g. `ocsp_decode(blob)`.",
    "ocsp, ocsp_decode, revocation, cert status, responder, rfc 6960, pki",
    "SELECT asn1.main.ocsp_decode(from_hex('30030a0100')) AS msg;",
    "Decode a minimal OCSPResponse into JSON (response_status 'successful').",
    "scalar/security.rs",
    crate::meta::CAT_SECURITY,
    ocsp::ocsp_decode
);

// --- krb_ticket -> STRUCT ---

fn krb_ticket_fields() -> Fields {
    Fields::from(vec![
        Field::new("tkt_vno", DataType::Int64, true),
        Field::new("realm", DataType::Utf8, true),
        Field::new("sname", DataType::Utf8, true),
        Field::new("name_type", DataType::Utf8, true),
        Field::new("enc_part_etype", DataType::Utf8, true),
        Field::new("enc_part_kvno", DataType::Int64, true),
        Field::new("enc_part_cipher", DataType::Binary, true),
    ])
}

pub struct KrbTicket;

impl ScalarFunction for KrbTicket {
    fn name(&self) -> &str {
        "krb_ticket"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description:
                "Parse the outer Kerberos Ticket (RFC 4120) into a STRUCT(tkt_vno, realm, \
                          sname, name_type, enc_part_etype, enc_part_kvno, enc_part_cipher). The \
                          EncTicketPart stays encrypted (etype named, cipher as BLOB)."
                    .into(),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.krb_ticket(from_hex('61073005a003020105')) AS ticket;"
                    .into(),
                description: "Project the outer [APPLICATION 1] Ticket envelope to a STRUCT (here \
                              tkt_vno = 5; realm/sname/enc-part NULL on this minimal ticket)."
                    .into(),
                expected_output: None,
            }],
            tags: {
                let mut tags = crate::meta::object_tags(
                    "Kerberos Ticket",
                    "Parse the outer Kerberos `Ticket` ([APPLICATION 1], RFC 4120) into a typed \
                     `STRUCT`: ticket version, realm, service principal name + name-type, and the \
                     EncryptedData envelope (named etype, kvno, and the still-encrypted cipher as \
                     a `BLOB` — nothing is decrypted). NULL for a non-Ticket blob.",
                    "Project the outer Kerberos Ticket into a `STRUCT`, e.g. `krb_ticket(blob)`.",
                    "kerberos, ticket, krb_ticket, sname, etype, enc-part, rfc 4120",
                    "scalar/security.rs",
                    crate::meta::CAT_SECURITY,
                );
                tags.push((
                    "vgi.example_queries".to_string(),
                    crate::meta::example_queries_json(&[(
                        "Project the outer [APPLICATION 1] Ticket envelope to a STRUCT (here \
                         tkt_vno = 5; realm/sname/enc-part NULL on this minimal ticket).",
                        "SELECT asn1.main.krb_ticket(from_hex('61073005a003020105')) AS ticket;",
                    )]),
                ));
                tags
            },
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "A Kerberos Ticket ([APPLICATION 1]) DER/BER blob. NULL or a non-Ticket blob yields \
             a NULL struct.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(krb_ticket_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut vno = Int64Builder::new();
        let mut realm = StringBuilder::new();
        let mut sname = StringBuilder::new();
        let mut name_type = StringBuilder::new();
        let mut etype = StringBuilder::new();
        let mut kvno = Int64Builder::new();
        let mut cipher = BinaryBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            let t = match blob_bytes(col, i)? {
                Some(b) => kerberos::krb_ticket(b),
                None => None,
            };
            match t {
                Some(t) => {
                    vno.append_option(t.tkt_vno);
                    realm.append_option(t.realm.as_deref());
                    sname.append_option(t.sname.as_deref());
                    name_type.append_option(t.name_type.as_deref());
                    etype.append_option(t.enc_part_etype.as_deref());
                    kvno.append_option(t.enc_part_kvno);
                    cipher.append_option(t.enc_part_cipher.as_deref());
                    valid.push(true);
                }
                None => {
                    vno.append_null();
                    realm.append_null();
                    sname.append_null();
                    name_type.append_null();
                    etype.append_null();
                    kvno.append_null();
                    cipher.append_null();
                    valid.push(false);
                }
            }
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(vno.finish()),
            Arc::new(realm.finish()),
            Arc::new(sname.finish()),
            Arc::new(name_type.finish()),
            Arc::new(etype.finish()),
            Arc::new(kvno.finish()),
            Arc::new(cipher.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            krb_ticket_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// --- pkcs8_info -> STRUCT ---

fn pkcs8_fields() -> Fields {
    Fields::from(vec![
        Field::new("version", DataType::Int64, true),
        Field::new("algorithm", DataType::Utf8, true),
        Field::new("params", DataType::Utf8, true),
        Field::new("public_key", DataType::Binary, true),
        Field::new("encrypted", DataType::Boolean, false),
        Field::new("kdf", DataType::Utf8, true),
        Field::new("enc_alg", DataType::Utf8, true),
    ])
}

pub struct Pkcs8Info;

impl ScalarFunction for Pkcs8Info {
    fn name(&self) -> &str {
        "pkcs8_info"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Structural PKCS#8 info: STRUCT(version, algorithm, params JSON, \
                          public_key BLOB, encrypted BOOL, kdf, enc_alg). Plaintext private-key \
                          octets are NEVER surfaced; encrypted keys name their PBES2/PBKDF2 OIDs."
                .into(),
            examples: vec![FunctionExample {
                sql:
                    "SELECT asn1.main.pkcs8_info(from_hex('3016020100300d06092a864886f70d0101010500\
                      04026869')) AS info;"
                        .into(),
                description: "Inspect a minimal PKCS#8 PrivateKeyInfo's structure (version 0, \
                              algorithm 'rsaEncryption') without exposing key material."
                    .into(),
                expected_output: None,
            }],
            tags: {
                let mut tags = crate::meta::object_tags(
                    "PKCS#8 Key Info",
                    "Decode a PKCS#8 PrivateKeyInfo (RFC 5208) or EncryptedPrivateKeyInfo into a \
                     typed `STRUCT`: version, the named key algorithm, its params as JSON, an \
                     optional surfaced public key (never the private key), an `encrypted` flag, \
                     and — for encrypted keys — the named PBES2 `kdf` and `enc_alg` OIDs. No \
                     decryption; plaintext key material is never exposed.",
                    "Inspect PKCS#8 key structure (no key material), e.g. `pkcs8_info(blob)`.",
                    "pkcs8, private key, pkcs8_info, encrypted key, pbes2, pbkdf2, rfc 5208, key \
                     info",
                    "scalar/security.rs",
                    crate::meta::CAT_SECURITY,
                );
                tags.push((
                    "vgi.example_queries".to_string(),
                    crate::meta::example_queries_json(&[(
                        "Inspect a minimal PKCS#8 PrivateKeyInfo's structure (version 0, \
                         algorithm 'rsaEncryption') without exposing key material.",
                        "SELECT asn1.main.pkcs8_info(from_hex('3016020100300d06092a864886f70d0101\
                          010500\
                          04026869')) AS info;",
                    )]),
                ));
                tags
            },
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "A PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo DER blob. NULL or a non-PKCS#8 \
             blob yields a NULL struct.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(pkcs8_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut version = Int64Builder::new();
        let mut algorithm = StringBuilder::new();
        let mut p = StringBuilder::new();
        let mut public_key = BinaryBuilder::new();
        let mut encrypted = BooleanBuilder::new();
        let mut kdf = StringBuilder::new();
        let mut enc_alg = StringBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            let info = match blob_bytes(col, i)? {
                Some(b) => pkcs::pkcs8_info(b),
                None => None,
            };
            match info {
                Some(info) => {
                    version.append_option(info.version);
                    algorithm.append_option(info.algorithm.as_deref());
                    p.append_value(&info.params_json);
                    public_key.append_option(info.public_key.as_deref());
                    encrypted.append_value(info.encrypted);
                    kdf.append_option(info.kdf.as_deref());
                    enc_alg.append_option(info.enc_alg.as_deref());
                    valid.push(true);
                }
                None => {
                    version.append_null();
                    algorithm.append_null();
                    p.append_null();
                    public_key.append_null();
                    encrypted.append_value(false);
                    kdf.append_null();
                    enc_alg.append_null();
                    valid.push(false);
                }
            }
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(version.finish()),
            Arc::new(algorithm.finish()),
            Arc::new(p.finish()),
            Arc::new(public_key.finish()),
            Arc::new(encrypted.finish()),
            Arc::new(kdf.finish()),
            Arc::new(enc_alg.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            pkcs8_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// --- cms_certs -> LIST<BLOB> ---

pub struct CmsCerts;

impl ScalarFunction for CmsCerts {
    fn name(&self) -> &str {
        "cms_certs"
    }

    fn metadata(&self) -> FunctionMetadata {
        let ex_sql =
            "SELECT asn1.main.cms_certs(from_hex('301106092a864886f70d010701a00404026869')) \
             AS certs;";
        let ex_desc = "Extract the embedded certificate LIST<BLOB> from a CMS blob (an empty list \
                       for this minimal id-data ContentInfo, which carries no certs).";
        let mut tags = crate::meta::object_tags(
            "CMS Embedded Certificates",
            "Return the list of embedded DER certificates carried in a CMS / PKCS#7 \
             SignedData (RFC 5652) as a `LIST(BLOB)`. Each element is a complete X.509 \
             certificate you can hash (sha256) and join to a vgi-x509 fingerprint, or re-feed \
             to asn1.decode. Empty list for a non-SignedData blob.",
            "Get the embedded CMS certificates as a `LIST(BLOB)`, e.g. `cms_certs(data)`.",
            "cms, pkcs7, cms_certs, embedded certificates, x509, signedData, rfc 5652, chain",
            "scalar/security.rs",
            crate::meta::CAT_SECURITY,
        );
        tags.push((
            "vgi.example_queries".to_string(),
            crate::meta::example_queries_json(&[(ex_desc, ex_sql)]),
        ));
        FunctionMetadata {
            description: "Return the embedded DER certificates of a CMS SignedData as a \
                          LIST(BLOB) — the join key to vgi-x509 (hash each with sha256)."
                .into(),
            return_type: Some(DataType::List(Arc::new(Field::new(
                "item",
                DataType::Binary,
                true,
            )))),
            examples: vec![FunctionExample {
                sql: ex_sql.into(),
                description: ex_desc.into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "A CMS / PKCS#7 SignedData DER blob. Returns its embedded certificates; a \
             non-SignedData blob yields an empty list.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::List(Arc::new(Field::new(
            "item",
            DataType::Binary,
            true,
        )))))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut per_row: Vec<Option<Vec<Vec<u8>>>> = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => per_row.push(Some(cms::cms_certs(b))),
                None => per_row.push(None),
            }
        }
        let out = build_blob_list(&per_row);
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// --- cms_content -> BLOB ---

pub struct CmsContent;

impl ScalarFunction for CmsContent {
    fn name(&self) -> &str {
        "cms_content"
    }

    fn metadata(&self) -> FunctionMetadata {
        let ex_sql =
            "SELECT asn1.main.cms_content(from_hex('301106092a864886f70d010701a00404026869')) \
             AS econtent;";
        let ex_desc = "Extract the encapsulated eContent BLOB from a CMS SignedData (NULL for \
                       this minimal id-data ContentInfo, which wraps no SignedData).";
        let mut tags = crate::meta::object_tags(
            "CMS Encapsulated Content",
            "Return the encapsulated content (`eContent`) bytes of a CMS / PKCS#7 SignedData \
             (RFC 5652) as a `BLOB`. This is the signed payload — often itself a nested CMS or \
             DER structure you can re-feed to asn1.decode. NULL when no eContent is present \
             (detached signature) or the blob is not a SignedData.",
            "Get the CMS signed payload bytes, e.g. `cms_content(data)`.",
            "cms, pkcs7, cms_content, eContent, signed payload, detached, rfc 5652",
            "scalar/security.rs",
            crate::meta::CAT_SECURITY,
        );
        tags.push((
            "vgi.example_queries".to_string(),
            crate::meta::example_queries_json(&[(ex_desc, ex_sql)]),
        ));
        FunctionMetadata {
            description: "Return the encapsulated eContent (BLOB) of a CMS SignedData — often a \
                          nested CMS/DER, re-feed to decode(). NULL when absent."
                .into(),
            return_type: Some(DataType::Binary),
            examples: vec![FunctionExample {
                sql: ex_sql.into(),
                description: ex_desc.into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "A CMS / PKCS#7 SignedData DER blob. Returns its eContent bytes, or NULL when \
             detached / not a SignedData.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Binary))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = BinaryBuilder::new();
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => match cms::cms_content(b) {
                    Some(c) => out.append_value(c),
                    None => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_scalar_blob};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    #[test]
    fn snmp_decode_binds_utf8() {
        assert_eq!(bound_type(&SnmpDecode), DataType::Utf8);
    }

    #[test]
    fn cms_certs_empty_on_non_cms() {
        let out = run_scalar_blob(
            &CmsCerts,
            &[Some(&[0x02, 0x01, 0x05]), None],
            Arguments::default(),
        )
        .unwrap();
        let list = out.as_list::<i32>();
        assert!(!list.is_null(0));
        assert_eq!(list.value(0).len(), 0);
        assert!(list.is_null(1));
    }

    #[test]
    fn pkcs8_struct_nulls_on_junk() {
        let out =
            run_scalar_blob(&Pkcs8Info, &[Some(&[0xff, 0x00])], Arguments::default()).unwrap();
        assert!(out.is_null(0));
    }
}
