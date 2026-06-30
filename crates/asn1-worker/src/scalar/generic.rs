//! Generic-codec scalars: decode/to_json/dump/tlv/at_path/oids/oid_name/oid/
//! is_valid/well_formed/to_der/reencode/pem_label, plus the worker version.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::DataType;
use asn1_core::dump::{dump, DumpFormat};
use asn1_core::tlv::{parse, Rules};
use asn1_core::{decode_json, reencode, tlv_json, tlvlist, to_json, validate};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{
    blob_bytes, build_oid_list, build_tlv_list, oid_list_field, oid_row_fields, text_str,
    tlv_list_field, tlv_row_fields, well_formed_fields,
};

fn rt(e: impl std::fmt::Display) -> RpcError {
    RpcError::runtime_error(e.to_string())
}

// ---- version ----

pub struct Asn1Version;

impl ScalarFunction for Asn1Version {
    fn name(&self) -> &str {
        "asn1_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Returns the asn1 worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.asn1_version();".into(),
                description: "Return the asn1 worker version string.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 Worker Version",
                "Return the semantic version string of the running asn1 worker binary. Useful for \
                 diagnostics and confirming which build is attached.",
                "Return the asn1 worker version, e.g. `asn1_version()` → '0.1.0'.",
                "version, build version, asn1_version, diagnostics, worker version, semver",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let out: ArrayRef = Arc::new(StringArray::from(vec![crate::version(); batch.num_rows()]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out]).map_err(rt)
    }
}

// ---- decode (mode-aware JSON) ----

/// Scalar functions only take positional args in DuckDB, so the optional second
/// const argument is exposed as a distinct arity overload (`two = true`) rather
/// than a named parameter.
pub struct Decode {
    pub two: bool,
}

impl ScalarFunction for Decode {
    fn name(&self) -> &str {
        "decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Decode a BER/CER/DER blob to JSON. mode ∈ {auto, struct, json, tlv}: \
                          auto/struct/json return the nested typed JSON projection; tlv returns \
                          the flat TLV-node list. NULL → NULL; a malformed blob yields {error,kind}."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.decode(payload) FROM read_blob('a.der');".into(),
                description: "Decode a DER blob to a nested JSON tree.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Decode ASN.1",
                "Decode any BER / CER / DER blob into JSON. The optional second argument `mode` is \
                 one of 'auto' (default), 'struct', 'json' — all returning the clean nested typed \
                 projection (SEQUENCE→array, primitives→their scalar value, OID→dotted string, \
                 time→ISO-8601, OCTET/BIT STRING→base64url) — or 'tlv', which returns the flat \
                 list of TLV nodes (path, class, tag, length, value). A stable JSON column type, \
                 so it never aborts a scan: NULL input yields NULL and a malformed blob yields a \
                 JSON object {error, kind} rather than an error.",
                "Decode an ASN.1 blob to JSON, e.g. `decode(payload)` or `decode(payload,'tlv')`.",
                "asn1, decode, ber, der, cer, tlv, parse, to json, struct, blob, binary",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 DER/BER/CER bytes to decode (BLOB, or VARCHAR text holding the bytes).",
        )];
        if self.two {
            specs.push(ArgSpec::const_arg(
                "mode",
                1,
                "varchar",
                "Output shape: 'auto' (default), 'struct', 'json' (the nested typed JSON), or \
                 'tlv' (the flat TLV-node list).",
            ));
        }
        specs
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let mode = params
            .arguments
            .const_str(1)
            .unwrap_or_else(|| "auto".to_string());
        let tlv_mode = mode.trim().eq_ignore_ascii_case("tlv");
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => {
                    let v = if tlv_mode {
                        tlv_json(b)
                    } else {
                        decode_json(b)
                    };
                    out.push(Some(v.to_string()));
                }
                None => out.push(None),
            }
        }
        let arr: ArrayRef = Arc::new(StringArray::from(out));
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- to_json ----

json_blob_scalar!(
    ToJson,
    "to_json",
    "ASN.1 to Self-Describing JSON",
    "Project a BER/CER/DER blob into self-describing JSON: each node carries {class, tag, \
     tag_name, constructed, value}, with OCTET/BIT STRING as base64url, OID as dotted+name, and \
     time as ISO-8601. Always succeeds on a well-formed blob.",
    "Project an ASN.1 blob to self-describing JSON, e.g. `to_json(payload)`.",
    "asn1, to_json, self-describing, ber, der, json, tlv, node, class, tag",
    "SELECT asn1.main.to_json(payload) FROM read_blob('a.der');",
    "Project a DER blob into self-describing JSON.",
    "scalar/generic.rs",
    to_json
);

// ---- dump ----

pub struct Dump {
    pub two: bool,
}

impl ScalarFunction for Dump {
    fn name(&self) -> &str {
        "dump"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Render an indented human-debug TLV dump of a blob. format ∈ {openssl, \
                          dumpasn1}: openssl mirrors `openssl asn1parse`; dumpasn1 mirrors \
                          Gutmann's annotated style with OID names."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.dump(payload) FROM read_blob('a.der');".into(),
                description: "Produce an openssl-asn1parse-style dump.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 Dump",
                "Render a BER/CER/DER blob as an indented human-debug TLV dump — the primary \
                 triage surface, preserving tags, lengths, raw bytes, and indefinite-length \
                 markers. The optional second argument `format` is 'openssl' (default; mirrors \
                 `openssl asn1parse`: offset, depth, header/length, tag name, primitive value) or \
                 'dumpasn1' (Gutmann's annotated indentation, with OID names from the bundled \
                 registry). A malformed blob renders a short parse-error line instead of erroring.",
                "Produce an indented TLV dump of a blob, e.g. `dump(payload)` or \
                 `dump(payload,'dumpasn1')`.",
                "asn1, dump, asn1parse, openssl, dumpasn1, tlv, triage, debug, hex",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 DER/BER/CER bytes to dump (BLOB, or VARCHAR text holding the bytes).",
        )];
        if self.two {
            specs.push(ArgSpec::const_arg(
                "format",
                1,
                "varchar",
                "Dump style: 'openssl' (default, like `openssl asn1parse`) or 'dumpasn1' \
                 (Gutmann's annotated style with OID names).",
            ));
        }
        specs
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let fmt = DumpFormat::parse(
            &params
                .arguments
                .const_str(1)
                .unwrap_or_else(|| "openssl".to_string()),
        );
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => {
                    let text = match parse(b) {
                        Ok(t) => dump(&t, fmt),
                        Err(e) => {
                            format!("<parse error: {} at offset {}>", e.kind.as_str(), e.offset)
                        }
                    };
                    out.push(Some(text));
                }
                None => out.push(None),
            }
        }
        let arr: ArrayRef = Arc::new(StringArray::from(out));
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- tlv (LIST<STRUCT>) ----

pub struct TlvFn;

impl ScalarFunction for TlvFn {
    fn name(&self) -> &str {
        "tlv"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Flatten a blob into a LIST of TLV nodes in document order: \
                          STRUCT(path, class, tag, tag_name, constructed, header_len, len, value \
                          JSON). The raw-structure escape hatch."
                .into(),
            return_type: Some(DataType::List(tlv_list_field())),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.tlv(payload) FROM read_blob('a.der');".into(),
                description: "List every TLV node of a blob.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 TLV Nodes",
                "Flatten a BER/CER/DER blob into a LIST of every TLV node in document order — \
                 STRUCT(path, class, tag, tag_name, constructed, header_len, len, value) where \
                 `path` is a JSONPath-ish locator (e.g. `$.0.2`) and `value` is the node's JSON \
                 value. The escape hatch for callers who want the raw structure without type \
                 inference. Empty list for a malformed blob.",
                "List the TLV nodes of a blob, e.g. `tlv(payload)`.",
                "asn1, tlv, nodes, path, class, tag, length, walk, structure, ber, der",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 DER/BER/CER bytes to walk (BLOB, or VARCHAR text holding the bytes).",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::List(tlv_list_field())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut per_row = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => per_row.push(Some(match parse(b) {
                    Ok(t) => tlvlist::flatten(&t),
                    Err(_) => Vec::new(),
                })),
                None => per_row.push(None),
            }
        }
        let out = build_tlv_list(&per_row);
        let _ = tlv_row_fields(); // keep the schema helper referenced
        RecordBatch::try_new(params.output_schema.clone(), vec![out]).map_err(rt)
    }
}

// ---- at_path ----

pub struct AtPath;

impl ScalarFunction for AtPath {
    fn name(&self) -> &str {
        "at_path"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return the JSON value of the node at a JSONPath-ish `path` (e.g. \
                          '$.0.2') within a blob, or JSON null if the path does not resolve."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.at_path(payload, '$.0') FROM read_blob('a.der');".into(),
                description: "Pull the value at a node path.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 Value at Path",
                "Return the decoded JSON value of the node located at `path` within a BER/CER/DER \
                 blob. `path` is the JSONPath-ish locator produced by `tlv()` (e.g. `$` for the \
                 root, `$.0.2` for the third child of the first child). Returns JSON `null` when \
                 the path does not resolve or the blob is malformed.",
                "Get the value at a node path, e.g. `at_path(payload, '$.0.2')`.",
                "asn1, at_path, path, jsonpath, node, navigate, extract, ber, der",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::any_column(
                "blob",
                0,
                "The ASN.1 DER/BER/CER bytes to navigate (BLOB, or VARCHAR text).",
            ),
            ArgSpec::column_typed(
                "path",
                1,
                DataType::Utf8,
                "A JSONPath-ish node locator, e.g. '$', '$.0', '$.0.2' (as produced by tlv()).",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let path = batch.column(1);
        let rows = batch.num_rows();
        let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
        for i in 0..rows {
            match (blob_bytes(blob, i)?, text_str(path, i)?) {
                (Some(b), Some(p)) => {
                    let v = match parse(b) {
                        Ok(t) => tlvlist::at_path(&t, p),
                        Err(_) => serde_json::Value::Null,
                    };
                    out.push(Some(v.to_string()));
                }
                _ => out.push(None),
            }
        }
        let arr: ArrayRef = Arc::new(StringArray::from(out));
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- oids (LIST<STRUCT>) ----

pub struct Oids;

impl ScalarFunction for Oids {
    fn name(&self) -> &str {
        "oids"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return every OBJECT IDENTIFIER in a blob as a LIST of \
                          STRUCT(oid, name, path) — the OID inventory / join surface."
                .into(),
            return_type: Some(DataType::List(oid_list_field())),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.oids(data) FROM unknown_blobs;".into(),
                description: "Inventory every OID used in a blob.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 OID Inventory",
                "Return every OBJECT IDENTIFIER in a BER/CER/DER blob as a LIST of STRUCT(oid, \
                 name, path): the dotted OID, its friendly name resolved from the bundled \
                 registry (NULL if unknown), and its node path. The inventory / join surface — \
                 e.g. find every blob using a deprecated `sha1WithRSAEncryption` signature. Empty \
                 list for a malformed blob.",
                "Inventory the OIDs in a blob, e.g. `oids(data)`.",
                "asn1, oids, object identifier, inventory, algorithm, signature, audit, join",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 DER/BER/CER bytes to inventory (BLOB, or VARCHAR text).",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::List(oid_list_field())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut per_row = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => per_row.push(Some(match parse(b) {
                    Ok(t) => tlvlist::oids(&t),
                    Err(_) => Vec::new(),
                })),
                None => per_row.push(None),
            }
        }
        let _ = oid_row_fields();
        let out = build_oid_list(&per_row);
        RecordBatch::try_new(params.output_schema.clone(), vec![out]).map_err(rt)
    }
}

// ---- oid_name / oid ----

pub struct OidName;

impl ScalarFunction for OidName {
    fn name(&self) -> &str {
        "oid_name"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Resolve a dotted OID to its friendly name from the bundled registry, or \
                          NULL if unknown."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.oid_name('1.2.840.113549.1.1.11');".into(),
                description: "Resolve an OID to 'sha256WithRSAEncryption'.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "OID → Name",
                "Resolve a dotted OBJECT IDENTIFIER (e.g. '1.2.840.113549.1.1.11') to its friendly \
                 name (e.g. 'sha256WithRSAEncryption') from the bundled registry of signature/digest \
                 algorithms, X.500 attribute types, content types, EKUs, curves, and SNMP/MIB \
                 anchors. Returns NULL for an OID not in the registry. The inverse of oid().",
                "Resolve a dotted OID to a name, e.g. `oid_name('2.5.4.3')` → 'id-at-commonName'.",
                "oid, oid_name, object identifier, name, resolve, registry, algorithm",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "oid",
            0,
            DataType::Utf8,
            "A dotted-decimal OID, e.g. '1.2.840.113549.1.1.11'. Resolved to its friendly name; \
             NULL if not in the registry.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                Some(s) => match asn1_core::oid::name_for(s.trim()) {
                    Some(n) => out.append_value(n),
                    None => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

pub struct OidFn;

impl ScalarFunction for OidFn {
    fn name(&self) -> &str {
        "oid"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Resolve a friendly OID name to its dotted form from the bundled \
                          registry, or NULL if unknown."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.oid('id-at-commonName');".into(),
                description: "Resolve a name to '2.5.4.3'.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Name → OID",
                "Resolve a friendly OID name (e.g. 'sha256WithRSAEncryption', case-insensitive) to \
                 its dotted OBJECT IDENTIFIER (e.g. '1.2.840.113549.1.1.11') from the bundled \
                 registry. Returns NULL for a name not in the registry. The inverse of oid_name().",
                "Resolve a name to a dotted OID, e.g. `oid('id-at-commonName')` → '2.5.4.3'.",
                "oid, name to oid, object identifier, dotted, resolve, registry, lookup",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "name",
            0,
            DataType::Utf8,
            "A friendly OID name, e.g. 'sha256WithRSAEncryption' (case-insensitive). Resolved to \
             its dotted form; NULL if not in the registry.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                Some(s) => match asn1_core::oid::oid_for(s.trim()) {
                    Some(d) => out.append_value(d),
                    None => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- is_valid ----

pub struct IsValid {
    pub two: bool,
}

impl ScalarFunction for IsValid {
    fn name(&self) -> &str {
        "is_valid"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Whether a blob is well-formed under the named encoding rules. rules ∈ \
                          {ber, cer, der} (default der); der/cer enforce canonical constraints. \
                          NULL → NULL; never errors."
                .into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.is_valid(data, 'der') FROM blobs;".into(),
                description: "Check DER well-formedness.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 Valid?",
                "Return whether a blob is well-formed under the named encoding rules. The optional \
                 second argument `rules` is 'der' (default), 'cer', or 'ber'; 'der'/'cer' \
                 additionally enforce canonical constraints (minimal length encoding, no \
                 indefinite length). Cheap and total — a malformed blob returns FALSE, never an \
                 error; NULL input returns NULL.",
                "Check a blob's well-formedness under encoding rules, e.g. `is_valid(data,'der')`.",
                "asn1, is_valid, validate, der, ber, cer, canonical, well-formed",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 bytes to validate (BLOB, or VARCHAR text holding the bytes).",
        )];
        if self.two {
            specs.push(ArgSpec::const_arg(
                "rules",
                1,
                "varchar",
                "Encoding rules to validate against: 'der' (default), 'cer', or 'ber'.",
            ));
        }
        specs
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rules = Rules::parse(
            &params
                .arguments
                .const_str(1)
                .unwrap_or_else(|| "der".to_string()),
        );
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = BooleanBuilder::new();
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => out.append_value(validate::is_valid(b, rules)),
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- well_formed (STRUCT) ----

pub struct WellFormed;

impl ScalarFunction for WellFormed {
    fn name(&self) -> &str {
        "well_formed"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Structured well-formedness of a blob: STRUCT(ok BOOL, error VARCHAR, \
                          kind VARCHAR). kind ∈ {truncated, trailing-bytes, invalid-tag, \
                          length-overflow, indefinite-in-der, non-canonical, bad-time, bad-oid, \
                          bad-utf8, nesting-limit, alloc-limit}. Never errors."
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.well_formed(data) FROM unknown_blobs;".into(),
                description: "Triage well-formedness with a failure kind.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ASN.1 Well-Formed",
                "Return the structured well-formedness of a blob: STRUCT(ok, error, kind). On \
                 failure `ok` is false and `kind` classifies the problem — truncated, \
                 trailing-bytes, invalid-tag, length-overflow, indefinite-in-der, non-canonical, \
                 bad-time, bad-oid, bad-utf8, nesting-limit, or alloc-limit — with a human `error` \
                 message. Total: a malformed (even hostile) blob returns ok=false, never crashing \
                 the scan; NULL input yields a NULL struct.",
                "Triage a blob's well-formedness with a failure kind, e.g. `well_formed(data)`.",
                "asn1, well_formed, validate, error kind, truncated, length overflow, triage, robust",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 bytes to check (BLOB, or VARCHAR text). NULL yields a NULL struct.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(well_formed_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut ok = BooleanBuilder::new();
        let mut error = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut valid = Vec::with_capacity(rows);
        for i in 0..rows {
            match blob_bytes(col, i)? {
                Some(b) => {
                    let wf = validate::well_formed(b);
                    ok.append_value(wf.ok);
                    if wf.error.is_empty() {
                        error.append_null();
                    } else {
                        error.append_value(&wf.error);
                    }
                    if wf.kind.is_empty() {
                        kind.append_null();
                    } else {
                        kind.append_value(&wf.kind);
                    }
                    valid.push(true);
                }
                None => {
                    ok.append_value(false);
                    error.append_null();
                    kind.append_null();
                    valid.push(false);
                }
            }
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ok.finish()),
            Arc::new(error.finish()),
            Arc::new(kind.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            well_formed_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out]).map_err(rt)
    }
}

// ---- to_der / reencode ----

pub struct ToDer;

impl ScalarFunction for ToDer {
    fn name(&self) -> &str {
        "to_der"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Re-encode a BER/CER blob to canonical DER (definite minimal lengths, \
                          sorted SET OF). Idempotent on DER; NULL → NULL; a malformed blob → NULL."
                .into(),
            return_type: Some(DataType::Binary),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.to_der(payload) FROM blobs;".into(),
                description: "Canonicalize captured BER to DER.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Canonicalize to DER",
                "Re-encode a parsed BER / CER blob to canonical DER: definite minimal-length \
                 encodings, indefinite forms collapsed, and SET OF children sorted by their \
                 encoding. Idempotent on DER input and round-trips through decode — useful for \
                 normalizing captured BER before hashing or fingerprinting. NULL or a malformed \
                 blob yields NULL.",
                "Re-encode a blob to canonical DER, e.g. `to_der(payload)`.",
                "asn1, to_der, canonical, der, reencode, normalize, fingerprint, ber to der",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 bytes to canonicalize (BLOB, or VARCHAR text). NULL/malformed → NULL.",
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
                Some(b) => match parse(b) {
                    Ok(t) => out.append_value(reencode::to_der(&t)),
                    Err(_) => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

pub struct Reencode {
    pub two: bool,
}

impl ScalarFunction for Reencode {
    fn name(&self) -> &str {
        "reencode"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Re-encode a parsed blob to a target rules set (currently canonical DER \
                          for any rules value). NULL → NULL; a malformed blob → NULL."
                .into(),
            return_type: Some(DataType::Binary),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.reencode(payload, 'der') FROM blobs;".into(),
                description: "Re-encode to canonical DER.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Re-encode ASN.1",
                "Re-encode a parsed BER / CER / DER blob to a target rules set named by the second \
                 argument `rules` ('der'/'cer'/'ber'). The worker canonicalizes to DER (definite \
                 minimal lengths, sorted SET OF) for any rules value. Round-trips through decode; \
                 NULL or a malformed blob yields NULL.",
                "Re-encode a blob to a rules set, e.g. `reencode(payload, 'der')`.",
                "asn1, reencode, der, ber, cer, canonical, normalize, rules",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "The ASN.1 bytes to re-encode (BLOB, or VARCHAR text). NULL/malformed → NULL.",
        )];
        if self.two {
            specs.push(ArgSpec::const_arg(
                "rules",
                1,
                "varchar",
                "Target encoding rules: 'der' (default), 'cer', or 'ber'. The worker emits \
                 canonical DER for any value.",
            ));
        }
        specs
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
                Some(b) => match parse(b) {
                    Ok(t) => out.append_value(reencode::to_der(&t)),
                    Err(_) => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
    }
}

// ---- pem_label ----

pub struct PemLabel;

impl ScalarFunction for PemLabel {
    fn name(&self) -> &str {
        "pem_label"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return the label of the first PEM block in a text (e.g. 'CERTIFICATE'), \
                          or NULL if there is no PEM block."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT asn1.main.pem_label(armor) FROM pem_texts;".into(),
                description: "Identify a PEM block's label.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "PEM Label",
                "Return the label of the first `-----BEGIN <label>-----` block in a PEM text \
                 (e.g. 'CERTIFICATE', 'PRIVATE KEY'), or NULL when the text contains no PEM block. \
                 Use pem_decode() to split a bundle into its DER blocks.",
                "Get the first PEM block's label, e.g. `pem_label(armor)` → 'CERTIFICATE'.",
                "pem, pem_label, armor, begin, certificate, private key, label",
                "scalar/generic.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "text",
            0,
            DataType::Utf8,
            "PEM-armored text. Returns the first block's label, or NULL if none.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                Some(s) => match asn1_core::pem::pem_label(s) {
                    Some(l) => out.append_value(l),
                    None => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr]).map_err(rt)
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
    fn decode_binds_utf8_and_decodes() {
        assert_eq!(bound_type(&Decode { two: false }), DataType::Utf8);
        let out = run_scalar_blob(
            &Decode { two: false },
            &[Some(&[0x30, 0x03, 0x02, 0x01, 0x2a]), None],
            Arguments::default(),
        )
        .unwrap();
        let s = out.as_string::<i32>();
        assert_eq!(s.value(0), "[42]");
        assert!(out.is_null(1));
    }

    #[test]
    fn well_formed_struct() {
        assert_eq!(
            bound_type(&WellFormed),
            DataType::Struct(well_formed_fields())
        );
        let out = run_scalar_blob(
            &WellFormed,
            &[Some(&[0x02, 0x01, 0x05]), Some(&[0x30, 0x05, 0x02])],
            Arguments::default(),
        )
        .unwrap();
        let s = out.as_struct();
        let ok = s.column(0).as_boolean();
        assert!(ok.value(0));
        assert!(!ok.value(1));
    }

    #[test]
    fn tlv_list_nonempty() {
        let out = run_scalar_blob(
            &TlvFn,
            &[Some(&[0x30, 0x03, 0x02, 0x01, 0x2a])],
            Arguments::default(),
        )
        .unwrap();
        let list = out.as_list::<i32>();
        assert_eq!(list.value(0).len(), 2);
    }
}
