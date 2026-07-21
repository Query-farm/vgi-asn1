//! `snmp_varbinds(blob) -> TABLE(request_id, pdu_type, oid, oid_name, type, value)`
//! — fan one SNMP PDU (a literal/scalar blob) into one row per varbind.

use std::sync::Arc;

use arrow_array::builder::{Int32Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use asn1_core::security::snmp;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use super::{commented, const_blob, one};

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "request_id",
            DataType::Int32,
            "The PDU request-id (NULL for v1 traps).",
        ),
        commented(
            "pdu_type",
            DataType::Utf8,
            "The PDU type, e.g. GetResponse, SNMPv2-Trap.",
        ),
        commented("oid", DataType::Utf8, "The varbind OID, dotted-decimal."),
        commented(
            "oid_name",
            DataType::Utf8,
            "The resolved OID name (NULL if unknown).",
        ),
        commented(
            "type",
            DataType::Utf8,
            "The SMI value type, e.g. Counter32, TimeTicks.",
        ),
        commented("value", DataType::Utf8, "The varbind value as JSON."),
    ]))
}

pub struct SnmpVarbinds;

impl TableFunction for SnmpVarbinds {
    fn name(&self) -> &str {
        "snmp_varbinds"
    }

    fn metadata(&self) -> FunctionMetadata {
        let ex_sql = "SELECT oid, oid_name, type \
                      FROM asn1.main.snmp_varbinds(from_hex('302e02010104067075626c6963a2210201\
                      010201000201003016301406082b060102010101000408526f757465724f53')) \
                      ORDER BY oid;";
        let ex_desc = "Shred an SNMP v2c GetResponse into its varbinds and project each OID, \
                       resolved name, and SMI type.";
        let mut tags = crate::meta::object_tags(
            "SNMP Varbinds",
            "Fan one SNMP PDU (RFC 1157/3416) into one row per varbind: the PDU request_id and \
             pdu_type, then each varbind's OID, resolved oid_name, SMI type, and JSON value. The \
             blob argument is a literal/scalar; for bulk per-row shredding of a column use the \
             scalar snmp_decode().",
            "Shred an SNMP PDU into one row per varbind. Columns: `request_id`, `pdu_type`, \
             `oid`, `oid_name`, `type`, `value`.",
            "snmp, varbind, snmp_varbinds, oid, mib, trap, pdu, shred, rfc 3416",
            "table/snmp_varbinds.rs",
            crate::meta::CAT_SECURITY,
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&[
                (
                    "request_id",
                    "INTEGER",
                    "The PDU request-id (NULL for v1 traps).",
                ),
                (
                    "pdu_type",
                    "VARCHAR",
                    "The PDU type, e.g. GetResponse, SNMPv2-Trap.",
                ),
                ("oid", "VARCHAR", "The varbind OID, dotted-decimal."),
                (
                    "oid_name",
                    "VARCHAR",
                    "The resolved OID name (NULL if unknown).",
                ),
                (
                    "type",
                    "VARCHAR",
                    "The SMI value type, e.g. Counter32, TimeTicks.",
                ),
                ("value", "VARCHAR", "The varbind value as JSON."),
            ]),
        ));
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&[(ex_desc, ex_sql)]),
        ));
        FunctionMetadata {
            description: "Fan an SNMP PDU into one row per varbind".into(),
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
        vec![ArgSpec::const_arg(
            "blob",
            0,
            "any",
            "An SNMP message payload (a literal value or scalar subquery). Fans into one row \
             per varbind.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let bytes = const_blob(&params.arguments);
        let mut request_id = Int32Builder::new();
        let mut pdu_type = StringBuilder::new();
        let mut oid = StringBuilder::new();
        let mut oid_name = StringBuilder::new();
        let mut ty = StringBuilder::new();
        let mut value = StringBuilder::new();

        if let Some(msg) = snmp::decode_message(&bytes) {
            for vb in &msg.varbinds {
                match msg.request_id {
                    Some(r) => request_id.append_value(r as i32),
                    None => request_id.append_null(),
                }
                pdu_type.append_value(&msg.pdu_type);
                oid.append_value(&vb.oid);
                oid_name.append_option(vb.oid_name.as_deref());
                ty.append_value(&vb.type_name);
                value.append_value(&vb.value_json);
            }
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(request_id.finish()),
            Arc::new(pdu_type.finish()),
            Arc::new(oid.finish()),
            Arc::new(oid_name.finish()),
            Arc::new(ty.finish()),
            Arc::new(value.finish()),
        ];
        let batch = RecordBatch::try_new(params.output_schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(one(batch))
    }
}
