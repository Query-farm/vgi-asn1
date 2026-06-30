//! `snmp_varbinds(blob) -> TABLE(request_id, pdu_type, oid, oid_name, type, value)`
//! — fan one SNMP PDU (a literal/scalar blob) into one row per varbind.

use std::sync::Arc;

use arrow_array::builder::{Int32Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use asn1_core::security::snmp;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
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
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n|---|---|---|\n\
             | `request_id` | INTEGER | PDU request-id. |\n\
             | `pdu_type` | VARCHAR | PDU type. |\n\
             | `oid` | VARCHAR | Varbind OID. |\n\
             | `oid_name` | VARCHAR | Resolved OID name. |\n\
             | `type` | VARCHAR | SMI value type. |\n\
             | `value` | VARCHAR | Value as JSON. |"
                .into(),
        ));
        FunctionMetadata {
            description: "Fan an SNMP PDU into one row per varbind".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "blob",
            0,
            "any",
            "An SNMP message blob (a literal BLOB/VARCHAR or scalar subquery). Fans into one row \
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
