//! `ldap_messages(blob) -> TABLE(message_id, op, dn, scope, filter, attributes,
//! result_code, matched_dn, diagnostic)` — fan a segment (one or more
//! LDAPMessages) into one row each.

use std::sync::Arc;

use arrow_array::builder::{Int32Builder, ListBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use asn1_core::security::ldap;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use super::{commented, const_blob, one};

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented("message_id", DataType::Int32, "The LDAP messageID."),
        commented(
            "op",
            DataType::Utf8,
            "The protocolOp name, e.g. SearchRequest.",
        ),
        commented("dn", DataType::Utf8, "The base/object DN (op-dependent)."),
        commented("scope", DataType::Utf8, "Search scope (SearchRequest)."),
        commented(
            "filter",
            DataType::Utf8,
            "RFC 4515 filter string (SearchRequest).",
        ),
        Field::new(
            "attributes",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            true,
        ),
        commented(
            "result_code",
            DataType::Utf8,
            "Named LDAPResult code (result ops).",
        ),
        commented("matched_dn", DataType::Utf8, "The matchedDN (result ops)."),
        commented(
            "diagnostic",
            DataType::Utf8,
            "The diagnosticMessage (result ops).",
        ),
    ]))
}

pub struct LdapMessages;

impl TableFunction for LdapMessages {
    fn name(&self) -> &str {
        "ldap_messages"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "LDAP Messages",
            "Fan a blob (one segment may carry several LDAPMessages, RFC 4511) into one row per \
             message: message_id, the protocolOp op name, plus dn / scope / RFC 4515 filter / \
             attributes / result fields as applicable. The blob argument is a literal/scalar; for \
             bulk per-row shredding of a column use the scalar ldap_decode().",
            "Shred LDAP messages into rows. Columns: `message_id`, `op`, `dn`, `scope`, `filter`, \
             `attributes`, `result_code`, `matched_dn`, `diagnostic`.",
            "ldap, ldap_messages, bind, search, filter, rfc 4511, rfc 4515, shred",
            "table/ldap_messages.rs",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n|---|---|---|\n\
             | `message_id` | INTEGER | LDAP messageID. |\n\
             | `op` | VARCHAR | protocolOp name. |\n\
             | `dn` | VARCHAR | base/object DN. |\n\
             | `scope` | VARCHAR | search scope. |\n\
             | `filter` | VARCHAR | RFC 4515 filter. |\n\
             | `attributes` | VARCHAR[] | requested/returned attributes. |\n\
             | `result_code` | VARCHAR | named result code. |\n\
             | `matched_dn` | VARCHAR | matchedDN. |\n\
             | `diagnostic` | VARCHAR | diagnosticMessage. |"
                .into(),
        ));
        FunctionMetadata {
            description: "Fan a blob's LDAP messages into one row each".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "blob",
            0,
            "any",
            "An LDAP wire blob (literal BLOB/VARCHAR or scalar subquery), possibly several \
             LDAPMessages back-to-back.",
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
        let mut message_id = Int32Builder::new();
        let mut op = StringBuilder::new();
        let mut dn = StringBuilder::new();
        let mut scope = StringBuilder::new();
        let mut filter = StringBuilder::new();
        let mut attributes = ListBuilder::new(StringBuilder::new());
        let mut result_code = StringBuilder::new();
        let mut matched_dn = StringBuilder::new();
        let mut diagnostic = StringBuilder::new();

        for r in ldap::ldap_messages(&bytes) {
            match r.message_id {
                Some(m) => message_id.append_value(m as i32),
                None => message_id.append_null(),
            }
            op.append_value(&r.op);
            dn.append_option(r.dn.as_deref());
            scope.append_option(r.scope.as_deref());
            filter.append_option(r.filter.as_deref());
            for a in &r.attributes {
                attributes.values().append_value(a);
            }
            attributes.append(true);
            result_code.append_option(r.result_code.as_deref());
            matched_dn.append_option(r.matched_dn.as_deref());
            diagnostic.append_option(r.diagnostic.as_deref());
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(message_id.finish()),
            Arc::new(op.finish()),
            Arc::new(dn.finish()),
            Arc::new(scope.finish()),
            Arc::new(filter.finish()),
            Arc::new(attributes.finish()),
            Arc::new(result_code.finish()),
            Arc::new(matched_dn.finish()),
            Arc::new(diagnostic.finish()),
        ];
        let batch = RecordBatch::try_new(params.output_schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(one(batch))
    }
}
