//! `oid_registry` — the curated OBJECT IDENTIFIER name registry as a browsable
//! table. Unlike the fan-out functions it takes no arguments, so an agent can
//! `SELECT * FROM asn1.main.oid_registry` to see every OID the worker resolves
//! (the reverse of `oid_name()` / `oid()`) without knowing any inputs. Exposed as
//! a function-backed [`CatTable`](vgi::catalog::CatTable) so it is a real,
//! directly-scannable relation.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use super::{commented, one};

/// The `(oid, name)` result schema of the registry table.
pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "oid",
            DataType::Utf8,
            "The dotted-decimal OBJECT IDENTIFIER, e.g. 1.2.840.113549.1.1.11.",
        ),
        commented(
            "name",
            DataType::Utf8,
            "The friendly name the worker resolves the OID to, e.g. sha256WithRSAEncryption.",
        ),
    ]))
}

pub struct OidRegistry;

impl TableFunction for OidRegistry {
    fn name(&self) -> &str {
        "oid_registry"
    }

    fn metadata(&self) -> FunctionMetadata {
        let ex_sql = "SELECT name FROM asn1.main.oid_registry \
                      WHERE oid = '1.2.840.113549.1.1.11';";
        let ex_desc = "Look up a single OID's friendly name by browsing the registry table.";
        let mut tags = crate::meta::object_tags(
            "OID Registry",
            "The complete curated OBJECT IDENTIFIER → friendly-name registry the worker ships, \
             one row per known OID (oid, name). Takes no arguments — a browsable entry point that \
             lists every OID `oid_name()` can resolve and `oid()` can look up, so an agent can \
             discover the vocabulary before decoding any blob.",
            "The curated OID → name registry as a table. Columns: `oid`, `name`.",
            "oid, object identifier, registry, oid name lookup, catalogue, names, browse",
            "table/oid_registry.rs",
            crate::meta::CAT_GENERIC,
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&[
                (
                    "oid",
                    "VARCHAR",
                    "The dotted-decimal OBJECT IDENTIFIER, e.g. 1.2.840.113549.1.1.11.",
                ),
                (
                    "name",
                    "VARCHAR",
                    "The friendly name the worker resolves the OID to.",
                ),
            ]),
        ));
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&[(ex_desc, ex_sql)]),
        ));
        FunctionMetadata {
            description: "The curated OID → friendly-name registry as a table".into(),
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
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let mut oid = StringBuilder::new();
        let mut name = StringBuilder::new();
        for (o, n) in asn1_core::oid::REGISTRY {
            oid.append_value(o);
            name.append_value(n);
        }
        let cols: Vec<ArrayRef> = vec![Arc::new(oid.finish()), Arc::new(name.finish())];
        let batch = RecordBatch::try_new(params.output_schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(one(batch))
    }
}
