//! `pem_decode(text) -> TABLE(idx INTEGER, label VARCHAR, der BLOB)` — split a PEM
//! bundle into its blocks. A producer table function over a constant text arg.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, Int32Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

fn commented(name: &str, ty: DataType, comment: &str) -> Field {
    Field::new(name, ty, true).with_metadata(std::collections::HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

pub fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "idx",
            DataType::Int32,
            "Zero-based index of the PEM block within the bundle.",
        ),
        commented(
            "label",
            DataType::Utf8,
            "The block label, e.g. 'CERTIFICATE' or 'PRIVATE KEY'.",
        ),
        commented(
            "der",
            DataType::Binary,
            "The base64-decoded DER bytes of the block (feed to asn1.decode).",
        ),
    ]))
}

pub struct PemDecode;

impl TableFunction for PemDecode {
    fn name(&self) -> &str {
        "pem_decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Decode PEM Bundle",
            "Split a PEM bundle (text) into its `-----BEGIN <label>-----` blocks, base64-decoding \
             each body to DER — one row per block: idx, label, der. The bridge from text armor to \
             the DER scalars (decode/cms_decode/…). Blocks with an unparseable body are skipped.",
            "Split a PEM bundle into DER blocks. Columns: `idx`, `label`, `der`.",
            "pem, pem_decode, armor, certificate, private key, base64, der, bundle, split",
            "table/pem_decode.rs",
            crate::meta::CAT_GENERIC,
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&[
                (
                    "idx",
                    "INTEGER",
                    "Zero-based index of the PEM block within the bundle.",
                ),
                (
                    "label",
                    "VARCHAR",
                    "The block label, e.g. 'CERTIFICATE' or 'PRIVATE KEY'.",
                ),
                (
                    "der",
                    "BLOB",
                    "The base64-decoded DER bytes of the block (feed to asn1.decode).",
                ),
            ]),
        ));
        FunctionMetadata {
            description: "Split a PEM bundle into its DER blocks (idx, label, der)".into(),
            examples: vec![FunctionExample {
                sql: "SELECT idx, label, octet_length(der) AS der_bytes \
                      FROM asn1.main.pem_decode('-----BEGIN CERTIFICATE-----' || chr(10) || \
                      'AQID' || chr(10) || '-----END CERTIFICATE-----') \
                      ORDER BY idx;"
                    .into(),
                description: "Split a one-block PEM bundle and list each block's index, label, \
                              and decoded DER length."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "text",
            0,
            "varchar",
            "The PEM-armored text bundle to split into its BEGIN/END blocks.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let text = params.arguments.const_str(0).unwrap_or_default();
        Ok(Box::new(PemProducer {
            schema: params.output_schema.clone(),
            blocks: asn1_core::pem::pem_decode(&text),
            done: false,
        }))
    }
}

struct PemProducer {
    schema: SchemaRef,
    blocks: Vec<asn1_core::pem::PemBlock>,
    done: bool,
}

impl TableProducer for PemProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        let mut idx = Int32Builder::new();
        let mut label = StringBuilder::new();
        let mut der = BinaryBuilder::new();
        for b in &self.blocks {
            idx.append_value(b.idx);
            label.append_value(&b.label);
            der.append_value(&b.der);
        }
        let cols: Vec<ArrayRef> = vec![
            Arc::new(idx.finish()),
            Arc::new(label.finish()),
            Arc::new(der.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
