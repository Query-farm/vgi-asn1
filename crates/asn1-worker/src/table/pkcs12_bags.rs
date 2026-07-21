//! `pkcs12_bags(blob) -> TABLE(bag_type, friendly_name, local_key_id, alg,
//! cert_sha256, encrypted)` — walk a PKCS#12 keystore's SafeBag list. Never
//! surfaces plaintext key material.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use asn1_core::security::pkcs;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use super::{commented, const_blob, one};

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "bag_type",
            DataType::Utf8,
            "SafeBag type, e.g. certBag, pkcs8ShroudedKeyBag.",
        ),
        commented(
            "friendly_name",
            DataType::Utf8,
            "friendlyName attribute, if present.",
        ),
        commented(
            "local_key_id",
            DataType::Utf8,
            "localKeyID attribute (hex), if present.",
        ),
        commented("alg", DataType::Utf8, "Named key algorithm (key bags)."),
        commented(
            "cert_sha256",
            DataType::Utf8,
            "SHA-256 (hex) of the cert (cert bags) — join to vgi-x509.",
        ),
        commented(
            "encrypted",
            DataType::Boolean,
            "Whether the bag's key material is encrypted.",
        ),
    ]))
}

pub struct Pkcs12Bags;

impl TableFunction for Pkcs12Bags {
    fn name(&self) -> &str {
        "pkcs12_bags"
    }

    fn metadata(&self) -> FunctionMetadata {
        let ex_sql = "SELECT bag_type, encrypted, cert_sha256 \
                      FROM asn1.main.pkcs12_bags(from_hex('3051020103304c06092a864886f70d010701a0\
                      3f043d303b303906092a864886f70d010701a02c042a30283026060b2a864886f70d010c0a01\
                      03a0173015060a2a864886f70d01091601a00704053003020105')) \
                      ORDER BY bag_type;";
        let ex_desc = "Walk a minimal PKCS#12 PFX and list each SafeBag's type, encryption flag, \
                       and (for cert bags) the vgi-x509 join hash.";
        let mut tags = crate::meta::object_tags(
            "PKCS#12 Bags",
            "Walk a PKCS#12 keystore (PFX → AuthenticatedSafe → SafeContents → SafeBag) into one \
             row per bag: bag_type (keyBag, pkcs8ShroudedKeyBag, certBag, crlBag, …), the \
             friendlyName / localKeyID attributes, the named key algorithm, and — for cert bags — \
             cert_sha256 (a join key to vgi-x509). Structural only: NEVER surfaces plaintext key \
             material and decrypts nothing. The blob argument is a literal/scalar.",
            "Walk a PKCS#12 keystore's bags (no key material). Columns: `bag_type`, \
             `friendly_name`, `local_key_id`, `alg`, `cert_sha256`, `encrypted`.",
            "pkcs12, p12, pfx, pkcs12_bags, keystore, safebag, certbag, friendlyname, x509",
            "table/pkcs12_bags.rs",
            crate::meta::CAT_SECURITY,
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&[
                (
                    "bag_type",
                    "VARCHAR",
                    "SafeBag type, e.g. certBag, pkcs8ShroudedKeyBag.",
                ),
                (
                    "friendly_name",
                    "VARCHAR",
                    "friendlyName attribute, if present.",
                ),
                (
                    "local_key_id",
                    "VARCHAR",
                    "localKeyID attribute (hex), if present.",
                ),
                ("alg", "VARCHAR", "Named key algorithm (key bags)."),
                (
                    "cert_sha256",
                    "VARCHAR",
                    "SHA-256 (hex) of the cert (cert bags) — join to vgi-x509.",
                ),
                (
                    "encrypted",
                    "BOOLEAN",
                    "Whether the bag's key material is encrypted.",
                ),
            ]),
        ));
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&[(ex_desc, ex_sql)]),
        ));
        FunctionMetadata {
            description: "Walk a PKCS#12 keystore into one row per SafeBag".into(),
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
            "A PKCS#12 (PFX) payload (a literal value or scalar subquery). Fans into one row per \
             SafeBag.",
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
        let mut bag_type = StringBuilder::new();
        let mut friendly_name = StringBuilder::new();
        let mut local_key_id = StringBuilder::new();
        let mut alg = StringBuilder::new();
        let mut cert_sha256 = StringBuilder::new();
        let mut encrypted = BooleanBuilder::new();

        for b in pkcs::pkcs12_bags(&bytes) {
            bag_type.append_value(&b.bag_type);
            friendly_name.append_option(b.friendly_name.as_deref());
            local_key_id.append_option(b.local_key_id.as_deref());
            alg.append_option(b.alg.as_deref());
            cert_sha256.append_option(b.cert_sha256.as_deref());
            encrypted.append_value(b.encrypted);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(bag_type.finish()),
            Arc::new(friendly_name.finish()),
            Arc::new(local_key_id.finish()),
            Arc::new(alg.finish()),
            Arc::new(cert_sha256.finish()),
            Arc::new(encrypted.finish()),
        ];
        let batch = RecordBatch::try_new(params.output_schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(one(batch))
    }
}
