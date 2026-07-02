//! A macro generating a `blob -> JSON(VARCHAR)` scalar from its metadata and a
//! `fn(&[u8]) -> serde_json::Value` core function. Used by the self-describing
//! decoders that return a stable JSON column type.

/// Generate a scalar `$ty` named `$name` that maps `$func` over a BLOB column.
macro_rules! json_blob_scalar {
    ($ty:ident, $name:literal, $title:literal, $desc:literal, $llm:literal, $md:literal,
     $kw:literal, $ex_sql:literal, $ex_desc:literal, $src:literal, $cat:expr, $func:path) => {
        pub struct $ty;

        impl vgi::ScalarFunction for $ty {
            fn name(&self) -> &str {
                $name
            }

            fn metadata(&self) -> vgi::FunctionMetadata {
                vgi::FunctionMetadata {
                    description: $desc.into(),
                    return_type: Some(arrow_schema::DataType::Utf8),
                    examples: vec![vgi::FunctionExample {
                        sql: $ex_sql.into(),
                        description: $ex_desc.into(),
                        expected_output: None,
                    }],
                    tags: crate::meta::object_tags($title, $llm, $md, $kw, $src, $cat),
                    ..Default::default()
                }
            }

            fn argument_specs(&self) -> Vec<vgi::ArgSpec> {
                vec![vgi::ArgSpec::any_column(
                    "blob",
                    0,
                    "The ASN.1 DER/BER/CER bytes to decode — raw binary, or text holding \
                     those bytes. NULL input yields NULL.",
                )]
            }

            fn on_bind(&self, _params: &vgi::BindParams) -> vgi_rpc::Result<vgi::BindResponse> {
                Ok(vgi::BindResponse::result(arrow_schema::DataType::Utf8))
            }

            fn process(
                &self,
                params: &vgi::ProcessParams,
                batch: &arrow_array::RecordBatch,
            ) -> vgi_rpc::Result<arrow_array::RecordBatch> {
                crate::scalar::json_output(params, batch, $func)
            }
        }
    };
}
