//! `cms_signers(blob) -> TABLE(...)` — one row per CMS SignerInfo, with the
//! signer identity, named algorithms, shredded signed attributes, and the
//! `signer_cert_sha256` join key to vgi-x509. Signatures surfaced, never verified.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, Int32Builder, StringBuilder, TimestampMicrosecondBuilder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef, TimeUnit};
use asn1_core::security::cms;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use super::{commented, const_blob, one};

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "version",
            DataType::Int32,
            "SignerInfo version (CMSVersion).",
        ),
        commented("signer_sid", DataType::Utf8, "Signer identifier kind."),
        commented(
            "signer_issuer",
            DataType::Utf8,
            "Signer cert issuer (CN=…,O=…).",
        ),
        commented(
            "signer_serial",
            DataType::Utf8,
            "Signer cert serial (decimal).",
        ),
        commented(
            "signer_skid",
            DataType::Utf8,
            "Subject key identifier (hex), if SKID-based.",
        ),
        commented("digest_alg", DataType::Utf8, "Named digest algorithm OID."),
        commented("sig_alg", DataType::Utf8, "Named signature algorithm OID."),
        commented(
            "signing_time",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            "signingTime signed attribute (UTC).",
        ),
        commented(
            "content_type",
            DataType::Utf8,
            "contentType (eContentType / signed attr).",
        ),
        commented(
            "message_digest",
            DataType::Binary,
            "messageDigest signed attribute bytes.",
        ),
        commented(
            "signature",
            DataType::Binary,
            "The signature bytes (surfaced, not verified).",
        ),
        commented(
            "signer_cert_sha256",
            DataType::Utf8,
            "SHA-256 (hex) of the matching embedded cert — join to vgi-x509.",
        ),
        commented(
            "signed_attrs",
            DataType::Utf8,
            "Remaining signed attributes as JSON.",
        ),
    ]))
}

pub struct CmsSigners;

impl TableFunction for CmsSigners {
    fn name(&self) -> &str {
        "cms_signers"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CMS Signers",
            "Shred a CMS / PKCS#7 SignedData (RFC 5652) into one row per SignerInfo: the signer's \
             identity (IssuerAndSerial or SubjectKeyIdentifier), the named digest/signature \
             algorithm OIDs, the well-known signed attributes (contentType, messageDigest, \
             signingTime) and the rest as JSON, the signature bytes, and signer_cert_sha256 — the \
             SHA-256 of the matching embedded certificate, a direct join key to a vgi-x509 \
             fingerprint. The signature is surfaced, never verified. The blob argument is a \
             literal/scalar; for bulk per-row use the scalar cms_decode().",
            "Shred CMS SignerInfos into rows (the vgi-x509 join surface). Key columns: \
             `digest_alg`, `sig_alg`, `signing_time`, `signer_cert_sha256`, `signature`.",
            "cms, pkcs7, cms_signers, signer, signed attributes, signing time, x509, sha256, \
             rfc 5652, code signing, s/mime",
            "table/cms_signers.rs",
            crate::meta::CAT_SECURITY,
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per SignerInfo. Notable columns: `digest_alg` / `sig_alg` (named OIDs), \
             `signing_time` (TIMESTAMP), `message_digest` / `signature` (BLOB), \
             `signer_cert_sha256` (hex SHA-256 of the matching embedded cert — join to \
             vgi-x509), and `signed_attrs` (remaining attributes as JSON)."
                .into(),
        ));
        FunctionMetadata {
            description: "Shred a CMS SignedData into one row per SignerInfo".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "blob",
            0,
            "any",
            "A CMS / PKCS#7 SignedData payload (a literal value or scalar subquery). Fans into \
             one row per SignerInfo.",
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
        let mut version = Int32Builder::new();
        let mut signer_sid = StringBuilder::new();
        let mut signer_issuer = StringBuilder::new();
        let mut signer_serial = StringBuilder::new();
        let mut signer_skid = StringBuilder::new();
        let mut digest_alg = StringBuilder::new();
        let mut sig_alg = StringBuilder::new();
        let mut signing_time = TimestampMicrosecondBuilder::new();
        let mut content_type = StringBuilder::new();
        let mut message_digest = BinaryBuilder::new();
        let mut signature = BinaryBuilder::new();
        let mut signer_cert_sha256 = StringBuilder::new();
        let mut signed_attrs = StringBuilder::new();

        for s in cms::cms_signers(&bytes) {
            match s.version {
                Some(v) => version.append_value(v as i32),
                None => version.append_null(),
            }
            signer_sid.append_value(&s.signer_sid);
            signer_issuer.append_option(s.signer_issuer.as_deref());
            signer_serial.append_option(s.signer_serial.as_deref());
            signer_skid.append_option(s.signer_skid.as_deref());
            digest_alg.append_option(s.digest_alg.as_deref());
            sig_alg.append_option(s.sig_alg.as_deref());
            match s.signing_time_micros {
                Some(m) => signing_time.append_value(m),
                None => signing_time.append_null(),
            }
            content_type.append_option(s.content_type.as_deref());
            message_digest.append_option(s.message_digest.as_deref());
            signature.append_option(s.signature.as_deref());
            signer_cert_sha256.append_option(s.signer_cert_sha256.as_deref());
            signed_attrs.append_value(&s.signed_attrs_json);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(version.finish()),
            Arc::new(signer_sid.finish()),
            Arc::new(signer_issuer.finish()),
            Arc::new(signer_serial.finish()),
            Arc::new(signer_skid.finish()),
            Arc::new(digest_alg.finish()),
            Arc::new(sig_alg.finish()),
            Arc::new(signing_time.finish()),
            Arc::new(content_type.finish()),
            Arc::new(message_digest.finish()),
            Arc::new(signature.finish()),
            Arc::new(signer_cert_sha256.finish()),
            Arc::new(signed_attrs.finish()),
        ];
        let batch = RecordBatch::try_new(params.output_schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(one(batch))
    }
}
