//! Scalar functions exposed by the asn1 worker, registered under `asn1.main`.

#[macro_use]
mod json_macro;
mod generic;
mod security;

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use vgi::{ProcessParams, Worker};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::blob_bytes;

/// Map a `fn(&[u8]) -> serde_json::Value` over the BLOB column at position 0,
/// producing a VARCHAR (JSON text) column. NULL input → NULL output.
pub(crate) fn json_output(
    params: &ProcessParams,
    batch: &RecordBatch,
    f: fn(&[u8]) -> serde_json::Value,
) -> Result<RecordBatch> {
    let col = batch.column(0);
    let rows = batch.num_rows();
    let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
    for i in 0..rows {
        match blob_bytes(col, i)? {
            Some(bytes) => out.push(Some(f(bytes).to_string())),
            None => out.push(None),
        }
    }
    let arr: ArrayRef = Arc::new(StringArray::from(out));
    RecordBatch::try_new(params.output_schema.clone(), vec![arr])
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    // Each optional-2nd-arg scalar registers a 1-arg and a 2-arg arity overload
    // (DuckDB scalars take only positional args).
    worker.register_scalar(generic::Decode { two: false });
    worker.register_scalar(generic::Decode { two: true });
    worker.register_scalar(generic::ToJson);
    worker.register_scalar(generic::Dump { two: false });
    worker.register_scalar(generic::Dump { two: true });
    worker.register_scalar(generic::TlvFn);
    worker.register_scalar(generic::AtPath);
    worker.register_scalar(generic::Oids);
    worker.register_scalar(generic::OidName);
    worker.register_scalar(generic::OidFn);
    worker.register_scalar(generic::IsValid { two: false });
    worker.register_scalar(generic::IsValid { two: true });
    worker.register_scalar(generic::WellFormed);
    worker.register_scalar(generic::ToDer);
    worker.register_scalar(generic::Reencode { two: false });
    worker.register_scalar(generic::Reencode { two: true });
    worker.register_scalar(generic::PemLabel);

    worker.register_scalar(security::SnmpDecode);
    worker.register_scalar(security::KrbDecode);
    worker.register_scalar(security::KrbTicket);
    worker.register_scalar(security::LdapDecode);
    worker.register_scalar(security::CmsDecode);
    worker.register_scalar(security::CmsCerts);
    worker.register_scalar(security::CmsContent);
    worker.register_scalar(security::Pkcs8Info);
    worker.register_scalar(security::OcspDecode);
}
