//! Producer table functions for the asn1 worker.
//!
//! The structural fan-out functions (`snmp_varbinds`, `ldap_messages`,
//! `cms_signers`, `pkcs12_bags`) and `pem_decode` take their input blob/text as a
//! **constant argument** and emit one batch of fanned rows. The vgi extension's
//! table-function binder accepts only literal parameters — it rejects a
//! correlated `LATERAL f(t.col)` column — so per-row bulk shredding over a column
//! is done with the scalar `*_decode` JSON functions, while these table functions
//! shred a single (literal or scalar-subquery) blob into typed rows.

mod cms_signers;
mod ldap_messages;
pub mod oid_registry;
mod pem_decode;
mod pkcs12_bags;
mod snmp_varbinds;

use std::collections::HashMap;

use arrow_array::RecordBatch;
use arrow_schema::{DataType, Field};
use vgi::arguments::Arguments;
use vgi::table_function::TableProducer;
use vgi::Worker;
use vgi_rpc::{OutputCollector, Result};

/// Register the producer table functions.
pub fn register(worker: &mut Worker) {
    worker.register_table(pem_decode::PemDecode);
    worker.register_table(snmp_varbinds::SnmpVarbinds);
    worker.register_table(ldap_messages::LdapMessages);
    worker.register_table(cms_signers::CmsSigners);
    worker.register_table(pkcs12_bags::Pkcs12Bags);
}

/// A column field carrying a `comment`, surfaced via `duckdb_columns().comment`.
pub(crate) fn commented(name: &str, ty: DataType, comment: &str) -> Field {
    Field::new(name, ty, true).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// Read the const blob argument at position 0, accepting a BLOB or a VARCHAR
/// literal. Returns an empty Vec when absent (yielding zero rows).
pub(crate) fn const_blob(args: &Arguments) -> Vec<u8> {
    if let Some(b) = args.const_bytes(0) {
        return b;
    }
    if let Some(s) = args.const_str(0) {
        return s.into_bytes();
    }
    Vec::new()
}

/// A table producer that emits exactly one prebuilt batch then stops.
pub(crate) struct SingleBatch {
    pub batch: Option<RecordBatch>,
}

impl TableProducer for SingleBatch {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        Ok(self.batch.take())
    }
}

/// Helper to box a one-shot producer from a built batch.
pub(crate) fn one(batch: RecordBatch) -> Box<dyn TableProducer> {
    Box::new(SingleBatch { batch: Some(batch) })
}
