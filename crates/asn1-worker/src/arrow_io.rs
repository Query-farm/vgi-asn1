//! Small Arrow helpers shared by the scalar/table functions: reading BLOB and
//! VARCHAR input cells, and building the `JSON` (VARCHAR), `LIST<STRUCT>`, and
//! result struct/blob outputs. The in-process test harness drives a
//! `ScalarFunction` end-to-end without the RPC/IPC plumbing.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, UInt32Builder, UInt64Builder,
};
use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use asn1_core::tlvlist::{OidRow, TlvRow};
use vgi_rpc::{Result, RpcError};

/// Borrow the raw bytes of a BLOB/VARCHAR cell at `row`, or `None` if null.
pub fn blob_bytes(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        DataType::Utf8 => col.as_string::<i32>().value(row).as_bytes(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).as_bytes(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB or VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// Borrow the UTF-8 text of a VARCHAR cell at `row`, or `None` if null.
pub fn text_str(col: &ArrayRef, row: usize) -> Result<Option<&str>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// The fixed `STRUCT` fields of one `asn1.tlv` row.
pub fn tlv_row_fields() -> Fields {
    Fields::from(vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("class", DataType::Utf8, false),
        Field::new("tag", DataType::UInt32, false),
        Field::new("tag_name", DataType::Utf8, false),
        Field::new("constructed", DataType::Boolean, false),
        Field::new("header_len", DataType::UInt32, false),
        Field::new("len", DataType::UInt64, false),
        Field::new("value", DataType::Utf8, true),
    ])
}

/// The element field of the `asn1.tlv` LIST.
pub fn tlv_list_field() -> Arc<Field> {
    Arc::new(Field::new("item", DataType::Struct(tlv_row_fields()), true))
}

/// Build a `LIST<STRUCT>` column of TLV rows, one list entry per input row
/// (`None` → NULL list).
pub fn build_tlv_list(rows_per_input: &[Option<Vec<TlvRow>>]) -> ArrayRef {
    let fields = tlv_row_fields();
    let mut path = StringBuilder::new();
    let mut class = StringBuilder::new();
    let mut tag = UInt32Builder::new();
    let mut tag_name = StringBuilder::new();
    let mut constructed = BooleanBuilder::new();
    let mut header_len = UInt32Builder::new();
    let mut len = UInt64Builder::new();
    let mut value = StringBuilder::new();

    let mut offsets: Vec<i32> = vec![0];
    let mut validity: Vec<bool> = Vec::with_capacity(rows_per_input.len());
    let mut total = 0i32;
    for entry in rows_per_input {
        match entry {
            Some(rows) => {
                for r in rows {
                    path.append_value(&r.path);
                    class.append_value(&r.class);
                    tag.append_value(r.tag);
                    tag_name.append_value(&r.tag_name);
                    constructed.append_value(r.constructed);
                    header_len.append_value(r.header_len);
                    len.append_value(r.len);
                    value.append_value(&r.value);
                    total += 1;
                }
                validity.push(true);
            }
            None => validity.push(false),
        }
        offsets.push(total);
    }

    let struct_arr = StructArray::new(
        fields,
        vec![
            Arc::new(path.finish()),
            Arc::new(class.finish()),
            Arc::new(tag.finish()),
            Arc::new(tag_name.finish()),
            Arc::new(constructed.finish()),
            Arc::new(header_len.finish()),
            Arc::new(len.finish()),
            Arc::new(value.finish()),
        ],
        None,
    );
    list_from_parts(tlv_list_field(), offsets, struct_arr, validity)
}

/// The fixed `STRUCT` fields of one `asn1.oids` row.
pub fn oid_row_fields() -> Fields {
    Fields::from(vec![
        Field::new("oid", DataType::Utf8, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("path", DataType::Utf8, false),
    ])
}

/// The element field of the `asn1.oids` LIST.
pub fn oid_list_field() -> Arc<Field> {
    Arc::new(Field::new("item", DataType::Struct(oid_row_fields()), true))
}

/// Build a `LIST<STRUCT(oid,name,path)>` column, one list per input row.
pub fn build_oid_list(rows_per_input: &[Option<Vec<OidRow>>]) -> ArrayRef {
    let fields = oid_row_fields();
    let mut oid = StringBuilder::new();
    let mut name = StringBuilder::new();
    let mut path = StringBuilder::new();

    let mut offsets: Vec<i32> = vec![0];
    let mut validity: Vec<bool> = Vec::with_capacity(rows_per_input.len());
    let mut total = 0i32;
    for entry in rows_per_input {
        match entry {
            Some(rows) => {
                for r in rows {
                    oid.append_value(&r.oid);
                    name.append_option(r.name.as_deref());
                    path.append_value(&r.path);
                    total += 1;
                }
                validity.push(true);
            }
            None => validity.push(false),
        }
        offsets.push(total);
    }

    let struct_arr = StructArray::new(
        fields,
        vec![
            Arc::new(oid.finish()),
            Arc::new(name.finish()),
            Arc::new(path.finish()),
        ],
        None,
    );
    list_from_parts(oid_list_field(), offsets, struct_arr, validity)
}

/// Build a `LIST<BLOB>` column (`cms_certs`), one list per input row.
pub fn build_blob_list(rows_per_input: &[Option<Vec<Vec<u8>>>]) -> ArrayRef {
    let mut lb = ListBuilder::new(BinaryBuilder::new());
    for entry in rows_per_input {
        match entry {
            Some(rows) => {
                for r in rows {
                    lb.values().append_value(r);
                }
                lb.append(true);
            }
            None => lb.append(false),
        }
    }
    Arc::new(lb.finish())
}

fn list_from_parts(
    field: Arc<Field>,
    offsets: Vec<i32>,
    values: StructArray,
    validity: Vec<bool>,
) -> ArrayRef {
    use arrow_array::ListArray;
    use arrow_buffer::OffsetBuffer;
    let nulls = NullBuffer::from(validity);
    Arc::new(ListArray::new(
        field,
        OffsetBuffer::new(offsets.into()),
        Arc::new(values),
        Some(nulls),
    ))
}

/// The `well_formed` result STRUCT fields.
pub fn well_formed_fields() -> Fields {
    Fields::from(vec![
        Field::new("ok", DataType::Boolean, false),
        Field::new("error", DataType::Utf8, true),
        Field::new("kind", DataType::Utf8, true),
    ])
}

/// Test-only harness shared by the scalar boundary tests.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::builder::BinaryBuilder;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A single-column BLOB input batch. `None` entries become NULLs.
    pub fn blob_batch(rows: &[Option<&[u8]>]) -> RecordBatch {
        let mut b = BinaryBuilder::new();
        for r in rows {
            match r {
                Some(s) => b.append_value(s),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "blob",
            arr.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![arr]).unwrap()
    }

    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            substream_id: None,
            if_none_match: None,
            if_modified_since: None,
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar over a prebuilt batch, returning the single result column.
    pub fn run_scalar<F: ScalarFunction>(
        f: &F,
        batch: RecordBatch,
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: arguments.clone(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), arguments);
        Ok(f.process(&params, &batch)?.column(0).clone())
    }

    /// Run a scalar over a single-column BLOB batch.
    pub fn run_scalar_blob<F: ScalarFunction>(
        f: &F,
        rows: &[Option<&[u8]>],
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        run_scalar(f, blob_batch(rows), arguments)
    }

    pub fn bound_type<F: ScalarFunction>(f: &F) -> arrow_schema::DataType {
        let bind = BindParams::default();
        let bound = f.on_bind(&bind).unwrap();
        bound.output_schema.field(0).data_type().clone()
    }
}
