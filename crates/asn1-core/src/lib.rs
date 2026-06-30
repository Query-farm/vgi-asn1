//! `asn1-core` — the pure (no Arrow / no VGI) engine behind the **vgi-asn1**
//! worker.
//!
//! It provides a panic-free generic BER/CER/DER **TLV codec** ([`tlv`]), an
//! OBJECT IDENTIFIER codec + name registry ([`oid`]), JSON ([`json`]) and
//! `dump` ([`dump`]) renderers, flat TLV/OID views ([`tlvlist`]), validation
//! ([`validate`]), canonical re-encoding ([`reencode`]), PEM armor ([`pem`]),
//! and structural decoders for SNMP / Kerberos / LDAP / CMS / PKCS / OCSP
//! ([`security`]). Every entry point is total on arbitrary input — malformed
//! bytes produce a typed error or an `{error: …}` value, never a panic, so the
//! worker can capture failures per row and keep scanning.

pub mod dump;
pub mod json;
pub mod oid;
pub mod pem;
pub mod reencode;
pub mod security;
pub mod tlv;
pub mod tlvlist;
pub mod validate;
pub mod value;

use serde_json::Value;

/// Decode `blob` into the clean nested JSON projection used by `asn1.decode`
/// (auto/struct/json modes). Returns `{error, kind}` on a malformed blob.
pub fn decode_json(blob: &[u8]) -> Value {
    match tlv::parse(blob) {
        Ok(t) => json::decode_value(&t),
        Err(e) => serde_json::json!({ "error": e.message, "kind": e.kind.as_str() }),
    }
}

/// The verbose self-describing JSON (`asn1.to_json`).
pub fn to_json(blob: &[u8]) -> Value {
    match tlv::parse(blob) {
        Ok(t) => json::to_json_verbose(&t),
        Err(e) => serde_json::json!({ "error": e.message, "kind": e.kind.as_str() }),
    }
}

/// The flat TLV-list JSON (`asn1.decode` mode `tlv`).
pub fn tlv_json(blob: &[u8]) -> Value {
    match tlv::parse(blob) {
        Ok(t) => {
            let rows: Vec<Value> = tlvlist::flatten(&t)
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "path": r.path,
                        "class": r.class,
                        "tag": r.tag,
                        "tag_name": r.tag_name,
                        "constructed": r.constructed,
                        "header_len": r.header_len,
                        "len": r.len,
                        "value": serde_json::from_str::<Value>(&r.value).unwrap_or(Value::Null),
                    })
                })
                .collect();
            Value::Array(rows)
        }
        Err(e) => serde_json::json!({ "error": e.message, "kind": e.kind.as_str() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_json_roundtrip() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x2a];
        assert_eq!(decode_json(&der), serde_json::json!([42]));
    }

    #[test]
    fn malformed_never_panics() {
        // A grab-bag of hostile inputs must all return error values, not panic.
        for bad in [
            &[0xff][..],
            &[0x30, 0x80][..],
            &[0x02, 0x7f][..],
            &[0x30, 0x05, 0x30, 0x03, 0x30][..],
        ] {
            let v = decode_json(bad);
            assert!(v.get("error").is_some(), "expected error for {bad:?}");
        }
    }
}
