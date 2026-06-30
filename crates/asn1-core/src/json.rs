//! Two JSON projections of a decoded TLV tree:
//!
//! * [`to_json_verbose`] — the self-describing `{class, tag, tag_name,
//!   constructed, value}` form behind `asn1.to_json` (always succeeds on a
//!   well-formed blob).
//! * [`decode_value`] — the cleaner, "typed" nested projection behind
//!   `asn1.decode` (SEQUENCE→array, primitives→their scalar value), used as the
//!   stable JSON column type.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::oid;
use crate::tlv::{universal_tag_name, Body, Class, Tlv};
use crate::value;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Friendly tag name for any node (universal names, else a `[class n]` label).
pub fn tag_label(t: &Tlv) -> String {
    if t.class == Class::Universal {
        universal_tag_name(t.tag)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("[UNIVERSAL {}]", t.tag))
    } else {
        format!(
            "[{} {}]",
            match t.class {
                Class::Application => "APPLICATION",
                Class::Context => "CONTEXT",
                Class::Private => "PRIVATE",
                Class::Universal => "UNIVERSAL",
            },
            t.tag
        )
    }
}

/// The verbose, self-describing JSON node (`asn1.to_json`).
pub fn to_json_verbose(t: &Tlv) -> Value {
    let mut obj = Map::new();
    obj.insert("class".into(), json!(t.class.as_str()));
    obj.insert("tag".into(), json!(t.tag));
    obj.insert("tag_name".into(), json!(tag_label(t)));
    obj.insert("constructed".into(), json!(t.constructed));
    if t.indefinite {
        obj.insert("indefinite".into(), json!(true));
    }
    match &t.body {
        Body::Constructed(children) => {
            let kids: Vec<Value> = children.iter().map(to_json_verbose).collect();
            obj.insert("value".into(), Value::Array(kids));
        }
        Body::Primitive(bytes) => {
            obj.insert("value".into(), primitive_value(t, bytes, true));
        }
    }
    Value::Object(obj)
}

/// The clean nested projection (`asn1.decode`).
pub fn decode_value(t: &Tlv) -> Value {
    match &t.body {
        Body::Constructed(children) => {
            let kids: Vec<Value> = children.iter().map(decode_value).collect();
            Value::Array(kids)
        }
        Body::Primitive(bytes) => primitive_value(t, bytes, false),
    }
}

/// Interpret a primitive node's value. `verbose` controls whether OID/BIT STRING
/// get the richer object form.
fn primitive_value(t: &Tlv, bytes: &[u8], verbose: bool) -> Value {
    if t.class == Class::Universal {
        match t.tag {
            1 => return json!(value::decode_bool(bytes).unwrap_or(false)),
            2 | 10 => {
                return match value::integer_to_i64(bytes) {
                    Some(v) => json!(v),
                    None => json!(value::integer_to_decimal(bytes)),
                };
            }
            5 => return Value::Null,
            6 => {
                let dotted = oid::decode_oid(bytes);
                return match dotted {
                    Some(d) => {
                        if verbose {
                            let name = oid::name_for(&d);
                            json!({ "oid": d, "name": name })
                        } else {
                            json!(d)
                        }
                    }
                    None => json!({ "base64": b64(bytes), "error": "bad-oid" }),
                };
            }
            13 => {
                return match oid::decode_relative_oid(bytes) {
                    Some(d) => json!(d),
                    None => json!({ "base64": b64(bytes) }),
                };
            }
            3 => {
                if let Some((unused, data)) = value::bitstring(bytes) {
                    return json!({
                        "unused_bits": unused,
                        "bytes": b64(data),
                        "bits": value::bitstring_bits(unused, data),
                    });
                }
                return json!({ "base64": b64(bytes) });
            }
            4 => return json!(b64(bytes)),
            23 | 24 => {
                if let Some(tv) = value::decode_time(t.tag, bytes) {
                    return json!(tv.iso);
                }
                return json!({ "raw": String::from_utf8_lossy(bytes) });
            }
            12 | 18 | 19 | 20 | 22 | 25 | 26 | 27 | 28 | 30 => {
                if let Some(s) = value::decode_string(t.tag, bytes) {
                    return json!(s);
                }
                return json!(b64(bytes));
            }
            _ => {}
        }
    }
    // Unknown / context / application / private primitive: opaque bytes.
    json!(b64(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse;

    #[test]
    fn verbose_sequence() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let v = to_json_verbose(&parse(&der).unwrap());
        assert_eq!(v["tag_name"], "SEQUENCE");
        assert_eq!(v["value"][0]["value"], 5);
    }

    #[test]
    fn decode_nested() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let v = decode_value(&parse(&der).unwrap());
        assert_eq!(v, json!([5]));
    }

    #[test]
    fn oid_value() {
        // OID 1.2.840.113549.1.1.11
        let b = oid::encode_oid("1.2.840.113549.1.1.11").unwrap();
        let mut der = vec![0x06, b.len() as u8];
        der.extend_from_slice(&b);
        let t = parse(&der).unwrap();
        assert_eq!(decode_value(&t), json!("1.2.840.113549.1.1.11"));
        let v = to_json_verbose(&t);
        assert_eq!(v["value"]["name"], "sha256WithRSAEncryption");
    }
}
