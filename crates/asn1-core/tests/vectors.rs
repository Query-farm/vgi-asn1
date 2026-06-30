//! Golden DER/BER vectors asserted through the public API.

use asn1_core::security::snmp;
use asn1_core::tlv::{parse, Rules};
use asn1_core::{decode_json, reencode, tlvlist, validate};
use serde_json::json;

/// Build `TLV` bytes for a SEQUENCE wrapping the given DER children.
fn seq(children: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30, children.len() as u8];
    v.extend_from_slice(children);
    v
}

#[test]
fn universal_tag_coverage() {
    // SEQUENCE { INTEGER 5, BOOLEAN true, OID 2.5.4.3, UTF8String "abc", NULL }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x02, 0x01, 0x05]);
    body.extend_from_slice(&[0x01, 0x01, 0xff]);
    body.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
    body.extend_from_slice(&[0x0c, 0x03, b'a', b'b', b'c']);
    body.extend_from_slice(&[0x05, 0x00]);
    let der = seq(&body);

    let v = decode_json(&der);
    assert_eq!(v, json!([5, true, "2.5.4.3", "abc", null]));

    // OID inventory resolves the name + path.
    let t = parse(&der).unwrap();
    let oids = tlvlist::oids(&t);
    assert_eq!(oids.len(), 1);
    assert_eq!(oids[0].oid, "2.5.4.3");
    assert_eq!(oids[0].name.as_deref(), Some("id-at-commonName"));
    assert_eq!(oids[0].path, "$.2");
}

#[test]
fn bignum_integer_to_string() {
    // INTEGER 2^80
    let mut der = vec![0x02, 0x0b, 0x01];
    der.extend_from_slice(&[0u8; 10]);
    let v = decode_json(&der);
    assert_eq!(v, json!("1208925819614629174706176"));
}

#[test]
fn der_roundtrips_through_decode() {
    let body = [0x02, 0x01, 0x07, 0x01, 0x01, 0x00];
    let der = seq(&body);
    let t = parse(&der).unwrap();
    assert_eq!(reencode::to_der(&t), der);
}

#[test]
fn indefinite_ber_valid_then_canonical_der() {
    // SEQUENCE (indefinite) { OCTET STRING "Hi" } EOC
    let ber = [0x30, 0x80, 0x04, 0x02, b'H', b'i', 0x00, 0x00];
    assert!(validate::is_valid(&ber, Rules::Ber));
    assert!(!validate::is_valid(&ber, Rules::Der));
    let t = parse(&ber).unwrap();
    assert_eq!(reencode::to_der(&t), [0x30, 0x04, 0x04, 0x02, b'H', b'i']);
}

#[test]
fn snmp_v2c_response_varbinds() {
    // Build an SNMPv2c Response with one varbind sysName.0 = "core-rtr-1".
    let oidb = asn1_core::oid::encode_oid("1.3.6.1.2.1.1.5.0").unwrap();
    let mut inner = vec![0x06, oidb.len() as u8];
    inner.extend_from_slice(&oidb);
    inner.extend_from_slice(&[0x04, 0x0a]);
    inner.extend_from_slice(b"core-rtr-1");
    let vb = seq(&inner);
    let vbl = seq(&vb);
    let mut body = vec![0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
    body.extend_from_slice(&vbl);
    let mut pdu = vec![0xa2, body.len() as u8];
    pdu.extend_from_slice(&body);
    let mut msg_body = vec![0x02, 0x01, 0x01, 0x04, 0x06];
    msg_body.extend_from_slice(b"public");
    msg_body.extend_from_slice(&pdu);
    let msg = seq(&msg_body);

    let m = snmp::decode_message(&msg).unwrap();
    assert_eq!(m.version, "v2c");
    assert_eq!(m.pdu_type, "GetResponse");
    assert_eq!(m.request_id, Some(42));
    assert_eq!(m.varbinds.len(), 1);
    assert_eq!(m.varbinds[0].oid, "1.3.6.1.2.1.1.5.0");
    assert_eq!(m.varbinds[0].type_name, "OCTET STRING");
    // OCTET STRING values surface as base64url (binary-safe) in the JSON value.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let expected = format!("\"{}\"", URL_SAFE_NO_PAD.encode(b"core-rtr-1"));
    assert_eq!(m.varbinds[0].value_json, expected);
}

#[test]
fn well_formed_classifies_failures() {
    assert_eq!(
        validate::well_formed(&[0x02, 0x05, 0x01]).kind,
        "length-overflow"
    );
    assert_eq!(validate::well_formed(&[0x02]).kind, "truncated");
    assert_eq!(
        validate::well_formed(&[0x05, 0x00, 0x00]).kind,
        "trailing-bytes"
    );
    assert!(validate::well_formed(&[0x05, 0x00]).ok);
}
