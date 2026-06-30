//! OCSP (RFC 6960): decode both `OCSPRequest` and `OCSPResponse` /
//! `BasicOCSPResponse` into a JSON projection. The signature is surfaced, never
//! verified.

use serde_json::{json, Value};

use super::{as_i64, explicit, kids, oid_named, render_name};
use crate::tlv::{parse, Class, Tlv};
use crate::value;

fn response_status_name(n: i64) -> String {
    match n {
        0 => "successful".into(),
        1 => "malformedRequest".into(),
        2 => "internalError".into(),
        3 => "tryLater".into(),
        5 => "sigRequired".into(),
        6 => "unauthorized".into(),
        n => n.to_string(),
    }
}

fn revocation_reason(n: i64) -> String {
    match n {
        0 => "unspecified".into(),
        1 => "keyCompromise".into(),
        2 => "cACompromise".into(),
        3 => "affiliationChanged".into(),
        4 => "superseded".into(),
        5 => "cessationOfOperation".into(),
        6 => "certificateHold".into(),
        8 => "removeFromCRL".into(),
        9 => "privilegeWithdrawn".into(),
        10 => "aACompromise".into(),
        n => n.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn time_of(t: &Tlv) -> Option<String> {
    t.primitive()
        .and_then(|b| value::decode_time(t.tag, b))
        .map(|tv| tv.iso)
}

/// `asn1.ocsp_decode`.
pub fn ocsp_decode(blob: &[u8]) -> Value {
    let Ok(root) = parse(blob) else {
        return json!({ "error": "not well-formed" });
    };
    if !root.is_universal(16) {
        return json!({ "error": "not an OCSP message" });
    }
    let c = kids(&root);
    match c.first() {
        // OCSPResponse: responseStatus ENUMERATED first.
        Some(first) if first.is_universal(10) => decode_response(&root),
        // OCSPRequest: tbsRequest SEQUENCE first.
        Some(first) if first.is_universal(16) => decode_request(&root),
        _ => json!({ "error": "unrecognized OCSP structure" }),
    }
}

fn decode_response(root: &Tlv) -> Value {
    let c = kids(root);
    let status = c.first().and_then(as_i64).map(response_status_name);
    // responseBytes [0] EXPLICIT ResponseBytes { responseType OID, response OCTET }
    let mut basic = Value::Null;
    if let Some(rb) = c.iter().find(|t| t.is_context(0)) {
        let inner = explicit(rb);
        let rbk = kids(inner);
        if let Some(resp) = rbk.get(1) {
            // response OCTET STRING -> BasicOCSPResponse DER
            let der = resp.gather_octets();
            if let Ok(basic_resp) = parse(&der) {
                basic = decode_basic(&basic_resp);
            }
        }
    }
    json!({
        "kind": "OCSPResponse",
        "response_status": status,
        "basic": basic,
    })
}

fn decode_basic(basic: &Tlv) -> Value {
    // BasicOCSPResponse ::= SEQ { tbsResponseData, signatureAlgorithm, signature BIT, certs [0]? }
    let c = kids(basic);
    let Some(tbs) = c.first().filter(|t| t.is_universal(16)) else {
        return Value::Null;
    };
    let tc = kids(tbs);
    // Skip optional [0] version; responderID is [1] or [2]; producedAt GeneralizedTime.
    let responder_id = tc
        .iter()
        .find(|t| t.class == Class::Context && (t.tag == 1 || t.tag == 2))
        .map(|t| match t.tag {
            1 => format!("byName:{}", render_name(explicit(t))),
            _ => format!("byKey:{}", hex(&explicit(t).gather_octets())),
        });
    let produced_at = tc.iter().find(|t| t.is_universal(24)).and_then(time_of);
    // responses SEQUENCE OF SingleResponse (last universal SEQUENCE in tbs).
    let responses = tc
        .iter()
        .rev()
        .find(|t| t.is_universal(16))
        .map(|t| kids(t).iter().map(decode_single).collect::<Vec<_>>())
        .unwrap_or_default();
    let sig_alg = c.get(1).and_then(|t| kids(t).first()).and_then(oid_named);

    json!({
        "responder_id": responder_id,
        "produced_at": produced_at,
        "sig_alg": sig_alg,
        "responses": responses,
    })
}

fn decode_single(sr: &Tlv) -> Value {
    // SingleResponse ::= SEQ { certID, certStatus CHOICE, thisUpdate, nextUpdate [0]?, exts [1]? }
    let c = kids(sr);
    let cert_id = c.first();
    let (issuer_name_hash, issuer_key_hash, serial) = match cert_id {
        Some(cid) => {
            let k = kids(cid);
            (
                k.get(1).and_then(|t| t.primitive()).map(hex),
                k.get(2).and_then(|t| t.primitive()).map(hex),
                k.get(3)
                    .and_then(|t| t.primitive())
                    .map(value::integer_to_decimal),
            )
        }
        None => (None, None, None),
    };
    // certStatus is a context CHOICE: [0] good (NULL), [1] revoked, [2] unknown.
    let status_node = c.iter().find(|t| t.class == Class::Context);
    let (cert_status, revocation_time, revocation_reason_str) = match status_node {
        Some(s) if s.tag == 0 => ("good".to_string(), None, None),
        Some(s) if s.tag == 1 => {
            // RevokedInfo ::= SEQ { revocationTime GeneralizedTime, revocationReason [0]? }
            let rk = kids(s);
            let rt = rk.first().and_then(time_of);
            let reason = rk
                .iter()
                .find(|t| t.is_context(0))
                .and_then(|t| as_i64(explicit(t)))
                .map(revocation_reason);
            ("revoked".to_string(), rt, reason)
        }
        Some(_) => ("unknown".to_string(), None, None),
        None => ("unknown".to_string(), None, None),
    };
    // thisUpdate / nextUpdate
    let this_update = c.iter().find(|t| t.is_universal(24)).and_then(time_of);
    let next_update = c
        .iter()
        .find(|t| t.is_context(0))
        .map(explicit)
        .filter(|t| t.is_universal(24))
        .and_then(time_of);

    json!({
        "cert_serial": serial,
        "issuer_name_hash": issuer_name_hash,
        "issuer_key_hash": issuer_key_hash,
        "cert_status": cert_status,
        "revocation_time": revocation_time,
        "revocation_reason": revocation_reason_str,
        "this_update": this_update,
        "next_update": next_update,
    })
}

fn decode_request(root: &Tlv) -> Value {
    // OCSPRequest ::= SEQ { tbsRequest TBSRequest, optionalSignature [0]? }
    let c = kids(root);
    let tbs = c.first();
    let request_list = tbs
        .map(kids)
        .and_then(|tc| tc.iter().rev().find(|t| t.is_universal(16)))
        .map(|reqs| {
            kids(reqs)
                .iter()
                .filter_map(|req| {
                    // Request ::= SEQ { reqCert CertID, singleRequestExtensions? }
                    let cid = kids(req).first()?;
                    let k = kids(cid);
                    Some(json!({
                        "issuer_name_hash": k.get(1).and_then(|t| t.primitive()).map(hex),
                        "issuer_key_hash": k.get(2).and_then(|t| t.primitive()).map(hex),
                        "cert_serial": k.get(3).and_then(|t| t.primitive()).map(value::integer_to_decimal),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "kind": "OCSPRequest",
        "requests": request_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_is_error() {
        assert!(ocsp_decode(&[0xff, 0x00])["error"].is_string());
        assert!(ocsp_decode(&[0x02, 0x01, 0x05])["error"].is_string());
    }

    #[test]
    fn reason_names() {
        assert_eq!(revocation_reason(1), "keyCompromise");
        assert_eq!(response_status_name(0), "successful");
    }
}
