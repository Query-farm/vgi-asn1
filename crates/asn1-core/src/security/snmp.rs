//! SNMP v1 / v2c / v3 PDU dispatch and varbind shredding (RFC 1157 / 1901 /
//! 3412 / 3416). Built on the generic TLV walk rather than a typed crate so a
//! malformed capture degrades gracefully.

use serde_json::{json, Value};

use super::{as_i64, as_oid, as_str, kids};
use crate::json::decode_value;
use crate::oid;
use crate::tlv::{parse, Class, Tlv};

/// One decoded varbind.
#[derive(Clone, Debug)]
pub struct Varbind {
    pub oid: String,
    pub oid_name: Option<String>,
    pub type_name: String,
    pub value_json: String,
}

/// The shredded SNMP message.
#[derive(Clone, Debug)]
pub struct SnmpMessage {
    pub version: String,
    pub community: Option<String>,
    pub pdu_type: String,
    pub request_id: Option<i64>,
    pub error_status: Option<String>,
    pub error_index: Option<i64>,
    pub enterprise: Option<String>,
    pub agent_addr: Option<String>,
    pub trap_type: Option<String>,
    pub specific_trap: Option<i64>,
    pub varbinds: Vec<Varbind>,
}

fn pdu_type_name(tag: u32) -> &'static str {
    match tag {
        0 => "GetRequest",
        1 => "GetNextRequest",
        2 => "GetResponse",
        3 => "SetRequest",
        4 => "Trap",
        5 => "GetBulkRequest",
        6 => "InformRequest",
        7 => "SNMPv2-Trap",
        8 => "Report",
        _ => "unknown",
    }
}

fn version_name(v: i64) -> String {
    match v {
        0 => "v1".into(),
        1 => "v2c".into(),
        3 => "v3".into(),
        n => n.to_string(),
    }
}

fn error_status_name(v: i64) -> String {
    match v {
        0 => "noError".into(),
        1 => "tooBig".into(),
        2 => "noSuchName".into(),
        3 => "badValue".into(),
        4 => "readOnly".into(),
        5 => "genErr".into(),
        n => n.to_string(),
    }
}

fn varbind_type(value: &Tlv) -> &'static str {
    match value.class {
        Class::Universal => match value.tag {
            2 => "Integer32",
            4 => "OCTET STRING",
            5 => "Null",
            6 => "OID",
            _ => "OCTET STRING",
        },
        Class::Application => match value.tag {
            0 => "IpAddress",
            1 => "Counter32",
            2 => "Gauge32",
            3 => "TimeTicks",
            4 => "Opaque",
            6 => "Counter64",
            _ => "Opaque",
        },
        Class::Context => match value.tag {
            0 => "noSuchObject",
            1 => "noSuchInstance",
            2 => "endOfMibView",
            _ => "context",
        },
        Class::Private => "private",
    }
}

fn shred_varbinds(list: &Tlv) -> Vec<Varbind> {
    let mut out = Vec::new();
    for vb in kids(list) {
        let parts = kids(vb);
        if parts.len() < 2 {
            continue;
        }
        let Some(oid_str) = as_oid(&parts[0]) else {
            continue;
        };
        let value = &parts[1];
        out.push(Varbind {
            oid_name: oid::name_for(&oid_str).map(|s| s.to_string()),
            oid: oid_str,
            type_name: varbind_type(value).to_string(),
            value_json: decode_value(value).to_string(),
        });
    }
    out
}

/// Decode an SNMP message from a blob, returning the intermediate structure.
pub fn decode_message(blob: &[u8]) -> Option<SnmpMessage> {
    let root = parse(blob).ok()?;
    let top = kids(&root);
    if top.len() < 3 {
        return None;
    }
    let version = version_name(as_i64(&top[0])?);
    let community = as_str(&top[1]);
    let pdu = &top[2];
    if pdu.class != Class::Context {
        return None;
    }
    let pdu_tag = pdu.tag;
    let pdu_type = pdu_type_name(pdu_tag).to_string();
    let body = kids(pdu);

    let mut msg = SnmpMessage {
        version,
        community,
        pdu_type,
        request_id: None,
        error_status: None,
        error_index: None,
        enterprise: None,
        agent_addr: None,
        trap_type: None,
        specific_trap: None,
        varbinds: Vec::new(),
    };

    if pdu_tag == 4 {
        // v1 Trap-PDU: enterprise, agent-addr, generic-trap, specific-trap,
        // time-stamp, varbinds
        if body.len() >= 6 {
            msg.enterprise = as_oid(&body[0]);
            msg.agent_addr = body[1].primitive().map(|b| {
                b.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            });
            msg.trap_type = as_i64(&body[2]).map(|v| v.to_string());
            msg.specific_trap = as_i64(&body[3]);
            msg.varbinds = shred_varbinds(&body[5]);
        }
    } else {
        // Standard PDU: request-id, error-status, error-index, varbinds
        if body.len() >= 4 {
            msg.request_id = as_i64(&body[0]);
            msg.error_status = as_i64(&body[1]).map(error_status_name);
            msg.error_index = as_i64(&body[2]);
            msg.varbinds = shred_varbinds(&body[3]);
        }
    }
    Some(msg)
}

/// `asn1.snmp_decode` JSON projection.
pub fn snmp_decode(blob: &[u8]) -> Value {
    match decode_message(blob) {
        Some(m) => {
            let vbs: Vec<Value> = m
                .varbinds
                .iter()
                .map(|v| {
                    json!({
                        "oid": v.oid,
                        "oid_name": v.oid_name,
                        "type": v.type_name,
                        "value": serde_json::from_str::<Value>(&v.value_json).unwrap_or(Value::Null),
                    })
                })
                .collect();
            json!({
                "version": m.version,
                "community": m.community,
                "pdu_type": m.pdu_type,
                "request_id": m.request_id,
                "error_status": m.error_status,
                "error_index": m.error_index,
                "enterprise": m.enterprise,
                "agent_addr": m.agent_addr,
                "trap_type": m.trap_type,
                "specific_trap": m.specific_trap,
                "varbinds": vbs,
            })
        }
        None => json!({ "error": "not a recognizable SNMP message" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SNMPv2c GetResponse: version=1, community="public", Response PDU with one
    // varbind sysDescr.0 = OCTET STRING "RouterOS".
    fn sample() -> Vec<u8> {
        // Build manually.
        // varbind: SEQ { OID 1.3.6.1.2.1.1.1.0, OCTET STRING "RouterOS" }
        let oidb = oid::encode_oid("1.3.6.1.2.1.1.1.0").unwrap();
        let mut vb = vec![0x30, 0u8];
        let mut inner = vec![0x06, oidb.len() as u8];
        inner.extend_from_slice(&oidb);
        inner.extend_from_slice(&[0x04, 0x08]);
        inner.extend_from_slice(b"RouterOS");
        vb[1] = inner.len() as u8;
        vb.extend_from_slice(&inner);
        // vblist
        let mut vbl = vec![0x30, vb.len() as u8];
        vbl.extend_from_slice(&vb);
        // pdu body: req-id=1, err=0, idx=0, vblist
        let mut body = vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        body.extend_from_slice(&vbl);
        let mut pdu = vec![0xa2, body.len() as u8]; // [2] Response
        pdu.extend_from_slice(&body);
        // message: version=1, community="public", pdu
        let mut msg_body = vec![0x02, 0x01, 0x01, 0x04, 0x06];
        msg_body.extend_from_slice(b"public");
        msg_body.extend_from_slice(&pdu);
        let mut msg = vec![0x30, msg_body.len() as u8];
        msg.extend_from_slice(&msg_body);
        msg
    }

    #[test]
    fn decodes_v2c_response() {
        let m = decode_message(&sample()).unwrap();
        assert_eq!(m.version, "v2c");
        assert_eq!(m.community.as_deref(), Some("public"));
        assert_eq!(m.pdu_type, "GetResponse");
        assert_eq!(m.request_id, Some(1));
        assert_eq!(m.varbinds.len(), 1);
        assert_eq!(m.varbinds[0].oid, "1.3.6.1.2.1.1.1.0");
        assert_eq!(m.varbinds[0].oid_name.as_deref(), Some("sysDescr.0"));
        assert_eq!(m.varbinds[0].type_name, "OCTET STRING");
    }

    #[test]
    fn malformed_is_error_value() {
        assert!(snmp_decode(&[0xff, 0x00])["error"].is_string());
    }
}
