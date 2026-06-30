//! Kerberos V5 (RFC 4120): `[APPLICATION n]` message dispatch and the outer
//! `Ticket` projection. The `EncTicketPart` stays encrypted — its `etype` is
//! named and the `cipher` is left as opaque bytes (no decryption).

use serde_json::{json, Value};

use super::{as_i64, as_str, ctx, explicit, kids};
use crate::json::decode_value;
use crate::tlv::{parse, Class, Tlv};

/// Friendly name for a Kerberos `[APPLICATION n]` message tag.
pub fn message_name(tag: u32) -> &'static str {
    match tag {
        1 => "Ticket",
        2 => "Authenticator",
        3 => "EncTicketPart",
        10 => "AS-REQ",
        11 => "AS-REP",
        12 => "TGS-REQ",
        13 => "TGS-REP",
        14 => "AP-REQ",
        15 => "AP-REP",
        30 => "KRB-ERROR",
        _ => "unknown",
    }
}

/// Friendly name for a Kerberos encryption type number.
pub fn etype_name(n: i64) -> String {
    match n {
        1 => "des-cbc-crc".into(),
        3 => "des-cbc-md5".into(),
        16 => "des3-cbc-sha1-kd".into(),
        17 => "aes128-cts-hmac-sha1-96".into(),
        18 => "aes256-cts-hmac-sha1-96".into(),
        19 => "aes128-cts-hmac-sha256-128".into(),
        20 => "aes256-cts-hmac-sha384-192".into(),
        23 => "rc4-hmac".into(),
        n => n.to_string(),
    }
}

/// `asn1.krb_decode`: dispatch on the application tag and project the body.
pub fn krb_decode(blob: &[u8]) -> Value {
    let Ok(root) = parse(blob) else {
        return json!({ "error": "not well-formed" });
    };
    if root.class != Class::Application {
        return json!({ "error": "not a Kerberos APPLICATION-tagged message" });
    }
    json!({
        "msg_type": message_name(root.tag),
        "app_tag": root.tag,
        "body": decode_value(explicit(&root)),
    })
}

/// The outer `Ticket` projection.
#[derive(Clone, Debug, Default)]
pub struct KrbTicket {
    pub tkt_vno: Option<i64>,
    pub realm: Option<String>,
    pub sname: Option<String>,
    pub name_type: Option<String>,
    pub enc_part_etype: Option<String>,
    pub enc_part_kvno: Option<i64>,
    pub enc_part_cipher: Option<Vec<u8>>,
}

fn name_type_str(n: i64) -> String {
    match n {
        0 => "NT-UNKNOWN".into(),
        1 => "NT-PRINCIPAL".into(),
        2 => "NT-SRV-INST".into(),
        3 => "NT-SRV-HST".into(),
        4 => "NT-SRV-XHST".into(),
        n => n.to_string(),
    }
}

/// Render a PrincipalName `SEQUENCE { [0] name-type, [1] SEQUENCE OF String }`
/// to `comp/comp` and return its name-type.
fn principal(t: &Tlv) -> (Option<String>, Option<String>) {
    let seq = explicit(t);
    let c = kids(seq);
    let nt = ctx(c, 0)
        .and_then(|n| as_i64(explicit(n)))
        .map(name_type_str);
    let comps = ctx(c, 1).map(|n| {
        kids(explicit(n))
            .iter()
            .filter_map(as_str)
            .collect::<Vec<_>>()
            .join("/")
    });
    (comps, nt)
}

/// `asn1.krb_ticket`: parse the outer `Ticket`.
pub fn krb_ticket(blob: &[u8]) -> Option<KrbTicket> {
    let root = parse(blob).ok()?;
    if root.class != Class::Application || root.tag != 1 {
        return None;
    }
    let seq = explicit(&root);
    let c = kids(seq);
    let (sname, name_type) = match ctx(c, 2) {
        Some(sn) => principal(sn),
        None => (None, None),
    };
    let (enc_part_etype, enc_part_kvno, enc_part_cipher) = match ctx(c, 3) {
        Some(ep) => {
            let ec = kids(explicit(ep));
            (
                ctx(ec, 0).and_then(|n| as_i64(explicit(n))).map(etype_name),
                ctx(ec, 1).and_then(|n| as_i64(explicit(n))),
                ctx(ec, 2).map(|n| explicit(n).gather_octets()),
            )
        }
        None => (None, None, None),
    };
    Some(KrbTicket {
        tkt_vno: ctx(c, 0).and_then(|n| as_i64(explicit(n))),
        realm: ctx(c, 1).and_then(|n| as_str(explicit(n))),
        sname,
        name_type,
        enc_part_etype,
        enc_part_kvno,
        enc_part_cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_kerberos_is_none() {
        assert!(krb_ticket(&[0x30, 0x03, 0x02, 0x01, 0x05]).is_none());
        assert!(krb_decode(&[0x30, 0x03, 0x02, 0x01, 0x05])["error"].is_string());
    }

    #[test]
    fn etype_names() {
        assert_eq!(etype_name(18), "aes256-cts-hmac-sha1-96");
        assert_eq!(message_name(11), "AS-REP");
    }
}
