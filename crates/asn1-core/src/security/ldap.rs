//! LDAP wire messages (RFC 4511): `protocolOp` CHOICE dispatch, RFC 4515 filter
//! rendering, and multi-message fan-out (one TCP segment may carry several
//! LDAPMessages).

use serde_json::{json, Value};

use super::{as_i64, as_str, kids};
use crate::json::decode_value;
use crate::tlv::{parse_all, Class, Tlv};

/// Friendly name for a `protocolOp` application tag.
pub fn op_name(tag: u32) -> &'static str {
    match tag {
        0 => "BindRequest",
        1 => "BindResponse",
        2 => "UnbindRequest",
        3 => "SearchRequest",
        4 => "SearchResultEntry",
        5 => "SearchResultDone",
        6 => "ModifyRequest",
        7 => "ModifyResponse",
        8 => "AddRequest",
        9 => "AddResponse",
        10 => "DelRequest",
        11 => "DelResponse",
        12 => "ModifyDNRequest",
        13 => "ModifyDNResponse",
        14 => "CompareRequest",
        15 => "CompareResponse",
        16 => "AbandonRequest",
        23 => "ExtendedRequest",
        24 => "ExtendedResponse",
        25 => "IntermediateResponse",
        _ => "unknown",
    }
}

fn scope_name(n: i64) -> String {
    match n {
        0 => "baseObject".into(),
        1 => "singleLevel".into(),
        2 => "wholeSubtree".into(),
        n => n.to_string(),
    }
}

fn result_code_name(n: i64) -> String {
    match n {
        0 => "success".into(),
        1 => "operationsError".into(),
        2 => "protocolError".into(),
        3 => "timeLimitExceeded".into(),
        4 => "sizeLimitExceeded".into(),
        7 => "authMethodNotSupported".into(),
        10 => "referral".into(),
        16 => "noSuchAttribute".into(),
        32 => "noSuchObject".into(),
        34 => "invalidDNSyntax".into(),
        48 => "inappropriateAuthentication".into(),
        49 => "invalidCredentials".into(),
        50 => "insufficientAccessRights".into(),
        53 => "unwillingToPerform".into(),
        n => n.to_string(),
    }
}

/// One shredded LDAP message row.
#[derive(Clone, Debug, Default)]
pub struct LdapRow {
    pub message_id: Option<i64>,
    pub op: String,
    pub dn: Option<String>,
    pub scope: Option<String>,
    pub filter: Option<String>,
    pub attributes: Vec<String>,
    pub result_code: Option<String>,
    pub matched_dn: Option<String>,
    pub diagnostic: Option<String>,
}

fn esc(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// Render a Filter node to RFC 4515 string form.
pub fn render_filter(t: &Tlv) -> String {
    if t.class != Class::Context {
        return "(?)".to_string();
    }
    let avas = |op: &str| -> String {
        let c = kids(t);
        if c.len() < 2 {
            return "(?)".to_string();
        }
        let attr = as_str(&c[0]).unwrap_or_default();
        let val = as_str(&c[1]).unwrap_or_default();
        format!("({}{}{})", esc(&attr), op, esc(&val))
    };
    match t.tag {
        0 => format!(
            "(&{})",
            kids(t).iter().map(render_filter).collect::<String>()
        ),
        1 => format!(
            "(|{})",
            kids(t).iter().map(render_filter).collect::<String>()
        ),
        2 => format!(
            "(!{})",
            kids(t).first().map(render_filter).unwrap_or_default()
        ),
        3 => avas("="),
        4 => render_substrings(t),
        5 => avas(">="),
        6 => avas("<="),
        7 => {
            // present: primitive attribute description bytes
            let attr = t
                .primitive()
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("");
            format!("({}=*)", esc(attr))
        }
        8 => avas("~="),
        _ => "(?)".to_string(),
    }
}

fn render_substrings(t: &Tlv) -> String {
    let c = kids(t);
    if c.len() < 2 {
        return "(?)".to_string();
    }
    let attr = as_str(&c[0]).unwrap_or_default();
    let mut pat = String::new();
    let mut first = true;
    for sub in kids(&c[1]) {
        let s = sub
            .primitive()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        match sub.tag {
            0 => {
                pat.push_str(&esc(s));
                pat.push('*');
            }
            1 => {
                if first {
                    pat.push('*');
                }
                pat.push_str(&esc(s));
                pat.push('*');
            }
            2 => {
                if !pat.ends_with('*') {
                    pat.push('*');
                }
                pat.push_str(&esc(s));
            }
            _ => {}
        }
        first = false;
    }
    if pat.is_empty() {
        pat.push('*');
    }
    format!("({}={})", esc(&attr), pat)
}

fn shred_op(op: &Tlv, row: &mut LdapRow) {
    let c = kids(op);
    match op.tag {
        3 => {
            // SearchRequest
            row.dn = c.first().and_then(as_str);
            row.scope = c.get(1).and_then(as_i64).map(scope_name);
            row.filter = c.get(6).map(render_filter);
            if let Some(attrs) = c.get(7) {
                row.attributes = kids(attrs).iter().filter_map(as_str).collect();
            }
        }
        4 => {
            // SearchResultEntry: objectName, attributes
            row.dn = c.first().and_then(as_str);
            if let Some(attrs) = c.get(1) {
                row.attributes = kids(attrs)
                    .iter()
                    .filter_map(|a| kids(a).first().and_then(as_str))
                    .collect();
            }
        }
        0 => {
            // BindRequest: version, name, ...
            row.dn = c.get(1).and_then(as_str);
        }
        8 | 10 | 12 => {
            row.dn = c.first().and_then(as_str);
        }
        1 | 5 | 7 | 9 | 11 | 13 | 15 | 24 => {
            // result-bearing ops: resultCode, matchedDN, diagnosticMessage
            row.result_code = c.first().and_then(as_i64).map(result_code_name);
            row.matched_dn = c.get(1).and_then(as_str);
            row.diagnostic = c.get(2).and_then(as_str);
        }
        _ => {}
    }
}

/// Fan a blob (one or more LDAPMessages) into rows.
pub fn ldap_messages(blob: &[u8]) -> Vec<LdapRow> {
    let Ok(msgs) = parse_all(blob) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for msg in &msgs {
        if !msg.is_universal(16) {
            continue;
        }
        let c = kids(msg);
        if c.len() < 2 {
            continue;
        }
        let mut row = LdapRow {
            message_id: as_i64(&c[0]),
            ..Default::default()
        };
        let op = &c[1];
        if op.class == Class::Application {
            row.op = op_name(op.tag).to_string();
            shred_op(op, &mut row);
        } else {
            row.op = "unknown".into();
        }
        rows.push(row);
    }
    rows
}

/// `asn1.ldap_decode`: the first message as JSON.
pub fn ldap_decode(blob: &[u8]) -> Value {
    let rows = ldap_messages(blob);
    let Some(r) = rows.first() else {
        // Fall back to a raw projection.
        return match parse_all(blob) {
            Ok(m) if !m.is_empty() => json!({ "raw": decode_value(&m[0]) }),
            _ => json!({ "error": "not an LDAPMessage" }),
        };
    };
    json!({
        "message_id": r.message_id,
        "op": r.op,
        "dn": r.dn,
        "scope": r.scope,
        "filter": r.filter,
        "attributes": r.attributes,
        "result_code": r.result_code,
        "matched_dn": r.matched_dn,
        "diagnostic": r.diagnostic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse;

    #[test]
    fn renders_equality_filter() {
        // [3] SEQ { OCTET "uid", OCTET "jdoe" }
        let mut f = vec![0xa3, 0u8];
        let mut inner = vec![0x04, 0x03];
        inner.extend_from_slice(b"uid");
        inner.extend_from_slice(&[0x04, 0x04]);
        inner.extend_from_slice(b"jdoe");
        f[1] = inner.len() as u8;
        f.extend_from_slice(&inner);
        let t = parse(&f).unwrap();
        assert_eq!(render_filter(&t), "(uid=jdoe)");
    }

    #[test]
    fn renders_present_filter() {
        // [7] primitive "objectClass"
        let mut f = vec![0x87, 11];
        f.extend_from_slice(b"objectClass");
        let t = parse(&f).unwrap();
        assert_eq!(render_filter(&t), "(objectClass=*)");
    }
}
