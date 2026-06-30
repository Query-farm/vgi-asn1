//! Structural decoders that walk the generic TLV tree into the named
//! security/telecom module shapes (SNMP, Kerberos, LDAP, CMS/PKCS#7, PKCS#8/#12,
//! OCSP). **No crypto verification anywhere** — signatures, MACs, and encrypted
//! parts are surfaced as bytes + the named algorithm OID for a downstream
//! verifier. Every decoder is total: a malformed/foreign blob yields `None` or an
//! `{error: …}` JSON value, never a panic.

pub mod cms;
pub mod kerberos;
pub mod ldap;
pub mod ocsp;
pub mod pkcs;
pub mod snmp;

use crate::tlv::{Body, Class, Tlv};
use crate::value;

/// Borrow a node's constructed children (empty slice if primitive).
pub(crate) fn kids(t: &Tlv) -> &[Tlv] {
    match &t.body {
        Body::Constructed(c) => c,
        Body::Primitive(_) => &[],
    }
}

/// Decode an INTEGER/ENUMERATED node to i64.
pub(crate) fn as_i64(t: &Tlv) -> Option<i64> {
    if t.is_universal(2) || t.is_universal(10) {
        value::integer_to_i64(t.primitive()?)
    } else {
        None
    }
}

/// Decode a string-flavored node to a Rust string. Handles the universal string
/// tags, OCTET STRINGs that carry text (LDAP/SNMP), and context-implicit strings
/// — all best-effort (UTF-8, then Latin-1), never panicking.
pub(crate) fn as_str(t: &Tlv) -> Option<String> {
    let b = t.primitive()?;
    if t.class == Class::Universal {
        if let Some(s) = value::decode_string(t.tag, b) {
            return Some(s);
        }
    }
    match std::str::from_utf8(b) {
        Ok(s) => Some(s.to_string()),
        Err(_) => Some(b.iter().map(|&c| c as char).collect()),
    }
}

/// Decode an OBJECT IDENTIFIER node to its dotted form.
pub(crate) fn as_oid(t: &Tlv) -> Option<String> {
    value::oid_string(t)
}

/// Resolve an OID node to `name (oid)` or just the dotted form.
pub(crate) fn oid_named(t: &Tlv) -> Option<String> {
    let dotted = as_oid(t)?;
    Some(match crate::oid::name_for(&dotted) {
        Some(n) => n.to_string(),
        None => dotted,
    })
}

/// Find the first child with the given context tag.
pub(crate) fn ctx(children: &[Tlv], tag: u32) -> Option<&Tlv> {
    children.iter().find(|c| c.is_context(tag))
}

/// Unwrap a single EXPLICIT wrapper: if `t` is constructed with exactly one
/// child, return that child; otherwise return `t`.
pub(crate) fn explicit(t: &Tlv) -> &Tlv {
    if let Body::Constructed(c) = &t.body {
        if c.len() == 1 {
            return &c[0];
        }
    }
    t
}

/// The short attribute key for a known X.500 attribute-type OID (`CN`, `O`, …).
pub(crate) fn short_attr(oid_str: &str) -> String {
    match oid_str {
        "2.5.4.3" => "CN".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "0.9.2342.19200300.100.1.25" => "DC".into(),
        "1.2.840.113549.1.9.1" => "E".into(),
        other => other.to_string(),
    }
}

/// Render an X.500 Name (RDNSequence) to a compact `CN=…,O=…` string.
pub(crate) fn render_name(name: &Tlv) -> String {
    let mut parts = Vec::new();
    for rdn in kids(name) {
        for atv in kids(rdn) {
            let ak = kids(atv);
            if ak.len() < 2 {
                continue;
            }
            let Some(oid_str) = as_oid(&ak[0]) else {
                continue;
            };
            let key = short_attr(&oid_str);
            let val = value::decode_string(ak[1].tag, ak[1].primitive().unwrap_or(&[]))
                .unwrap_or_default();
            parts.push(format!("{key}={val}"));
        }
    }
    parts.join(",")
}
