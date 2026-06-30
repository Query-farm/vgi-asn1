//! Human-readable TLV dumps: an `openssl asn1parse`-style indented offset/length
//! tree, and a Gutmann `dumpasn1`-style annotated form (the *format* is
//! reproduced; OID names come from the permissive bundled registry).

use crate::oid;
use crate::tlv::{universal_tag_name, Body, Class, Tlv};
use crate::value;

/// Dump style selector.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    Openssl,
    Dumpasn1,
}

impl DumpFormat {
    pub fn parse(s: &str) -> DumpFormat {
        match s.trim().to_ascii_lowercase().as_str() {
            "dumpasn1" => DumpFormat::Dumpasn1,
            _ => DumpFormat::Openssl,
        }
    }
}

/// Render the whole tree to a multi-line string.
pub fn dump(root: &Tlv, fmt: DumpFormat) -> String {
    let mut lines = Vec::new();
    render(root, 0, fmt, &mut lines);
    lines.join("\n")
}

fn tag_name(t: &Tlv) -> String {
    match t.class {
        Class::Universal => universal_tag_name(t.tag)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("[UNIVERSAL {}]", t.tag)),
        Class::Application => format!("[APPLICATION {}]", t.tag),
        Class::Context => format!("cont [ {} ]", t.tag),
        Class::Private => format!("[PRIVATE {}]", t.tag),
    }
}

fn scalar(t: &Tlv) -> Option<String> {
    let bytes = t.primitive()?;
    if t.class != Class::Universal {
        return None;
    }
    match t.tag {
        1 => value::decode_bool(bytes).map(|b| if b { "255".into() } else { "0".into() }),
        2 | 10 => Some(value::integer_to_decimal(bytes)),
        6 => oid::decode_oid(bytes).map(|d| match oid::name_for(&d) {
            Some(n) => format!("{d} ({n})"),
            None => d,
        }),
        13 => oid::decode_relative_oid(bytes),
        12 | 18 | 19 | 20 | 22 | 25 | 26 | 27 | 28 | 30 => value::decode_string(t.tag, bytes),
        23 | 24 => value::decode_time(t.tag, bytes).map(|tv| tv.iso),
        4 => Some(format!("[HEX DUMP]:{}", hex(bytes))),
        3 => value::bitstring(bytes).map(|(u, d)| format!("unused={u} {}", hex(d))),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn render(t: &Tlv, depth: usize, fmt: DumpFormat, out: &mut Vec<String>) {
    let kind = if t.constructed { "cons" } else { "prim" };
    let name = tag_name(t);
    let value = scalar(t).map(|v| format!(":{v}")).unwrap_or_default();
    let len_disp: String = if t.indefinite {
        "inf".into()
    } else {
        format!("{:>4}", t.content_len)
    };
    match fmt {
        DumpFormat::Openssl => {
            out.push(format!(
                "{:>5}:d={} hl={} l={} {}: {}{}",
                t.offset, depth, t.header_len, len_disp, kind, name, value
            ));
        }
        DumpFormat::Dumpasn1 => {
            let indent = "  ".repeat(depth);
            out.push(format!(
                "{:>5}: {}{} {}{}",
                t.offset,
                indent,
                if t.constructed { "+" } else { " " },
                name,
                value
            ));
        }
    }
    if let Body::Constructed(children) = &t.body {
        for c in children {
            render(c, depth + 1, fmt, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse;

    #[test]
    fn openssl_style() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let s = dump(&parse(&der).unwrap(), DumpFormat::Openssl);
        assert!(s.contains("SEQUENCE"));
        assert!(s.contains("INTEGER"));
        assert!(s.contains(":5"));
    }

    #[test]
    fn dumpasn1_oid_name() {
        let b = oid::encode_oid("1.2.840.113549.1.1.11").unwrap();
        let mut der = vec![0x06, b.len() as u8];
        der.extend_from_slice(&b);
        let s = dump(&parse(&der).unwrap(), DumpFormat::Dumpasn1);
        assert!(s.contains("sha256WithRSAEncryption"));
    }
}
