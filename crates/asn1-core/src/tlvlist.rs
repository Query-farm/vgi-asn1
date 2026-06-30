//! Flat, document-order views of the TLV tree: the `asn1.tlv` row list, the
//! `asn1.oids` inventory, and `asn1.at_path` navigation. Paths are JSONPath-ish:
//! `$` is the root and each `.<n>` selects the n-th child (e.g. `$.0.2`).

use serde_json::Value;

use crate::json::{decode_value, tag_label};
use crate::oid;
use crate::tlv::{Body, Tlv};
use crate::value;

/// One row of `asn1.tlv`.
#[derive(Clone, Debug)]
pub struct TlvRow {
    pub path: String,
    pub class: String,
    pub tag: u32,
    pub tag_name: String,
    pub constructed: bool,
    pub header_len: u32,
    pub len: u64,
    /// JSON-encoded value of the node (scalar for primitives, null for groups).
    pub value: String,
}

/// Flatten the tree into document-order rows.
pub fn flatten(root: &Tlv) -> Vec<TlvRow> {
    let mut rows = Vec::new();
    walk(root, "$".to_string(), &mut rows);
    rows
}

fn node_value_json(t: &Tlv) -> String {
    match &t.body {
        Body::Constructed(_) => "null".to_string(),
        Body::Primitive(_) => decode_value(t).to_string(),
    }
}

fn walk(t: &Tlv, path: String, rows: &mut Vec<TlvRow>) {
    rows.push(TlvRow {
        path: path.clone(),
        class: t.class.as_str().to_string(),
        tag: t.tag,
        tag_name: tag_label(t),
        constructed: t.constructed,
        header_len: t.header_len as u32,
        len: t.content_len as u64,
        value: node_value_json(t),
    });
    if let Body::Constructed(children) = &t.body {
        for (i, c) in children.iter().enumerate() {
            walk(c, format!("{path}.{i}"), rows);
        }
    }
}

/// One row of `asn1.oids`.
#[derive(Clone, Debug)]
pub struct OidRow {
    pub oid: String,
    pub name: Option<String>,
    pub path: String,
}

/// Collect every OBJECT IDENTIFIER in the tree with its dotted form, resolved
/// name, and path.
pub fn oids(root: &Tlv) -> Vec<OidRow> {
    let mut out = Vec::new();
    collect_oids(root, "$".to_string(), &mut out);
    out
}

fn collect_oids(t: &Tlv, path: String, out: &mut Vec<OidRow>) {
    if let Some(dotted) = value::oid_string(t) {
        out.push(OidRow {
            name: oid::name_for(&dotted).map(|s| s.to_string()),
            oid: dotted,
            path: path.clone(),
        });
    }
    if let Body::Constructed(children) = &t.body {
        for (i, c) in children.iter().enumerate() {
            collect_oids(c, format!("{path}.{i}"), out);
        }
    }
}

/// Resolve `path` against the tree, returning the matching node's decoded JSON
/// value, or `Value::Null` if the path does not resolve.
pub fn at_path(root: &Tlv, path: &str) -> Value {
    match navigate(root, path) {
        Some(node) => decode_value(node),
        None => Value::Null,
    }
}

fn navigate<'a>(root: &'a Tlv, path: &str) -> Option<&'a Tlv> {
    let trimmed = path.trim();
    let trimmed = trimmed.strip_prefix('$').unwrap_or(trimmed);
    let mut node = root;
    for seg in trimmed.split('.') {
        if seg.is_empty() {
            continue;
        }
        // Accept `2` or `2[0]`-style; take the leading integer.
        let idx: usize = seg
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;
        node = node.children()?.get(idx)?;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse;

    #[test]
    fn flatten_paths() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let rows = flatten(&parse(&der).unwrap());
        assert_eq!(rows[0].path, "$");
        assert_eq!(rows[1].path, "$.0");
        assert_eq!(rows[2].path, "$.1");
        assert_eq!(rows[2].value, "2");
    }

    #[test]
    fn at_path_resolves() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09];
        let t = parse(&der).unwrap();
        assert_eq!(at_path(&t, "$.1"), serde_json::json!(9));
        assert_eq!(at_path(&t, "$.5"), Value::Null);
    }

    #[test]
    fn oid_inventory() {
        let b = oid::encode_oid("2.5.4.3").unwrap();
        let mut der = vec![0x30, (b.len() + 2) as u8, 0x06, b.len() as u8];
        der.extend_from_slice(&b);
        let rows = oids(&parse(&der).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].oid, "2.5.4.3");
        assert_eq!(rows[0].name.as_deref(), Some("id-at-commonName"));
        assert_eq!(rows[0].path, "$.0");
    }
}
