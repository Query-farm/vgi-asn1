//! PEM armor handling: split a `-----BEGIN <label>-----` … `-----END-----`
//! bundle into its DER blocks (`asn1.pem_decode`) and report the first label
//! (`asn1.pem_label`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// One decoded PEM block.
#[derive(Clone, Debug)]
pub struct PemBlock {
    pub idx: i32,
    pub label: String,
    pub der: Vec<u8>,
}

/// Split a PEM bundle into its blocks, base64-decoding each body to DER. Blocks
/// whose body is not valid base64 are skipped. Never panics.
pub fn pem_decode(text: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut idx = 0i32;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(label) = begin_label(trimmed) else {
            continue;
        };
        let mut body = String::new();
        let end_marker = format!("-----END {label}-----");
        for l in lines.by_ref() {
            let lt = l.trim();
            if lt == end_marker || lt.starts_with("-----END") {
                break;
            }
            body.push_str(lt);
        }
        if let Ok(der) = STANDARD.decode(body.as_bytes()) {
            blocks.push(PemBlock {
                idx,
                label: label.to_string(),
                der,
            });
            idx += 1;
        }
    }
    blocks
}

/// The label of the first PEM block, or `None`.
pub fn pem_label(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| begin_label(l.trim()).map(|s| s.to_string()))
}

fn begin_label(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("-----BEGIN ")?;
    rest.strip_suffix("-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
BAUG
-----END PRIVATE KEY-----";

    #[test]
    fn splits_blocks() {
        let blocks = pem_decode(SAMPLE);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der, vec![1, 2, 3]);
        assert_eq!(blocks[1].label, "PRIVATE KEY");
        assert_eq!(blocks[1].der, vec![4, 5, 6]);
    }

    #[test]
    fn first_label() {
        assert_eq!(pem_label(SAMPLE).as_deref(), Some("CERTIFICATE"));
        assert_eq!(pem_label("no pem here"), None);
    }
}
