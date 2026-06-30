//! Re-encode a decoded TLV tree to canonical **DER**: definite minimal lengths,
//! indefinite forms collapsed, and SET OF children sorted by their encoding.
//! Idempotent on DER input, so `to_der(decode(der)) == der` for canonical input.

use crate::tlv::{Body, Class, Tlv};

/// Re-encode `t` (and its subtree) to canonical DER bytes.
pub fn to_der(t: &Tlv) -> Vec<u8> {
    let mut out = Vec::new();
    encode_node(t, &mut out);
    out
}

fn encode_node(t: &Tlv, out: &mut Vec<u8>) {
    let content = match &t.body {
        Body::Primitive(b) => b.clone(),
        Body::Constructed(children) => {
            let mut encoded: Vec<Vec<u8>> = children
                .iter()
                .map(|c| {
                    let mut v = Vec::new();
                    encode_node(c, &mut v);
                    v
                })
                .collect();
            // DER: SET OF (universal SET, tag 17) is sorted by encoding.
            if t.class == Class::Universal && t.tag == 17 {
                encoded.sort();
            }
            encoded.concat()
        }
    };
    encode_identifier(t, out);
    encode_length(content.len(), out);
    out.extend_from_slice(&content);
}

fn encode_identifier(t: &Tlv, out: &mut Vec<u8>) {
    let class_bits = match t.class {
        Class::Universal => 0x00,
        Class::Application => 0x40,
        Class::Context => 0x80,
        Class::Private => 0xc0,
    };
    let cons = if t.constructed { 0x20 } else { 0x00 };
    if t.tag < 0x1f {
        out.push(class_bits | cons | t.tag as u8);
    } else {
        out.push(class_bits | cons | 0x1f);
        // base-128, big-endian, minimal, continuation bit on all but last.
        let mut stack = [0u8; 5];
        let mut n = 0;
        let mut v = t.tag;
        stack[n] = (v & 0x7f) as u8;
        n += 1;
        v >>= 7;
        while v > 0 {
            stack[n] = ((v & 0x7f) as u8) | 0x80;
            n += 1;
            v >>= 7;
        }
        for i in (0..n).rev() {
            out.push(stack[i]);
        }
    }
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let sig = &bytes[first..];
        out.push(0x80 | sig.len() as u8);
        out.extend_from_slice(sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse;

    #[test]
    fn der_roundtrip_identity() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff];
        let t = parse(&der).unwrap();
        assert_eq!(to_der(&t), der);
    }

    #[test]
    fn indefinite_to_definite() {
        let ber = [0x30, 0x80, 0x04, 0x02, b'H', b'i', 0x00, 0x00];
        let t = parse(&ber).unwrap();
        let der = to_der(&t);
        assert_eq!(der, [0x30, 0x04, 0x04, 0x02, b'H', b'i']);
    }

    #[test]
    fn long_length() {
        // OCTET STRING of 200 bytes
        let mut der = vec![0x04, 0x81, 0xc8];
        der.extend(std::iter::repeat_n(0xaa, 200));
        let t = parse(&der).unwrap();
        assert_eq!(to_der(&t), der);
    }
}
