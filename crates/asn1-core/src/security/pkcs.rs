//! PKCS#8 (RFC 5208 PrivateKeyInfo + EncryptedPrivateKeyInfo) structural info and
//! the PKCS#12 SafeBag walk. **No plaintext key material is ever surfaced** —
//! key bags expose only the algorithm + `encrypted` flag and the friendly-name /
//! local-key-id attributes; nothing is decrypted.

use sha2::{Digest, Sha256};

use super::{as_i64, as_oid, explicit, kids, oid_named};
use crate::json::decode_value;
use crate::tlv::{parse, Class, Tlv};
use crate::value;

/// Structural PKCS#8 info.
#[derive(Clone, Debug, Default)]
pub struct Pkcs8Info {
    pub version: Option<i64>,
    pub algorithm: Option<String>,
    pub params_json: String,
    pub public_key: Option<Vec<u8>>,
    pub encrypted: bool,
    pub kdf: Option<String>,
    pub enc_alg: Option<String>,
}

/// `asn1.pkcs8_info`: decode a PrivateKeyInfo or EncryptedPrivateKeyInfo.
pub fn pkcs8_info(blob: &[u8]) -> Option<Pkcs8Info> {
    let root = parse(blob).ok()?;
    if !root.is_universal(16) {
        return None;
    }
    let c = kids(&root);
    let mut info = Pkcs8Info {
        params_json: "null".into(),
        ..Default::default()
    };

    match c.first() {
        // EncryptedPrivateKeyInfo: SEQ { encryptionAlgorithm AlgId, encryptedData }
        Some(first) if first.is_universal(16) => {
            info.encrypted = true;
            let alg = first;
            let ac = kids(alg);
            let alg_oid = ac.first().and_then(as_oid);
            if alg_oid.as_deref() == Some("1.2.840.113549.1.5.13") {
                // PBES2 { keyDerivationFunc, encryptionScheme }
                if let Some(params) = ac.get(1) {
                    let pc = kids(params);
                    info.kdf = pc.first().and_then(|k| kids(k).first()).and_then(oid_named);
                    info.enc_alg = pc.get(1).and_then(|k| kids(k).first()).and_then(oid_named);
                }
                info.algorithm = Some("id-PBES2".into());
            } else {
                info.algorithm = ac.first().and_then(oid_named);
                info.enc_alg = info.algorithm.clone();
            }
        }
        // PrivateKeyInfo: SEQ { version INT, privateKeyAlgorithm AlgId, privateKey OCTET, [1]? }
        Some(first) if first.is_universal(2) => {
            info.version = as_i64(first);
            if let Some(alg) = c.get(1).filter(|t| t.is_universal(16)) {
                let ac = kids(alg);
                info.algorithm = ac.first().and_then(oid_named);
                if let Some(params) = ac.get(1) {
                    info.params_json = decode_value(params).to_string();
                }
            }
            // OneAsymmetricKey v2 optional [1] publicKey (BIT STRING) — surface it
            // (public, not private).
            if let Some(pk) = c.iter().find(|t| t.is_context(1)) {
                let inner = explicit(pk);
                if inner.is_universal(3) {
                    if let Some((_, data)) = inner.primitive().and_then(value::bitstring) {
                        info.public_key = Some(data.to_vec());
                    }
                } else {
                    info.public_key = Some(inner.gather_octets());
                }
            }
        }
        _ => return None,
    }
    Some(info)
}

/// One PKCS#12 SafeBag row.
#[derive(Clone, Debug, Default)]
pub struct BagRow {
    pub bag_type: String,
    pub friendly_name: Option<String>,
    pub local_key_id: Option<String>,
    pub alg: Option<String>,
    pub cert_sha256: Option<String>,
    pub encrypted: bool,
}

fn bag_type_name(oid_str: &str) -> &'static str {
    match oid_str {
        "1.2.840.113549.1.12.10.1.1" => "keyBag",
        "1.2.840.113549.1.12.10.1.2" => "pkcs8ShroudedKeyBag",
        "1.2.840.113549.1.12.10.1.3" => "certBag",
        "1.2.840.113549.1.12.10.1.4" => "crlBag",
        "1.2.840.113549.1.12.10.1.5" => "secretBag",
        "1.2.840.113549.1.12.10.1.6" => "safeContentsBag",
        _ => "unknown",
    }
}

/// `asn1.pkcs12_bags`: walk PFX → AuthenticatedSafe → SafeContents → SafeBag.
pub fn pkcs12_bags(blob: &[u8]) -> Vec<BagRow> {
    let mut rows = Vec::new();
    let Ok(pfx) = parse(blob) else {
        return rows;
    };
    let pc = kids(&pfx);
    // pfx: SEQ { version INT, authSafe ContentInfo, macData? }
    let Some(auth_safe) = pc.get(1).filter(|t| t.is_universal(16)) else {
        return rows;
    };
    // authSafe ContentInfo(id-data): content [0] EXPLICIT OCTET STRING = DER of
    // AuthenticatedSafe.
    let Some(content) = kids(auth_safe).iter().find(|t| t.is_context(0)) else {
        return rows;
    };
    let inner = explicit(content);
    let der = inner.gather_octets();
    let Ok(authenticated_safe) = parse(&der) else {
        return rows;
    };
    for ci in kids(&authenticated_safe) {
        let cik = kids(ci);
        let ct = cik.first().and_then(as_oid);
        match ct.as_deref() {
            Some("1.2.840.113549.1.7.1") => {
                // id-data: content [0] EXPLICIT OCTET STRING = DER of SafeContents
                if let Some(c0) = cik.iter().find(|t| t.is_context(0)) {
                    let sc_der = explicit(c0).gather_octets();
                    if let Ok(safe_contents) = parse(&sc_der) {
                        for bag in kids(&safe_contents) {
                            if let Some(r) = shred_bag(bag, false) {
                                rows.push(r);
                            }
                        }
                    }
                }
            }
            Some("1.2.840.113549.1.7.6") => {
                // id-encryptedData: bags are encrypted; surface a placeholder.
                rows.push(BagRow {
                    bag_type: "encryptedData".into(),
                    encrypted: true,
                    ..Default::default()
                });
            }
            _ => {}
        }
    }
    rows
}

fn shred_bag(bag: &Tlv, _encrypted_ctx: bool) -> Option<BagRow> {
    if !bag.is_universal(16) {
        return None;
    }
    let c = kids(bag);
    let bag_id = c.first().and_then(as_oid)?;
    let mut row = BagRow {
        bag_type: bag_type_name(&bag_id).to_string(),
        encrypted: bag_id == "1.2.840.113549.1.12.10.1.2",
        ..Default::default()
    };
    // bagValue [0] EXPLICIT
    let bag_value = c.get(1).map(explicit);
    match bag_id.as_str() {
        "1.2.840.113549.1.12.10.1.3" => {
            // CertBag SEQ { certId OID, certValue [0] EXPLICIT OCTET STRING }
            if let Some(cb) = bag_value {
                if let Some(cv) = kids(cb).iter().find(|t| t.is_context(0)) {
                    let cert_der = explicit(cv).gather_octets();
                    if !cert_der.is_empty() {
                        row.cert_sha256 = Some(hex(&Sha256::digest(&cert_der)));
                    }
                }
            }
        }
        "1.2.840.113549.1.12.10.1.1" | "1.2.840.113549.1.12.10.1.2" => {
            // Key bags: surface only the algorithm.
            if let Some(kv) = bag_value {
                // shrouded: EncryptedPrivateKeyInfo; plain: PrivateKeyInfo
                let kk = kids(kv);
                if let Some(first) = kk.first() {
                    if first.is_universal(16) {
                        row.alg = kids(first).first().and_then(oid_named);
                    } else if let Some(alg) = kk.get(1).filter(|t| t.is_universal(16)) {
                        row.alg = kids(alg).first().and_then(oid_named);
                    }
                }
            }
        }
        _ => {}
    }
    // bagAttributes SET OF Attribute (friendlyName / localKeyID)
    if let Some(attrs) = c
        .iter()
        .find(|t| t.is_universal(17) || (t.class == Class::Context && t.tag == 1))
    {
        for attr in kids(attrs) {
            let ak = kids(attr);
            let Some(aoid) = ak.first().and_then(as_oid) else {
                continue;
            };
            let first_val = ak.get(1).and_then(|v| kids(v).first());
            match aoid.as_str() {
                "1.2.840.113549.1.9.20" => {
                    row.friendly_name = first_val
                        .and_then(|v| value::decode_string(v.tag, v.primitive().unwrap_or(&[])));
                }
                "1.2.840.113549.1.9.21" => {
                    row.local_key_id = first_val.and_then(|v| v.primitive()).map(hex);
                }
                _ => {}
            }
        }
    }
    Some(row)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_is_none_or_empty() {
        assert!(pkcs8_info(&[0xff, 0x00]).is_none());
        assert!(pkcs12_bags(&[0xff, 0x00]).is_empty());
    }

    #[test]
    fn plain_pkcs8_algorithm() {
        // SEQ { INTEGER 0, SEQ { OID rsaEncryption, NULL }, OCTET STRING (key) }
        let alg_oid = crate::oid::encode_oid("1.2.840.113549.1.1.1").unwrap();
        let mut algid = vec![0x30, 0u8];
        let mut ai = vec![0x06, alg_oid.len() as u8];
        ai.extend_from_slice(&alg_oid);
        ai.extend_from_slice(&[0x05, 0x00]); // NULL
        algid[1] = ai.len() as u8;
        algid.extend_from_slice(&ai);
        let mut body = vec![0x02, 0x01, 0x00];
        body.extend_from_slice(&algid);
        body.extend_from_slice(&[0x04, 0x02, 0xde, 0xad]); // private key octets
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        let info = pkcs8_info(&der).unwrap();
        assert!(!info.encrypted);
        assert_eq!(info.version, Some(0));
        assert_eq!(info.algorithm.as_deref(), Some("rsaEncryption"));
        // Private key bytes are NOT surfaced.
        assert!(info.public_key.is_none());
    }
}
