//! CMS / PKCS#7 (RFC 5652): ContentInfo dispatch, SignedData shredding —
//! SignerInfo identification, named digest/signature algorithms, well-known
//! signed attributes, embedded certificates, and the `vgi-x509` join key
//! (`signer_cert_sha256`). **Signatures are surfaced, never verified.**

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{as_i64, as_oid, kids, oid_named, render_name};
use crate::json::decode_value;
use crate::oid;
use crate::reencode::to_der;
use crate::tlv::{parse, Class, Tlv};
use crate::value;

/// Locate the SignedData SEQUENCE inside a ContentInfo, if this blob is a CMS
/// SignedData (`1.2.840.113549.1.7.2`). Accepts a bare SignedData too.
fn signed_data(root: &Tlv) -> Option<&Tlv> {
    let top = kids(root);
    if top.len() >= 2 {
        if let Some(ct) = as_oid(&top[0]) {
            if ct == "1.2.840.113549.1.7.2" {
                // content is [0] EXPLICIT SignedData
                let content = top.get(1)?;
                if content.class == Class::Context {
                    return kids(content).first();
                }
            }
        }
    }
    // Maybe already a bare SignedData SEQUENCE (version INTEGER first).
    if top.first().map(|t| t.is_universal(2)).unwrap_or(false) {
        return Some(root);
    }
    None
}

/// The ContentInfo content-type name + dispatched content JSON.
pub fn cms_decode(blob: &[u8]) -> Value {
    let Ok(root) = parse(blob) else {
        return json!({ "error": "not well-formed" });
    };
    let top = kids(&root);
    if top.len() >= 2 {
        if let Some(ct) = as_oid(&top[0]) {
            let name = oid::name_for(&ct).unwrap_or("unknown");
            let content = top
                .get(1)
                .map(|c| decode_value(super::explicit(c)))
                .unwrap_or(Value::Null);
            return json!({
                "content_type": name,
                "content_type_oid": ct,
                "content": content,
            });
        }
    }
    json!({ "error": "not a CMS ContentInfo" })
}

/// Return the embedded certificates' DER bytes (the join key set to `vgi-x509`).
pub fn cms_certs(blob: &[u8]) -> Vec<Vec<u8>> {
    let Ok(root) = parse(blob) else {
        return Vec::new();
    };
    let Some(sd) = signed_data(&root) else {
        return Vec::new();
    };
    // certificates is [0] IMPLICIT SET OF Certificate.
    let mut out = Vec::new();
    if let Some(certs) = kids(sd).iter().find(|c| c.is_context(0)) {
        for cert in kids(certs) {
            // Plain X.509 certs are universal SEQUENCE; skip attribute-cert tags.
            if cert.is_universal(16) {
                out.push(to_der(cert));
            }
        }
    }
    out
}

/// Return the encapsulated eContent bytes, if present.
pub fn cms_content(blob: &[u8]) -> Option<Vec<u8>> {
    let root = parse(blob).ok()?;
    let sd = signed_data(&root)?;
    // encapContentInfo is the SEQUENCE after digestAlgorithms (a SET).
    let sdk = kids(sd);
    let enc = sdk.iter().find(|c| {
        c.is_universal(16) && kids(c).first().map(|f| f.is_universal(6)).unwrap_or(false)
    })?;
    // eContent is [0] EXPLICIT OCTET STRING.
    let econtent = kids(enc).iter().find(|c| c.is_context(0))?;
    let inner = super::explicit(econtent);
    Some(inner.gather_octets())
}

/// One shredded SignerInfo row.
#[derive(Clone, Debug, Default)]
pub struct SignerRow {
    pub version: Option<i64>,
    pub signer_sid: String,
    pub signer_issuer: Option<String>,
    pub signer_serial: Option<String>,
    pub signer_skid: Option<String>,
    pub digest_alg: Option<String>,
    pub sig_alg: Option<String>,
    pub signing_time_micros: Option<i64>,
    pub content_type: Option<String>,
    pub message_digest: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub signer_cert_sha256: Option<String>,
    pub signed_attrs_json: String,
}

/// Shred every SignerInfo into a row.
pub fn cms_signers(blob: &[u8]) -> Vec<SignerRow> {
    let Ok(root) = parse(blob) else {
        return Vec::new();
    };
    let Some(sd) = signed_data(&root) else {
        return Vec::new();
    };
    let sdk = kids(sd);
    let certs = collect_certs(sd);

    // signerInfos is the final SET OF SignerInfo.
    let Some(signers) = sdk.iter().rev().find(|c| c.is_universal(17)) else {
        return Vec::new();
    };
    // The encapContentInfo eContentType (fallback content_type).
    let encap_ct = sdk
        .iter()
        .find(|c| c.is_universal(16) && kids(c).first().map(|f| f.is_universal(6)).unwrap_or(false))
        .and_then(|c| kids(c).first())
        .and_then(as_oid)
        .and_then(|d| oid::name_for(&d).map(|s| s.to_string()));

    let mut rows = Vec::new();
    for si in kids(signers) {
        if si.is_universal(16) {
            rows.push(shred_signer(si, &certs, &encap_ct));
        }
    }
    rows
}

struct CertInfo {
    sha256: String,
    issuer_der: Option<Vec<u8>>,
    serial: Option<String>,
}

fn collect_certs(sd: &Tlv) -> Vec<CertInfo> {
    let mut out = Vec::new();
    if let Some(certs) = kids(sd).iter().find(|c| c.is_context(0)) {
        for cert in kids(certs) {
            if cert.is_universal(16) {
                let der = to_der(cert);
                let sha256 = hex(&Sha256::digest(&der));
                let (issuer_der, serial) = cert_issuer_serial(cert);
                out.push(CertInfo {
                    sha256,
                    issuer_der,
                    serial,
                });
            }
        }
    }
    out
}

/// Extract a certificate's issuer Name DER and serialNumber from its
/// tbsCertificate (handling the optional EXPLICIT [0] version).
fn cert_issuer_serial(cert: &Tlv) -> (Option<Vec<u8>>, Option<String>) {
    let tbs = match kids(cert).first() {
        Some(t) if t.is_universal(16) => t,
        _ => return (None, None),
    };
    let c = kids(tbs);
    let mut pos = 0;
    if c.first().map(|t| t.is_context(0)).unwrap_or(false) {
        pos = 1;
    }
    let serial = c
        .get(pos)
        .filter(|t| t.is_universal(2))
        .and_then(|t| t.primitive().map(value::integer_to_decimal));
    // issuer = pos + 2 (serial, signature-algid, issuer)
    let issuer = c.get(pos + 2).filter(|t| t.is_universal(16)).map(to_der);
    (issuer, serial)
}

fn shred_signer(si: &Tlv, certs: &[CertInfo], encap_ct: &Option<String>) -> SignerRow {
    let c = kids(si);
    let mut row = SignerRow::default();
    let mut idx = 0;
    // version
    if let Some(v) = c.first().and_then(as_i64) {
        row.version = Some(v);
        idx = 1;
    }
    // signer identifier
    if let Some(sid) = c.get(idx) {
        if sid.is_universal(16) {
            // IssuerAndSerialNumber
            row.signer_sid = "issuerAndSerialNumber".into();
            let sk = kids(sid);
            if let Some(issuer) = sk.first().filter(|t| t.is_universal(16)) {
                row.signer_issuer = Some(render_name(issuer));
                let issuer_der = to_der(issuer);
                let serial = sk
                    .get(1)
                    .and_then(|t| t.primitive())
                    .map(value::integer_to_decimal);
                row.signer_serial = serial.clone();
                // Match an embedded cert by issuer+serial.
                row.signer_cert_sha256 = certs
                    .iter()
                    .find(|ci| ci.issuer_der.as_deref() == Some(&issuer_der) && ci.serial == serial)
                    .map(|ci| ci.sha256.clone());
            }
        } else if sid.is_context(0) {
            // [0] subjectKeyIdentifier
            row.signer_sid = "subjectKeyIdentifier".into();
            row.signer_skid = sid.primitive().map(hex);
        }
        idx += 1;
    }
    // digestAlgorithm
    if let Some(da) = c.get(idx).filter(|t| t.is_universal(16)) {
        row.digest_alg = kids(da).first().and_then(oid_named);
        idx += 1;
    }
    // optional signedAttrs [0]
    if let Some(attrs) = c.get(idx).filter(|t| t.is_context(0)) {
        apply_signed_attrs(attrs, &mut row);
        idx += 1;
    }
    // signatureAlgorithm
    if let Some(sa) = c.get(idx).filter(|t| t.is_universal(16)) {
        row.sig_alg = kids(sa).first().and_then(oid_named);
        idx += 1;
    }
    // signature OCTET STRING
    if let Some(sig) = c.get(idx).filter(|t| t.is_universal(4)) {
        row.signature = Some(sig.gather_octets());
    }
    if row.content_type.is_none() {
        row.content_type = encap_ct.clone();
    }
    if row.signed_attrs_json.is_empty() {
        row.signed_attrs_json = "{}".to_string();
    }
    row
}

fn apply_signed_attrs(attrs: &Tlv, row: &mut SignerRow) {
    let mut extra = serde_json::Map::new();
    for attr in kids(attrs) {
        let ak = kids(attr);
        let Some(oid_str) = ak.first().and_then(as_oid) else {
            continue;
        };
        let values = ak.get(1); // SET OF AttributeValue
        let first_val = values.and_then(|v| kids(v).first());
        match oid_str.as_str() {
            "1.2.840.113549.1.9.3" => {
                // contentType
                row.content_type = first_val
                    .and_then(as_oid)
                    .and_then(|d| oid::name_for(&d).map(|s| s.to_string()).or(Some(d)));
            }
            "1.2.840.113549.1.9.4" => {
                // messageDigest OCTET STRING
                row.message_digest = first_val.map(|v| v.gather_octets());
            }
            "1.2.840.113549.1.9.5" => {
                // signingTime
                if let Some(v) = first_val {
                    row.signing_time_micros = v
                        .primitive()
                        .and_then(|b| value::decode_time(v.tag, b))
                        .map(|t| t.micros);
                }
            }
            _ => {
                let name = oid::name_for(&oid_str).unwrap_or(&oid_str);
                let val = first_val.map(decode_value).unwrap_or(Value::Null);
                extra.insert(name.to_string(), val);
            }
        }
    }
    row.signed_attrs_json = Value::Object(extra).to_string();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_cms_yields_error_value() {
        assert!(cms_decode(&[0x02, 0x01, 0x05])["error"].is_string());
        assert!(cms_certs(&[0x02, 0x01, 0x05]).is_empty());
        assert!(cms_signers(&[0x02, 0x01, 0x05]).is_empty());
    }

    #[test]
    fn render_name_basic() {
        // Name: SEQ { SET { SEQ { OID 2.5.4.3, UTF8String "Acme" } } }
        let cn = oid::encode_oid("2.5.4.3").unwrap();
        let mut atv = vec![0x30, 0u8];
        let mut inner = vec![0x06, cn.len() as u8];
        inner.extend_from_slice(&cn);
        inner.extend_from_slice(&[0x0c, 0x04]);
        inner.extend_from_slice(b"Acme");
        atv[1] = inner.len() as u8;
        atv.extend_from_slice(&inner);
        let mut set = vec![0x31, atv.len() as u8];
        set.extend_from_slice(&atv);
        let mut name = vec![0x30, set.len() as u8];
        name.extend_from_slice(&set);
        let t = parse(&name).unwrap();
        assert_eq!(render_name(&t), "CN=Acme");
    }
}
