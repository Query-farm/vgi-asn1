//! OBJECT IDENTIFIER codec + a curated dotted-OID ↔ friendly-name registry.
//!
//! The registry is assembled from the permissive public OID space (RustCrypto
//! `const-oid`/IANA-style names) covering the OIDs the structural decoders meet:
//! signature & digest algorithms, X.500 attribute types, PKCS#7/CMS content
//! types, CMS/PKCS#9 attributes, EC curves, PBES2/PBKDF2, PKCS#12 bag types, EKUs,
//! certificate extensions, SNMP SMI/MIB-2 anchors, Kerberos, and OCSP. Gutmann's
//! `dumpasn1.cfg` is deliberately **not** bundled (ambiguous redistribution); all
//! names here come from open/permissive sources.

/// Decode an OBJECT IDENTIFIER's content octets into a dotted-decimal string.
pub fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    // No subidentifier may end with a continuation bit set.
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut acc: u128 = 0;
    let mut started = false;
    for &b in bytes {
        if !started && b == 0x80 {
            // Non-minimal subidentifier (leading 0x80).
            return None;
        }
        started = true;
        acc = acc.checked_shl(7)?.checked_add((b & 0x7f) as u128)?;
        if b & 0x80 == 0 {
            arcs.push(acc);
            acc = 0;
            started = false;
        }
    }
    if started {
        return None;
    }
    let first = arcs[0];
    let (x, y) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut out = format!("{x}.{y}");
    for arc in &arcs[1..] {
        out.push('.');
        out.push_str(&arc.to_string());
    }
    Some(out)
}

/// Decode a RELATIVE-OID's content octets into a dotted-decimal string (no
/// 40·X+Y joint-first-arc rule).
pub fn decode_relative_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut acc: u128 = 0;
    let mut started = false;
    for &b in bytes {
        if !started && b == 0x80 {
            return None;
        }
        started = true;
        acc = acc.checked_shl(7)?.checked_add((b & 0x7f) as u128)?;
        if b & 0x80 == 0 {
            arcs.push(acc);
            acc = 0;
            started = false;
        }
    }
    if started {
        return None;
    }
    Some(
        arcs.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Encode a dotted-decimal OID string back into its content octets. Returns
/// `None` for a syntactically invalid OID (fewer than two arcs, bad first arcs,
/// non-numeric components).
pub fn encode_oid(dotted: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u128> = dotted
        .split('.')
        .map(|s| s.parse::<u128>().ok())
        .collect::<Option<Vec<_>>>()?;
    if arcs.len() < 2 {
        return None;
    }
    if arcs[0] > 2 {
        return None;
    }
    if arcs[0] < 2 && arcs[1] >= 40 {
        return None;
    }
    let mut out = Vec::new();
    let first = arcs[0] * 40 + arcs[1];
    push_base128(&mut out, first);
    for arc in &arcs[2..] {
        push_base128(&mut out, *arc);
    }
    Some(out)
}

fn push_base128(out: &mut Vec<u8>, mut v: u128) {
    let mut stack = [0u8; 19];
    let mut n = 0;
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

/// Resolve a dotted OID to its friendly name, or `None` if not in the registry.
pub fn name_for(dotted: &str) -> Option<&'static str> {
    REGISTRY.iter().find(|(o, _)| *o == dotted).map(|(_, n)| *n)
}

/// Resolve a friendly name to its dotted OID, or `None`. Case-insensitive.
pub fn oid_for(name: &str) -> Option<&'static str> {
    REGISTRY
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(name))
        .map(|(o, _)| *o)
}

/// The bundled registry, `(dotted, name)`.
pub static REGISTRY: &[(&str, &str)] = &[
    // --- Digest algorithms ---
    ("1.2.840.113549.2.5", "md5"),
    ("1.3.14.3.2.26", "sha1"),
    ("2.16.840.1.101.3.4.2.1", "sha256"),
    ("2.16.840.1.101.3.4.2.2", "sha384"),
    ("2.16.840.1.101.3.4.2.3", "sha512"),
    ("2.16.840.1.101.3.4.2.4", "sha224"),
    ("2.16.840.1.101.3.4.2.7", "sha3-256"),
    ("2.16.840.1.101.3.4.2.8", "sha3-384"),
    ("2.16.840.1.101.3.4.2.9", "sha3-512"),
    // --- Public-key + signature algorithms ---
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.14", "sha224WithRSAEncryption"),
    ("1.2.840.10045.2.1", "id-ecPublicKey"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.10040.4.1", "id-dsa"),
    ("1.2.840.10040.4.3", "dsa-with-sha1"),
    ("1.3.101.112", "id-Ed25519"),
    ("1.3.101.113", "id-Ed448"),
    // --- EC named curves ---
    ("1.2.840.10045.3.1.7", "prime256v1"),
    ("1.3.132.0.34", "secp384r1"),
    ("1.3.132.0.35", "secp521r1"),
    ("1.3.132.0.10", "secp256k1"),
    // --- X.500 attribute types (RFC 5280 §4.1.2.4) ---
    ("2.5.4.3", "id-at-commonName"),
    ("2.5.4.4", "id-at-surname"),
    ("2.5.4.5", "id-at-serialNumber"),
    ("2.5.4.6", "id-at-countryName"),
    ("2.5.4.7", "id-at-localityName"),
    ("2.5.4.8", "id-at-stateOrProvinceName"),
    ("2.5.4.9", "id-at-streetAddress"),
    ("2.5.4.10", "id-at-organizationName"),
    ("2.5.4.11", "id-at-organizationalUnitName"),
    ("2.5.4.12", "id-at-title"),
    ("2.5.4.42", "id-at-givenName"),
    ("0.9.2342.19200300.100.1.1", "id-userid"),
    ("0.9.2342.19200300.100.1.25", "id-domainComponent"),
    ("1.2.840.113549.1.9.1", "id-emailAddress"),
    // --- Certificate extensions (RFC 5280) ---
    ("2.5.29.14", "id-ce-subjectKeyIdentifier"),
    ("2.5.29.15", "id-ce-keyUsage"),
    ("2.5.29.17", "id-ce-subjectAltName"),
    ("2.5.29.19", "id-ce-basicConstraints"),
    ("2.5.29.31", "id-ce-cRLDistributionPoints"),
    ("2.5.29.32", "id-ce-certificatePolicies"),
    ("2.5.29.35", "id-ce-authorityKeyIdentifier"),
    ("2.5.29.37", "id-ce-extKeyUsage"),
    ("1.3.6.1.5.5.7.1.1", "id-pe-authorityInfoAccess"),
    // --- Extended key usage ---
    ("1.3.6.1.5.5.7.3.1", "id-kp-serverAuth"),
    ("1.3.6.1.5.5.7.3.2", "id-kp-clientAuth"),
    ("1.3.6.1.5.5.7.3.3", "id-kp-codeSigning"),
    ("1.3.6.1.5.5.7.3.4", "id-kp-emailProtection"),
    ("1.3.6.1.5.5.7.3.8", "id-kp-timeStamping"),
    ("1.3.6.1.5.5.7.3.9", "id-kp-OCSPSigning"),
    // --- PKCS#7 / CMS content types (RFC 5652) ---
    ("1.2.840.113549.1.7.1", "id-data"),
    ("1.2.840.113549.1.7.2", "id-signedData"),
    ("1.2.840.113549.1.7.3", "id-envelopedData"),
    ("1.2.840.113549.1.7.4", "id-signedAndEnvelopedData"),
    ("1.2.840.113549.1.7.5", "id-digestedData"),
    ("1.2.840.113549.1.7.6", "id-encryptedData"),
    ("1.2.840.113549.1.9.16.1.4", "id-ct-TSTInfo"),
    ("1.2.840.113549.1.9.16.1.9", "id-ct-compressedData"),
    // --- PKCS#9 / CMS signed attributes (RFC 2985 / 5652) ---
    ("1.2.840.113549.1.9.3", "id-contentType"),
    ("1.2.840.113549.1.9.4", "id-messageDigest"),
    ("1.2.840.113549.1.9.5", "id-signingTime"),
    ("1.2.840.113549.1.9.6", "id-countersignature"),
    ("1.2.840.113549.1.9.15", "id-smimeCapabilities"),
    ("1.2.840.113549.1.9.16.2.12", "id-signingCertificate"),
    ("1.2.840.113549.1.9.16.2.47", "id-signingCertificateV2"),
    // --- PKCS#1/#5/#8/#12 ---
    ("1.2.840.113549.1.5.13", "id-PBES2"),
    ("1.2.840.113549.1.5.12", "id-PBKDF2"),
    ("1.2.840.113549.1.5.3", "pbeWithMD5AndDES-CBC"),
    ("1.2.840.113549.2.7", "hmacWithSHA1"),
    ("1.2.840.113549.2.9", "hmacWithSHA256"),
    ("1.2.840.113549.3.7", "des-EDE3-CBC"),
    ("2.16.840.1.101.3.4.1.2", "aes128-CBC"),
    ("2.16.840.1.101.3.4.1.42", "aes256-CBC"),
    ("1.2.840.113549.1.12.10.1.1", "keyBag"),
    ("1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag"),
    ("1.2.840.113549.1.12.10.1.3", "certBag"),
    ("1.2.840.113549.1.12.10.1.4", "crlBag"),
    ("1.2.840.113549.1.12.10.1.5", "secretBag"),
    ("1.2.840.113549.1.12.10.1.6", "safeContentsBag"),
    ("1.2.840.113549.1.9.20", "friendlyName"),
    ("1.2.840.113549.1.9.21", "localKeyID"),
    ("1.2.840.113549.1.9.22.1", "x509Certificate"),
    // --- OCSP (RFC 6960) ---
    ("1.3.6.1.5.5.7.48.1", "id-pkix-ocsp"),
    ("1.3.6.1.5.5.7.48.1.1", "id-pkix-ocsp-basic"),
    ("1.3.6.1.5.5.7.48.1.2", "id-pkix-ocsp-nonce"),
    ("1.3.6.1.5.5.7.48.2", "id-ad-caIssuers"),
    // --- Kerberos (RFC 4120) PKINIT/etc anchors ---
    ("1.2.840.113554.1.2.2", "krb5"),
    // --- SNMP SMI / MIB-2 (RFC 1155/1213) ---
    ("1.3.6.1", "internet"),
    ("1.3.6.1.2.1", "mib-2"),
    ("1.3.6.1.2.1.1", "system"),
    ("1.3.6.1.2.1.1.1", "sysDescr"),
    ("1.3.6.1.2.1.1.1.0", "sysDescr.0"),
    ("1.3.6.1.2.1.1.2", "sysObjectID"),
    ("1.3.6.1.2.1.1.3", "sysUpTime"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime.0"),
    ("1.3.6.1.2.1.1.4", "sysContact"),
    ("1.3.6.1.2.1.1.5", "sysName"),
    ("1.3.6.1.2.1.1.6", "sysLocation"),
    ("1.3.6.1.6.3.1.1.4.1.0", "snmpTrapOID.0"),
    ("1.3.6.1.6.3.1.1.5.1", "coldStart"),
    ("1.3.6.1.4.1", "enterprises"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_oid() {
        let dotted = "1.2.840.113549.1.1.11";
        let bytes = encode_oid(dotted).unwrap();
        assert_eq!(decode_oid(&bytes).as_deref(), Some(dotted));
    }

    #[test]
    fn well_known_names() {
        assert_eq!(
            name_for("1.2.840.113549.1.1.11"),
            Some("sha256WithRSAEncryption")
        );
        assert_eq!(name_for("2.5.4.3"), Some("id-at-commonName"));
        assert_eq!(
            oid_for("sha256WithRSAEncryption"),
            Some("1.2.840.113549.1.1.11")
        );
        assert_eq!(oid_for("ID-AT-COMMONNAME"), Some("2.5.4.3"));
    }

    #[test]
    fn small_oids() {
        // 2.5 -> joint first arc 85
        assert_eq!(decode_oid(&[0x55]).as_deref(), Some("2.5"));
        // 1.2.840.113549 (well-known prefix)
        let b = encode_oid("1.2.840.113549").unwrap();
        assert_eq!(decode_oid(&b).as_deref(), Some("1.2.840.113549"));
    }

    #[test]
    fn malformed_oid_none() {
        assert!(decode_oid(&[0x80]).is_none()); // trailing continuation
        assert!(decode_oid(&[]).is_none());
    }
}
