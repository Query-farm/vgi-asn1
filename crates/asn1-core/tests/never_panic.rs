//! Robustness gate: the decoders must NEVER panic on arbitrary or truncated
//! input — they capture the error per row instead. Proptest fuzzes every public
//! entry point with random bytes and random truncations of valid DER.

use asn1_core::security::{cms, kerberos, ldap, ocsp, pkcs, snmp};
use asn1_core::tlv::Rules;
use asn1_core::{decode_json, tlv_json, to_json, validate};
use proptest::prelude::*;

/// Drive every entry point; the harness fails only if one panics.
fn exercise(bytes: &[u8]) {
    let _ = decode_json(bytes);
    let _ = to_json(bytes);
    let _ = tlv_json(bytes);
    let _ = validate::well_formed(bytes);
    let _ = validate::is_valid(bytes, Rules::Ber);
    let _ = validate::is_valid(bytes, Rules::Der);
    if let Ok(t) = asn1_core::tlv::parse(bytes) {
        let _ = asn1_core::dump::dump(&t, asn1_core::dump::DumpFormat::Openssl);
        let _ = asn1_core::dump::dump(&t, asn1_core::dump::DumpFormat::Dumpasn1);
        let _ = asn1_core::reencode::to_der(&t);
        let _ = asn1_core::tlvlist::flatten(&t);
        let _ = asn1_core::tlvlist::oids(&t);
        let _ = asn1_core::tlvlist::at_path(&t, "$.0.1.2");
    }
    let _ = snmp::snmp_decode(bytes);
    let _ = snmp::decode_message(bytes);
    let _ = kerberos::krb_decode(bytes);
    let _ = kerberos::krb_ticket(bytes);
    let _ = ldap::ldap_decode(bytes);
    let _ = ldap::ldap_messages(bytes);
    let _ = cms::cms_decode(bytes);
    let _ = cms::cms_signers(bytes);
    let _ = cms::cms_certs(bytes);
    let _ = cms::cms_content(bytes);
    let _ = pkcs::pkcs8_info(bytes);
    let _ = pkcs::pkcs12_bags(bytes);
    let _ = ocsp::ocsp_decode(bytes);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        exercise(&bytes);
    }

    // Random truncations of a non-trivial nested DER blob: a SEQUENCE wrapping
    // mixed primitives. Every prefix must be handled without panicking.
    #[test]
    fn truncations_never_panic(n in 0usize..40) {
        let der: [u8; 24] = [
            0x30, 0x16, // SEQUENCE len 22
            0x02, 0x01, 0x05, // INTEGER 5
            0x01, 0x01, 0xff, // BOOLEAN true
            0x06, 0x03, 0x55, 0x04, 0x03, // OID 2.5.4.3
            0x0c, 0x03, b'a', b'b', b'c', // UTF8String "abc"
            0x04, 0x02, 0xde, 0xad, // OCTET STRING
            0x05, 0x00, // NULL
        ];
        let take = n.min(der.len());
        exercise(&der[..take]);
    }

    // A length field claiming far more than the input must NOT pre-allocate /
    // OOM — it returns length-overflow.
    #[test]
    fn length_overflow_is_safe(claimed in 0u8..=0x7f) {
        let blob = [0x04, 0x84, 0xff, 0xff, 0xff, claimed];
        let wf = validate::well_formed(&blob);
        prop_assert!(!wf.ok);
        prop_assert_eq!(wf.kind, "length-overflow");
    }
}
