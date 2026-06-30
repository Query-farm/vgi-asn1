//! `asn1.is_valid` (well-formed under a named rules set) and `asn1.well_formed`
//! (structural well-formedness with a classified failure `kind`). Both are total:
//! malformed input yields `false` / `ok=false`, never a panic.

use crate::tlv::{parse_rules, Rules};

/// Is `blob` well-formed under the named encoding rules? `der`/`cer` additionally
/// enforce minimal length encoding and reject indefinite lengths (handled in the
/// parser).
pub fn is_valid(blob: &[u8], rules: Rules) -> bool {
    parse_rules(blob, rules).is_ok()
}

/// Structured well-formedness result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WellFormed {
    pub ok: bool,
    pub error: String,
    pub kind: String,
}

/// Parse `blob` as BER (the loosest rules) and report well-formedness with a
/// classified `kind` on failure.
pub fn well_formed(blob: &[u8]) -> WellFormed {
    match parse_rules(blob, Rules::Ber) {
        Ok(_) => WellFormed {
            ok: true,
            error: String::new(),
            kind: String::new(),
        },
        Err(e) => WellFormed {
            ok: false,
            error: e.message.clone(),
            kind: e.kind.as_str().to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_der() {
        assert!(is_valid(&[0x02, 0x01, 0x05], Rules::Der));
    }

    #[test]
    fn indefinite_invalid_der_valid_ber() {
        let ber = [0x30, 0x80, 0x04, 0x02, b'H', b'i', 0x00, 0x00];
        assert!(is_valid(&ber, Rules::Ber));
        assert!(!is_valid(&ber, Rules::Der));
    }

    #[test]
    fn well_formed_kinds() {
        assert!(well_formed(&[0x02, 0x01, 0x05]).ok);
        let wf = well_formed(&[0x30, 0x05, 0x02]);
        assert!(!wf.ok);
        assert_eq!(wf.kind, "length-overflow");
        let wf = well_formed(&[0x05, 0x00, 0xff]);
        assert_eq!(wf.kind, "trailing-bytes");
    }
}
