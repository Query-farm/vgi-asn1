//! Generic BER / CER / DER **TLV reader** — the load-bearing core.
//!
//! Parses a byte slice into a dynamic tree of [`Tlv`] nodes (tag / length /
//! value), handling the universal/application/context/private classes, the
//! high-tag-number form, the long-form and **indefinite** length encodings, and
//! constructed nesting. It is written to be *panic-free on arbitrary input*: every
//! malformed encoding returns a typed [`DecodeError`] with a [`ErrorKind`] rather
//! than crashing, and both recursion depth ([`MAX_NESTING`]) and allocation (a
//! declared length may never exceed the bytes actually present) are bounded so a
//! hostile blob cannot stack-overflow or OOM the worker.

/// Maximum constructed nesting depth before a blob is rejected with
/// [`ErrorKind::NestingLimit`]. Guards against deep-nesting denial-of-service.
pub const MAX_NESTING: usize = 256;

/// ASN.1 tag class (the top two bits of the identifier octet).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

impl Class {
    /// Lowercase class name used by `tlv()` / `to_json()` / `dump()`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Class::Universal => "universal",
            Class::Application => "application",
            Class::Context => "context",
            Class::Private => "private",
        }
    }
}

/// The decoded body of a node: either primitive content bytes or constructed
/// child nodes.
#[derive(Clone, Debug)]
pub enum Body {
    /// Primitive content octets (verbatim).
    Primitive(Vec<u8>),
    /// Constructed children, in document order.
    Constructed(Vec<Tlv>),
}

/// One ASN.1 TLV node in the decoded tree.
#[derive(Clone, Debug)]
pub struct Tlv {
    pub class: Class,
    pub constructed: bool,
    /// Tag number (within the class). Universal tags use [`universal_tag_name`].
    pub tag: u32,
    /// Number of identifier + length octets that precede the content.
    pub header_len: usize,
    /// Number of content octets (for indefinite encodings, the spanned bytes
    /// excluding the two end-of-contents octets).
    pub content_len: usize,
    /// True when the node used the BER indefinite-length form.
    pub indefinite: bool,
    /// Absolute byte offset of this node from the start of the document.
    pub offset: usize,
    pub body: Body,
}

/// Classification of a decode failure, mirroring the `well_formed().kind` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Truncated,
    TrailingBytes,
    InvalidTag,
    LengthOverflow,
    IndefiniteInDer,
    NonCanonical,
    BadTime,
    BadOid,
    BadUtf8,
    NestingLimit,
    AllocLimit,
}

impl ErrorKind {
    /// The hyphenated string surfaced in `well_formed().kind`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::Truncated => "truncated",
            ErrorKind::TrailingBytes => "trailing-bytes",
            ErrorKind::InvalidTag => "invalid-tag",
            ErrorKind::LengthOverflow => "length-overflow",
            ErrorKind::IndefiniteInDer => "indefinite-in-der",
            ErrorKind::NonCanonical => "non-canonical",
            ErrorKind::BadTime => "bad-time",
            ErrorKind::BadOid => "bad-oid",
            ErrorKind::BadUtf8 => "bad-utf8",
            ErrorKind::NestingLimit => "nesting-limit",
            ErrorKind::AllocLimit => "alloc-limit",
        }
    }
}

/// A typed, non-panicking decode error.
#[derive(Clone, Debug)]
pub struct DecodeError {
    pub kind: ErrorKind,
    pub message: String,
    pub offset: usize,
}

impl DecodeError {
    fn new(kind: ErrorKind, offset: usize, message: impl Into<String>) -> Self {
        DecodeError {
            kind,
            offset,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at offset {}: {}",
            self.kind.as_str(),
            self.offset,
            self.message
        )
    }
}

impl std::error::Error for DecodeError {}

/// Encoding-rule strictness for parsing/validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rules {
    Ber,
    Cer,
    Der,
}

impl Rules {
    /// Parse a rules name (`ber` / `cer` / `der`); defaults to BER on anything else.
    pub fn parse(s: &str) -> Rules {
        match s.trim().to_ascii_lowercase().as_str() {
            "der" => Rules::Der,
            "cer" => Rules::Cer,
            _ => Rules::Ber,
        }
    }
    fn allows_indefinite(&self) -> bool {
        !matches!(self, Rules::Der)
    }
}

struct Parser {
    rules: Rules,
}

impl Parser {
    fn err(&self, kind: ErrorKind, offset: usize, msg: impl Into<String>) -> DecodeError {
        DecodeError::new(kind, offset, msg)
    }

    /// Parse exactly one TLV starting at the front of `buf`. `abs` is the absolute
    /// document offset of `buf[0]`. Returns the node and the number of bytes it
    /// consumed.
    fn parse_tlv(&self, buf: &[u8], abs: usize, depth: usize) -> Result<(Tlv, usize), DecodeError> {
        if depth > MAX_NESTING {
            return Err(self.err(
                ErrorKind::NestingLimit,
                abs,
                "maximum nesting depth exceeded",
            ));
        }
        if buf.is_empty() {
            return Err(self.err(ErrorKind::Truncated, abs, "expected a tag byte"));
        }

        let id = buf[0];
        let class = match id >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            _ => Class::Private,
        };
        let constructed = id & 0x20 != 0;
        let mut idx = 1usize;

        // Tag number: low form or high-tag-number form (0x1f).
        let tag: u32 = if id & 0x1f != 0x1f {
            (id & 0x1f) as u32
        } else {
            let mut t: u64 = 0;
            let mut count = 0usize;
            loop {
                if idx >= buf.len() {
                    return Err(self.err(ErrorKind::Truncated, abs, "truncated high-tag-number"));
                }
                let b = buf[idx];
                idx += 1;
                if count == 0 && b == 0x80 {
                    return Err(self.err(
                        ErrorKind::NonCanonical,
                        abs,
                        "high-tag-number must not start with 0x80",
                    ));
                }
                count += 1;
                t = (t << 7) | (b & 0x7f) as u64;
                if t > u32::MAX as u64 {
                    return Err(self.err(ErrorKind::InvalidTag, abs, "tag number too large"));
                }
                if b & 0x80 == 0 {
                    break;
                }
            }
            if t < 0x1f {
                return Err(self.err(
                    ErrorKind::NonCanonical,
                    abs,
                    "high-tag-number form used for a low tag",
                ));
            }
            t as u32
        };

        // Length octet(s).
        if idx >= buf.len() {
            return Err(self.err(ErrorKind::Truncated, abs, "expected a length byte"));
        }
        let l0 = buf[idx];
        idx += 1;
        let mut indefinite = false;
        let mut content_len = 0usize;
        if l0 < 0x80 {
            content_len = l0 as usize;
        } else if l0 == 0x80 {
            if !constructed {
                return Err(self.err(
                    ErrorKind::InvalidTag,
                    abs,
                    "indefinite length on a primitive node",
                ));
            }
            if !self.rules.allows_indefinite() {
                return Err(self.err(
                    ErrorKind::IndefiniteInDer,
                    abs,
                    "indefinite length not allowed under DER",
                ));
            }
            indefinite = true;
        } else if l0 == 0xff {
            return Err(self.err(ErrorKind::InvalidTag, abs, "reserved length octet 0xff"));
        } else {
            let n = (l0 & 0x7f) as usize;
            if n > 8 {
                return Err(self.err(
                    ErrorKind::LengthOverflow,
                    abs,
                    "length spans more than 8 octets",
                ));
            }
            if idx + n > buf.len() {
                return Err(self.err(ErrorKind::Truncated, abs, "truncated long-form length"));
            }
            if self.rules == Rules::Der && buf[idx] == 0x00 && n > 1 {
                return Err(self.err(ErrorKind::NonCanonical, abs, "non-minimal long-form length"));
            }
            let mut v: u64 = 0;
            for k in 0..n {
                v = (v << 8) | buf[idx + k] as u64;
            }
            idx += n;
            if self.rules == Rules::Der && v < 0x80 {
                return Err(self.err(
                    ErrorKind::NonCanonical,
                    abs,
                    "long-form length used where short form fits",
                ));
            }
            if v > usize::MAX as u64 {
                return Err(self.err(ErrorKind::LengthOverflow, abs, "length exceeds usize"));
            }
            content_len = v as usize;
        }

        let header_len = idx;

        if indefinite {
            let mut children = Vec::new();
            let mut p = header_len;
            loop {
                if p >= buf.len() {
                    return Err(self.err(
                        ErrorKind::Truncated,
                        abs + p,
                        "missing end-of-contents marker",
                    ));
                }
                // End-of-contents: a 0x00 0x00 pair.
                if buf[p] == 0x00 {
                    if p + 1 >= buf.len() {
                        return Err(self.err(
                            ErrorKind::Truncated,
                            abs + p,
                            "truncated end-of-contents",
                        ));
                    }
                    if buf[p + 1] == 0x00 {
                        p += 2;
                        break;
                    }
                    return Err(self.err(
                        ErrorKind::InvalidTag,
                        abs + p,
                        "malformed end-of-contents",
                    ));
                }
                let (child, used) = self.parse_tlv(&buf[p..], abs + p, depth + 1)?;
                children.push(child);
                p = p
                    .checked_add(used)
                    .ok_or_else(|| self.err(ErrorKind::LengthOverflow, abs, "offset overflow"))?;
            }
            let total = p;
            Ok((
                Tlv {
                    class,
                    constructed,
                    tag,
                    header_len,
                    content_len: total.saturating_sub(header_len + 2),
                    indefinite: true,
                    offset: abs,
                    body: Body::Constructed(children),
                },
                total,
            ))
        } else {
            let end = header_len
                .checked_add(content_len)
                .ok_or_else(|| self.err(ErrorKind::LengthOverflow, abs, "tag+length overflow"))?;
            if end > buf.len() {
                return Err(self.err(
                    ErrorKind::LengthOverflow,
                    abs,
                    format!(
                        "declared length {content_len} exceeds the {} available bytes",
                        buf.len().saturating_sub(header_len)
                    ),
                ));
            }
            let content = &buf[header_len..end];
            let body = if constructed {
                let children = self.parse_children(content, abs + header_len, depth + 1)?;
                Body::Constructed(children)
            } else {
                Body::Primitive(content.to_vec())
            };
            Ok((
                Tlv {
                    class,
                    constructed,
                    tag,
                    header_len,
                    content_len,
                    indefinite: false,
                    offset: abs,
                    body,
                },
                end,
            ))
        }
    }

    fn parse_children(
        &self,
        buf: &[u8],
        abs: usize,
        depth: usize,
    ) -> Result<Vec<Tlv>, DecodeError> {
        let mut out = Vec::new();
        let mut p = 0usize;
        while p < buf.len() {
            let (t, used) = self.parse_tlv(&buf[p..], abs + p, depth)?;
            if used == 0 {
                return Err(self.err(ErrorKind::InvalidTag, abs + p, "zero-length element"));
            }
            out.push(t);
            p += used;
        }
        Ok(out)
    }
}

/// Parse a single top-level TLV from `data` under the given rules, requiring the
/// node to span the whole slice (trailing bytes are an error).
pub fn parse_rules(data: &[u8], rules: Rules) -> Result<Tlv, DecodeError> {
    let p = Parser { rules };
    let (tlv, used) = p.parse_tlv(data, 0, 0)?;
    if used != data.len() {
        return Err(DecodeError::new(
            ErrorKind::TrailingBytes,
            used,
            format!(
                "{} trailing byte(s) after the top-level element",
                data.len() - used
            ),
        ));
    }
    Ok(tlv)
}

/// Parse a single top-level TLV, BER-permissive (accepts indefinite lengths).
/// This is the entry point for the lenient `decode`/`to_json`/`dump` surface.
pub fn parse(data: &[u8]) -> Result<Tlv, DecodeError> {
    parse_rules(data, Rules::Ber)
}

/// Parse a stream of back-to-back top-level TLVs (e.g. several LDAPMessages in one
/// TCP segment). BER-permissive.
pub fn parse_all(data: &[u8]) -> Result<Vec<Tlv>, DecodeError> {
    let p = Parser { rules: Rules::Ber };
    p.parse_children(data, 0, 0)
}

impl Tlv {
    /// Borrow the constructed children, if any.
    pub fn children(&self) -> Option<&[Tlv]> {
        match &self.body {
            Body::Constructed(c) => Some(c),
            Body::Primitive(_) => None,
        }
    }

    /// Borrow primitive content octets, if this is a primitive node.
    pub fn primitive(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Primitive(b) => Some(b),
            Body::Constructed(_) => None,
        }
    }

    /// True if this is a universal-class node with the given tag number.
    pub fn is_universal(&self, tag: u32) -> bool {
        self.class == Class::Universal && self.tag == tag
    }

    /// True if this is a context-class node with the given tag number.
    pub fn is_context(&self, tag: u32) -> bool {
        self.class == Class::Context && self.tag == tag
    }

    /// Gather the leaf octets of a (possibly constructed) OCTET/BIT STRING by
    /// concatenating primitive segments — handles BER constructed strings.
    pub fn gather_octets(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.gather_into(&mut out);
        out
    }

    fn gather_into(&self, out: &mut Vec<u8>) {
        match &self.body {
            Body::Primitive(b) => out.extend_from_slice(b),
            Body::Constructed(c) => {
                for child in c {
                    child.gather_into(out);
                }
            }
        }
    }
}

/// Friendly name for a universal-class tag number, or `None` if unrecognized.
pub fn universal_tag_name(tag: u32) -> Option<&'static str> {
    Some(match tag {
        0 => "END-OF-CONTENTS",
        1 => "BOOLEAN",
        2 => "INTEGER",
        3 => "BIT STRING",
        4 => "OCTET STRING",
        5 => "NULL",
        6 => "OBJECT IDENTIFIER",
        7 => "ObjectDescriptor",
        8 => "EXTERNAL",
        9 => "REAL",
        10 => "ENUMERATED",
        11 => "EMBEDDED PDV",
        12 => "UTF8String",
        13 => "RELATIVE-OID",
        16 => "SEQUENCE",
        17 => "SET",
        18 => "NumericString",
        19 => "PrintableString",
        20 => "TeletexString",
        21 => "VideotexString",
        22 => "IA5String",
        23 => "UTCTime",
        24 => "GeneralizedTime",
        25 => "GraphicString",
        26 => "VisibleString",
        27 => "GeneralString",
        28 => "UniversalString",
        29 => "CHARACTER STRING",
        30 => "BMPString",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_integer() {
        // INTEGER 42
        let t = parse(&[0x02, 0x01, 0x2a]).unwrap();
        assert!(t.is_universal(2));
        assert_eq!(t.primitive(), Some(&[0x2a][..]));
    }

    #[test]
    fn parses_sequence() {
        // SEQUENCE { INTEGER 1, BOOLEAN true }
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff];
        let t = parse(&der).unwrap();
        assert!(t.is_universal(16));
        let c = t.children().unwrap();
        assert_eq!(c.len(), 2);
        assert!(c[0].is_universal(2));
        assert!(c[1].is_universal(1));
    }

    #[test]
    fn truncated_is_error_not_panic() {
        assert_eq!(
            parse(&[0x30, 0x05, 0x02]).unwrap_err().kind,
            ErrorKind::LengthOverflow
        );
        assert_eq!(parse(&[0x02]).unwrap_err().kind, ErrorKind::Truncated);
        assert_eq!(parse(&[]).unwrap_err().kind, ErrorKind::Truncated);
    }

    #[test]
    fn trailing_bytes_flagged() {
        assert_eq!(
            parse(&[0x05, 0x00, 0xff]).unwrap_err().kind,
            ErrorKind::TrailingBytes
        );
    }

    #[test]
    fn indefinite_length_ber() {
        // SEQUENCE (indefinite) { OCTET STRING "Hi" } EOC
        let ber = [0x30, 0x80, 0x04, 0x02, b'H', b'i', 0x00, 0x00];
        let t = parse(&ber).unwrap();
        assert!(t.indefinite);
        assert_eq!(t.children().unwrap().len(), 1);
        // Indefinite is rejected under DER.
        assert_eq!(
            parse_rules(&ber, Rules::Der).unwrap_err().kind,
            ErrorKind::IndefiniteInDer
        );
    }

    #[test]
    fn high_tag_number() {
        // [APPLICATION 31] primitive, length 0  -> 0x5f 0x1f 0x00
        let t = parse(&[0x5f, 0x1f, 0x00]).unwrap();
        assert_eq!(t.class, Class::Application);
        assert_eq!(t.tag, 31);
    }
}
