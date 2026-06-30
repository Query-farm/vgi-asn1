//! Best-effort interpretation of primitive ASN.1 content octets into the scalar
//! shapes the SQL surface needs: integers (with arbitrary-precision fallback to a
//! base-10 string), booleans, times normalized to ISO-8601 + epoch microseconds,
//! the various string flavors, and BIT STRING decomposition. Every function is
//! total — malformed content yields `None`, never a panic.

use crate::tlv::Tlv;

/// Render a (possibly multi-precision) INTEGER's two's-complement big-endian
/// content octets as a base-10 string.
pub fn integer_to_decimal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    let negative = bytes[0] & 0x80 != 0;
    // Magnitude as unsigned big-endian bytes.
    let mut mag: Vec<u8> = if negative {
        // two's-complement negate: invert then +1
        let mut inv: Vec<u8> = bytes.iter().map(|b| !b).collect();
        let mut carry = 1u16;
        for b in inv.iter_mut().rev() {
            let v = *b as u16 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        inv
    } else {
        bytes.to_vec()
    };
    // Strip leading zeros.
    while mag.len() > 1 && mag[0] == 0 {
        mag.remove(0);
    }
    let mut digits = unsigned_bytes_to_decimal(&mag);
    if negative && digits != "0" {
        digits.insert(0, '-');
    }
    digits
}

/// Convert unsigned big-endian bytes to a decimal string via repeated long
/// division by 10.
fn unsigned_bytes_to_decimal(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return "0".to_string();
    }
    let mut value = bytes.to_vec();
    let mut out = Vec::new();
    while !value.iter().all(|&b| b == 0) {
        let mut rem = 0u16;
        for b in value.iter_mut() {
            let cur = (rem << 8) | *b as u16;
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        out.push(b'0' + rem as u8);
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}

/// Decode an INTEGER/ENUMERATED to `i64` when it fits, else `None`.
pub fn integer_to_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let negative = bytes[0] & 0x80 != 0;
    let mut v: i64 = if negative { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | b as i64;
    }
    Some(v)
}

/// Decode a BOOLEAN's single content octet.
pub fn decode_bool(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [b] => Some(*b != 0),
        _ => None,
    }
}

/// A decoded time value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeValue {
    /// ISO-8601 normalized, e.g. `2023-09-15T12:00:00Z`.
    pub iso: String,
    /// Microseconds since the Unix epoch (UTC).
    pub micros: i64,
}

/// Parse a UTCTime (universal tag 23) or GeneralizedTime (tag 24).
pub fn decode_time(tag: u32, bytes: &[u8]) -> Option<TimeValue> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    match tag {
        23 => parse_utctime(s),
        24 => parse_generalized(s),
        _ => None,
    }
}

fn digits(s: &str, start: usize, len: usize) -> Option<i64> {
    let part = s.get(start..start + len)?;
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<i64>().ok()
}

fn parse_utctime(s: &str) -> Option<TimeValue> {
    // YYMMDDHHMM[SS](Z|±HHMM). We accept Z and offset forms.
    if s.len() < 11 {
        return None;
    }
    let yy = digits(s, 0, 2)?;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    let month = digits(s, 2, 2)?;
    let day = digits(s, 4, 2)?;
    let hour = digits(s, 6, 2)?;
    let minute = digits(s, 8, 2)?;
    let rest = &s[10..];
    let (second, tz) = if rest.len() >= 2 && rest.as_bytes()[0].is_ascii_digit() {
        (digits(s, 10, 2)?, &s[12..])
    } else {
        (0, rest)
    };
    let offset = parse_tz(tz)?;
    assemble(year, month, day, hour, minute, second, 0, offset)
}

fn parse_generalized(s: &str) -> Option<TimeValue> {
    // YYYYMMDDHH[MM[SS[.fff]]](Z|±HHMM)?
    if s.len() < 10 {
        return None;
    }
    let year = digits(s, 0, 4)?;
    let month = digits(s, 4, 2)?;
    let day = digits(s, 6, 2)?;
    let hour = digits(s, 8, 2)?;
    let mut pos = 10;
    let mut minute = 0;
    let mut second = 0;
    if s.len() > pos + 1 && s.as_bytes()[pos].is_ascii_digit() {
        minute = digits(s, pos, 2)?;
        pos += 2;
        if s.len() > pos + 1 && s.as_bytes()[pos].is_ascii_digit() {
            second = digits(s, pos, 2)?;
            pos += 2;
        }
    }
    let mut micros_frac = 0i64;
    if s.get(pos..pos + 1) == Some(".") || s.get(pos..pos + 1) == Some(",") {
        pos += 1;
        let start = pos;
        while pos < s.len() && s.as_bytes()[pos].is_ascii_digit() {
            pos += 1;
        }
        let frac = &s[start..pos];
        // Scale to microseconds (6 digits).
        let mut f = String::from(frac);
        f.truncate(6);
        while f.len() < 6 {
            f.push('0');
        }
        micros_frac = f.parse::<i64>().unwrap_or(0);
    }
    let offset = parse_tz(&s[pos..])?;
    let mut tv = assemble(year, month, day, hour, minute, second, micros_frac, offset)?;
    // assemble already folded micros_frac in; keep iso including frac when present
    if micros_frac != 0 {
        tv.iso = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            year_of(tv.micros),
            month_of(tv.micros),
            day_of(tv.micros),
            hour_of(tv.micros),
            min_of(tv.micros),
            sec_of(tv.micros),
            micros_frac
        );
    }
    Some(tv)
}

fn parse_tz(tz: &str) -> Option<i64> {
    let tz = tz.trim();
    if tz.is_empty() || tz == "Z" {
        return Some(0);
    }
    let sign = match tz.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return Some(0), // local time: treat as UTC, best-effort
    };
    if tz.len() < 5 {
        return None;
    }
    let h = digits(tz, 1, 2)?;
    let m = digits(tz, 3, 2)?;
    Some(sign * (h * 3600 + m * 60))
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    micros_frac: i64,
    offset_secs: i64,
) -> Option<TimeValue> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86400 + hour * 3600 + minute * 60 + second - offset_secs;
    let micros = secs.checked_mul(1_000_000)?.checked_add(micros_frac)?;
    let iso = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    Some(TimeValue { iso, micros })
}

/// Days from the Unix epoch (1970-01-01) for a civil Y-M-D (Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// Helpers to reformat an epoch-micros value back into civil components (only used
// to re-emit a fractional ISO string).
fn civil_from_micros(micros: i64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = micros.div_euclid(1_000_000);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn year_of(u: i64) -> i64 {
    civil_from_micros(u).0
}
fn month_of(u: i64) -> u32 {
    civil_from_micros(u).1
}
fn day_of(u: i64) -> u32 {
    civil_from_micros(u).2
}
fn hour_of(u: i64) -> u32 {
    civil_from_micros(u).3
}
fn min_of(u: i64) -> u32 {
    civil_from_micros(u).4
}
fn sec_of(u: i64) -> u32 {
    civil_from_micros(u).5
}

/// Decode a string-flavored primitive (by universal tag) to a Rust `String`,
/// best-effort. BMP/Universal strings are transcoded from UCS-2/UCS-4.
pub fn decode_string(tag: u32, bytes: &[u8]) -> Option<String> {
    match tag {
        12 | 18 | 19 | 22 | 26 | 27 | 20 | 25 => {
            // UTF8/Numeric/Printable/IA5/Visible/General/Teletex/Graphic:
            // try UTF-8, fall back to latin-1.
            match std::str::from_utf8(bytes) {
                Ok(s) => Some(s.to_string()),
                Err(_) => Some(bytes.iter().map(|&b| b as char).collect()),
            }
        }
        30 => {
            // BMPString: UCS-2 big-endian.
            if !bytes.len().is_multiple_of(2) {
                return None;
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        28 => {
            // UniversalString: UCS-4 big-endian.
            if !bytes.len().is_multiple_of(4) {
                return None;
            }
            let mut s = String::new();
            for c in bytes.chunks_exact(4) {
                let cp = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            }
            Some(s)
        }
        _ => None,
    }
}

/// Decompose a BIT STRING: returns `(unused_bits, data_bytes)`.
pub fn bitstring(bytes: &[u8]) -> Option<(u8, &[u8])> {
    match bytes.split_first() {
        Some((unused, rest)) if *unused <= 7 => Some((*unused, rest)),
        _ => None,
    }
}

/// Render a BIT STRING as a string of '0'/'1' (most-significant bit first),
/// honoring the unused-bit count.
pub fn bitstring_bits(unused: u8, data: &[u8]) -> String {
    let total = data.len() * 8 - unused.min(7) as usize;
    let mut out = String::with_capacity(total);
    for (i, byte) in data.iter().enumerate() {
        for bit in 0..8 {
            if i * 8 + bit >= total {
                break;
            }
            out.push(if byte & (0x80 >> bit) != 0 { '1' } else { '0' });
        }
    }
    out
}

/// Convenience: the OID dotted string of a node that is an OBJECT IDENTIFIER.
pub fn oid_string(t: &Tlv) -> Option<String> {
    if t.is_universal(6) {
        crate::oid::decode_oid(t.primitive()?)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(integer_to_decimal(&[0x2a]), "42");
        assert_eq!(integer_to_decimal(&[0xff]), "-1");
        assert_eq!(integer_to_decimal(&[0x00, 0x80]), "128");
        assert_eq!(integer_to_i64(&[0xff, 0xff]), Some(-1));
        // bignum: 2^64
        assert_eq!(
            integer_to_decimal(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            "18446744073709551616"
        );
        assert_eq!(integer_to_i64(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn utctime() {
        let t = decode_time(23, b"230915120000Z").unwrap();
        assert_eq!(t.iso, "2023-09-15T12:00:00Z");
    }

    #[test]
    fn generalizedtime_fraction() {
        let t = decode_time(24, b"20230915120000.5Z").unwrap();
        assert!(t.iso.starts_with("2023-09-15T12:00:00.500000"));
    }

    #[test]
    fn epoch_anchor() {
        let t = decode_time(24, b"19700101000000Z").unwrap();
        assert_eq!(t.micros, 0);
    }

    #[test]
    fn bmpstring() {
        // "Hi" in UCS-2 BE
        assert_eq!(
            decode_string(30, &[0, b'H', 0, b'i']).as_deref(),
            Some("Hi")
        );
    }
}
