// Small helpers: JSON string escaping, timestamp formatting, integers, base64, HS256 JWT verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

/// Appends `s` as a JSON string literal (quotes included). Only `"`, `\` and control characters are escaped.
#[inline]
pub fn json_str(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    let mut start = 0;
    for (i, &b) in s.iter().enumerate() {
        if b >= 0x20 && b != b'"' && b != b'\\' {
            continue;
        }
        out.extend_from_slice(&s[start..i]);
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 15) as usize]);
            }
        }
        start = i + 1;
    }
    out.extend_from_slice(&s[start..]);
    out.push(b'"');
}

#[inline]
pub fn push_int(out: &mut Vec<u8>, v: i64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let neg = v < 0;
    let mut n = v.unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if neg {
        out.push(b'-');
    }
    out.extend_from_slice(&buf[i..]);
}

#[inline]
fn push2(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}

/// Appends a Postgres binary TIMESTAMPTZ (microseconds since 2000-01-01 UTC) as `"YYYY-MM-DDTHH:MM:SS.mmmZ"`,
/// truncated (not rounded) to milliseconds.
pub fn push_timestamp(out: &mut Vec<u8>, pg_us: i64) {
    const PG_EPOCH_MS: i64 = 946_684_800_000;
    let ms = pg_us.div_euclid(1000) + PG_EPOCH_MS;
    let days = ms.div_euclid(86_400_000);
    let ms_of_day = ms.rem_euclid(86_400_000) as u32;
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    out.push(b'"');
    let y = y as u32;
    push2(out, y / 100);
    push2(out, y % 100);
    out.push(b'-');
    push2(out, m);
    out.push(b'-');
    push2(out, d);
    out.push(b'T');
    let s = ms_of_day / 1000;
    push2(out, s / 3600);
    out.push(b':');
    push2(out, s / 60 % 60);
    out.push(b':');
    push2(out, s % 60);
    out.push(b'.');
    let frac = ms_of_day % 1000;
    out.push(b'0' + (frac / 100) as u8);
    push2(out, frac % 100);
    out.extend_from_slice(b"Z\"");
}

/// A positive decimal integer (digits only, no sign), at most i64::MAX.
pub fn parse_pos_id(s: &[u8]) -> Option<i64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    if v == 0 || v > i64::MAX as u64 { None } else { Some(v as i64) }
}

fn b64_val(c: u8, url: bool) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' if url => 62,
        b'_' if url => 63,
        b'+' if !url => 62,
        b'/' if !url => 63,
        _ => return None,
    } as u32)
}

/// Decodes base64 (standard or URL alphabet); padding is ignored.
pub fn b64_decode(s: &[u8], url: bool) -> Option<Vec<u8>> {
    let s = if url { s } else { s.strip_suffix(b"==").or_else(|| s.strip_suffix(b"=")).unwrap_or(s) };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        acc = (acc << 6) | b64_val(c, url)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 6 {
        return None; // a dangling 6-bit group is not valid base64
    }
    Some(out)
}

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for ch in data.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub enum AuthError {
    Missing,
    Invalid,
    Payload,
}

pub struct AuthUser {
    pub id: i64,
    pub username: String,
}

/// Verifies `Authorization: Bearer <jwt>` (HS256 signature, `alg`, `exp`) and extracts `sub` and `username`.
pub fn verify_jwt(header: Option<&[u8]>, key: &HmacSha256, now_s: f64) -> Result<AuthUser, AuthError> {
    let token = match header {
        Some(h) if h.starts_with(b"Bearer ") => &h[7..],
        _ => return Err(AuthError::Missing),
    };
    let mut parts = token.split(|&b| b == b'.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(AuthError::Invalid),
    };
    let sig = b64_decode(s, true).ok_or(AuthError::Invalid)?;
    let mut mac = key.clone();
    mac.update(&token[..h.len() + 1 + p.len()]);
    mac.verify_slice(&sig).map_err(|_| AuthError::Invalid)?;
    let header: serde_json::Value =
        serde_json::from_slice(&b64_decode(h, true).ok_or(AuthError::Invalid)?).map_err(|_| AuthError::Invalid)?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return Err(AuthError::Invalid);
    }
    let payload: serde_json::Value =
        serde_json::from_slice(&b64_decode(p, true).ok_or(AuthError::Invalid)?).map_err(|_| AuthError::Invalid)?;
    match payload.get("exp").and_then(|e| e.as_f64()) {
        Some(exp) if exp > now_s => {}
        _ => return Err(AuthError::Invalid),
    }
    let id = payload.get("sub").and_then(|s| s.as_str()).and_then(|s| parse_pos_id(s.as_bytes()));
    let username = payload.get("username").and_then(|u| u.as_str());
    match (id, username) {
        (Some(id), Some(u)) => Ok(AuthUser { id, username: u.to_owned() }),
        _ => Err(AuthError::Payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        // 2025-12-31T23:59:19.409999Z: microseconds since 2000-01-01
        let unix_us: i64 = 1_767_225_559_409_999;
        let mut v = Vec::new();
        push_timestamp(&mut v, unix_us - 946_684_800_000_000);
        assert_eq!(v, b"\"2025-12-31T23:59:19.409Z\"");
        v.clear();
        push_timestamp(&mut v, 0);
        assert_eq!(v, b"\"2000-01-01T00:00:00.000Z\"");
        v.clear();
        push_timestamp(&mut v, -1);
        assert_eq!(v, b"\"1999-12-31T23:59:59.999Z\"");
        v.clear();
        push_timestamp(&mut v, (1_709_208_000_123_456i64) - 946_684_800_000_000); // 2024-02-29T12:00:00.123Z
        assert_eq!(v, b"\"2024-02-29T12:00:00.123Z\"");
    }

    #[test]
    fn ids() {
        assert_eq!(parse_pos_id(b"1"), Some(1));
        assert_eq!(parse_pos_id(b"0"), None);
        assert_eq!(parse_pos_id(b"-1"), None);
        assert_eq!(parse_pos_id(b"1.5"), None);
        assert_eq!(parse_pos_id(b"abc"), None);
        assert_eq!(parse_pos_id(b""), None);
    }

    #[test]
    fn escape() {
        let mut v = Vec::new();
        json_str(&mut v, "a\"b\\c\nd\u{1}é".as_bytes());
        assert_eq!(v, "\"a\\\"b\\\\c\\nd\\u0001é\"".as_bytes());
    }

    #[test]
    fn base64() {
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_decode(b"aGVsbG8=", false).unwrap(), b"hello");
        assert_eq!(b64_decode(b"aGVsbG8", true).unwrap(), b"hello");
    }
}
