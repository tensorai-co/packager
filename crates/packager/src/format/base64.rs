//! Standard base64 (RFC 4648) with padding.

use crate::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data`.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

/// URL-safe base64 without padding (RFC 4648 §5), as JWTs use.
pub fn encode_url(data: &[u8]) -> String {
    encode(data).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

/// Decodes URL-safe or standard base64, with or without padding.
pub fn decode_url(s: &str) -> Result<Vec<u8>> {
    decode(&s.replace('-', "+").replace('_', "/"))
}

/// Decodes `s`, ignoring whitespace.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut n = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            c if c.is_ascii_whitespace() => continue,
            _ => return Err(Error::malformed("base64", format!("invalid character `{}`", c as char))),
        };
        acc = acc << 6 | v as u32;
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
            n = 0;
        }
    }
    match n {
        2 => out.push((acc >> 4) as u8),
        3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => {}
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn vectors() {
        for (raw, enc) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(super::encode(raw.as_bytes()), enc);
            assert_eq!(super::decode(enc).unwrap(), raw.as_bytes());
        }
    }
}
