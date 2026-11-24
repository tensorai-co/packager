//! Cryptography from the specifications, tested against published vectors: hashes and
//! checksums, big integers, RSA and ECDSA, ASN.1, X.509, PKCS#8/#12 and the ciphers they need.

pub mod bigint;
pub mod cipher;
pub mod crc;
pub mod der;
pub mod ec;
pub mod hmac;
pub mod keys;
pub mod pkcs12;
pub mod rsa;
pub mod sha1;
pub mod sha2;
pub mod sigv4;
pub mod x509;

pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

/// Decodes hex (either case).
pub fn unhex(s: &str) -> crate::Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(crate::Error::Other(format!("odd-length hex `{s}`")));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| crate::Error::Other(format!("bad hex `{s}`")))).collect()
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// SHA-1 of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

/// Cryptographically secure random bytes from the OS.
pub fn random_bytes(n: usize) -> crate::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| crate::Error::Other(format!("no OS randomness (/dev/urandom): {e}")))?;
    Ok(buf)
}
