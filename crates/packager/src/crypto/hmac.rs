//! A common digest interface, HMAC (RFC 2104) and PBKDF2 (RFC 8018).

use crate::crypto::{Sha1, Sha256};
use crate::crypto::sha2::Sha512;

/// The hash functions the signing code can be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1 (legacy formats only).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// Digest length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    /// Block length in bytes.
    pub fn block_len(self) -> usize {
        match self {
            HashAlg::Sha1 | HashAlg::Sha256 => 64,
            HashAlg::Sha384 | HashAlg::Sha512 => 128,
        }
    }
    /// One-shot digest.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        self.digest_parts(&[data])
    }
    /// Digest of the concatenation of `parts`.
    pub fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => {
                let mut h = Sha1::new();
                parts.iter().for_each(|p| h.update(p));
                h.finish().to_vec()
            }
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finish().to_vec()
            }
            HashAlg::Sha384 => {
                let mut h = Sha512::new384();
                parts.iter().for_each(|p| h.update(p));
                h.finish()
            }
            HashAlg::Sha512 => {
                let mut h = Sha512::new();
                parts.iter().for_each(|p| h.update(p));
                h.finish()
            }
        }
    }
}

/// HMAC of `data` under `key`.
pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    let bl = alg.block_len();
    let mut k = if key.len() > bl { alg.digest(key) } else { key.to_vec() };
    k.resize(bl, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = alg.digest_parts(&[&ipad, data]);
    alg.digest_parts(&[&opad, &inner])
}

/// PBKDF2 with HMAC-`alg`.
pub fn pbkdf2(alg: HashAlg, password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 1u32;
    while out.len() < len {
        let mut u = hmac(alg, password, &[salt, &block.to_be_bytes()].concat());
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hmac(alg, password, &u);
            t.iter_mut().zip(&u).for_each(|(a, b)| *a ^= b);
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn vectors() {
        // RFC 4231 test case 2.
        assert_eq!(hex(&hmac(HashAlg::Sha256, b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // RFC 6070 (PBKDF2-HMAC-SHA1).
        assert_eq!(hex(&pbkdf2(HashAlg::Sha1, b"password", b"salt", 4096, 20)), "4b007901b765489abead49d926f721d065a429c1");
    }
}
