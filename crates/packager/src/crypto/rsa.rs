//! RSA (PKCS#1 v2.2): PKCS#1 v1.5 signatures, verification and key generation.

use crate::crypto::bigint::BigUint;
use crate::crypto::hmac::HashAlg;
use crate::{Error, Result};

/// An RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Modulus.
    pub n: BigUint,
    /// Public exponent.
    pub e: BigUint,
}

/// An RSA private key with CRT parameters.
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// Modulus.
    pub n: BigUint,
    /// Public exponent.
    pub e: BigUint,
    /// Private exponent.
    pub d: BigUint,
    /// First prime.
    pub p: BigUint,
    /// Second prime.
    pub q: BigUint,
    /// d mod (p-1).
    pub dp: BigUint,
    /// d mod (q-1).
    pub dq: BigUint,
    /// q^-1 mod p.
    pub qinv: BigUint,
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPrivateKey({} bits)", self.n.bits())
    }
}

/// The DER `DigestInfo` prefix for each hash (RFC 8017 §9.2, note 1).
pub fn digest_info_prefix(alg: HashAlg) -> &'static [u8] {
    match alg {
        HashAlg::Sha1 => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
        HashAlg::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        HashAlg::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        HashAlg::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
    }
}

fn emsa_pkcs1_v15(alg: HashAlg, digest: &[u8], k: usize) -> Result<Vec<u8>> {
    if digest.len() != alg.len() {
        return Err(Error::Other(format!("rsa: digest is {} bytes, expected {}", digest.len(), alg.len())));
    }
    let t = [digest_info_prefix(alg), digest].concat();
    if k < t.len() + 11 {
        return Err(Error::Other("rsa: key too small for this digest".into()));
    }
    let mut em = vec![0xffu8; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t.len() - 1] = 0;
    em[k - t.len()..].copy_from_slice(&t);
    Ok(em)
}

impl RsaPublicKey {
    /// Modulus length in bytes.
    pub fn size(&self) -> usize {
        self.n.bits().div_ceil(8)
    }
    /// Checks a PKCS#1 v1.5 signature over a precomputed digest.
    pub fn verify_pkcs1_v15(&self, alg: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let k = self.size();
        if sig.len() != k {
            return false;
        }
        let s = BigUint::from_be_bytes(sig);
        if s >= self.n {
            return false;
        }
        let m = s.modpow(&self.e, &self.n).to_be_bytes_padded(k);
        emsa_pkcs1_v15(alg, digest, k).is_ok_and(|em| em == m)
    }
}

impl RsaPrivateKey {
    /// Builds a key from n, e, d, p, q, deriving the CRT values.
    pub fn from_components(n: BigUint, e: BigUint, d: BigUint, p: BigUint, q: BigUint) -> Result<Self> {
        let one = BigUint::from_u64(1);
        if p.mul(&q) != n {
            return Err(Error::malformed("rsa key", "p·q ≠ n"));
        }
        let dp = d.rem(&p.sub(&one));
        let dq = d.rem(&q.sub(&one));
        let qinv = q.modinv(&p).ok_or_else(|| Error::malformed("rsa key", "q has no inverse mod p"))?;
        Ok(RsaPrivateKey { n, e, d, p, q, dp, dq, qinv })
    }

    /// The public half.
    pub fn public(&self) -> RsaPublicKey {
        RsaPublicKey { n: self.n.clone(), e: self.e.clone() }
    }

    /// PKCS#1 v1.5 signature over a precomputed digest (CRT, then checked against the public key
    /// so a fault can't leak the key).
    pub fn sign_pkcs1_v15(&self, alg: HashAlg, digest: &[u8]) -> Result<Vec<u8>> {
        let k = self.public().size();
        let m = BigUint::from_be_bytes(&emsa_pkcs1_v15(alg, digest, k)?);
        let m1 = m.modpow(&self.dp, &self.p);
        let m2 = m.modpow(&self.dq, &self.q);
        // h = qinv (m1 - m2) mod p
        let diff = if m1 >= m2.rem(&self.p) { m1.sub(&m2.rem(&self.p)) } else { m1.add(&self.p).sub(&m2.rem(&self.p)) };
        let h = self.qinv.mul(&diff).rem(&self.p);
        let s = m2.add(&h.mul(&self.q));
        let sig = s.to_be_bytes_padded(k);
        if !self.public().verify_pkcs1_v15(alg, digest, &sig) {
            return Err(Error::Other("rsa: signature self-check failed".into()));
        }
        Ok(sig)
    }

    /// Generates a key with `bits`-bit modulus and e = 65537.
    pub fn generate(bits: usize) -> Result<Self> {
        if bits < 1024 || bits % 2 != 0 {
            return Err(Error::Other("rsa: key size must be an even number of bits ≥ 1024".into()));
        }
        let e = BigUint::from_u64(65537);
        let one = BigUint::from_u64(1);
        loop {
            let p = random_prime(bits / 2, &e)?;
            let q = random_prime(bits / 2, &e)?;
            if p == q {
                continue;
            }
            let n = p.mul(&q);
            if n.bits() != bits {
                continue;
            }
            let (pm1, qm1) = (p.sub(&one), q.sub(&one));
            let lambda = pm1.mul(&qm1).divrem(&pm1.gcd(&qm1)).0;
            let Some(d) = e.modinv(&lambda) else { continue };
            let (p, q) = if p > q { (p, q) } else { (q, p) };
            return RsaPrivateKey::from_components(n, e, d, p, q);
        }
    }
}

fn random_prime(bits: usize, e: &BigUint) -> Result<BigUint> {
    let one = BigUint::from_u64(1);
    loop {
        let mut c = BigUint::from_be_bytes(&crate::crypto::random_bytes(bits / 8)?);
        c.set_bit(bits - 1);
        c.set_bit(bits - 2);
        c.set_bit(0);
        if c.bits() != bits {
            continue;
        }
        if c.sub(&one).gcd(e) != one {
            continue;
        }
        if c.is_probable_prime(if bits >= 1024 { 5 } else { 12 })? {
            return Ok(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let k = RsaPrivateKey::generate(1024).unwrap();
        let digest = HashAlg::Sha256.digest(b"hello");
        let sig = k.sign_pkcs1_v15(HashAlg::Sha256, &digest).unwrap();
        assert!(k.public().verify_pkcs1_v15(HashAlg::Sha256, &digest, &sig));
        let other = HashAlg::Sha256.digest(b"hellO");
        assert!(!k.public().verify_pkcs1_v15(HashAlg::Sha256, &other, &sig));
    }
}
