//! ECDSA over NIST P-256 and P-384 (FIPS 186-5), with deterministic nonces (RFC 6979).

use crate::crypto::bigint::BigUint;
use crate::crypto::der;
use crate::crypto::hmac::{HashAlg, hmac};
use crate::{Error, Result};

/// A supported curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

struct Params {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    n: BigUint,
    gx: BigUint,
    gy: BigUint,
}

impl Curve {
    fn params(self) -> Params {
        let h = BigUint::from_hex;
        match self {
            Curve::P256 => Params {
                p: h("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                a: h("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
                b: h("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                n: h("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                gx: h("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                gy: h("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            },
            Curve::P384 => Params {
                p: h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                a: h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
                b: h("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
                n: h("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
                gx: h("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
                gy: h("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
            },
        }
    }
    /// Field/scalar size in bytes.
    pub fn size(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
    /// The hash conventionally paired with the curve.
    pub fn hash(self) -> HashAlg {
        match self {
            Curve::P256 => HashAlg::Sha256,
            Curve::P384 => HashAlg::Sha384,
        }
    }
    /// The curve's OID body.
    pub fn oid(self) -> &'static [u8] {
        match self {
            Curve::P256 => der::oids::P256,
            Curve::P384 => der::oids::P384,
        }
    }
    /// The curve for an OID body.
    pub fn from_oid(oid: &[u8]) -> Option<Curve> {
        [Curve::P256, Curve::P384].into_iter().find(|c| c.oid() == oid)
    }
}

/// A point in Jacobian coordinates (Z = 0 is infinity).
#[derive(Clone)]
struct Jac {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

struct Field<'a> {
    p: &'a BigUint,
}

impl Field<'_> {
    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let s = a.add(b);
        if &s >= self.p { s.sub(self.p) } else { s }
    }
    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        if a >= b { a.sub(b) } else { a.add(self.p).sub(b) }
    }
    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.mul(b).rem(self.p)
    }
    fn inv(&self, a: &BigUint) -> BigUint {
        a.modpow(&self.p.sub(&BigUint::from_u64(2)), self.p)
    }
}

fn infinity() -> Jac {
    Jac { x: BigUint::from_u64(1), y: BigUint::from_u64(1), z: BigUint::zero() }
}

fn double(f: &Field, a_coef: &BigUint, pt: &Jac) -> Jac {
    if pt.z.is_zero() || pt.y.is_zero() {
        return infinity();
    }
    let (x, y, z) = (&pt.x, &pt.y, &pt.z);
    let yy = f.mul(y, y);
    let s = f.mul(&BigUint::from_u64(4), &f.mul(x, &yy));
    let zz = f.mul(z, z);
    let m = f.add(&f.mul(&BigUint::from_u64(3), &f.mul(x, x)), &f.mul(a_coef, &f.mul(&zz, &zz)));
    let x3 = f.sub(&f.mul(&m, &m), &f.add(&s, &s));
    let y3 = f.sub(&f.mul(&m, &f.sub(&s, &x3)), &f.mul(&BigUint::from_u64(8), &f.mul(&yy, &yy)));
    let z3 = f.mul(&BigUint::from_u64(2), &f.mul(y, z));
    Jac { x: x3, y: y3, z: z3 }
}

fn add(f: &Field, a_coef: &BigUint, p1: &Jac, p2: &Jac) -> Jac {
    if p1.z.is_zero() {
        return p2.clone();
    }
    if p2.z.is_zero() {
        return p1.clone();
    }
    let z1z1 = f.mul(&p1.z, &p1.z);
    let z2z2 = f.mul(&p2.z, &p2.z);
    let u1 = f.mul(&p1.x, &z2z2);
    let u2 = f.mul(&p2.x, &z1z1);
    let s1 = f.mul(&p1.y, &f.mul(&p2.z, &z2z2));
    let s2 = f.mul(&p2.y, &f.mul(&p1.z, &z1z1));
    if u1 == u2 {
        return if s1 == s2 { double(f, a_coef, p1) } else { infinity() };
    }
    let h = f.sub(&u2, &u1);
    let r = f.sub(&s2, &s1);
    let hh = f.mul(&h, &h);
    let hhh = f.mul(&h, &hh);
    let v = f.mul(&u1, &hh);
    let x3 = f.sub(&f.sub(&f.mul(&r, &r), &hhh), &f.add(&v, &v));
    let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.mul(&s1, &hhh));
    let z3 = f.mul(&h, &f.mul(&p1.z, &p2.z));
    Jac { x: x3, y: y3, z: z3 }
}

fn scalar_mul(c: &Params, k: &BigUint, x: &BigUint, y: &BigUint) -> Option<(BigUint, BigUint)> {
    let f = Field { p: &c.p };
    let base = Jac { x: x.clone(), y: y.clone(), z: BigUint::from_u64(1) };
    let mut acc = infinity();
    for i in (0..k.bits()).rev() {
        acc = double(&f, &c.a, &acc);
        if k.bit(i) {
            acc = add(&f, &c.a, &acc, &base);
        }
    }
    to_affine(&f, &acc)
}

fn to_affine(f: &Field, pt: &Jac) -> Option<(BigUint, BigUint)> {
    if pt.z.is_zero() {
        return None;
    }
    let zi = f.inv(&pt.z);
    let zi2 = f.mul(&zi, &zi);
    Some((f.mul(&pt.x, &zi2), f.mul(&pt.y, &f.mul(&zi2, &zi))))
}

/// An ECDSA public key (uncompressed point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPublicKey {
    /// Curve.
    pub curve: Curve,
    /// X coordinate.
    pub x: BigUint,
    /// Y coordinate.
    pub y: BigUint,
}

/// An ECDSA private key.
#[derive(Clone)]
pub struct EcPrivateKey {
    /// Curve.
    pub curve: Curve,
    /// Secret scalar.
    pub d: BigUint,
}

impl std::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcPrivateKey({:?})", self.curve)
    }
}

impl EcPublicKey {
    /// Parses an uncompressed SEC1 point (`04 || X || Y`).
    pub fn from_sec1(curve: Curve, bytes: &[u8]) -> Result<Self> {
        let n = curve.size();
        if bytes.len() != 1 + 2 * n || bytes[0] != 4 {
            return Err(Error::malformed("ec key", "only uncompressed points are supported"));
        }
        let k = EcPublicKey { curve, x: BigUint::from_be_bytes(&bytes[1..1 + n]), y: BigUint::from_be_bytes(&bytes[1 + n..]) };
        let c = curve.params();
        let f = Field { p: &c.p };
        let lhs = f.mul(&k.y, &k.y);
        let rhs = f.add(&f.add(&f.mul(&f.mul(&k.x, &k.x), &k.x), &f.mul(&c.a, &k.x)), &c.b);
        if lhs != rhs {
            return Err(Error::malformed("ec key", "point isn't on the curve"));
        }
        Ok(k)
    }
    /// The uncompressed SEC1 encoding.
    pub fn to_sec1(&self) -> Vec<u8> {
        let n = self.curve.size();
        [&[4u8][..], &self.x.to_be_bytes_padded(n), &self.y.to_be_bytes_padded(n)].concat()
    }
    /// Checks a DER `Ecdsa-Sig-Value` over a precomputed digest.
    pub fn verify(&self, digest: &[u8], sig_der: &[u8]) -> bool {
        let Ok(t) = der::parse(sig_der) else { return false };
        let mut r = t.reader();
        let (Ok(rr), Ok(ss)) = (r.expect(der::tag::INTEGER).and_then(|x| x.as_biguint()), r.expect(der::tag::INTEGER).and_then(|x| x.as_biguint())) else {
            return false;
        };
        let c = self.curve.params();
        if rr.is_zero() || ss.is_zero() || rr >= c.n || ss >= c.n {
            return false;
        }
        let e = bits2int(digest, &c.n);
        let Some(w) = ss.modinv(&c.n) else { return false };
        let u1 = e.mul(&w).rem(&c.n);
        let u2 = rr.mul(&w).rem(&c.n);
        let f = Field { p: &c.p };
        let p1 = scalar_mul(&c, &u1, &c.gx, &c.gy).map(|(x, y)| Jac { x, y, z: BigUint::from_u64(1) }).unwrap_or_else(infinity);
        let p2 = scalar_mul(&c, &u2, &self.x, &self.y).map(|(x, y)| Jac { x, y, z: BigUint::from_u64(1) }).unwrap_or_else(infinity);
        match to_affine(&f, &add(&f, &c.a, &p1, &p2)) {
            Some((x, _)) => x.rem(&c.n) == rr,
            None => false,
        }
    }
}

/// Converts a DER `Ecdsa-Sig-Value` to the fixed-size `r || s` form (JWS, WebAuthn).
pub fn der_to_raw(sig: &[u8], size: usize) -> Result<Vec<u8>> {
    let t = der::parse(sig)?;
    let mut r = t.reader();
    let rr = r.expect(der::tag::INTEGER)?.as_biguint()?;
    let ss = r.expect(der::tag::INTEGER)?.as_biguint()?;
    Ok([rr.to_be_bytes_padded(size), ss.to_be_bytes_padded(size)].concat())
}

/// Converts fixed-size `r || s` to a DER `Ecdsa-Sig-Value`.
pub fn raw_to_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    der::seq(&[&der::integer_unsigned_bytes(r), &der::integer_unsigned_bytes(s)])
}

fn bits2int(digest: &[u8], n: &BigUint) -> BigUint {
    let v = BigUint::from_be_bytes(digest);
    let dl = digest.len() * 8;
    if dl > n.bits() { v.shr(dl - n.bits()) } else { v }
}

impl EcPrivateKey {
    /// A new random key.
    pub fn generate(curve: Curve) -> Result<Self> {
        Ok(EcPrivateKey { curve, d: BigUint::random_below(&curve.params().n)? })
    }
    /// The public point.
    pub fn public(&self) -> EcPublicKey {
        let c = self.curve.params();
        let (x, y) = scalar_mul(&c, &self.d, &c.gx, &c.gy).unwrap_or_default();
        EcPublicKey { curve: self.curve, x, y }
    }
    /// Signs a precomputed digest; returns a DER `Ecdsa-Sig-Value`.
    pub fn sign(&self, digest: &[u8], alg: HashAlg) -> Result<Vec<u8>> {
        let c = self.curve.params();
        let e = bits2int(digest, &c.n).rem(&c.n);
        let mut nonces = Rfc6979::new(&c.n, &self.d, digest, alg);
        loop {
            let k = nonces.next();
            let Some((x, _)) = scalar_mul(&c, &k, &c.gx, &c.gy) else { continue };
            let r = x.rem(&c.n);
            if r.is_zero() {
                continue;
            }
            let kinv = k.modinv(&c.n).ok_or_else(|| Error::Other("ecdsa: k not invertible".into()))?;
            let s = kinv.mul(&e.add(&r.mul(&self.d)).rem(&c.n)).rem(&c.n);
            if s.is_zero() {
                continue;
            }
            return Ok(der::seq(&[&der::integer_big(&r), &der::integer_big(&s)]));
        }
    }
}

/// RFC 6979 §3.2 nonce generation (HMAC-DRBG).
struct Rfc6979 {
    k: Vec<u8>,
    v: Vec<u8>,
    alg: HashAlg,
    n: BigUint,
}

impl Rfc6979 {
    fn new(n: &BigUint, d: &BigUint, digest: &[u8], alg: HashAlg) -> Self {
        let rlen = n.bits().div_ceil(8);
        let x = d.to_be_bytes_padded(rlen);
        let h = bits2int(digest, n).rem(n).to_be_bytes_padded(rlen);
        let hl = alg.len();
        let mut v = vec![1u8; hl];
        let mut k = vec![0u8; hl];
        k = hmac(alg, &k, &[&v[..], &[0], &x, &h].concat());
        v = hmac(alg, &k, &v);
        k = hmac(alg, &k, &[&v[..], &[1], &x, &h].concat());
        v = hmac(alg, &k, &v);
        Rfc6979 { k, v, alg, n: n.clone() }
    }
    fn next(&mut self) -> BigUint {
        let qlen = self.n.bits();
        loop {
            let mut t = Vec::new();
            while t.len() * 8 < qlen {
                self.v = hmac(self.alg, &self.k, &self.v);
                t.extend_from_slice(&self.v);
            }
            let k = bits2int(&t, &self.n);
            if !k.is_zero() && k < self.n {
                // Prepare for a retry, per the RFC.
                self.k = hmac(self.alg, &self.k, &[&self.v[..], &[0]].concat());
                self.v = hmac(self.alg, &self.k, &self.v);
                return k;
            }
            self.k = hmac(self.alg, &self.k, &[&self.v[..], &[0]].concat());
            self.v = hmac(self.alg, &self.k, &self.v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6979_p256_sha256_vector() {
        // RFC 6979 A.2.5, message "sample".
        let d = BigUint::from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let key = EcPrivateKey { curve: Curve::P256, d };
        let pubk = key.public();
        assert_eq!(pubk.x, BigUint::from_hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"));
        let digest = HashAlg::Sha256.digest(b"sample");
        let sig = key.sign(&digest, HashAlg::Sha256).unwrap();
        let t = der::parse(&sig).unwrap();
        let mut r = t.reader();
        assert_eq!(r.read().unwrap().as_biguint().unwrap(), BigUint::from_hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"));
        assert_eq!(r.read().unwrap().as_biguint().unwrap(), BigUint::from_hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"));
        assert!(pubk.verify(&digest, &sig));
        assert!(!pubk.verify(&HashAlg::Sha256.digest(b"other"), &sig));
        assert!(EcPublicKey::from_sec1(Curve::P256, &pubk.to_sec1()).is_ok());
    }
}
