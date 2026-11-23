//! Arbitrary-precision unsigned integers: enough arithmetic for RSA and elliptic curves
//! (Montgomery exponentiation, Knuth division, inverses, Miller–Rabin).
//!
//! Not constant time. Signing keys usually live in an HSM or the OS key store behind a
//! [`Signer`](crate::sign::Signer); the in-process key path is for files the user already holds.

use std::cmp::Ordering;

/// An unsigned integer as little-endian 64-bit limbs, without leading zero limbs.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl std::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", crate::crypto::hex(&self.to_be_bytes()))
    }
}

impl BigUint {
    /// Zero.
    pub fn zero() -> Self {
        BigUint { limbs: Vec::new() }
    }
    /// A small value.
    pub fn from_u64(v: u64) -> Self {
        let mut b = BigUint { limbs: vec![v] };
        b.trim();
        b
    }
    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }
    /// From big-endian bytes.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        for chunk in bytes.rchunks(8) {
            let mut v = 0u64;
            for &b in chunk {
                v = v << 8 | b as u64;
            }
            limbs.push(v);
        }
        let mut r = BigUint { limbs };
        r.trim();
        r
    }
    /// Minimal big-endian bytes (empty for zero).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for l in self.limbs.iter().rev() {
            out.extend_from_slice(&l.to_be_bytes());
        }
        let skip = out.iter().take_while(|&&b| b == 0).count();
        out.drain(..skip);
        out
    }
    /// Big-endian bytes left-padded to `len` (truncating high bytes if longer).
    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let b = self.to_be_bytes();
        if b.len() >= len {
            return b[b.len() - len..].to_vec();
        }
        let mut out = vec![0u8; len - b.len()];
        out.extend_from_slice(&b);
        out
    }
    /// Parses hex (for tests and constants).
    pub fn from_hex(s: &str) -> Self {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let s = if s.len() % 2 == 1 { format!("0{s}") } else { s };
        let bytes: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0)).collect();
        Self::from_be_bytes(&bytes)
    }
    /// Whether this is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }
    /// Whether this is odd.
    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }
    /// Number of significant bits.
    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 64 + (64 - top.leading_zeros() as usize),
        }
    }
    /// Bit `i`.
    pub fn bit(&self, i: usize) -> bool {
        self.limbs.get(i / 64).is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }
    /// Sets bit `i`.
    pub fn set_bit(&mut self, i: usize) {
        if self.limbs.len() <= i / 64 {
            self.limbs.resize(i / 64 + 1, 0);
        }
        self.limbs[i / 64] |= 1 << (i % 64);
    }

    /// `self + other`.
    pub fn add(&self, other: &BigUint) -> BigUint {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u128;
        for i in 0..n {
            let s = *self.limbs.get(i).unwrap_or(&0) as u128 + *other.limbs.get(i).unwrap_or(&0) as u128 + carry;
            out.push(s as u64);
            carry = s >> 64;
        }
        if carry > 0 {
            out.push(carry as u64);
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }
    /// `self - other`; `other` must not exceed `self`.
    pub fn sub(&self, other: &BigUint) -> BigUint {
        debug_assert!(self >= other);
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;
        for i in 0..self.limbs.len() {
            let mut d = self.limbs[i] as i128 - *other.limbs.get(i).unwrap_or(&0) as i128 - borrow;
            borrow = 0;
            if d < 0 {
                d += 1 << 64;
                borrow = 1;
            }
            out.push(d as u64);
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }
    /// `self * other`.
    pub fn mul(&self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }
        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = a as u128 * b as u128 + out[i + j] as u128 + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + other.limbs.len()] = carry as u64;
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }
    /// `self << n`.
    pub fn shl(&self, n: usize) -> BigUint {
        if self.is_zero() {
            return BigUint::zero();
        }
        let (words, bits) = (n / 64, n % 64);
        let mut out = vec![0u64; words];
        if bits == 0 {
            out.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u64;
            for &l in &self.limbs {
                out.push(l << bits | carry);
                carry = l >> (64 - bits);
            }
            out.push(carry);
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }
    /// `self >> n`.
    pub fn shr(&self, n: usize) -> BigUint {
        let (words, bits) = (n / 64, n % 64);
        if words >= self.limbs.len() {
            return BigUint::zero();
        }
        let src = &self.limbs[words..];
        let mut out = Vec::with_capacity(src.len());
        for i in 0..src.len() {
            let lo = src[i] >> bits;
            let hi = if bits > 0 { src.get(i + 1).map_or(0, |h| h << (64 - bits)) } else { 0 };
            out.push(lo | hi);
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }

    /// (quotient, remainder). Panics on division by zero.
    pub fn divrem(&self, d: &BigUint) -> (BigUint, BigUint) {
        assert!(!d.is_zero(), "division by zero");
        if self < d {
            return (BigUint::zero(), self.clone());
        }
        if d.limbs.len() == 1 {
            let dv = d.limbs[0] as u128;
            let mut q = vec![0u64; self.limbs.len()];
            let mut r = 0u128;
            for i in (0..self.limbs.len()).rev() {
                let cur = r << 64 | self.limbs[i] as u128;
                q[i] = (cur / dv) as u64;
                r = cur % dv;
            }
            let mut q = BigUint { limbs: q };
            q.trim();
            return (q, BigUint::from_u64(r as u64));
        }
        // Knuth algorithm D with normalization.
        let s = d.limbs.last().map_or(0, |t| t.leading_zeros()) as usize;
        let v = d.shl(s).limbs;
        let mut u = self.shl(s).limbs;
        u.push(0);
        let n = v.len();
        let m = u.len() - n - 1;
        let mut q = vec![0u64; m + 1];
        let b: u128 = 1 << 64;
        for j in (0..=m).rev() {
            let num = (u[j + n] as u128) << 64 | u[j + n - 1] as u128;
            let mut qhat = num / v[n - 1] as u128;
            let mut rhat = num % v[n - 1] as u128;
            while qhat >= b || qhat * v[n - 2] as u128 > (rhat << 64 | u[j + n - 2] as u128) {
                qhat -= 1;
                rhat += v[n - 1] as u128;
                if rhat >= b {
                    break;
                }
            }
            // u[j..j+n+1] -= qhat * v
            let mut borrow: i128 = 0;
            let mut carry: u128 = 0;
            for i in 0..n {
                let p = qhat * v[i] as u128 + carry;
                carry = p >> 64;
                let t = u[i + j] as i128 - (p as u64) as i128 - borrow;
                u[i + j] = t as u64;
                borrow = if t < 0 { 1 } else { 0 };
            }
            let t = u[j + n] as i128 - carry as i128 - borrow;
            u[j + n] = t as u64;
            if t < 0 {
                qhat -= 1;
                let mut c: u128 = 0;
                for i in 0..n {
                    let s2 = u[i + j] as u128 + v[i] as u128 + c;
                    u[i + j] = s2 as u64;
                    c = s2 >> 64;
                }
                u[j + n] = u[j + n].wrapping_add(c as u64);
            }
            q[j] = qhat as u64;
        }
        let mut q = BigUint { limbs: q };
        q.trim();
        let mut r = BigUint { limbs: u[..n].to_vec() };
        r.trim();
        (q, r.shr(s))
    }
    /// `self mod m`.
    pub fn rem(&self, m: &BigUint) -> BigUint {
        self.divrem(m).1
    }

    /// `self^e mod m` (Montgomery for odd `m`, square-and-multiply otherwise).
    pub fn modpow(&self, e: &BigUint, m: &BigUint) -> BigUint {
        if m.limbs.len() == 1 && m.limbs[0] == 1 {
            return BigUint::zero();
        }
        if m.is_odd() {
            return Montgomery::new(m).pow(&self.rem(m), e);
        }
        let mut result = BigUint::from_u64(1);
        let base = self.rem(m);
        for i in (0..e.bits()).rev() {
            result = result.mul(&result).rem(m);
            if e.bit(i) {
                result = result.mul(&base).rem(m);
            }
        }
        result
    }

    /// `self^-1 mod m`, if it exists.
    pub fn modinv(&self, m: &BigUint) -> Option<BigUint> {
        // Extended Euclid tracking signed coefficients as (magnitude, negative).
        let (mut r0, mut r1) = (m.clone(), self.rem(m));
        let (mut t0, mut t1) = ((BigUint::zero(), false), (BigUint::from_u64(1), false));
        while !r1.is_zero() {
            let (q, r) = r0.divrem(&r1);
            r0 = std::mem::replace(&mut r1, r);
            // t2 = t0 - q * t1
            let qt = (q.mul(&t1.0), t1.1);
            let t2 = signed_sub(&t0, &qt);
            t0 = std::mem::replace(&mut t1, t2);
        }
        if r0 != BigUint::from_u64(1) {
            return None;
        }
        Some(if t0.1 { m.sub(&t0.0.rem(m)).rem(m) } else { t0.0.rem(m) })
    }

    /// Greatest common divisor.
    pub fn gcd(&self, other: &BigUint) -> BigUint {
        let (mut a, mut b) = (self.clone(), other.clone());
        while !b.is_zero() {
            let r = a.rem(&b);
            a = std::mem::replace(&mut b, r);
        }
        a
    }

    /// A uniformly random value in `[1, bound)`.
    pub fn random_below(bound: &BigUint) -> crate::Result<BigUint> {
        let bytes = bound.bits().div_ceil(8);
        loop {
            let mut buf = crate::crypto::random_bytes(bytes)?;
            let extra = bytes * 8 - bound.bits();
            if extra > 0 {
                buf[0] &= 0xff >> extra;
            }
            let v = BigUint::from_be_bytes(&buf);
            if !v.is_zero() && &v < bound {
                return Ok(v);
            }
        }
    }

    /// Miller–Rabin with `rounds` random bases (after trial division by small primes).
    pub fn is_probable_prime(&self, rounds: usize) -> crate::Result<bool> {
        const SMALL: [u64; 30] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113];
        if self.bits() <= 7 {
            let v = self.limbs.first().copied().unwrap_or(0);
            return Ok(SMALL.contains(&v));
        }
        for &p in &SMALL {
            if self.rem(&BigUint::from_u64(p)).is_zero() {
                return Ok(false);
            }
        }
        let one = BigUint::from_u64(1);
        let nm1 = self.sub(&one);
        let mut d = nm1.clone();
        let mut s = 0;
        while !d.is_odd() {
            d = d.shr(1);
            s += 1;
        }
        let mont = Montgomery::new(self);
        let three = BigUint::from_u64(3);
        'witness: for _ in 0..rounds {
            let a = BigUint::random_below(&nm1.sub(&three))?.add(&BigUint::from_u64(2));
            let mut x = mont.pow(&a, &d);
            if x == one || x == nm1 {
                continue;
            }
            for _ in 1..s {
                x = x.mul(&x).rem(self);
                if x == nm1 {
                    continue 'witness;
                }
            }
            return Ok(false);
        }
        Ok(true)
    }
}

fn signed_sub(a: &(BigUint, bool), b: &(BigUint, bool)) -> (BigUint, bool) {
    // a - b with sign flags (true = negative).
    match (a.1, b.1) {
        (false, true) => (a.0.add(&b.0), false),
        (true, false) => (a.0.add(&b.0), true),
        (neg, _) => {
            if a.0 >= b.0 {
                (a.0.sub(&b.0), neg)
            } else {
                (b.0.sub(&a.0), !neg)
            }
        }
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs.len().cmp(&other.limbs.len()).then_with(|| {
            for i in (0..self.limbs.len()).rev() {
                match self.limbs[i].cmp(&other.limbs[i]) {
                    Ordering::Equal => continue,
                    o => return o,
                }
            }
            Ordering::Equal
        })
    }
}

/// Montgomery arithmetic modulo an odd `m` (CIOS multiplication).
pub struct Montgomery {
    m: Vec<u64>,
    m_big: BigUint,
    minv: u64, // -m^-1 mod 2^64
    r2: BigUint,
}

impl Montgomery {
    /// Context for odd modulus `m`.
    pub fn new(m: &BigUint) -> Self {
        let m0 = m.limbs[0];
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        let n = m.limbs.len();
        let r2 = BigUint::from_u64(1).shl(128 * n).rem(m);
        Montgomery { m: m.limbs.clone(), m_big: m.clone(), minv: inv.wrapping_neg(), r2 }
    }

    #[allow(clippy::needless_range_loop)] // CIOS indexes several arrays in lockstep
    fn mont_mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = self.m.len();
        let mut t = vec![0u64; n + 2];
        for i in 0..n {
            let ai = *a.get(i).unwrap_or(&0) as u128;
            let mut c: u128 = 0;
            for j in 0..n {
                let s = t[j] as u128 + ai * *b.get(j).unwrap_or(&0) as u128 + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = t[n] as u128 + c;
            t[n] = s as u64;
            t[n + 1] = (s >> 64) as u64;
            let mq = t[0].wrapping_mul(self.minv) as u128;
            let s = t[0] as u128 + mq * self.m[0] as u128;
            let mut c = s >> 64;
            for j in 1..n {
                let s = t[j] as u128 + mq * self.m[j] as u128 + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = t[n] as u128 + c;
            t[n - 1] = s as u64;
            t[n] = t[n + 1] + (s >> 64) as u64;
        }
        t.truncate(n + 1);
        // Conditional subtraction.
        let ge = t[n] != 0 || {
            let mut ge = true;
            for j in (0..n).rev() {
                if t[j] != self.m[j] {
                    ge = t[j] > self.m[j];
                    break;
                }
            }
            ge
        };
        if ge {
            let mut borrow = 0u64;
            for j in 0..n {
                let (d1, b1) = t[j].overflowing_sub(self.m[j]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                t[j] = d2;
                borrow = (b1 || b2) as u64;
            }
        }
        t.truncate(n);
        t
    }

    fn to_mont(&self, a: &BigUint) -> Vec<u64> {
        self.mont_mul(&a.limbs, &self.r2.limbs)
    }

    fn leave_mont(&self, a: &[u64]) -> BigUint {
        let mut r = BigUint { limbs: self.mont_mul(a, &[1]) };
        r.trim();
        r
    }

    /// `base^e mod m`, with `base < m`. Uses a 4-bit fixed window.
    pub fn pow(&self, base: &BigUint, e: &BigUint) -> BigUint {
        let one = self.to_mont(&BigUint::from_u64(1));
        if e.is_zero() {
            return BigUint::from_u64(1).rem(&self.m_big);
        }
        let b = self.to_mont(base);
        let mut table = vec![one.clone(), b.clone()];
        for i in 2..16 {
            let next = self.mont_mul(&table[i - 1], &b);
            table.push(next);
        }
        let mut acc = one;
        let bits = e.bits();
        let windows = bits.div_ceil(4);
        for w in (0..windows).rev() {
            for _ in 0..4 {
                acc = self.mont_mul(&acc, &acc);
            }
            let mut idx = 0usize;
            for k in (0..4).rev() {
                idx = idx << 1 | e.bit(w * 4 + k) as usize;
            }
            if idx != 0 {
                acc = self.mont_mul(&acc, &table[idx]);
            }
        }
        self.leave_mont(&acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let a = BigUint::from_hex("ffffffffffffffffffffffffffffffff0123456789abcdef");
        let b = BigUint::from_hex("fedcba9876543210ffffffffffff");
        let (q, r) = a.divrem(&b);
        assert_eq!(q.mul(&b).add(&r), a);
        assert!(r < b);
        assert_eq!(a.shl(77).shr(77), a);
        assert_eq!(BigUint::from_u64(3).modinv(&BigUint::from_u64(11)), Some(BigUint::from_u64(4)));
        // 2^255 - 19 is prime; Fermat: 2^(p-1) = 1.
        let p = BigUint::from_u64(1).shl(255).sub(&BigUint::from_u64(19));
        let e = p.sub(&BigUint::from_u64(1));
        assert_eq!(BigUint::from_u64(2).modpow(&e, &p), BigUint::from_u64(1));
        assert!(p.is_probable_prime(8).unwrap());
        assert!(!p.add(&BigUint::from_u64(2)).is_probable_prime(8).unwrap());
        // Even modulus path.
        assert_eq!(BigUint::from_u64(7).modpow(&BigUint::from_u64(5), &BigUint::from_u64(100)), BigUint::from_u64(7));
        let m = BigUint::from_hex("c5f2a1b3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f50617283940a1b2c3d4f");
        let x = BigUint::from_hex("123456789abcdef0123456789abcdef");
        let inv = x.modinv(&m).unwrap();
        assert_eq!(x.mul(&inv).rem(&m), BigUint::from_u64(1));
    }
}
