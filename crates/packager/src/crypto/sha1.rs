//! SHA-1 (FIPS 180-4). Only for formats that require it: Apple's legacy hash slots,
//! XAR checksums and name-based UUIDs. Never for anything security-relevant on its own.

/// Streaming SHA-1.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// A fresh hasher.
    pub fn new() -> Self {
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    /// Feeds `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buf_len > 0 {
            let n = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            self.compress(block.try_into().unwrap_or(&[0; 64]));
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len += data.len();
    }

    /// The digest.
    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{hex, sha1};

    #[test]
    fn vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million = vec![b'a'; 1_000_000];
        assert_eq!(hex(&sha1(&million)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }
}
