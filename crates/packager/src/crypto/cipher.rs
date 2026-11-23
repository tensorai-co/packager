//! Block ciphers for decrypting key containers (PKCS#12, encrypted PKCS#8): AES (FIPS 197),
//! Triple DES (SP 800-67) and RC2 (RFC 2268), each with CBC decryption and PKCS#7 unpadding.

use crate::{Error, Result};

// ---------------------------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------------------------

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn aes_sboxes() -> ([u8; 256], [u8; 256]) {
    let mut sbox = [0u8; 256];
    let mut inv = [0u8; 256];
    for i in 0..256u16 {
        // Multiplicative inverse in GF(2^8), then the affine transform.
        let x = i as u8;
        let mut y = if x == 0 { 0 } else { (1..=255u8).find(|&c| gmul(x, c) == 1).unwrap_or(0) };
        let mut s = y;
        for _ in 0..4 {
            y = y.rotate_left(1);
            s ^= y;
        }
        s ^= 0x63;
        sbox[i as usize] = s;
        inv[s as usize] = x;
    }
    (sbox, inv)
}

/// An expanded AES key.
pub struct Aes {
    rounds: usize,
    w: Vec<[u8; 4]>,
    sbox: [u8; 256],
    inv: [u8; 256],
}

impl Aes {
    /// Expands a 16-, 24- or 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        let nk = key.len() / 4;
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(Error::Other("aes: key must be 16, 24 or 32 bytes".into()));
        }
        let (sbox, inv) = aes_sboxes();
        let rounds = nk + 6;
        let mut w: Vec<[u8; 4]> = key.chunks(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let mut rcon = 1u8;
        for i in nk..4 * (rounds + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [sbox[t[1] as usize] ^ rcon, sbox[t[2] as usize], sbox[t[3] as usize], sbox[t[0] as usize]];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| sbox[b as usize]);
            }
            let prev = w[i - nk];
            w.push([prev[0] ^ t[0], prev[1] ^ t[1], prev[2] ^ t[2], prev[3] ^ t[3]]);
        }
        Ok(Aes { rounds, w, sbox, inv })
    }

    fn add_round_key(&self, s: &mut [u8; 16], round: usize) {
        for c in 0..4 {
            for r in 0..4 {
                s[c * 4 + r] ^= self.w[round * 4 + c][r];
            }
        }
    }

    /// Encrypts one block (used by the tests).
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, 0);
        for round in 1..=self.rounds {
            for b in block.iter_mut() {
                *b = self.sbox[*b as usize];
            }
            let s = *block;
            for c in 0..4 {
                for r in 0..4 {
                    block[c * 4 + r] = s[((c + r) % 4) * 4 + r];
                }
            }
            if round != self.rounds {
                for c in 0..4 {
                    let a = [block[c * 4], block[c * 4 + 1], block[c * 4 + 2], block[c * 4 + 3]];
                    block[c * 4] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
                    block[c * 4 + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
                    block[c * 4 + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
                    block[c * 4 + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
                }
            }
            self.add_round_key(block, round);
        }
    }

    /// Decrypts one block.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, self.rounds);
        for round in (0..self.rounds).rev() {
            let s = *block;
            for c in 0..4 {
                for r in 0..4 {
                    block[((c + r) % 4) * 4 + r] = s[c * 4 + r];
                }
            }
            for b in block.iter_mut() {
                *b = self.inv[*b as usize];
            }
            self.add_round_key(block, round);
            if round != 0 {
                for c in 0..4 {
                    let a = [block[c * 4], block[c * 4 + 1], block[c * 4 + 2], block[c * 4 + 3]];
                    block[c * 4] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
                    block[c * 4 + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
                    block[c * 4 + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
                    block[c * 4 + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
                }
            }
        }
    }
}

/// AES-CBC decryption with PKCS#7 unpadding.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let aes = Aes::new(key)?;
    cbc_decrypt::<16>(iv, data, |b| aes.decrypt_block(b))
}

fn cbc_decrypt<const N: usize>(iv: &[u8], data: &[u8], mut decrypt: impl FnMut(&mut [u8; N])) -> Result<Vec<u8>> {
    if iv.len() != N || data.is_empty() || data.len() % N != 0 {
        return Err(Error::Other("cbc: bad IV or ciphertext length".into()));
    }
    let mut prev: [u8; N] = iv.try_into().map_err(|_| Error::Other("cbc: bad IV".into()))?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(N) {
        let mut block: [u8; N] = chunk.try_into().map_err(|_| Error::Other("cbc: bad block".into()))?;
        let ct = block;
        decrypt(&mut block);
        for i in 0..N {
            block[i] ^= prev[i];
        }
        out.extend_from_slice(&block);
        prev = ct;
    }
    let pad = *out.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > N || out[out.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(Error::Other("decryption failed (wrong password?)".into()));
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// DES / Triple DES
// ---------------------------------------------------------------------------------------------

const IP: [u8; 64] = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const FP: [u8; 64] = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const E: [u8; 48] = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const P: [u8; 32] = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const PC1: [u8; 56] = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2: [u8; 48] = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

fn permute(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        out = out << 1 | (input >> (in_bits - pos as u32)) & 1;
    }
    out
}

struct Des {
    subkeys: [u64; 16],
}

impl Des {
    fn new(key: &[u8]) -> Self {
        let k = u64::from_be_bytes(key[..8].try_into().unwrap_or_default());
        let cd = permute(k, &PC1, 64);
        let (mut c, mut d) = ((cd >> 28) as u32 & 0x0fff_ffff, cd as u32 & 0x0fff_ffff);
        let mut subkeys = [0u64; 16];
        for (i, &s) in SHIFTS.iter().enumerate() {
            c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
            d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
            subkeys[i] = permute((c as u64) << 28 | d as u64, &PC2, 56);
        }
        Des { subkeys }
    }
    fn feistel(r: u32, k: u64) -> u32 {
        let x = permute(r as u64, &E, 32) ^ k;
        let mut out = 0u32;
        for (i, sbox) in SBOX.iter().enumerate() {
            let six = (x >> (42 - 6 * i)) & 0x3f;
            let row = ((six & 0x20) >> 4) | (six & 1);
            let col = (six >> 1) & 0xf;
            out = out << 4 | sbox[(row * 16 + col) as usize] as u32;
        }
        permute(out as u64, &P, 32) as u32
    }
    fn crypt(&self, block: u64, decrypt: bool) -> u64 {
        let ip = permute(block, &IP, 64);
        let (mut l, mut r) = ((ip >> 32) as u32, ip as u32);
        for i in 0..16 {
            let k = if decrypt { self.subkeys[15 - i] } else { self.subkeys[i] };
            let t = r;
            r = l ^ Self::feistel(r, k);
            l = t;
        }
        permute((r as u64) << 32 | l as u64, &FP, 64)
    }
}

/// Triple-DES (EDE3) CBC decryption with PKCS#7 unpadding.
pub fn des3_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 24 {
        return Err(Error::Other("3des: key must be 24 bytes".into()));
    }
    let (k1, k2, k3) = (Des::new(&key[..8]), Des::new(&key[8..16]), Des::new(&key[16..]));
    cbc_decrypt::<8>(iv, data, |b| {
        let v = u64::from_be_bytes(*b);
        let v = k1.crypt(k2.crypt(k3.crypt(v, true), false), true);
        *b = v.to_be_bytes();
    })
}

// ---------------------------------------------------------------------------------------------
// RC2
// ---------------------------------------------------------------------------------------------

const PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32, 0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

fn rc2_key(key: &[u8], effective_bits: usize) -> [u16; 64] {
    let mut l = [0u8; 128];
    l[..key.len()].copy_from_slice(key);
    let t = key.len();
    for i in t..128 {
        l[i] = PITABLE[(l[i - 1].wrapping_add(l[i - t])) as usize];
    }
    let t8 = effective_bits.div_ceil(8);
    let tm = (0xffu32 >> (8 * t8 - effective_bits)) as u8;
    l[128 - t8] = PITABLE[(l[128 - t8] & tm) as usize];
    for i in (0..128 - t8).rev() {
        l[i] = PITABLE[(l[i + 1] ^ l[i + t8]) as usize];
    }
    let mut k = [0u16; 64];
    for i in 0..64 {
        k[i] = l[2 * i] as u16 | (l[2 * i + 1] as u16) << 8;
    }
    k
}

fn rc2_decrypt_block(k: &[u16; 64], block: &mut [u8; 8]) {
    let mut r = [0u16; 4];
    for i in 0..4 {
        r[i] = block[2 * i] as u16 | (block[2 * i + 1] as u16) << 8;
    }
    let mut j = 63i32;
    let s = [1u32, 2, 3, 5];
    let mix_round = |r: &mut [u16; 4], j: &mut i32| {
        for i in (0..4).rev() {
            r[i] = r[i].rotate_right(s[i]);
            r[i] = r[i].wrapping_sub(k[*j as usize]).wrapping_sub(r[(i + 3) % 4] & r[(i + 2) % 4]).wrapping_sub(!r[(i + 3) % 4] & r[(i + 1) % 4]);
            *j -= 1;
        }
    };
    let mash_round = |r: &mut [u16; 4]| {
        for i in (0..4).rev() {
            r[i] = r[i].wrapping_sub(k[(r[(i + 3) % 4] & 63) as usize]);
        }
    };
    for _ in 0..5 {
        mix_round(&mut r, &mut j);
    }
    mash_round(&mut r);
    for _ in 0..6 {
        mix_round(&mut r, &mut j);
    }
    mash_round(&mut r);
    for _ in 0..5 {
        mix_round(&mut r, &mut j);
    }
    for i in 0..4 {
        block[2 * i] = r[i] as u8;
        block[2 * i + 1] = (r[i] >> 8) as u8;
    }
}

/// RC2-CBC decryption with PKCS#7 unpadding.
pub fn rc2_cbc_decrypt(key: &[u8], effective_bits: usize, iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() || key.len() > 128 {
        return Err(Error::Other("rc2: bad key length".into()));
    }
    let k = rc2_key(key, effective_bits);
    cbc_decrypt::<8>(iv, data, |b| rc2_decrypt_block(&k, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn aes_fips197() {
        let key: Vec<u8> = (0u8..32).collect();
        let mut block: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let aes = Aes::new(&key).unwrap();
        aes.encrypt_block(&mut block);
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
        aes.decrypt_block(&mut block);
        assert_eq!(hex(&block), "00112233445566778899aabbccddeeff");
        let aes128 = Aes::new(&key[..16]).unwrap();
        let mut b2: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        aes128.encrypt_block(&mut b2);
        assert_eq!(hex(&b2), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn des_vector() {
        // Classic DES test: key 133457799BBCDFF1, plaintext 0123456789ABCDEF → 85E813540F0AB405.
        let d = Des::new(&[0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);
        assert_eq!(d.crypt(0x0123456789abcdef, false), 0x85e813540f0ab405);
        assert_eq!(d.crypt(0x85e813540f0ab405, true), 0x0123456789abcdef);
    }

    #[test]
    fn rc2_rfc2268() {
        // RFC 2268 §5: key 88, 64 effective bits, plaintext 0 → 61a8a244adacccf0 (decrypt back).
        let k = rc2_key(&[0x88], 64);
        let mut b = [0x61, 0xa8, 0xa2, 0x44, 0xad, 0xac, 0xcc, 0xf0];
        rc2_decrypt_block(&k, &mut b);
        assert_eq!(b, [0u8; 8]);
    }
}
