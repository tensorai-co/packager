//! A DEFLATE decompressor (RFC 1951), used by the readers (PNG decode, round-trip tests,
//! inspecting existing packages).

use crate::{Error, Result};

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn bad(msg: &str) -> Error {
    Error::malformed("deflate", msg)
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn need(&mut self, count: u32) -> Result<()> {
        while self.n < count {
            let b = *self.data.get(self.pos).ok_or_else(|| bad("unexpected end of stream"))?;
            self.pos += 1;
            self.acc |= (b as u64) << self.n;
            self.n += 8;
        }
        Ok(())
    }
    fn bits(&mut self, count: u32) -> Result<u32> {
        if count == 0 {
            return Ok(0);
        }
        self.need(count)?;
        let v = (self.acc & ((1u64 << count) - 1)) as u32;
        self.acc >>= count;
        self.n -= count;
        Ok(v)
    }
    fn align(&mut self) {
        let drop = self.n % 8;
        self.acc >>= drop;
        self.n -= drop;
    }
}

/// A canonical Huffman decoder: a 9-bit lookup table with a slow path for longer codes.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
    fast: Vec<u16>, // (len << 12) | symbol, 0 = slow path
}

const FAST_BITS: u32 = 9;

impl Huffman {
    fn new(lens: &[u8]) -> Result<Self> {
        let mut counts = [0u16; 16];
        for &l in lens {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut left: i32 = 1;
        for &c in &counts[1..] {
            left = (left << 1) - c as i32;
            if left < 0 {
                return Err(bad("over-subscribed Huffman code"));
            }
        }
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + counts[i];
        }
        let mut symbols = vec![0u16; lens.len()];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        let mut fast = vec![0u16; 1 << FAST_BITS];
        let codes = crate::compress::deflate::canonical_codes(lens);
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 && (l as u32) <= FAST_BITS {
                let mut c = codes[s] as usize;
                while c < fast.len() {
                    fast[c] = ((l as u16) << 12) | s as u16;
                    c += 1 << l;
                }
            }
        }
        Ok(Huffman { counts, symbols, fast })
    }

    fn decode(&self, b: &mut Bits) -> Result<u16> {
        let _ = b.need(FAST_BITS);
        if b.n >= FAST_BITS {
            let e = self.fast[(b.acc & ((1 << FAST_BITS) - 1)) as usize];
            if e != 0 {
                let l = (e >> 12) as u32;
                b.acc >>= l;
                b.n -= l;
                return Ok(e & 0xfff);
            }
        }
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(bad("invalid Huffman code"))
    }
}

/// Decompresses a raw DEFLATE stream. Returns the data and the number of input bytes consumed.
pub fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut out = Vec::with_capacity(data.len() * 3);
    let mut b = Bits { data, pos: 0, acc: 0, n: 0 };
    loop {
        let last = b.bits(1)?;
        match b.bits(2)? {
            0 => {
                b.align();
                let len = b.bits(16)? as u16;
                let nlen = b.bits(16)? as u16;
                if len != !nlen {
                    return Err(bad("stored block length mismatch"));
                }
                for _ in 0..len {
                    out.push(b.bits(8)? as u8);
                }
            }
            1 => {
                let mut lens = [0u8; 288];
                for (i, l) in lens.iter_mut().enumerate() {
                    *l = match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let lit = Huffman::new(&lens)?;
                let dist = Huffman::new(&[5u8; 30])?;
                codes(&mut b, &mut out, &lit, &dist)?;
            }
            2 => {
                let hlit = b.bits(5)? as usize + 257;
                let hdist = b.bits(5)? as usize + 1;
                let hclen = b.bits(4)? as usize + 4;
                let mut cl = [0u8; 19];
                for &i in CL_ORDER.iter().take(hclen) {
                    cl[i] = b.bits(3)? as u8;
                }
                let clh = Huffman::new(&cl)?;
                let mut lens = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lens.len() {
                    let sym = clh.decode(&mut b)?;
                    let (val, rep) = match sym {
                        0..=15 => (sym as u8, 1),
                        16 => {
                            let prev = *lens.get(i.wrapping_sub(1)).ok_or_else(|| bad("repeat with no previous length"))?;
                            (prev, 3 + b.bits(2)? as usize)
                        }
                        17 => (0, 3 + b.bits(3)? as usize),
                        _ => (0, 11 + b.bits(7)? as usize),
                    };
                    if i + rep > lens.len() {
                        return Err(bad("code lengths overflow"));
                    }
                    lens[i..i + rep].fill(val);
                    i += rep;
                }
                let lit = Huffman::new(&lens[..hlit])?;
                let dist = Huffman::new(&lens[hlit..])?;
                codes(&mut b, &mut out, &lit, &dist)?;
            }
            _ => return Err(bad("reserved block type")),
        }
        if last == 1 {
            break;
        }
    }
    // Bytes fully consumed: whole bytes read minus whole bytes still buffered.
    let consumed = b.pos - (b.n / 8) as usize;
    Ok((out, consumed))
}

fn codes(b: &mut Bits, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman) -> Result<()> {
    loop {
        let sym = lit.decode(b)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let i = (sym - 257) as usize;
                let len = LEN_BASE[i] as usize + b.bits(LEN_EXTRA[i] as u32)? as usize;
                let d = dist.decode(b)? as usize;
                if d >= 30 {
                    return Err(bad("invalid distance code"));
                }
                let dist = DIST_BASE[d] as usize + b.bits(DIST_EXTRA[d] as u32)? as usize;
                if dist > out.len() {
                    return Err(bad("distance before start of output"));
                }
                let start = out.len() - dist;
                for k in 0..len {
                    out.push(out[start + k]);
                }
            }
            _ => return Err(bad("invalid literal/length code")),
        }
    }
}
