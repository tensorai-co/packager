//! DEFLATE plus the zlib (RFC 1950) and gzip (RFC 1952) framings.

pub mod deflate;
pub mod inflate;

pub use deflate::{deflate, Level};
pub use inflate::inflate;

use crate::crypto::crc::{adler32, crc32};
use crate::{Error, Result};

/// zlib-framed DEFLATE.
pub fn zlib(data: &[u8], level: Level) -> Vec<u8> {
    let mut w = deflate::BitWriter::new(vec![0x78, 0xDA]);
    deflate::deflate_into(&mut w, data, level);
    let mut out = w.finish();
    out.extend_from_slice(&adler32(1, data).to_be_bytes());
    out
}

/// Decodes a zlib stream, checking its Adler-32.
pub fn unzlib(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 6 || (u16::from_be_bytes([data[0], data[1]]) % 31 != 0) || data[0] & 0x0f != 8 {
        return Err(Error::malformed("zlib", "bad header"));
    }
    if data[1] & 0x20 != 0 {
        return Err(Error::malformed("zlib", "preset dictionaries are not supported"));
    }
    let (out, used) = inflate(&data[2..])?;
    let tail = data.get(2 + used..2 + used + 4).ok_or_else(|| Error::malformed("zlib", "missing checksum"))?;
    if u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) != adler32(1, &out) {
        return Err(Error::malformed("zlib", "Adler-32 mismatch"));
    }
    Ok(out)
}

/// gzip-framed DEFLATE with a zero modification time and no file name, so output is deterministic.
pub fn gzip(data: &[u8], level: Level) -> Vec<u8> {
    let xfl = if level == Level::BEST { 2 } else { 0 };
    // OS byte 3 (Unix), like gzip on every Unix.
    let mut w = deflate::BitWriter::new(vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 3]);
    deflate::deflate_into(&mut w, data, level);
    let mut out = w.finish();
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Decodes a single-member gzip stream, checking its CRC-32 and size.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::malformed("gzip", m);
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err(bad("bad header"));
    }
    let flags = data[3];
    let mut p = 10;
    if flags & 4 != 0 {
        let xlen = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
        p += 2 + xlen;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            while *data.get(p).ok_or_else(|| bad("truncated header"))? != 0 {
                p += 1;
            }
            p += 1;
        }
    }
    if flags & 2 != 0 {
        p += 2;
    }
    let (out, used) = inflate(data.get(p..).ok_or_else(|| bad("truncated header"))?)?;
    let t = data.get(p + used..p + used + 8).ok_or_else(|| bad("missing trailer"))?;
    if u32::from_le_bytes([t[0], t[1], t[2], t[3]]) != crc32(&out) {
        return Err(bad("CRC-32 mismatch"));
    }
    if u32::from_le_bytes([t[4], t[5], t[6], t[7]]) != out.len() as u32 {
        return Err(bad("size mismatch"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        let words: [&[u8]; 6] = [b"apple ", b"banana ", b"cherry ", b"\x00\x00\x00\x00", b"zz", b"Contents/MacOS/"];
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            if x >> 28 < 3 {
                out.push((x >> 16) as u8);
            } else {
                out.extend_from_slice(words[(x >> 20) as usize % words.len()]);
            }
        }
        out.truncate(n);
        out
    }

    #[test]
    fn round_trips() {
        for &n in &[0usize, 1, 2, 3, 100, 65535, 65536, 70_000, 300_000] {
            for level in [Level::STORE, Level::FAST, Level::DEFAULT, Level::BEST] {
                let d = sample(n, n as u32 + 7);
                let c = deflate(&d, level);
                let (back, used) = inflate(&c).unwrap();
                assert_eq!(back, d, "n={n} level={level:?}");
                assert_eq!(used, c.len());
                assert_eq!(unzlib(&zlib(&d, level)).unwrap(), d);
                assert_eq!(gunzip(&gzip(&d, level)).unwrap(), d);
            }
        }
    }

    #[test]
    fn compresses() {
        let d = sample(200_000, 1);
        let c = deflate(&d, Level::DEFAULT);
        assert!(c.len() < d.len() / 3, "{} -> {}", d.len(), c.len());
        let zeros = vec![0u8; 1 << 20];
        assert!(deflate(&zeros, Level::DEFAULT).len() < 2000);
        // Random data falls back to stored blocks with little overhead.
        let mut x = 1u32;
        let rnd: Vec<u8> = (0..100_000).map(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; x as u8 }).collect();
        assert!(deflate(&rnd, Level::DEFAULT).len() < rnd.len() + 100);
    }
}
