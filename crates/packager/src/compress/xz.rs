//! The `.xz` container (one stream, one block, the LZMA2 filter), as `xz`, `dpkg` and the Linux
//! kernel's SquashFS driver read it.

use super::lzma::{self, Options, dict_size_byte, dict_size_from_byte};
use crate::crypto::crc::crc32;
use crate::{Error, Result};

const MAGIC: &[u8; 6] = b"\xFD7zXZ\0";
const FOOTER_MAGIC: &[u8; 2] = b"YZ";

/// The integrity check stored after the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// None.
    None,
    /// CRC-32: what SquashFS images use (the kernel's decoder always supports it).
    Crc32,
    /// CRC-64: `xz`'s default.
    Crc64,
}

impl Check {
    fn id(self) -> u8 {
        match self {
            Check::None => 0,
            Check::Crc32 => 1,
            Check::Crc64 => 4,
        }
    }
    fn compute(self, data: &[u8]) -> Vec<u8> {
        match self {
            Check::None => Vec::new(),
            Check::Crc32 => crc32(data).to_le_bytes().to_vec(),
            Check::Crc64 => crc64(data).to_le_bytes().to_vec(),
        }
    }
}

/// CRC-64/XZ (ECMA-182 polynomial, reflected).
pub fn crc64(data: &[u8]) -> u64 {
    static TABLE: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u64;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xC96C_5795_D787_0F42 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    let mut c = !0u64;
    for &b in data {
        c = t[((c ^ u64::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint(data: &[u8], p: &mut usize) -> Result<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let b = *data.get(*p).ok_or_else(|| Error::malformed("xz", "truncated number"))?;
        *p += 1;
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(Error::malformed("xz", "number too long"))
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Compresses `data` into an `.xz` stream with a CRC-64 check, like `xz` does.
pub fn xz(data: &[u8], opts: &Options) -> Vec<u8> {
    xz_with(data, opts, Check::Crc64)
}

/// Compresses `data` into an `.xz` stream with the given check. The dictionary is capped at the
/// input size (rounded up to an encodable size), so small inputs need little memory to decode.
pub fn xz_with(data: &[u8], opts: &Options, check: Check) -> Vec<u8> {
    let (dict_byte, dict) = dict_size_byte(opts.dict_size.min(data.len().max(4096).min(u32::MAX as usize) as u32));
    let opts = opts.dict_size(dict);
    let flags = [0u8, check.id()];
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&flags);
    out.extend_from_slice(&crc32(&flags).to_le_bytes());

    let mut records = Vec::new();
    if !data.is_empty() {
        let block_start = out.len();
        // Block header: size, flags (one filter, no size fields), LZMA2 with its dictionary byte.
        let mut hdr = vec![0u8, 0x00, 0x21, 0x01, dict_byte];
        pad4(&mut hdr);
        hdr[0] = ((hdr.len() + 4) / 4 - 1) as u8;
        let hcrc = crc32(&hdr);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&hcrc.to_le_bytes());
        let payload = lzma::lzma2_encode(data, &opts);
        out.extend_from_slice(&payload);
        let unpadded = (out.len() - block_start) as u64 + check.compute(&[]).len() as u64;
        pad4(&mut out);
        out.extend_from_slice(&check.compute(data));
        records.push((unpadded, data.len() as u64));
    }

    let index_start = out.len();
    out.push(0);
    varint(&mut out, records.len() as u64);
    for (unpadded, size) in &records {
        varint(&mut out, *unpadded);
        varint(&mut out, *size);
    }
    pad4(&mut out);
    let icrc = crc32(&out[index_start..]);
    out.extend_from_slice(&icrc.to_le_bytes());
    let index_size = out.len() - index_start;

    let mut footer = ((index_size / 4 - 1) as u32).to_le_bytes().to_vec();
    footer.extend_from_slice(&flags);
    out.extend_from_slice(&crc32(&footer).to_le_bytes());
    out.extend_from_slice(&footer);
    out.extend_from_slice(FOOTER_MAGIC);
    out
}

/// Decompresses a single `.xz` stream (any number of LZMA2 blocks; checks none, CRC-32, CRC-64
/// or SHA-256). `max_out` bounds the output size.
pub fn unxz(data: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::malformed("xz", m);
    if data.len() < 32 || !data.starts_with(MAGIC) {
        return Err(bad("missing magic"));
    }
    let flags = &data[6..8];
    if crc32(flags).to_le_bytes() != data[8..12] {
        return Err(bad("stream header CRC mismatch"));
    }
    if flags[0] != 0 || flags[1] > 15 {
        return Err(bad("unsupported stream flags"));
    }
    let check_len = match flags[1] {
        0 => 0,
        1..=3 => 4,
        4..=6 => 8,
        7..=9 => 16,
        10..=12 => 32,
        _ => 64,
    };
    let mut p = 12;
    let mut out = Vec::new();
    let mut records = Vec::new();
    loop {
        let size_byte = *data.get(p).ok_or_else(|| bad("truncated"))?;
        if size_byte == 0 {
            break;
        }
        let block_start = p;
        let hsize = (usize::from(size_byte) + 1) * 4;
        let hdr = data.get(p..p + hsize).ok_or_else(|| bad("truncated block header"))?;
        if crc32(&hdr[..hsize - 4]).to_le_bytes() != hdr[hsize - 4..] {
            return Err(bad("block header CRC mismatch"));
        }
        let bflags = hdr[1];
        if bflags & 0x3C != 0 {
            return Err(bad("reserved block flags set"));
        }
        let mut q = 2;
        if bflags & 0x40 != 0 {
            read_varint(hdr, &mut q)?;
        }
        if bflags & 0x80 != 0 {
            read_varint(hdr, &mut q)?;
        }
        let filters = usize::from(bflags & 3) + 1;
        if filters != 1 {
            return Err(bad("only the LZMA2 filter alone is supported"));
        }
        let id = read_varint(hdr, &mut q)?;
        let psize = read_varint(hdr, &mut q)?;
        if id != 0x21 || psize != 1 {
            return Err(bad("only the LZMA2 filter alone is supported"));
        }
        dict_size_from_byte(*hdr.get(q).ok_or_else(|| bad("truncated filter"))?)?;
        p += hsize;
        let start_len = out.len();
        let (block, used) = lzma::lzma2_decode(&data[p..], max_out.saturating_sub(out.len()))?;
        out.extend_from_slice(&block);
        p += used;
        let unpadded = (p - block_start + check_len) as u64;
        while p % 4 != 0 {
            if *data.get(p).ok_or_else(|| bad("truncated"))? != 0 {
                return Err(bad("nonzero block padding"));
            }
            p += 1;
        }
        let stored = data.get(p..p + check_len).ok_or_else(|| bad("truncated check"))?;
        let produced = &out[start_len..];
        let ok = match flags[1] {
            0 => true,
            1 => crc32(produced).to_le_bytes() == stored,
            4 => crc64(produced).to_le_bytes() == stored,
            10 => crate::crypto::sha256(produced) == stored,
            _ => true,
        };
        if !ok {
            return Err(bad("integrity check failed"));
        }
        p += check_len;
        records.push((unpadded, produced.len() as u64));
    }
    // Index.
    let index_start = p;
    p += 1;
    let n = read_varint(data, &mut p)?;
    if n != records.len() as u64 {
        return Err(bad("index doesn't match the blocks"));
    }
    for (unpadded, size) in &records {
        if read_varint(data, &mut p)? != *unpadded || read_varint(data, &mut p)? != *size {
            return Err(bad("index doesn't match the blocks"));
        }
    }
    while (p - index_start) % 4 != 0 {
        p += 1;
    }
    let icrc = data.get(p..p + 4).ok_or_else(|| bad("truncated index"))?;
    if crc32(&data[index_start..p]).to_le_bytes() != icrc {
        return Err(bad("index CRC mismatch"));
    }
    p += 4;
    let footer = data.get(p..p + 12).ok_or_else(|| bad("truncated footer"))?;
    if &footer[10..12] != FOOTER_MAGIC || footer[8..10] != *flags || crc32(&footer[4..10]).to_le_bytes() != footer[..4] {
        return Err(bad("bad stream footer"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc64_vector() {
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn round_trips() {
        for n in [0usize, 1, 1000, 131_072, 300_000] {
            let d = crate::compress::lzma::tests_sample(n);
            for check in [Check::None, Check::Crc32, Check::Crc64] {
                let x = xz_with(&d, &Options::DEFAULT, check);
                assert_eq!(x.len() % 4, 0);
                assert_eq!(unxz(&x, usize::MAX).unwrap(), d, "n={n} {check:?}");
            }
        }
        // A one-byte change is caught.
        let mut x = xz(b"hello hello hello hello", &Options::DEFAULT);
        let n = x.len();
        x[n - 20] ^= 1;
        assert!(unxz(&x, usize::MAX).is_err());
    }
}
