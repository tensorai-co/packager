//! Cabinet files (MS-CAB), as embedded in `.msi` packages: one folder, MSZIP-compressed in
//! 32 KB blocks (`CK` + a DEFLATE stream each), with CFDATA checksums.
//!
//! Each block is compressed on its own, which every MSZIP decoder accepts (they keep the
//! previous block as history, but nothing here refers back to it).

use crate::compress::{Level, deflate};
use crate::{Error, Result};

const BLOCK: usize = 32 * 1024;

/// A file to put in a cabinet.
#[derive(Debug, Clone)]
pub struct CabFile {
    /// Name in the cabinet (for MSI: the `File` table key).
    pub name: String,
    /// Contents.
    pub data: Vec<u8>,
}

/// The CFDATA checksum (MS-CAB `CSUMCompute`).
fn checksum(data: &[u8], seed: u32) -> u32 {
    let mut csum = seed;
    let (words, rest) = data.as_chunks::<4>();
    for c in words {
        csum ^= u32::from_le_bytes(*c);
    }
    let mut ul = 0u32;
    for &b in rest {
        ul = (ul << 8) | u32::from(b);
    }
    csum ^ ul
}

fn dos_time(unix: i64) -> (u16, u16) {
    let days = unix.max(315_532_800).div_euclid(86_400);
    let secs = unix.max(315_532_800).rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (((y - 1980).clamp(0, 127) << 9 | m << 5 | d) as u16, (((secs / 3600) << 11) | (((secs % 3600) / 60) << 5) | ((secs % 60) / 2)) as u16)
}

/// Writes a cabinet holding `files` in order.
pub fn write(files: &[CabFile], mtime: i64) -> Result<Vec<u8>> {
    if files.len() > 0xffff {
        return Err(Error::Other("a cabinet holds at most 65535 files".into()));
    }
    let total: usize = files.iter().map(|f| f.data.len()).sum();
    if total > u32::MAX as usize {
        return Err(Error::Other("cabinets over 4 GB aren't supported (multiple cabinets aren't implemented yet)".into()));
    }
    let (date, time) = dos_time(mtime);
    // The folder's uncompressed stream, in blocks.
    let mut folder = Vec::with_capacity(total);
    for f in files {
        folder.extend_from_slice(&f.data);
    }
    let mut blocks = Vec::new();
    for chunk in folder.chunks(BLOCK) {
        let mut b = b"CK".to_vec();
        b.extend_from_slice(&deflate(chunk, Level::DEFAULT));
        let mut hdr = [0u8; 8];
        hdr[4..6].copy_from_slice(&(b.len() as u16).to_le_bytes());
        hdr[6..8].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
        let c = checksum(&hdr[4..8], checksum(&b, 0));
        hdr[..4].copy_from_slice(&c.to_le_bytes());
        blocks.push((hdr, b));
    }
    if blocks.len() > 0xffff {
        return Err(Error::Other("cabinet folder too large".into()));
    }
    let mut entries = Vec::new();
    let mut off = 0u32;
    for f in files {
        let utf = !f.name.is_ascii();
        let mut e = Vec::new();
        e.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes()); // folder 0
        e.extend_from_slice(&date.to_le_bytes());
        e.extend_from_slice(&time.to_le_bytes());
        e.extend_from_slice(&(0x20u16 | if utf { 0x80 } else { 0 }).to_le_bytes()); // archive, UTF-8 name
        e.extend_from_slice(f.name.as_bytes());
        e.push(0);
        entries.extend_from_slice(&e);
        off += f.data.len() as u32;
    }
    let coff_files = 36 + 8;
    let coff_data = coff_files + entries.len();
    let size = coff_data + blocks.iter().map(|(h, b)| h.len() + b.len()).sum::<usize>();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(coff_files as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]); // version 1.3
    out.extend_from_slice(&1u16.to_le_bytes()); // folders
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // set id
    out.extend_from_slice(&0u16.to_le_bytes()); // cabinet number
    out.extend_from_slice(&(coff_data as u32).to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u16).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // MSZIP
    out.extend_from_slice(&entries);
    for (h, b) in &blocks {
        out.extend_from_slice(h);
        out.extend_from_slice(b);
    }
    Ok(out)
}

/// Reads a cabinet written by [`write()`] (one MSZIP folder of independent blocks): the files.
pub fn read(data: &[u8]) -> Result<Vec<CabFile>> {
    let bad = |m: &str| Error::malformed("cab", m);
    let le16 = |p: usize| data.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize).ok_or_else(|| bad("truncated"));
    let le32 = |p: usize| data.get(p..p + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize).ok_or_else(|| bad("truncated"));
    if data.get(..4) != Some(b"MSCF") {
        return Err(bad("not a cabinet"));
    }
    let (coff_files, n_folders, n_files) = (le32(16)?, le16(26)?, le16(28)?);
    if n_folders != 1 || le16(30)? != 0 {
        return Err(bad("only single-folder cabinets without reserved areas are supported"));
    }
    let (data_off, n_blocks, comp) = (le32(36)?, le16(40)?, le16(42)?);
    let mut folder = Vec::new();
    let mut p = data_off;
    for _ in 0..n_blocks {
        let (c, u) = (le16(p + 4)?, le16(p + 6)?);
        let b = data.get(p + 8..p + 8 + c).ok_or_else(|| bad("block out of range"))?;
        let stored = le32(p)? as u32;
        if stored != 0 && stored != checksum(&data[p + 4..p + 8], checksum(b, 0)) {
            return Err(bad("block checksum mismatch"));
        }
        let out = match comp & 0xf {
            0 => b.to_vec(),
            1 => crate::compress::inflate(b.strip_prefix(b"CK").ok_or_else(|| bad("MSZIP block without CK"))?)?.0,
            _ => return Err(bad("unsupported compression")),
        };
        if out.len() != u {
            return Err(bad("block size mismatch"));
        }
        folder.extend_from_slice(&out);
        p += 8 + c;
    }
    let mut files = Vec::new();
    let mut q = coff_files;
    for _ in 0..n_files {
        let (size, off) = (le32(q)?, le32(q + 4)?);
        let end = data[q + 16..].iter().position(|&b| b == 0).ok_or_else(|| bad("unterminated name"))?;
        let name = String::from_utf8_lossy(&data[q + 16..q + 16 + end]).into_owned();
        files.push(CabFile { name, data: folder.get(off..off + size).ok_or_else(|| bad("file out of range"))?.to_vec() });
        q += 16 + end + 1;
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let files = vec![
            CabFile { name: "a".into(), data: b"hello".to_vec() },
            CabFile { name: "big".into(), data: (0..100_000u32).map(|i| (i % 7) as u8).collect() },
            CabFile { name: "empty".into(), data: Vec::new() },
            CabFile { name: "rand".into(), data: (0..70_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect() },
        ];
        let cab = write(&files, 1_700_000_000).unwrap();
        let back = read(&cab).unwrap();
        for (a, b) in files.iter().zip(&back) {
            assert_eq!((a.name.as_str(), &a.data), (b.name.as_str(), &b.data));
        }
        assert_eq!(checksum(&[1, 2, 3, 4, 5], 0), 0x0403_0201 ^ 5);
    }
}
