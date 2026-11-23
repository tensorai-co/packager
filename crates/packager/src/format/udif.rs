//! UDIF disk images (`.dmg`): a single whole-disk partition split into chunks (zlib, zero-fill
//! or raw), a `blkx` table describing them in an XML resource plist, and the 512-byte `koly`
//! trailer. The layout matches `hdiutil create -layout NONE -format UDZO`.

use crate::compress::{unzlib, zlib, Level};
use crate::crypto::crc::{crc32, Crc32};
use crate::format::plist::{Dict, Value};
use crate::util::{be32, PutBe};
use crate::{Error, Result};

const SECTOR: usize = 512;
const CHUNK_SECTORS: usize = 2048; // 1 MiB, like hdiutil
const CHUNK_ZERO: u32 = 0x0000_0000;
const CHUNK_RAW: u32 = 0x0000_0001;
const CHUNK_ZLIB: u32 = 0x8000_0005;
const CHUNK_END: u32 = 0xffff_ffff;

/// The partition's filesystem, as named in the `blkx` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// Case-sensitive HFS+.
    Hfsx,
    /// HFS+.
    Hfs,
}

impl PartitionType {
    fn name(self) -> &'static str {
        match self {
            PartitionType::Hfsx => "whole disk (Apple_HFSX : 0)",
            PartitionType::Hfs => "whole disk (Apple_HFS : 0)",
        }
    }
}

/// Wraps a raw volume (a multiple of 512 bytes) as a zlib-compressed UDIF image.
pub fn write_udzo(volume: &[u8], ptype: PartitionType, level: Level) -> Result<Vec<u8>> {
    if volume.len() % SECTOR != 0 {
        return Err(Error::Other("udif: volume size isn't a multiple of 512".into()));
    }
    let sectors = volume.len() / SECTOR;
    let mut data = Vec::with_capacity(volume.len() / 3);
    let mut chunks: Vec<(u32, u64, u64, u64, u64)> = Vec::new(); // type, sector, count, offset, length
    let mut buffers_needed = 0usize;
    for (i, chunk) in volume.chunks(CHUNK_SECTORS * SECTOR).enumerate() {
        let sector = (i * CHUNK_SECTORS) as u64;
        let count = (chunk.len() / SECTOR) as u64;
        buffers_needed = buffers_needed.max(count as usize);
        if chunk.iter().all(|&b| b == 0) {
            chunks.push((CHUNK_ZERO, sector, count, data.len() as u64, 0));
            continue;
        }
        let z = zlib(chunk, level);
        let (ty, bytes) = if z.len() < chunk.len() { (CHUNK_ZLIB, z) } else { (CHUNK_RAW, chunk.to_vec()) };
        chunks.push((ty, sector, count, data.len() as u64, bytes.len() as u64));
        data.extend_from_slice(&bytes);
    }
    chunks.push((CHUNK_END, sectors as u64, 0, data.len() as u64, 0));
    let partition_crc = crc32(volume);

    let mut mish = Vec::with_capacity(204 + 40 * chunks.len());
    mish.extend_from_slice(b"mish");
    mish.u32(1);
    mish.u64(0); // first sector
    mish.u64(sectors as u64);
    mish.u64(0); // data offset
    mish.u32(buffers_needed as u32);
    mish.u32(0xffff_fffe); // block descriptor: whole disk
    mish.extend_from_slice(&[0u8; 24]);
    checksum(&mut mish, partition_crc);
    mish.u32(chunks.len() as u32);
    for (ty, sector, count, off, len) in &chunks {
        mish.u32(*ty);
        mish.u32(0);
        mish.u64(*sector);
        mish.u64(*count);
        mish.u64(*off);
        mish.u64(*len);
    }

    let entry = |data: Vec<u8>, name: &str| {
        let mut d = Dict::new().with("Attributes", "0x0050");
        if !name.is_empty() {
            d.insert("CFName", name);
        }
        d.insert("Data", Value::Data(data));
        d.insert("ID", "0");
        d.insert("Name", name);
        Value::Dict(d)
    };
    let resources = Value::Dict(Dict::new().with(
        "resource-fork",
        Dict::new().with("blkx", vec![entry(mish, ptype.name())]).with("plst", vec![entry(vec![0u8; 1032], "")]),
    ));
    let xml = resources.to_xml().into_bytes();

    let xml_offset = data.len() as u64;
    let data_len = data.len() as u64;
    let mut out = data;
    out.extend_from_slice(&xml);
    let mut koly = Vec::with_capacity(512);
    koly.extend_from_slice(b"koly");
    koly.u32(4);
    koly.u32(512);
    koly.u32(1); // flags: flattened
    koly.u64(0); // running data fork offset
    koly.u64(0); // data fork offset
    koly.u64(data_len);
    koly.u64(0); // resource fork offset
    koly.u64(0); // resource fork length
    koly.u32(0); // segment number
    koly.u32(0); // segment count
    koly.extend_from_slice(&[0u8; 16]); // segment ID
    koly.u32(0); // data fork checksum: none (as hdiutil writes)
    koly.u32(0);
    koly.extend_from_slice(&[0u8; 128]);
    koly.u64(xml_offset);
    koly.u64(xml.len() as u64);
    koly.extend_from_slice(&[0u8; 120]);
    let mut master = Crc32::new();
    master.update(&partition_crc.to_be_bytes());
    checksum(&mut koly, master.value());
    koly.u32(2); // image variant
    koly.u64(sectors as u64);
    koly.extend_from_slice(&[0u8; 12]);
    debug_assert_eq!(koly.len(), 512);
    out.extend_from_slice(&koly);
    Ok(out)
}

fn checksum(out: &mut Vec<u8>, crc: u32) {
    out.u32(2); // CRC32
    out.u32(32);
    out.u32(crc);
    out.extend_from_slice(&[0u8; 124]);
}

/// Reads a UDIF image back into its raw volume, checking the partition CRC.
pub fn read(image: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::malformed("udif", m);
    if image.len() < 512 {
        return Err(bad("too short"));
    }
    let k = &image[image.len() - 512..];
    if &k[..4] != b"koly" {
        return Err(bad("missing koly trailer"));
    }
    let u64at = |b: &[u8], p: usize| u64::from_be_bytes(b[p..p + 8].try_into().unwrap_or_default());
    let data_off = u64at(k, 24) as usize;
    let (xml_off, xml_len) = (u64at(k, 216) as usize, u64at(k, 224) as usize);
    let xml = image.get(xml_off..xml_off + xml_len).ok_or_else(|| bad("plist out of range"))?;
    let v = Value::parse(xml)?;
    let blkx = v
        .as_dict()
        .and_then(|d| d.get("resource-fork"))
        .and_then(|r| r.as_dict())
        .and_then(|r| r.get("blkx"))
        .ok_or_else(|| bad("no blkx resource"))?;
    let Value::Array(parts) = blkx else { return Err(bad("blkx isn't an array")) };
    let mut out = Vec::new();
    for p in parts {
        let Some(Value::Data(m)) = p.as_dict().and_then(|d| d.get("Data")) else { return Err(bad("blkx entry without data")) };
        if m.len() < 204 || &m[..4] != b"mish" {
            return Err(bad("bad mish block"));
        }
        let first = u64at(m, 8) as usize * SECTOR;
        let total = u64at(m, 16) as usize * SECTOR;
        let base = u64at(m, 24) as usize + data_off;
        let crc = be32(m, 72);
        let n = be32(m, 200) as usize;
        if out.len() < first + total {
            out.resize(first + total, 0);
        }
        for i in 0..n {
            let c = m.get(204 + 40 * i..244 + 40 * i).ok_or_else(|| bad("truncated chunk table"))?;
            let ty = be32(c, 0);
            let start = first + u64at(c, 8) as usize * SECTOR;
            let len = u64at(c, 16) as usize * SECTOR;
            let (off, clen) = (base + u64at(c, 24) as usize, u64at(c, 32) as usize);
            let src = image.get(off..off + clen).ok_or_else(|| bad("chunk out of range"))?;
            match ty {
                CHUNK_ZERO | 0x0000_0002 | 0x7fff_fffe | CHUNK_END => {}
                CHUNK_RAW => out[start..start + len].copy_from_slice(&src[..len.min(src.len())]),
                CHUNK_ZLIB => {
                    let d = unzlib(src)?;
                    out[start..start + d.len().min(len)].copy_from_slice(&d[..d.len().min(len)]);
                }
                t => return Err(bad(&format!("unsupported chunk type {t:#x}"))),
            }
        }
        if crc32(&out[first..first + total]) != crc {
            return Err(bad("partition CRC32 mismatch"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut vol = vec![0u8; 5 * 1024 * 1024 + 4096];
        for (i, b) in vol.iter_mut().enumerate().skip(1024 * 1024).take(300_000) {
            *b = (i % 251) as u8;
        }
        let img = write_udzo(&vol, PartitionType::Hfsx, Level::FAST).unwrap();
        assert!(img.len() < 200_000);
        assert_eq!(read(&img).unwrap(), vol);
    }
}
