//! ZIP archives (writer): DEFLATE or stored entries with Unix modes and symlinks, like
//! `ditto -c -k --keepParent` makes for notarizing app bundles. No ZIP64 yet (4 GB limit).

use std::path::Path;

use crate::compress::{Level, deflate};
use crate::crypto::crc::crc32;
use crate::util::{EntryKind, slash_path, walk};
use crate::{Error, Result};

/// What an entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipKind {
    /// A directory (`name` ends with `/`).
    Dir,
    /// A regular file.
    File(Vec<u8>),
    /// A symbolic link to this target.
    Symlink(String),
}

/// An entry to archive.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// Path with `/` separators.
    pub name: String,
    /// Kind and contents.
    pub kind: ZipKind,
    /// Unix permission bits (`0o755`…).
    pub mode: u32,
}

fn dos_time(unix: i64) -> (u16, u16) {
    // DOS dates start in 1980; earlier times clamp to 1980-01-01 00:00.
    let days = unix.max(315_532_800).div_euclid(86_400);
    let secs = unix.max(315_532_800).rem_euclid(86_400);
    // Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let time = (((secs / 3600) << 11) | (((secs % 3600) / 60) << 5) | ((secs % 60) / 2)) as u16;
    let date = (((y - 1980).clamp(0, 127) << 9) | (m << 5) | d) as u16;
    (time, date)
}

/// How an entry's data is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Stored as is.
    Stored,
    /// DEFLATE.
    Deflate,
}

/// An entry as written: where its local record starts and how big it is.
#[derive(Debug, Clone)]
pub struct Written {
    /// Name as stored.
    pub name: String,
    /// Offset of the local file header.
    pub offset: usize,
    /// Length of the local file header (30 + name + extra): the block map's `LfhSize`.
    pub header_len: usize,
    /// Uncompressed size.
    pub size: usize,
    /// Stored (compressed) size.
    pub stored_size: usize,
    /// Method used.
    pub method: Method,
}

/// A ZIP writer that keeps local records and the central directory apart, for formats that hash
/// them separately (MSIX).
pub struct ZipWriter {
    out: Vec<u8>,
    central: Vec<u8>,
    entries: Vec<Written>,
    time: u16,
    date: u16,
    utf8: bool,
    zip64_end: bool,
    appx: bool,
}

impl ZipWriter {
    /// A writer stamping entries with `mtime`. `utf8` sets the UTF-8 name flag (MSIX names are
    /// percent-encoded ASCII and leave it off).
    pub fn new(mtime: i64, utf8: bool) -> Self {
        let (time, date) = dos_time(mtime);
        ZipWriter { out: Vec::new(), central: Vec::new(), entries: Vec::new(), time, date, utf8, zip64_end: false, appx: false }
    }

    /// Writes entries the way `makeappx` does, which Windows' APPX reader requires: ZIP64 end
    /// records, "made by" MS-DOS 4.5 with no external attributes, and (for entries added with
    /// [`ZipWriter::add_described`]) version 4.5 with a ZIP64 data descriptor after the data.
    pub fn appx(mut self) -> Self {
        self.appx = true;
        self.zip64_end = true;
        self
    }

    /// Always end with a ZIP64 end record and locator (the classic end record then holds
    /// `0xFFFF…` placeholders), as `makeappx` does and MSIX signatures hash.
    pub fn zip64_end(mut self) -> Self {
        self.zip64_end = true;
        self
    }

    /// Adds an entry. `stored` is the data as it goes in the archive (already compressed for
    /// [`Method::Deflate`]); `data_crc` and `size` describe the uncompressed data.
    pub fn add_raw(&mut self, name: &str, method: Method, stored: &[u8], data_crc: u32, size: usize, unix_mode: u32) -> Result<&Written> {
        self.add_entry(name, method, stored, data_crc, size, unix_mode, false)
    }

    /// [`ZipWriter::add_raw`] with sizes and CRC in a ZIP64 data descriptor after the data
    /// (what `makeappx` does for payload files).
    pub fn add_described(&mut self, name: &str, method: Method, stored: &[u8], data_crc: u32, size: usize) -> Result<&Written> {
        self.add_entry(name, method, stored, data_crc, size, 0, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entry(&mut self, name: &str, method: Method, stored: &[u8], data_crc: u32, size: usize, unix_mode: u32, descriptor: bool) -> Result<&Written> {
        let offset = self.out.len();
        if offset > u32::MAX as usize || stored.len() > u32::MAX as usize || size > u32::MAX as usize {
            return Err(Error::Other("ZIP archives over 4 GB aren't supported yet".into()));
        }
        let m: u16 = if method == Method::Deflate { 8 } else { 0 };
        let flags: u16 = if self.utf8 { 0x0800 } else { 0 } | if descriptor { 0x0008 } else { 0 };
        let needed: u16 = if descriptor { 45 } else { 20 };
        let fields = |h: &mut Vec<u8>, local: bool| {
            h.extend_from_slice(&needed.to_le_bytes());
            h.extend_from_slice(&flags.to_le_bytes());
            h.extend_from_slice(&m.to_le_bytes());
            h.extend_from_slice(&self.time.to_le_bytes());
            h.extend_from_slice(&self.date.to_le_bytes());
            let zeroed = local && descriptor;
            h.extend_from_slice(&(if zeroed { 0 } else { data_crc }).to_le_bytes());
            h.extend_from_slice(&(if zeroed { 0 } else { stored.len() as u32 }).to_le_bytes());
            h.extend_from_slice(&(if zeroed { 0 } else { size as u32 }).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        let mut local = 0x0403_4b50u32.to_le_bytes().to_vec();
        fields(&mut local, true);
        local.extend_from_slice(name.as_bytes());
        let header_len = local.len();
        let mut c = 0x0201_4b50u32.to_le_bytes().to_vec();
        let made_by: u16 = if self.appx { 45 } else { 0x0300 | 20 }; // MS-DOS 4.5, or Unix 2.0
        c.extend_from_slice(&made_by.to_le_bytes());
        fields(&mut c, false);
        c.extend_from_slice(&0u16.to_le_bytes()); // comment
        c.extend_from_slice(&0u16.to_le_bytes()); // disk
        c.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        c.extend_from_slice(&(if self.appx { 0 } else { unix_mode << 16 }).to_le_bytes());
        c.extend_from_slice(&(offset as u32).to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(&local);
        self.out.extend_from_slice(stored);
        if descriptor {
            self.out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            self.out.extend_from_slice(&data_crc.to_le_bytes());
            self.out.extend_from_slice(&(stored.len() as u64).to_le_bytes());
            self.out.extend_from_slice(&(size as u64).to_le_bytes());
        }
        self.central.extend_from_slice(&c);
        self.entries.push(Written { name: name.to_string(), offset, header_len, size, stored_size: stored.len(), method });
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Adds a file, deflating it when `compress` is set and that makes it smaller.
    pub fn add(&mut self, name: &str, data: &[u8], compress: bool, unix_mode: u32) -> Result<&Written> {
        let crc = crc32(data);
        let deflated = (compress && !data.is_empty()).then(|| deflate(data, Level::DEFAULT));
        match deflated {
            Some(d) if d.len() < data.len() => self.add_raw(name, Method::Deflate, &d, crc, data.len(), unix_mode),
            _ => self.add_raw(name, Method::Stored, data, crc, data.len(), unix_mode),
        }
    }

    /// The local records written so far.
    pub fn local_records(&self) -> &[u8] {
        &self.out
    }
    /// The central directory records written so far.
    pub fn central_directory(&self) -> &[u8] {
        &self.central
    }
    /// The entries written so far.
    pub fn entries(&self) -> &[Written] {
        &self.entries
    }

    /// The end-of-central-directory record(s) for the archive as it stands.
    pub fn end_record(&self) -> Result<Vec<u8>> {
        end_records(self.entries.len(), self.central.len(), self.out.len(), self.zip64_end)
    }

    /// The finished archive.
    pub fn finish(self) -> Result<Vec<u8>> {
        let end = self.end_record()?;
        let mut out = self.out;
        out.extend_from_slice(&self.central);
        out.extend_from_slice(&end);
        Ok(out)
    }
}

/// The end records for an archive with `count` entries whose central directory (`cd_len`
/// bytes) starts at `cd_offset`: with `zip64`, a ZIP64 end record and locator before a classic
/// record of placeholders.
pub fn end_records(count: usize, cd_len: usize, cd_offset: usize, zip64: bool) -> Result<Vec<u8>> {
    let mut e = Vec::new();
    if zip64 {
        let z64_at = cd_offset + cd_len;
        e.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        e.extend_from_slice(&44u64.to_le_bytes());
        e.extend_from_slice(&45u16.to_le_bytes()); // made by
        e.extend_from_slice(&45u16.to_le_bytes()); // needed
        e.extend_from_slice(&[0; 8]); // disk numbers
        e.extend_from_slice(&(count as u64).to_le_bytes());
        e.extend_from_slice(&(count as u64).to_le_bytes());
        e.extend_from_slice(&(cd_len as u64).to_le_bytes());
        e.extend_from_slice(&(cd_offset as u64).to_le_bytes());
        e.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&(z64_at as u64).to_le_bytes());
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        e.extend_from_slice(&[0; 4]);
        e.extend_from_slice(&[0xff; 12]); // entries, entries, size, offset
        e.extend_from_slice(&0u16.to_le_bytes());
        return Ok(e);
    }
    if count > 0xffff || cd_offset > u32::MAX as usize {
        return Err(Error::Other("this ZIP needs ZIP64 end records".into()));
    }
    e.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    e.extend_from_slice(&[0; 4]); // disk numbers
    e.extend_from_slice(&(count as u16).to_le_bytes());
    e.extend_from_slice(&(count as u16).to_le_bytes());
    e.extend_from_slice(&(cd_len as u32).to_le_bytes());
    e.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    Ok(e)
}

/// Writes a ZIP archive. File data is DEFLATE-compressed unless that doesn't help.
pub fn write(entries: &[ZipEntry], mtime: i64) -> Result<Vec<u8>> {
    let mut w = ZipWriter::new(mtime, true);
    for e in entries {
        match &e.kind {
            ZipKind::Dir => {
                let name = if e.name.ends_with('/') { e.name.clone() } else { format!("{}/", e.name) };
                w.add_raw(&name, Method::Stored, &[], 0, 0, 0o040000 | (e.mode & 0o7777))?;
            }
            ZipKind::File(d) => {
                w.add(&e.name, d, true, 0o100000 | (e.mode & 0o7777))?;
            }
            ZipKind::Symlink(t) => {
                w.add_raw(&e.name, Method::Stored, t.as_bytes(), crc32(t.as_bytes()), t.len(), 0o120000 | (e.mode & 0o7777))?;
            }
        }
    }
    w.finish()
}

/// Archives a directory under its own name (`My.app/…`), keeping symlinks and executable bits.
pub fn from_dir(dir: &Path, mtime: i64) -> Result<Vec<u8>> {
    use crate::error::IoContext;
    let top = dir.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::invalid("zip", dir.display().to_string(), "has no name"))?;
    let mut entries = vec![ZipEntry { name: format!("{top}/"), kind: ZipKind::Dir, mode: 0o755 }];
    for e in walk(dir)? {
        let name = format!("{top}/{}", slash_path(&e.rel));
        entries.push(match e.kind {
            EntryKind::Dir => ZipEntry { name: format!("{name}/"), kind: ZipKind::Dir, mode: 0o755 },
            EntryKind::Symlink(t) => ZipEntry { name, kind: ZipKind::Symlink(t.to_string_lossy().into_owned()), mode: 0o755 },
            EntryKind::File { executable } => ZipEntry { name, kind: ZipKind::File(std::fs::read(&e.path).at(&e.path)?), mode: if executable { 0o755 } else { 0o644 } },
        });
    }
    write(&entries, mtime)
}

/// An entry found by [`read_entries`].
#[derive(Debug, Clone)]
pub struct ReadEntry {
    /// Name as stored.
    pub name: String,
    /// Offset of the local file header.
    pub offset: usize,
    /// Length of the local file header.
    pub header_len: usize,
    /// Method.
    pub method: Method,
    /// Stored (compressed) size.
    pub stored_size: usize,
    /// Uncompressed size.
    pub size: usize,
    /// CRC-32 of the uncompressed data.
    pub crc: u32,
    /// Offset of the central directory record.
    pub central_offset: usize,
    /// Length of the central directory record.
    pub central_len: usize,
}

/// Lists an archive's entries from its central directory (no ZIP64 yet), returning them with
/// the central directory's offset.
pub fn read_entries(data: &[u8]) -> Result<(Vec<ReadEntry>, usize)> {
    let bad = |m: &str| Error::malformed("zip", m);
    let le16 = |p: usize| data.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize).ok_or_else(|| bad("truncated"));
    let le32 = |p: usize| data.get(p..p + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize).ok_or_else(|| bad("truncated"));
    let min = data.len().saturating_sub(22 + 0xffff);
    let eocd = (min..=data.len().saturating_sub(22)).rev().find(|&i| data[i..i + 4] == [0x50, 0x4b, 0x05, 0x06]).ok_or_else(|| bad("no end of central directory"))?;
    let le64 = |p: usize| data.get(p..p + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()) as usize).ok_or_else(|| bad("truncated"));
    let (mut count, mut cd_off) = (le16(eocd + 10)?, le32(eocd + 16)?);
    if eocd >= 20 && le32(eocd - 20)? == 0x0706_4b50 {
        let z = le64(eocd - 20 + 8)?;
        if le32(z)? != 0x0606_4b50 {
            return Err(bad("bad ZIP64 end record"));
        }
        count = le64(z + 32)?;
        cd_off = le64(z + 48)?;
    } else if count == 0xffff || cd_off == 0xffff_ffff {
        return Err(bad("ZIP64 placeholders without a ZIP64 locator"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = cd_off;
    for _ in 0..count {
        if le32(p)? != 0x0201_4b50 {
            return Err(bad("bad central directory record"));
        }
        let method = match le16(p + 10)? {
            0 => Method::Stored,
            8 => Method::Deflate,
            m => return Err(bad(&format!("unsupported compression method {m}"))),
        };
        let (crc, mut stored_size, mut size) = (le32(p + 16)? as u32, le32(p + 20)?, le32(p + 24)?);
        let (nl, xl, cl) = (le16(p + 28)?, le16(p + 30)?, le16(p + 32)?);
        let mut offset = le32(p + 42)?;
        // ZIP64 extended information: the 0xFFFFFFFF fields, in order.
        let mut x = p + 46 + nl;
        while x + 4 <= p + 46 + nl + xl {
            let (id, len) = (le16(x)?, le16(x + 2)?);
            if id == 1 {
                let mut q = x + 4;
                for f in [&mut size, &mut stored_size, &mut offset] {
                    if *f == 0xffff_ffff {
                        *f = le64(q)?;
                        q += 8;
                    }
                }
            }
            x += 4 + len;
        }
        let name = String::from_utf8_lossy(data.get(p + 46..p + 46 + nl).ok_or_else(|| bad("truncated name"))?).into_owned();
        if le32(offset)? != 0x0403_4b50 {
            return Err(bad("bad local file header"));
        }
        let header_len = 30 + le16(offset + 26)? + le16(offset + 28)?;
        out.push(ReadEntry { name, offset, header_len, method, stored_size, size, crc, central_offset: p, central_len: 46 + nl + xl + cl });
        p += 46 + nl + xl + cl;
    }
    Ok((out, cd_off))
}

/// An entry's uncompressed data, checking its CRC.
pub fn entry_data(data: &[u8], e: &ReadEntry) -> Result<Vec<u8>> {
    let start = e.offset + e.header_len;
    let stored = data.get(start..start + e.stored_size).ok_or_else(|| Error::malformed("zip", "entry out of range"))?;
    let out = match e.method {
        Method::Stored => stored.to_vec(),
        Method::Deflate => crate::compress::inflate(stored)?.0,
    };
    if crc32(&out) != e.crc {
        return Err(Error::malformed("zip", format!("{}: CRC mismatch", e.name)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structure() {
        let z = write(
            &[
                ZipEntry { name: "a/".into(), kind: ZipKind::Dir, mode: 0o755 },
                ZipEntry { name: "a/x".into(), kind: ZipKind::File(vec![b'x'; 5000]), mode: 0o755 },
                ZipEntry { name: "a/l".into(), kind: ZipKind::Symlink("x".into()), mode: 0o755 },
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(&z[..4], b"PK\x03\x04");
        let eocd = &z[z.len() - 22..];
        assert_eq!(&eocd[..4], b"PK\x05\x06");
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 3);
        assert!(z.len() < 5000, "the repetitive file is deflated");
        assert_eq!(dos_time(315_532_800), (0, 1 << 5 | 1));
    }
}
