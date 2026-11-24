//! ZIP archives (writer): DEFLATE or stored entries with Unix modes and symlinks, like
//! `ditto -c -k --keepParent` makes for notarizing app bundles. No ZIP64 yet (4 GB limit).

use std::path::Path;

use crate::compress::{deflate, Level};
use crate::crypto::crc::crc32;
use crate::util::{slash_path, walk, EntryKind};
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

/// Writes a ZIP archive. File data is DEFLATE-compressed unless that doesn't help.
pub fn write(entries: &[ZipEntry], mtime: i64) -> Result<Vec<u8>> {
    let (time, date) = dos_time(mtime);
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let (type_bits, data): (u32, &[u8]) = match &e.kind {
            ZipKind::Dir => (0o040000, &[]),
            ZipKind::File(d) => (0o100000, d),
            ZipKind::Symlink(t) => (0o120000, t.as_bytes()),
        };
        let name = match e.kind {
            ZipKind::Dir if !e.name.ends_with('/') => format!("{}/", e.name),
            _ => e.name.clone(),
        };
        let crc = crc32(data);
        let compressed = if matches!(e.kind, ZipKind::File(_)) && !data.is_empty() { Some(deflate(data, Level::DEFAULT)) } else { None };
        let (method, stored): (u16, &[u8]) = match &compressed {
            Some(c) if c.len() < data.len() => (8, c),
            _ => (0, data),
        };
        let offset = out.len();
        if offset > u32::MAX as usize || stored.len() > u32::MAX as usize {
            return Err(Error::Other("ZIP archives over 4 GB aren't supported yet".into()));
        }
        let flags: u16 = 0x0800; // names are UTF-8
        let header = |sig: u32, central_dir: bool| {
            let mut h = Vec::with_capacity(46 + name.len());
            h.extend_from_slice(&sig.to_le_bytes());
            if central_dir {
                h.extend_from_slice(&(0x0300u16 | 20).to_le_bytes()); // made by Unix, spec 2.0
            }
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&flags.to_le_bytes());
            h.extend_from_slice(&method.to_le_bytes());
            h.extend_from_slice(&time.to_le_bytes());
            h.extend_from_slice(&date.to_le_bytes());
            h.extend_from_slice(&crc.to_le_bytes());
            h.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central_dir {
                h.extend_from_slice(&0u16.to_le_bytes()); // comment
                h.extend_from_slice(&0u16.to_le_bytes()); // disk
                h.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
                h.extend_from_slice(&((type_bits | (e.mode & 0o7777)) << 16).to_le_bytes());
                h.extend_from_slice(&(offset as u32).to_le_bytes());
            }
            h.extend_from_slice(name.as_bytes());
            h
        };
        out.extend_from_slice(&header(0x0403_4b50, false));
        out.extend_from_slice(stored);
        central.extend_from_slice(&header(0x0201_4b50, true));
    }
    let cd_offset = out.len();
    if entries.len() > 0xffff {
        return Err(Error::Other("ZIP archives with over 65535 entries aren't supported yet".into()));
    }
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // disk numbers
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
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
