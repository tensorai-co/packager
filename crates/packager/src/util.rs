//! Small shared helpers: timestamps, byte writing, filesystem walking.

use std::path::{Path, PathBuf};

use crate::error::IoContext;
use crate::Result;

/// The timestamp every package uses: `SOURCE_DATE_EPOCH` when set, else 1980-01-01, so the same
/// input gives byte-identical output.
pub fn source_date_epoch() -> i64 {
    std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(315_532_800)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `secs` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", t / 3600, t / 60 % 60, t % 60)
}

/// `secs` since the Unix epoch as an RFC 2822 date (`Tue, 01 Jan 1980 00:00:00 +0000`), as
/// Debian changelogs write them.
pub fn rfc2822(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][m as usize - 1];
    let t = secs.rem_euclid(86_400);
    format!("{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} +0000", t / 3600, t / 60 % 60, t % 60)
}

/// Big-endian appends.
pub(crate) trait PutBe {
    fn u8(&mut self, v: u8);
    fn u16(&mut self, v: u16);
    fn u32(&mut self, v: u32);
    fn u64(&mut self, v: u64);
}

impl PutBe for Vec<u8> {
    fn u8(&mut self, v: u8) {
        self.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_be_bytes());
    }
}

pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub(crate) fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}
pub(crate) fn put_le32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_le64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// What a directory entry is, without following symlinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory.
    Dir,
    /// A regular file, with its permission bits.
    File {
        /// Whether any execute bit is set.
        executable: bool,
    },
    /// A symbolic link and its target, as stored.
    Symlink(PathBuf),
}

/// One entry of a tree walk.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Path relative to the walk root, `/`-separated components.
    pub rel: PathBuf,
    /// The full path on disk.
    pub path: PathBuf,
    /// Kind.
    pub kind: EntryKind,
}

/// Walks `root` depth first with entries sorted by name (byte order), so every consumer sees the
/// same deterministic order. The root itself isn't included.
pub fn walk(root: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    walk_into(root, Path::new(""), &mut out)?;
    Ok(out)
}

fn walk_into(dir: &Path, rel: &Path, out: &mut Vec<Entry>) -> Result<()> {
    let mut names: Vec<_> = std::fs::read_dir(dir).at(dir)?.map(|e| e.map(|e| e.file_name())).collect::<Result<_, _>>().at(dir)?;
    names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
    for name in names {
        let path = dir.join(&name);
        let rel = rel.join(&name);
        let meta = std::fs::symlink_metadata(&path).at(&path)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(&path).at(&path)?;
            out.push(Entry { rel, path, kind: EntryKind::Symlink(target) });
        } else if ft.is_dir() {
            out.push(Entry { rel: rel.clone(), path: path.clone(), kind: EntryKind::Dir });
            walk_into(&path, &rel, out)?;
        } else if ft.is_file() {
            out.push(Entry { rel, path, kind: EntryKind::File { executable: is_executable(&meta) } });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Sets a file's mode on Unix; a no-op elsewhere (the containers store modes themselves).
pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).at(path)?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Creates a symlink on Unix. On other hosts symlinks only exist inside the containers.
pub fn symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).at(link)?;
    #[cfg(not(unix))]
    let _ = (target, link);
    Ok(())
}

/// Copies a tree, preserving symlinks and the executable bit, and never copying extended
/// attributes or resource forks (they break code signatures).
pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src).at(src)?;
    if meta.is_file() {
        return copy_file(src, dst, is_executable(&meta));
    }
    std::fs::create_dir_all(dst).at(dst)?;
    for e in walk(src)? {
        let to = dst.join(&e.rel);
        match &e.kind {
            EntryKind::Dir => std::fs::create_dir_all(&to).at(&to)?,
            EntryKind::File { executable } => copy_file(&e.path, &to, *executable)?,
            EntryKind::Symlink(t) => symlink(t, &to)?,
        }
    }
    Ok(())
}

/// Copies file contents only (not `fs::copy`, which clones extended attributes on macOS).
pub fn copy_file(src: &Path, dst: &Path, executable: bool) -> Result<()> {
    let data = std::fs::read(src).at(src)?;
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p).at(p)?;
    }
    std::fs::write(dst, data).at(dst)?;
    set_mode(dst, if executable { 0o755 } else { 0o644 })
}

/// `rel` as a `/`-separated string.
pub fn slash_path(rel: &Path) -> String {
    rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso8601(315_532_800), "1980-01-01T00:00:00Z");
        assert_eq!(super::iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(super::rfc2822(315_532_800), "Tue, 01 Jan 1980 00:00:00 +0000");
        assert_eq!(super::rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
    }
}
