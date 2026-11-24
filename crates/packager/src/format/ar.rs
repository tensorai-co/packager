//! `ar` archives in the common format `dpkg-deb` writes for `.deb` files: the `!<arch>` magic,
//! then 60-byte member headers with names of up to 16 bytes (no `/` terminator), each member
//! padded to an even length with `\n`.

use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"!<arch>\n";

/// One member: name, modification time, mode and contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// File name, at most 16 bytes, no spaces or `/`.
    pub name: String,
    /// Modification time (Unix seconds).
    pub mtime: i64,
    /// File mode (`0o100644`).
    pub mode: u32,
    /// Contents.
    pub data: Vec<u8>,
}

impl Member {
    /// A member owned by root with mode `0o100644`, like `dpkg-deb` writes them.
    pub fn new(name: impl Into<String>, mtime: i64, data: Vec<u8>) -> Self {
        Member { name: name.into(), mtime, mode: 0o100644, data }
    }
}

fn field(out: &mut Vec<u8>, s: &str, width: usize) -> Result<()> {
    if s.len() > width {
        return Err(Error::Other(format!("ar: `{s}` doesn't fit a {width}-byte field")));
    }
    out.extend_from_slice(s.as_bytes());
    out.extend(std::iter::repeat_n(b' ', width - s.len()));
    Ok(())
}

/// Writes an archive (uid and gid 0).
pub fn write(members: &[Member]) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    for m in members {
        if m.name.is_empty() || m.name.len() > 16 || m.name.contains(['/', ' ']) {
            return Err(Error::invalid("ar", "name", format!("`{}` must be 1–16 bytes without `/` or spaces", m.name)));
        }
        field(&mut out, &m.name, 16)?;
        field(&mut out, &m.mtime.max(0).to_string(), 12)?;
        field(&mut out, "0", 6)?;
        field(&mut out, "0", 6)?;
        field(&mut out, &format!("{:o}", m.mode), 8)?;
        field(&mut out, &m.data.len().to_string(), 10)?;
        out.extend_from_slice(b"`\n");
        out.extend_from_slice(&m.data);
        if m.data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// Reads an archive. Names written with a trailing `/` (System V style) have it removed.
pub fn read(data: &[u8]) -> Result<Vec<Member>> {
    if !data.starts_with(MAGIC) {
        return Err(Error::malformed("ar", "missing !<arch> magic"));
    }
    let mut out = Vec::new();
    let mut p = MAGIC.len();
    while p < data.len() {
        let h = data.get(p..p + 60).ok_or_else(|| Error::malformed("ar", "truncated header"))?;
        if &h[58..60] != b"`\n" {
            return Err(Error::malformed("ar", format!("bad header terminator at offset {p}")));
        }
        let text = |r: std::ops::Range<usize>| String::from_utf8_lossy(&h[r]).trim().to_string();
        let name = text(0..16);
        let name = name.strip_suffix('/').unwrap_or(&name).to_string();
        let num = |r: std::ops::Range<usize>, radix: u32| -> Result<u64> {
            let s = text(r);
            if s.is_empty() { Ok(0) } else { u64::from_str_radix(&s, radix).map_err(|_| Error::malformed("ar", format!("bad number `{s}`"))) }
        };
        let mtime = num(16..28, 10)? as i64;
        let mode = num(40..48, 8)? as u32;
        let size = num(48..58, 10)? as usize;
        let body = data.get(p + 60..p + 60 + size).ok_or_else(|| Error::malformed("ar", format!("{name}: truncated")))?;
        out.push(Member { name, mtime, mode, data: body.to_vec() });
        p += 60 + size + (size % 2);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_layout() {
        let ms = vec![Member::new("debian-binary", 315_532_800, b"2.0\n".to_vec()), Member::new("control.tar.gz", 315_532_800, vec![1, 2, 3])];
        let a = write(&ms).unwrap();
        assert!(a.starts_with(b"!<arch>\ndebian-binary   315532800   0     0     100644  4         `\n2.0\n"));
        // Odd-sized member padded with a newline.
        assert_eq!(a.len(), 8 + 60 + 4 + 60 + 3 + 1);
        assert_eq!(read(&a).unwrap(), ms);
        assert!(write(&[Member::new("seventeen-chars-x", 0, vec![])]).is_err());
    }
}
