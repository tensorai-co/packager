//! cpio "odc" (POSIX.1 portable ASCII) archives, as used for `.pkg` payloads, plus the file-tree
//! model shared with `Bom` and the disk-image writer.

use std::path::Path;

use crate::error::IoContext;
use crate::util::{slash_path, walk, EntryKind};
use crate::{Error, Result};

/// What a tree entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory.
    Dir,
    /// A regular file and its contents.
    File(Vec<u8>),
    /// A symbolic link and its target.
    Symlink(String),
}

/// One entry of an installable file tree, with ownership and modes as they'll be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Path with `./` prefix and `/` separators (`.` for the root).
    pub path: String,
    /// Kind and contents.
    pub kind: NodeKind,
    /// Permission bits (without file-type bits).
    pub perm: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Modification time (Unix seconds).
    pub mtime: i64,
}

impl Node {
    /// Mode including the file-type bits.
    pub fn mode(&self) -> u32 {
        self.perm
            | match self.kind {
                NodeKind::Dir => 0o040000,
                NodeKind::File(_) => 0o100000,
                NodeKind::Symlink(_) => 0o120000,
            }
    }
    /// Size as archives record it: file length, or link-target length.
    pub fn size(&self) -> usize {
        match &self.kind {
            NodeKind::Dir => 0,
            NodeKind::File(d) => d.len(),
            NodeKind::Symlink(t) => t.len(),
        }
    }
    /// The bytes archives store as the entry's data.
    pub fn data(&self) -> &[u8] {
        match &self.kind {
            NodeKind::Dir => &[],
            NodeKind::File(d) => d,
            NodeKind::Symlink(t) => t.as_bytes(),
        }
    }
    /// The last path component.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// Reads `dir` into a tree rooted at `.`, every entry placed under `prefix` (e.g. `My App.app`),
/// owned by root:wheel (0:0) with normalized modes: 0755 for directories and executables, 0644
/// otherwise. Intermediate directories of `prefix` are included.
pub fn tree_from_dir(dir: &Path, prefix: &str, mtime: i64) -> Result<Vec<Node>> {
    let mk = |path: String, kind: NodeKind, perm: u32| Node { path, kind, perm, uid: 0, gid: 0, mtime };
    let mut out = vec![mk(".".into(), NodeKind::Dir, 0o755)];
    let mut acc = String::from(".");
    for comp in prefix.split('/').filter(|c| !c.is_empty()) {
        acc.push('/');
        acc.push_str(comp);
        out.push(mk(acc.clone(), NodeKind::Dir, 0o755));
    }
    for e in walk(dir)? {
        let path = format!("{acc}/{}", slash_path(&e.rel));
        out.push(match e.kind {
            EntryKind::Dir => mk(path, NodeKind::Dir, 0o755),
            EntryKind::File { executable } => {
                let data = std::fs::read(&e.path).at(&e.path)?;
                mk(path, NodeKind::File(data), if executable { 0o755 } else { 0o644 })
            }
            EntryKind::Symlink(t) => mk(path, NodeKind::Symlink(t.to_string_lossy().into_owned()), 0o755),
        });
    }
    Ok(out)
}

fn octal(out: &mut Vec<u8>, v: u64, width: usize) -> Result<()> {
    let s = format!("{v:0width$o}");
    if s.len() > width {
        return Err(Error::Other(format!("cpio: value {v} doesn't fit in {width} octal digits")));
    }
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Writes an odc archive of `nodes`, in order, ending with `TRAILER!!!`.
pub fn write_odc(nodes: &[Node]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        let name = n.path.as_bytes();
        octal_header(&mut out, i as u64 + 1, n.mode() as u64, n.uid as u64, n.gid as u64, if n.kind == NodeKind::Dir { 2 } else { 1 }, n.mtime.max(0) as u64, name.len() as u64 + 1, n.size() as u64)?;
        out.extend_from_slice(name);
        out.push(0);
        out.extend_from_slice(n.data());
    }
    octal_header(&mut out, 0, 0, 0, 0, 1, 0, 11, 0)?;
    out.extend_from_slice(b"TRAILER!!!\0");
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn octal_header(out: &mut Vec<u8>, ino: u64, mode: u64, uid: u64, gid: u64, nlink: u64, mtime: u64, namesize: u64, filesize: u64) -> Result<()> {
    out.extend_from_slice(b"070707");
    octal(out, 0, 6)?; // dev
    octal(out, ino, 6)?;
    octal(out, mode, 6)?;
    octal(out, uid, 6)?;
    octal(out, gid, 6)?;
    octal(out, nlink, 6)?;
    octal(out, 0, 6)?; // rdev
    octal(out, mtime, 11)?;
    octal(out, namesize, 6)?;
    octal(out, filesize, 11)
}

/// Reads an odc archive back into (path, mode, data) triples.
pub fn read_odc(data: &[u8]) -> Result<Vec<(String, u32, Vec<u8>)>> {
    let bad = |m: &str| Error::malformed("cpio", m);
    let num = |s: &[u8]| -> Result<u64> {
        u64::from_str_radix(std::str::from_utf8(s).map_err(|_| bad("non-ASCII header"))?, 8).map_err(|_| bad("bad octal field"))
    };
    let mut p = 0;
    let mut out = Vec::new();
    loop {
        let h = data.get(p..p + 76).ok_or_else(|| bad("truncated header"))?;
        if &h[..6] != b"070707" {
            return Err(bad("bad magic"));
        }
        let mode = num(&h[18..24])? as u32;
        let namesize = num(&h[59..65])? as usize;
        let filesize = num(&h[65..76])? as usize;
        let name = data.get(p + 76..p + 76 + namesize).ok_or_else(|| bad("truncated name"))?;
        let name = String::from_utf8_lossy(&name[..namesize.saturating_sub(1)]).into_owned();
        let body = data.get(p + 76 + namesize..p + 76 + namesize + filesize).ok_or_else(|| bad("truncated data"))?;
        p += 76 + namesize + filesize;
        if name == "TRAILER!!!" {
            return Ok(out);
        }
        out.push((name, mode, body.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let nodes = vec![
            Node { path: ".".into(), kind: NodeKind::Dir, perm: 0o755, uid: 0, gid: 0, mtime: 0 },
            Node { path: "./a".into(), kind: NodeKind::File(b"hello".to_vec()), perm: 0o644, uid: 0, gid: 0, mtime: 5 },
            Node { path: "./l".into(), kind: NodeKind::Symlink("a".into()), perm: 0o755, uid: 0, gid: 0, mtime: 5 },
        ];
        let back = read_odc(&write_odc(&nodes).unwrap()).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[1], ("./a".into(), 0o100644, b"hello".to_vec()));
        assert_eq!(back[2].1, 0o120755);
    }
}
