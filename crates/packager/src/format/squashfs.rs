//! SquashFS 4.0 images, the filesystem inside every `.snap`: a writer (xz or zlib, no
//! fragments, no extended attributes, deterministic) and a reader. Entries use the
//! [`cpio::Node`] tree model.
//!
//! Layout written: superblock, file data blocks, inode table, directory table, then the id
//! table (one metadata block and its index), padded to 4 KiB, which is what `mksquashfs
//! -no-fragments -no-xattrs -noappend` writes and what the kernel and `unsquashfs` check.
//!
//! [`cpio::Node`]: crate::format::cpio::Node

use std::collections::{BTreeMap, HashMap};

use crate::compress::lzma::Options as LzmaOptions;
use crate::compress::xz::{self, Check};
use crate::compress::{unzlib, zlib, Level};
use crate::format::cpio::{Node, NodeKind};
use crate::{Error, Result};

const MAGIC: u32 = 0x7371_7368;
const METADATA_SIZE: usize = 8192;
const INVALID: u64 = u64::MAX;
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;
const NO_XATTR: u32 = 0xFFFF_FFFF;
const UNCOMPRESSED_BLOCK: u32 = 1 << 24;

const FLAG_NO_FRAGMENTS: u16 = 0x0010;
const FLAG_NO_XATTRS: u16 = 0x0200;

const DIR: u16 = 1;
const FILE: u16 = 2;
const SYMLINK: u16 = 3;
const LDIR: u16 = 8;
const LFILE: u16 = 9;

/// The compressor for data and metadata blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// xz (LZMA2), id 4: what snaps use, and what the Snap Store requires.
    Xz,
    /// zlib, id 1 (SquashFS calls it gzip).
    Gzip,
}

impl Compression {
    fn id(self) -> u16 {
        match self {
            Compression::Gzip => 1,
            Compression::Xz => 4,
        }
    }
    /// The name `mksquashfs` and `unsquashfs -s` use.
    pub fn name(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Xz => "xz",
        }
    }
}

/// Image settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Compressor.
    pub compression: Compression,
    /// Data block size: a power of two from 4 KiB to 1 MiB (default 128 KiB, like `mksquashfs`).
    pub block_size: u32,
    /// The filesystem's creation time (Unix seconds).
    pub mkfs_time: i64,
}

impl Default for Options {
    fn default() -> Self {
        Options { compression: Compression::Xz, block_size: 1 << 17, mkfs_time: crate::util::source_date_epoch() }
    }
}

fn compress(c: Compression, data: &[u8], block_size: u32) -> Vec<u8> {
    match c {
        // A dictionary no larger than the block: the kernel preallocates one block's worth.
        Compression::Xz => xz::xz_with(data, &LzmaOptions::DEFAULT.dict_size(block_size), Check::Crc32),
        Compression::Gzip => zlib(data, Level::BEST),
    }
}

fn decompress(c: Compression, data: &[u8], max: usize) -> Result<Vec<u8>> {
    let out = match c {
        Compression::Xz => xz::unxz(data, max)?,
        Compression::Gzip => unzlib(data)?,
    };
    if out.len() > max {
        return Err(Error::malformed("squashfs", "block decompresses past its size"));
    }
    Ok(out)
}

/// Writes 8 KiB metadata blocks, each compressed on its own with a 2-byte length header.
struct MetaWriter {
    compression: Compression,
    block_size: u32,
    out: Vec<u8>,
    buf: Vec<u8>,
}

impl MetaWriter {
    fn new(compression: Compression, block_size: u32) -> Self {
        MetaWriter { compression, block_size, out: Vec::new(), buf: Vec::new() }
    }
    /// (start of the current block in the table, offset within its uncompressed bytes).
    fn pos(&self) -> (u64, u16) {
        (self.out.len() as u64, self.buf.len() as u16)
    }
    fn write(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while self.buf.len() >= METADATA_SIZE {
            let rest = self.buf.split_off(METADATA_SIZE);
            let block = std::mem::replace(&mut self.buf, rest);
            self.flush_block(&block);
        }
    }
    fn flush_block(&mut self, block: &[u8]) {
        let c = compress(self.compression, block, self.block_size);
        if c.len() < block.len() {
            self.out.extend_from_slice(&(c.len() as u16).to_le_bytes());
            self.out.extend_from_slice(&c);
        } else {
            self.out.extend_from_slice(&(block.len() as u16 | 0x8000).to_le_bytes());
            self.out.extend_from_slice(block);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if !self.buf.is_empty() {
            let block = std::mem::take(&mut self.buf);
            self.flush_block(&block);
        }
        self.out
    }
}

/// The tree built from the node list.
struct Tree<'a> {
    /// Path ("" for the root) → its node (None for implied directories).
    nodes: BTreeMap<String, Option<&'a Node>>,
    /// Directory path → children names, sorted.
    children: BTreeMap<String, Vec<String>>,
}

fn normalize(path: &str) -> Result<String> {
    let p = path.strip_prefix("./").unwrap_or(path);
    let p = if p == "." { "" } else { p.trim_end_matches('/') };
    if p.split('/').any(|c| c == ".." || c == ".") || p.starts_with('/') || p.contains("//") {
        return Err(Error::invalid("squashfs", "path", format!("`{path}` must be relative without `.` or `..` components")));
    }
    Ok(p.to_string())
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }
}

impl<'a> Tree<'a> {
    fn build(nodes: &'a [Node]) -> Result<Self> {
        let mut t = Tree { nodes: BTreeMap::new(), children: BTreeMap::new() };
        t.nodes.insert(String::new(), None);
        t.children.insert(String::new(), Vec::new());
        for n in nodes {
            let p = normalize(&n.path)?;
            // Implied parents.
            let mut parent = String::new();
            let comps: Vec<&str> = if p.is_empty() { Vec::new() } else { p.split('/').collect() };
            for (i, c) in comps.iter().enumerate() {
                let here = join(&parent, c);
                if i + 1 < comps.len() && !t.nodes.contains_key(&here) {
                    t.nodes.insert(here.clone(), None);
                    t.children.insert(here.clone(), Vec::new());
                    if let Some(v) = t.children.get_mut(&parent) {
                        v.push(c.to_string());
                    }
                }
                parent = here;
            }
            if t.nodes.get(&p).is_some_and(|x| x.is_some()) {
                return Err(Error::invalid("squashfs", "path", format!("`{}` appears twice", n.path)));
            }
            let existed = t.nodes.contains_key(&p);
            if existed && !matches!(n.kind, NodeKind::Dir) && t.children.get(&p).is_some_and(|c| !c.is_empty()) {
                return Err(Error::invalid("squashfs", "path", format!("`{}` has entries under it but isn't a directory", n.path)));
            }
            t.nodes.insert(p.clone(), Some(n));
            if matches!(n.kind, NodeKind::Dir) {
                t.children.entry(p.clone()).or_default();
            } else {
                t.children.remove(&p);
            }
            if !existed && !p.is_empty() {
                let (dir, name) = p.rsplit_once('/').unwrap_or(("", &p));
                t.children.get_mut(dir).ok_or_else(|| Error::invalid("squashfs", "path", format!("`{}`'s parent isn't a directory", n.path)))?.push(name.to_string());
            }
        }
        for v in t.children.values_mut() {
            v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            v.dedup();
        }
        Ok(t)
    }
}

struct Writer<'a> {
    opts: Options,
    tree: Tree<'a>,
    ids: Vec<u32>,
    numbers: HashMap<String, u32>,
    data: Vec<u8>,
    /// File path → (blocks_start, block size entries).
    blocks: HashMap<String, (u64, Vec<u32>)>,
    inodes: MetaWriter,
    dirs: MetaWriter,
}

impl Writer<'_> {
    fn id_index(&mut self, id: u32) -> u16 {
        match self.ids.iter().position(|&x| x == id) {
            Some(i) => i as u16,
            None => {
                self.ids.push(id);
                (self.ids.len() - 1) as u16
            }
        }
    }

    /// Numbers inodes in the order they're written: children before their directory.
    fn number(&mut self, dir: &str, next: &mut u32) {
        for name in self.tree.children.get(dir).cloned().unwrap_or_default() {
            let p = join(dir, &name);
            if self.tree.children.contains_key(&p) {
                self.number(&p, next);
            } else {
                *next += 1;
                self.numbers.insert(p, *next);
            }
        }
        *next += 1;
        self.numbers.insert(dir.to_string(), *next);
    }

    fn write_data(&mut self, dir: &str) {
        for name in self.tree.children.get(dir).cloned().unwrap_or_default() {
            let p = join(dir, &name);
            if self.tree.children.contains_key(&p) {
                self.write_data(&p);
            } else if let Some(Some(Node { kind: NodeKind::File(d), .. })) = self.tree.nodes.get(&p) {
                let start = self.data.len() as u64;
                let mut sizes = Vec::new();
                for chunk in d.chunks(self.opts.block_size as usize) {
                    let c = compress(self.opts.compression, chunk, self.opts.block_size);
                    if c.len() < chunk.len() {
                        sizes.push(c.len() as u32);
                        self.data.extend_from_slice(&c);
                    } else {
                        sizes.push(chunk.len() as u32 | UNCOMPRESSED_BLOCK);
                        self.data.extend_from_slice(chunk);
                    }
                }
                self.blocks.insert(p, (start, sizes));
            }
        }
    }

    fn header(&mut self, kind: u16, node: Option<&Node>, number: u32) -> Vec<u8> {
        let (perm, uid, gid, mtime) = match node {
            Some(n) => (n.perm, n.uid, n.gid, n.mtime),
            None => (0o755, 0, 0, self.opts.mkfs_time),
        };
        let mut h = Vec::with_capacity(64);
        h.extend_from_slice(&kind.to_le_bytes());
        h.extend_from_slice(&((perm & 0o7777) as u16).to_le_bytes());
        let (u, g) = (self.id_index(uid), self.id_index(gid));
        h.extend_from_slice(&u.to_le_bytes());
        h.extend_from_slice(&g.to_le_bytes());
        h.extend_from_slice(&(mtime.clamp(0, u32::MAX as i64) as u32).to_le_bytes());
        h.extend_from_slice(&number.to_le_bytes());
        h
    }

    /// Writes `dir`'s subtree, then its listing and inode; returns its inode reference.
    fn write_dir(&mut self, dir: &str, parent: u32) -> Result<u64> {
        let number = self.numbers[dir];
        let mut entries: Vec<(String, u64, u32, u16)> = Vec::new();
        let mut subdirs = 0u32;
        for name in self.tree.children.get(dir).cloned().unwrap_or_default() {
            let p = join(dir, &name);
            if self.tree.children.contains_key(&p) {
                subdirs += 1;
                let r = self.write_dir(&p, number)?;
                entries.push((name, r, self.numbers[&p], DIR));
                continue;
            }
            let num = self.numbers[&p];
            let node = self.tree.nodes[&p].ok_or_else(|| Error::Other(format!("squashfs: no node for {p}")))?;
            let (blk, off) = self.inodes.pos();
            let r = (blk << 16) | u64::from(off);
            match &node.kind {
                NodeKind::File(d) => {
                    let (start, sizes) = self.blocks[&p].clone();
                    let size = d.len() as u64;
                    let mut ino;
                    if start <= u64::from(u32::MAX) && size <= u64::from(u32::MAX) {
                        ino = self.header(FILE, Some(node), num);
                        ino.extend_from_slice(&(start as u32).to_le_bytes());
                        ino.extend_from_slice(&NO_FRAGMENT.to_le_bytes());
                        ino.extend_from_slice(&0u32.to_le_bytes());
                        ino.extend_from_slice(&(size as u32).to_le_bytes());
                    } else {
                        ino = self.header(LFILE, Some(node), num);
                        ino.extend_from_slice(&start.to_le_bytes());
                        ino.extend_from_slice(&size.to_le_bytes());
                        ino.extend_from_slice(&0u64.to_le_bytes());
                        ino.extend_from_slice(&1u32.to_le_bytes());
                        ino.extend_from_slice(&NO_FRAGMENT.to_le_bytes());
                        ino.extend_from_slice(&0u32.to_le_bytes());
                        ino.extend_from_slice(&NO_XATTR.to_le_bytes());
                    }
                    for s in sizes {
                        ino.extend_from_slice(&s.to_le_bytes());
                    }
                    self.inodes.write(&ino);
                    entries.push((name, r, num, FILE));
                }
                NodeKind::Symlink(t) => {
                    let mut ino = self.header(SYMLINK, Some(node), num);
                    ino.extend_from_slice(&1u32.to_le_bytes());
                    ino.extend_from_slice(&(t.len() as u32).to_le_bytes());
                    ino.extend_from_slice(t.as_bytes());
                    self.inodes.write(&ino);
                    entries.push((name, r, num, SYMLINK));
                }
                NodeKind::Dir => unreachable!("directories are in `children`"),
            }
        }

        // The listing: runs of entries sharing an inode block, ≤ 256 each, with small deltas.
        let (lblk, loff) = self.dirs.pos();
        let mut listing = Vec::new();
        let mut i = 0;
        while i < entries.len() {
            let block = entries[i].1 >> 16;
            let base = entries[i].2;
            let mut j = i;
            while j < entries.len() && j - i < 256 && entries[j].1 >> 16 == block && (i64::from(entries[j].2) - i64::from(base)).abs() <= 32767 {
                j += 1;
            }
            listing.extend_from_slice(&((j - i - 1) as u32).to_le_bytes());
            listing.extend_from_slice(&(block as u32).to_le_bytes());
            listing.extend_from_slice(&base.to_le_bytes());
            for (name, r, num, kind) in &entries[i..j] {
                if name.is_empty() || name.len() > 256 {
                    return Err(Error::invalid("squashfs", "name", format!("`{name}` must be 1–256 bytes")));
                }
                listing.extend_from_slice(&((r & 0xFFFF) as u16).to_le_bytes());
                listing.extend_from_slice(&((i64::from(*num) - i64::from(base)) as i16).to_le_bytes());
                listing.extend_from_slice(&kind.to_le_bytes());
                listing.extend_from_slice(&((name.len() - 1) as u16).to_le_bytes());
                listing.extend_from_slice(name.as_bytes());
            }
            i = j;
        }
        self.dirs.write(&listing);

        let node = self.tree.nodes.get(dir).copied().flatten();
        let (blk, off) = self.inodes.pos();
        let size = listing.len() + 3;
        let nlink = 2 + subdirs;
        let mut ino;
        if size <= 0xFFFF {
            ino = self.header(DIR, node, number);
            ino.extend_from_slice(&(lblk as u32).to_le_bytes());
            ino.extend_from_slice(&nlink.to_le_bytes());
            ino.extend_from_slice(&(size as u16).to_le_bytes());
            ino.extend_from_slice(&loff.to_le_bytes());
            ino.extend_from_slice(&parent.to_le_bytes());
        } else {
            ino = self.header(LDIR, node, number);
            ino.extend_from_slice(&nlink.to_le_bytes());
            ino.extend_from_slice(&(size as u32).to_le_bytes());
            ino.extend_from_slice(&(lblk as u32).to_le_bytes());
            ino.extend_from_slice(&parent.to_le_bytes());
            ino.extend_from_slice(&0u16.to_le_bytes());
            ino.extend_from_slice(&loff.to_le_bytes());
            ino.extend_from_slice(&NO_XATTR.to_le_bytes());
        }
        self.inodes.write(&ino);
        Ok((blk << 16) | u64::from(off))
    }
}

/// Writes an image holding `nodes` (paths like `./meta/snap.yaml`; parents are implied when
/// missing). Directory entries are sorted by name; data is written in that order.
pub fn write(nodes: &[Node], opts: &Options) -> Result<Vec<u8>> {
    if !opts.block_size.is_power_of_two() || !(4096..=1 << 20).contains(&opts.block_size) {
        return Err(Error::invalid("squashfs", "block_size", "must be a power of two from 4 KiB to 1 MiB"));
    }
    let tree = Tree::build(nodes)?;
    let mut w = Writer {
        opts: *opts,
        tree,
        ids: Vec::new(),
        numbers: HashMap::new(),
        // The superblock's space, so recorded block starts are absolute offsets.
        data: vec![0u8; 96],
        blocks: HashMap::new(),
        inodes: MetaWriter::new(opts.compression, opts.block_size),
        dirs: MetaWriter::new(opts.compression, opts.block_size),
    };
    let mut count = 0;
    w.number("", &mut count);
    w.write_data("");
    let root = w.write_dir("", count + 1)?;

    let mut out = std::mem::take(&mut w.data);
    let inode_table_start = out.len() as u64;
    let inodes = std::mem::replace(&mut w.inodes, MetaWriter::new(opts.compression, opts.block_size)).finish();
    out.extend_from_slice(&inodes);
    let directory_table_start = out.len() as u64;
    let dirs = std::mem::replace(&mut w.dirs, MetaWriter::new(opts.compression, opts.block_size)).finish();
    out.extend_from_slice(&dirs);
    let fragment_table_start = out.len() as u64;
    let id_block_start = out.len() as u64;
    let mut ids = MetaWriter::new(opts.compression, opts.block_size);
    let id_bytes: Vec<u8> = w.ids.iter().flat_map(|i| i.to_le_bytes()).collect();
    // One index entry per 8 KiB of ids (2048 ids).
    let mut index = Vec::new();
    for chunk in id_bytes.chunks(METADATA_SIZE) {
        index.push(id_block_start + ids.pos().0);
        ids.write(chunk);
    }
    out.extend_from_slice(&ids.finish());
    let id_table_start = out.len() as u64;
    for i in index {
        out.extend_from_slice(&i.to_le_bytes());
    }
    let bytes_used = out.len() as u64;

    let mut sb = Vec::with_capacity(96);
    sb.extend_from_slice(&MAGIC.to_le_bytes());
    sb.extend_from_slice(&count.to_le_bytes());
    sb.extend_from_slice(&(opts.mkfs_time.clamp(0, u32::MAX as i64) as u32).to_le_bytes());
    sb.extend_from_slice(&opts.block_size.to_le_bytes());
    sb.extend_from_slice(&0u32.to_le_bytes());
    sb.extend_from_slice(&opts.compression.id().to_le_bytes());
    sb.extend_from_slice(&(opts.block_size.trailing_zeros() as u16).to_le_bytes());
    sb.extend_from_slice(&(FLAG_NO_FRAGMENTS | FLAG_NO_XATTRS).to_le_bytes());
    sb.extend_from_slice(&(w.ids.len() as u16).to_le_bytes());
    sb.extend_from_slice(&4u16.to_le_bytes());
    sb.extend_from_slice(&0u16.to_le_bytes());
    sb.extend_from_slice(&root.to_le_bytes());
    sb.extend_from_slice(&bytes_used.to_le_bytes());
    sb.extend_from_slice(&id_table_start.to_le_bytes());
    sb.extend_from_slice(&INVALID.to_le_bytes());
    sb.extend_from_slice(&inode_table_start.to_le_bytes());
    sb.extend_from_slice(&directory_table_start.to_le_bytes());
    sb.extend_from_slice(&fragment_table_start.to_le_bytes());
    sb.extend_from_slice(&INVALID.to_le_bytes());
    out[..96].copy_from_slice(&sb);
    // Pad to 4 KiB for block devices, like mksquashfs.
    out.resize(out.len().div_ceil(4096) * 4096, 0);
    Ok(out)
}

/// What the superblock says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Compressor.
    pub compression: Compression,
    /// Data block size.
    pub block_size: u32,
    /// Number of inodes.
    pub inodes: u32,
    /// Bytes used (before padding).
    pub bytes_used: u64,
    /// Creation time.
    pub mkfs_time: u32,
    /// Superblock flags.
    pub flags: u16,
}

struct Super {
    info: Info,
    root: u64,
    id_table_start: u64,
    inode_table_start: u64,
    directory_table_start: u64,
    fragment_table_start: u64,
    fragments: u32,
    ids: u16,
}

fn le16(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([d[at], d[at + 1]])
}
fn le32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}
fn le64(d: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[at..at + 8]);
    u64::from_le_bytes(b)
}

fn superblock(data: &[u8]) -> Result<Super> {
    let bad = |m: &str| Error::malformed("squashfs", m);
    if data.len() < 96 || le32(data, 0) != MAGIC {
        return Err(bad("missing hsqs magic"));
    }
    if le16(data, 28) != 4 {
        return Err(bad("only version 4.0 is supported"));
    }
    let compression = match le16(data, 20) {
        1 => Compression::Gzip,
        4 => Compression::Xz,
        other => return Err(bad(&format!("unsupported compressor id {other}"))),
    };
    let block_size = le32(data, 12);
    if !block_size.is_power_of_two() || u32::from(le16(data, 22)) != block_size.trailing_zeros() {
        return Err(bad("bad block size"));
    }
    let info = Info { compression, block_size, inodes: le32(data, 4), bytes_used: le64(data, 40), mkfs_time: le32(data, 8), flags: le16(data, 24) };
    if info.bytes_used > data.len() as u64 {
        return Err(bad("image is truncated"));
    }
    Ok(Super {
        info,
        root: le64(data, 32),
        id_table_start: le64(data, 48),
        inode_table_start: le64(data, 64),
        directory_table_start: le64(data, 72),
        fragment_table_start: le64(data, 80),
        fragments: le32(data, 16),
        ids: le16(data, 26),
    })
}

/// Reads the superblock.
pub fn info(data: &[u8]) -> Result<Info> {
    Ok(superblock(data)?.info)
}

/// A metadata table: decompressed bytes and where each block (by on-disk offset) begins.
struct Table {
    bytes: Vec<u8>,
    starts: HashMap<u64, usize>,
}

fn read_table(data: &[u8], c: Compression, start: u64, end: u64) -> Result<Table> {
    let bad = |m: &str| Error::malformed("squashfs", m);
    let mut t = Table { bytes: Vec::new(), starts: HashMap::new() };
    let mut p = start as usize;
    while (p as u64) < end {
        t.starts.insert(p as u64 - start, t.bytes.len());
        let hdr = le16(data.get(p..p + 2).ok_or_else(|| bad("truncated metadata"))?, 0);
        let len = usize::from(hdr & 0x7FFF);
        let raw = data.get(p + 2..p + 2 + len).ok_or_else(|| bad("truncated metadata block"))?;
        if hdr & 0x8000 != 0 {
            t.bytes.extend_from_slice(raw);
        } else {
            t.bytes.extend(decompress(c, raw, METADATA_SIZE)?);
        }
        p += 2 + len;
    }
    Ok(t)
}

impl Table {
    fn at(&self, block: u64, offset: u16) -> Result<usize> {
        self.starts.get(&block).map(|s| s + usize::from(offset)).ok_or_else(|| Error::malformed("squashfs", "reference to a missing metadata block"))
    }
    fn get(&self, at: usize, len: usize) -> Result<&[u8]> {
        self.bytes.get(at..at + len).ok_or_else(|| Error::malformed("squashfs", "metadata runs past its table"))
    }
}

/// Reads every entry of an image (paths `./…`, the root as `.`), with file contents.
pub fn read(data: &[u8]) -> Result<Vec<Node>> {
    let sb = superblock(data)?;
    let c = sb.info.compression;
    if sb.fragments != 0 {
        return Err(Error::malformed("squashfs", "fragments aren't supported by this reader"));
    }
    let inodes = read_table(data, c, sb.inode_table_start, sb.directory_table_start)?;
    let dirs = read_table(data, c, sb.directory_table_start, sb.fragment_table_start.min(sb.id_table_start))?;
    // Ids.
    let id_block = le64(data.get(sb.id_table_start as usize..sb.id_table_start as usize + 8).ok_or_else(|| Error::malformed("squashfs", "truncated id index"))?, 0);
    let idt = read_table(data, c, id_block, sb.id_table_start)?;
    let ids: Vec<u32> = (0..usize::from(sb.ids)).map(|i| idt.get(i * 4, 4).map(|b| le32(b, 0))).collect::<Result<_>>()?;
    let id = |i: u16| ids.get(usize::from(i)).copied().ok_or_else(|| Error::malformed("squashfs", "bad id index"));

    let mut out = Vec::new();
    let mut stack = vec![(".".to_string(), sb.root, 0usize)];
    while let Some((path, r, depth)) = stack.pop() {
        if depth > 256 {
            return Err(Error::malformed("squashfs", "directories nested too deeply"));
        }
        let at = inodes.at(r >> 16, (r & 0xFFFF) as u16)?;
        let h = inodes.get(at, 16)?;
        let (kind, perm, uid, gid, mtime) = (le16(h, 0), u32::from(le16(h, 2)), id(le16(h, 4))?, id(le16(h, 6))?, i64::from(le32(h, 8)));
        let node = |k: NodeKind| Node { path: path.clone(), kind: k, perm, uid, gid, mtime };
        match kind {
            DIR | LDIR => {
                let (start, size, offset) = if kind == DIR {
                    let b = inodes.get(at + 16, 16)?;
                    (u64::from(le32(b, 0)), usize::from(le16(b, 8)), le16(b, 10))
                } else {
                    let b = inodes.get(at + 16, 24)?;
                    (u64::from(le32(b, 8)), le32(b, 4) as usize, le16(b, 18))
                };
                out.push(node(NodeKind::Dir));
                let mut p = dirs.at(start, offset)?;
                let end = p + size.saturating_sub(3);
                let mut children = Vec::new();
                while p < end {
                    let hd = dirs.get(p, 12)?;
                    let (count, block) = (le32(hd, 0) as usize + 1, u64::from(le32(hd, 4)));
                    p += 12;
                    for _ in 0..count {
                        let e = dirs.get(p, 8)?;
                        let off = le16(e, 0);
                        let name_len = usize::from(le16(e, 6)) + 1;
                        let name = String::from_utf8_lossy(dirs.get(p + 8, name_len)?).into_owned();
                        if name.contains('/') || name == "." || name == ".." {
                            return Err(Error::malformed("squashfs", format!("bad entry name `{name}`")));
                        }
                        children.push((format!("{path}/{name}"), (block << 16) | u64::from(off)));
                        p += 8 + name_len;
                    }
                }
                for (cp, cr) in children.into_iter().rev() {
                    stack.push((cp, cr, depth + 1));
                }
            }
            FILE | LFILE => {
                let (start, size, frag, hdr_len) = if kind == FILE {
                    let b = inodes.get(at + 16, 16)?;
                    (u64::from(le32(b, 0)), u64::from(le32(b, 12)), le32(b, 4), 32)
                } else {
                    let b = inodes.get(at + 16, 40)?;
                    (le64(b, 0), le64(b, 8), le32(b, 28), 56)
                };
                if frag != NO_FRAGMENT {
                    return Err(Error::malformed("squashfs", "fragments aren't supported by this reader"));
                }
                let bs = u64::from(sb.info.block_size);
                let nblocks = size.div_ceil(bs) as usize;
                let sizes = inodes.get(at + hdr_len, nblocks * 4)?;
                let mut content = Vec::with_capacity(size as usize);
                let mut p = start as usize;
                for i in 0..nblocks {
                    let s = le32(sizes, i * 4);
                    let want = (size - i as u64 * bs).min(bs) as usize;
                    let len = (s & !UNCOMPRESSED_BLOCK) as usize;
                    if len == 0 {
                        content.resize(content.len() + want, 0);
                        continue;
                    }
                    let raw = data.get(p..p + len).ok_or_else(|| Error::malformed("squashfs", "data block past the image"))?;
                    let block = if s & UNCOMPRESSED_BLOCK != 0 { raw.to_vec() } else { decompress(c, raw, bs as usize)? };
                    if block.len() != want {
                        return Err(Error::malformed("squashfs", format!("{path}: block {i} has the wrong size")));
                    }
                    content.extend_from_slice(&block);
                    p += len;
                }
                out.push(node(NodeKind::File(content)));
            }
            SYMLINK => {
                let b = inodes.get(at + 16, 8)?;
                let len = le32(b, 4) as usize;
                let target = String::from_utf8_lossy(inodes.get(at + 24, len)?).into_owned();
                out.push(node(NodeKind::Symlink(target)));
            }
            other => return Err(Error::malformed("squashfs", format!("{path}: unsupported inode type {other}"))),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(path: &str, kind: NodeKind, perm: u32) -> Node {
        Node { path: path.into(), kind, perm, uid: 0, gid: 0, mtime: 315_532_800 }
    }

    fn sample_tree() -> Vec<Node> {
        let mut v = vec![
            n(".", NodeKind::Dir, 0o755),
            n("./meta", NodeKind::Dir, 0o755),
            n("./meta/snap.yaml", NodeKind::File(b"name: hello\nversion: '1.0'\n".to_vec()), 0o644),
            n("./bin", NodeKind::Dir, 0o755),
            n("./bin/hello", NodeKind::File(crate::compress::lzma::tests_sample(300_000)), 0o755),
            n("./bin/link", NodeKind::Symlink("hello".into()), 0o777),
            n("./empty", NodeKind::File(Vec::new()), 0o644),
            n("./emptydir", NodeKind::Dir, 0o700),
            n("./zeros", NodeKind::File(vec![0; 140_000]), 0o600),
        ];
        // Enough entries to need several directory headers and metadata blocks.
        v.push(n("./many", NodeKind::Dir, 0o755));
        for i in 0..700 {
            v.push(n(&format!("./many/file-with-a-longish-name-{i:04}.txt"), NodeKind::File(format!("file {i}\n").into_bytes()), 0o644));
        }
        v
    }

    #[test]
    fn round_trip() {
        let nodes = sample_tree();
        for compression in [Compression::Xz, Compression::Gzip] {
            let img = write(&nodes, &Options { compression, block_size: 1 << 17, mkfs_time: 315_532_800 }).unwrap();
            assert_eq!(img.len() % 4096, 0);
            let i = info(&img).unwrap();
            assert_eq!(i.compression, compression);
            assert_eq!(i.inodes as usize, nodes.len());
            let back = read(&img).unwrap();
            let mut want: Vec<(String, NodeKind, u32)> = nodes.iter().map(|x| (x.path.clone(), x.kind.clone(), x.perm)).collect();
            let mut got: Vec<(String, NodeKind, u32)> = back.iter().map(|x| (x.path.clone(), x.kind.clone(), x.perm)).collect();
            want.sort_by(|a, b| a.0.cmp(&b.0));
            got.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(got.len(), want.len());
            for (g, w) in got.iter().zip(&want) {
                assert!(g == w, "{} differs ({compression:?})", w.0);
            }
            // Deterministic.
            assert!(img == write(&nodes, &Options { compression, block_size: 1 << 17, mkfs_time: 315_532_800 }).unwrap());
        }
    }

    #[test]
    fn implied_parents_and_errors() {
        let img = write(&[n("./a/b/c", NodeKind::File(b"x".to_vec()), 0o644)], &Options::default()).unwrap();
        let back = read(&img).unwrap();
        assert_eq!(back.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(), [".", "./a", "./a/b", "./a/b/c"]);
        assert!(write(&[n("./x", NodeKind::Dir, 0o755), n("./x", NodeKind::Dir, 0o755)], &Options::default()).is_err());
        assert!(write(&[n("./../x", NodeKind::Dir, 0o755)], &Options::default()).is_err());
    }
}
