//! OLE Compound File Binary (MS-CFB), the container of `.msi` databases: a FAT file system
//! inside a file, with 512-byte sectors (version 3), a mini stream for streams under 4 KB, a
//! red-black tree of directory entries per storage, and DIFAT sectors for files over ~7 MB.
//!
//! The writer produces a flat root storage (what MSI databases are); the reader also walks
//! nested storages.

use crate::{Error, Result};

const SECTOR: usize = 512;
const MINI: usize = 64;
const MINI_CUTOFF: usize = 4096;
const ENDOFCHAIN: u32 = 0xffff_fffe;
const FREESECT: u32 = 0xffff_ffff;
const FATSECT: u32 = 0xffff_fffd;
const DIFSECT: u32 = 0xffff_fffc;
const NOSTREAM: u32 = 0xffff_ffff;
const PER_FAT: usize = SECTOR / 4;

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("cfb", m)
}

/// A stream in a compound file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    /// Name as UTF-16 code units (MSI names use code points from 0x3800 up).
    pub name: Vec<u16>,
    /// Contents.
    pub data: Vec<u8>,
}

impl Stream {
    /// A stream with a plain name.
    pub fn new(name: &str, data: Vec<u8>) -> Self {
        Stream { name: name.encode_utf16().collect(), data }
    }
}

/// Directory order: shorter names first, then code units compared after simple uppercasing.
fn name_cmp(a: &[u16], b: &[u16]) -> std::cmp::Ordering {
    let up = |c: u16| if (u16::from(b'a')..=u16::from(b'z')).contains(&c) { c - 32 } else { c };
    a.len().cmp(&b.len()).then_with(|| a.iter().map(|&c| up(c)).cmp(b.iter().map(|&c| up(c))))
}

/// A directory entry, as written.
struct Entry {
    name: Vec<u16>,
    kind: u8,
    color: u8,
    left: u32,
    right: u32,
    child: u32,
    clsid: [u8; 16],
    start: u32,
    size: u64,
}

impl Entry {
    fn bytes(&self) -> [u8; 128] {
        let mut b = [0u8; 128];
        for (i, c) in self.name.iter().take(31).enumerate() {
            b[2 * i..2 * i + 2].copy_from_slice(&c.to_le_bytes());
        }
        let name_len = if self.kind == 0 { 0 } else { (self.name.len().min(31) as u16 + 1) * 2 };
        b[64..66].copy_from_slice(&name_len.to_le_bytes());
        b[66] = self.kind;
        b[67] = self.color;
        b[68..72].copy_from_slice(&self.left.to_le_bytes());
        b[72..76].copy_from_slice(&self.right.to_le_bytes());
        b[76..80].copy_from_slice(&self.child.to_le_bytes());
        b[80..96].copy_from_slice(&self.clsid);
        b[116..120].copy_from_slice(&self.start.to_le_bytes());
        b[120..128].copy_from_slice(&self.size.to_le_bytes());
        b
    }
}

/// Builds a balanced sibling tree over `ids` (sorted), coloring the deepest level red so every
/// path has the same number of black nodes. Returns the subtree root.
fn tree(entries: &mut [Entry], ids: &[u32], depth: usize, max_depth: usize) -> u32 {
    if ids.is_empty() {
        return NOSTREAM;
    }
    let mid = ids.len() / 2;
    let id = ids[mid];
    let left = tree(entries, &ids[..mid], depth + 1, max_depth);
    let right = tree(entries, &ids[mid + 1..], depth + 1, max_depth);
    let e = &mut entries[id as usize];
    e.left = left;
    e.right = right;
    e.color = if depth == max_depth && depth > 0 { 0 } else { 1 }; // 0 red, 1 black
    id
}

/// Writes a compound file whose root (with `root_clsid`) holds `streams`.
pub fn write(streams: &[Stream], root_clsid: [u8; 16]) -> Result<Vec<u8>> {
    let mut sorted: Vec<&Stream> = streams.iter().collect();
    sorted.sort_by(|a, b| name_cmp(&a.name, &b.name));
    for w in sorted.windows(2) {
        if name_cmp(&w[0].name, &w[1].name) == std::cmp::Ordering::Equal {
            return Err(Error::invalid("cfb", String::from_utf16_lossy(&w[0].name), "two streams have the same name"));
        }
    }
    if let Some(s) = sorted.iter().find(|s| s.name.len() > 31 || s.name.is_empty()) {
        return Err(Error::invalid("cfb", String::from_utf16_lossy(&s.name), "stream names must be 1–31 characters"));
    }

    // Mini stream: small streams in 64-byte mini sectors.
    let mut mini_stream = Vec::new();
    let mut mini_fat: Vec<u32> = Vec::new();
    let mut starts = vec![0u32; sorted.len()];
    for (i, s) in sorted.iter().enumerate() {
        if s.data.len() < MINI_CUTOFF && !s.data.is_empty() {
            let first = mini_fat.len() as u32;
            let n = s.data.len().div_ceil(MINI);
            for k in 0..n {
                mini_fat.push(if k + 1 == n { ENDOFCHAIN } else { first + k as u32 + 1 });
            }
            starts[i] = first;
            mini_stream.extend_from_slice(&s.data);
            mini_stream.resize(mini_fat.len() * MINI, 0);
        }
    }

    // Regular sectors: big streams, the mini stream, the mini FAT, the directory.
    let mut sectors: Vec<u8> = Vec::new();
    let mut fat: Vec<u32> = Vec::new();
    let chain = |data: &[u8], sectors: &mut Vec<u8>, fat: &mut Vec<u32>| -> u32 {
        if data.is_empty() {
            return ENDOFCHAIN;
        }
        let first = fat.len() as u32;
        let n = data.len().div_ceil(SECTOR);
        for k in 0..n {
            fat.push(if k + 1 == n { ENDOFCHAIN } else { first + k as u32 + 1 });
        }
        sectors.extend_from_slice(data);
        sectors.resize(fat.len() * SECTOR, 0);
        first
    };
    for (i, s) in sorted.iter().enumerate() {
        if s.data.len() >= MINI_CUTOFF {
            starts[i] = chain(&s.data, &mut sectors, &mut fat);
        } else if s.data.is_empty() {
            starts[i] = ENDOFCHAIN;
        }
    }
    let mini_start = chain(&mini_stream, &mut sectors, &mut fat);
    let minifat_bytes: Vec<u8> = mini_fat.iter().flat_map(|v| v.to_le_bytes()).collect();
    let mut minifat_padded = minifat_bytes.clone();
    minifat_padded.resize(minifat_bytes.len().div_ceil(SECTOR) * SECTOR, 0xff);
    let minifat_start = if mini_fat.is_empty() { ENDOFCHAIN } else { chain(&minifat_padded, &mut sectors, &mut fat) };
    let minifat_sectors = minifat_padded.len() / SECTOR;

    // Directory: root, then streams in sorted order; one balanced tree of siblings.
    let mut entries = vec![Entry { name: "Root Entry".encode_utf16().collect(), kind: 5, color: 1, left: NOSTREAM, right: NOSTREAM, child: NOSTREAM, clsid: root_clsid, start: mini_start, size: mini_stream.len() as u64 }];
    if mini_stream.is_empty() {
        entries[0].start = ENDOFCHAIN;
    }
    for (i, s) in sorted.iter().enumerate() {
        entries.push(Entry { name: s.name.clone(), kind: 2, color: 1, left: NOSTREAM, right: NOSTREAM, child: NOSTREAM, clsid: [0; 16], start: starts[i], size: s.data.len() as u64 });
    }
    let ids: Vec<u32> = (1..entries.len() as u32).collect();
    let max_depth = if ids.is_empty() { 0 } else { (usize::BITS - ids.len().leading_zeros()) as usize - 1 };
    entries[0].child = tree(&mut entries, &ids, 0, max_depth);
    let mut dir: Vec<u8> = entries.iter().flat_map(|e| e.bytes()).collect();
    while dir.len() % SECTOR != 0 {
        dir.extend_from_slice(&Entry { name: Vec::new(), kind: 0, color: 0, left: NOSTREAM, right: NOSTREAM, child: NOSTREAM, clsid: [0; 16], start: 0, size: 0 }.bytes());
    }
    let dir_start = chain(&dir, &mut sectors, &mut fat);

    // FAT and DIFAT sectors describe everything, themselves included.
    let data_sectors = fat.len();
    let (mut n_fat, mut n_difat) = (0usize, 0usize);
    loop {
        let total = data_sectors + n_fat + n_difat;
        let need_fat = total.div_ceil(PER_FAT);
        let need_difat = need_fat.saturating_sub(109).div_ceil(PER_FAT - 1);
        if need_fat == n_fat && need_difat == n_difat {
            break;
        }
        n_fat = need_fat;
        n_difat = need_difat;
    }
    let fat_first = data_sectors as u32;
    let difat_first = (data_sectors + n_fat) as u32;
    fat.extend(std::iter::repeat_n(FATSECT, n_fat));
    fat.extend(std::iter::repeat_n(DIFSECT, n_difat));
    fat.resize(n_fat * PER_FAT, FREESECT);
    let fat_ids: Vec<u32> = (0..n_fat as u32).map(|k| fat_first + k).collect();

    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    header[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    header[26..28].copy_from_slice(&3u16.to_le_bytes());
    header[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    header[30..32].copy_from_slice(&9u16.to_le_bytes());
    header[32..34].copy_from_slice(&6u16.to_le_bytes());
    header[44..48].copy_from_slice(&(n_fat as u32).to_le_bytes());
    header[48..52].copy_from_slice(&dir_start.to_le_bytes());
    header[56..60].copy_from_slice(&(MINI_CUTOFF as u32).to_le_bytes());
    header[60..64].copy_from_slice(&minifat_start.to_le_bytes());
    header[64..68].copy_from_slice(&(minifat_sectors as u32).to_le_bytes());
    header[68..72].copy_from_slice(&(if n_difat > 0 { difat_first } else { ENDOFCHAIN }).to_le_bytes());
    header[72..76].copy_from_slice(&(n_difat as u32).to_le_bytes());
    for k in 0..109 {
        let v = fat_ids.get(k).copied().unwrap_or(FREESECT);
        header[76 + 4 * k..80 + 4 * k].copy_from_slice(&v.to_le_bytes());
    }

    let mut out = Vec::with_capacity(SECTOR * (1 + fat.len()));
    out.extend_from_slice(&header);
    out.extend_from_slice(&sectors);
    out.extend(fat.iter().flat_map(|v| v.to_le_bytes()));
    // DIFAT sectors: 127 FAT sector ids each, then the next DIFAT sector.
    let rest = fat_ids.get(109..).unwrap_or_default();
    for k in 0..n_difat {
        let mut s = [FREESECT; PER_FAT];
        for (j, id) in rest.iter().skip(k * (PER_FAT - 1)).take(PER_FAT - 1).enumerate() {
            s[j] = *id;
        }
        s[PER_FAT - 1] = if k + 1 < n_difat { difat_first + k as u32 + 1 } else { ENDOFCHAIN };
        out.extend(s.iter().flat_map(|v| v.to_le_bytes()));
    }
    Ok(out)
}

/// An entry read back from a compound file.
#[derive(Debug, Clone)]
pub struct ReadEntry {
    /// Name as UTF-16 code units.
    pub name: Vec<u16>,
    /// The raw name bytes as stored (UTF-16LE with the terminator), for hashing.
    pub raw_name: Vec<u8>,
    /// Whether this is a storage (directory) rather than a stream.
    pub is_storage: bool,
    /// The CLSID (storages).
    pub clsid: [u8; 16],
    /// Contents (streams).
    pub data: Vec<u8>,
    /// Children (storages).
    pub children: Vec<ReadEntry>,
}

/// Reads a compound file: the root storage with every stream and storage below it.
pub fn read(data: &[u8]) -> Result<ReadEntry> {
    if data.get(..8) != Some(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Err(bad("not a compound file"));
    }
    let le16 = |p: usize| data.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| bad("truncated"));
    let le32 = |p: usize| data.get(p..p + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| bad("truncated"));
    let sector = 1usize << le16(30)?;
    let mini = 1usize << le16(32)?;
    if !(sector == 512 || sector == 4096) || mini != 64 {
        return Err(bad("unsupported sector size"));
    }
    let per = sector / 4;
    let at = |id: u32| SECTOR.max(sector) + id as usize * sector;
    // DIFAT → FAT sector ids.
    let n_fat = le32(44)? as usize;
    let mut fat_ids: Vec<u32> = (0..109.min(n_fat)).map(|k| le32(76 + 4 * k)).collect::<Result<_>>()?;
    let mut d = le32(68)?;
    let mut guard = 0;
    while fat_ids.len() < n_fat && d != ENDOFCHAIN && d != FREESECT {
        for k in 0..per - 1 {
            if fat_ids.len() < n_fat {
                fat_ids.push(le32(at(d) + 4 * k)?);
            }
        }
        d = le32(at(d) + 4 * (per - 1))?;
        guard += 1;
        if guard > 1 << 20 {
            return Err(bad("DIFAT loop"));
        }
    }
    let mut fat = Vec::with_capacity(n_fat * per);
    for id in &fat_ids {
        for k in 0..per {
            fat.push(le32(at(*id) + 4 * k)?);
        }
    }
    let follow = |table: &[u32], first: u32| -> Result<Vec<u32>> {
        let mut v = Vec::new();
        let mut s = first;
        while s != ENDOFCHAIN {
            if s as usize >= table.len() || v.len() > table.len() {
                return Err(bad("broken sector chain"));
            }
            v.push(s);
            s = table[s as usize];
        }
        Ok(v)
    };
    let read_chain = |first: u32, len: usize| -> Result<Vec<u8>> {
        let chain = follow(&fat, first)?;
        let mut out = Vec::with_capacity(len.min(chain.len() * sector));
        for s in chain {
            out.extend_from_slice(data.get(at(s)..at(s) + sector).ok_or_else(|| bad("sector out of range"))?);
        }
        out.truncate(len);
        Ok(out)
    };
    let dir_first = le32(48)?;
    let dir_bytes = read_chain(dir_first, usize::MAX)?;
    let entry = |i: u32| dir_bytes.get(i as usize * 128..i as usize * 128 + 128).ok_or_else(|| bad("directory entry out of range"));
    let root = entry(0)?;
    let root_start = u32::from_le_bytes(root[116..120].try_into().unwrap_or_default());
    let root_size = u64::from_le_bytes(root[120..128].try_into().unwrap_or_default()) as usize;
    let mini_stream = if root_size > 0 { read_chain(root_start, root_size)? } else { Vec::new() };
    let minifat_first = le32(60)?;
    let minifat_bytes = if minifat_first == ENDOFCHAIN { Vec::new() } else { read_chain(minifat_first, usize::MAX)? };
    let minifat: Vec<u32> = minifat_bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    let cutoff = le32(56)? as usize;

    fn build<'d>(
        i: u32,
        entry: &dyn Fn(u32) -> Result<&'d [u8]>,
        stream_data: &dyn Fn(u32, usize) -> Result<Vec<u8>>,
        depth: usize,
    ) -> Result<ReadEntry> {
        if depth > 64 {
            return Err(Error::malformed("cfb", "directory too deep"));
        }
        let e = entry(i)?;
        let nl = (u16::from_le_bytes([e[64], e[65]]) as usize).min(64);
        let raw_name = e[..nl].to_vec();
        let name: Vec<u16> = raw_name.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        let kind = e[66];
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&e[80..96]);
        let start = u32::from_le_bytes(e[116..120].try_into().unwrap_or_default());
        let size = u64::from_le_bytes(e[120..128].try_into().unwrap_or_default()) as usize;
        let mut out = ReadEntry { name, raw_name, is_storage: kind == 1 || kind == 5, clsid, data: Vec::new(), children: Vec::new() };
        if kind == 2 {
            out.data = stream_data(start, size)?;
        } else {
            let child = u32::from_le_bytes(e[76..80].try_into().unwrap_or_default());
            let mut stack = vec![child];
            let mut seen = 0;
            while let Some(c) = stack.pop() {
                if c == NOSTREAM {
                    continue;
                }
                seen += 1;
                if seen > 1 << 16 {
                    return Err(Error::malformed("cfb", "directory loop"));
                }
                let ce = entry(c)?;
                stack.push(u32::from_le_bytes(ce[68..72].try_into().unwrap_or_default()));
                stack.push(u32::from_le_bytes(ce[72..76].try_into().unwrap_or_default()));
                out.children.push(build(c, entry, stream_data, depth + 1)?);
            }
            out.children.sort_by(|a, b| name_cmp(&a.name, &b.name));
        }
        Ok(out)
    }
    let stream_data = |start: u32, size: usize| -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        if size < cutoff {
            let mut out = Vec::with_capacity(size);
            for s in follow(&minifat, start)? {
                out.extend_from_slice(mini_stream.get(s as usize * mini..s as usize * mini + mini).ok_or_else(|| bad("mini sector out of range"))?);
            }
            out.truncate(size);
            Ok(out)
        } else {
            read_chain(start, size)
        }
    };
    build(0, &entry, &stream_data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small_large_and_many() {
        let mut streams = vec![Stream::new("small", b"hello".to_vec()), Stream::new("empty", Vec::new()), Stream::new("exactly4096", vec![7; 4096])];
        // Enough data to need DIFAT sectors (> 109 FAT sectors × 64 KB).
        streams.push(Stream::new("big", (0..8_000_000u32).map(|i| (i * 31 % 251) as u8).collect()));
        for i in 0..40 {
            streams.push(Stream::new(&format!("s{i:02}"), vec![i as u8; 100 + 37 * i]));
        }
        let clsid = [0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
        let file = write(&streams, clsid).unwrap();
        let root = read(&file).unwrap();
        assert_eq!(root.clsid, clsid);
        assert_eq!(root.children.len(), streams.len());
        for s in &streams {
            let got = root.children.iter().find(|c| c.name == s.name).unwrap();
            assert_eq!(got.data, s.data, "{}", String::from_utf16_lossy(&s.name));
        }
        assert!(u32::from_le_bytes(file[72..76].try_into().unwrap()) > 0, "expected DIFAT sectors");
    }
}
