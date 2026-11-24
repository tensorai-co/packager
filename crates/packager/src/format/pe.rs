//! PE/COFF executables (`.exe`, `.dll`): headers, sections and data directories, the PE checksum,
//! and the resource tree, so icons, version information and manifests can be set before signing
//! (what `rcedit` does). Editing writes the new resource tree into a new last section and points
//! the resource directory at it; the old tree is left as unused bytes, as linkers place `.rsrc`
//! before `.reloc`.

use std::collections::BTreeMap;

use crate::format::ico::{self, IconImage};
use crate::{Error, Result};

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("pe", m)
}

fn le16(b: &[u8], p: usize) -> Result<u16> {
    b.get(p..p + 2).map(|x| u16::from_le_bytes([x[0], x[1]])).ok_or_else(|| bad("truncated"))
}
fn le32(b: &[u8], p: usize) -> Result<u32> {
    b.get(p..p + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| bad("truncated"))
}
fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn align(v: u32, a: u32) -> u32 {
    if a == 0 { v } else { v.div_ceil(a) * a }
}

/// Data directory indices.
pub mod dir {
    /// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
    pub const RESOURCE: usize = 2;
    /// `IMAGE_DIRECTORY_ENTRY_SECURITY`: the certificate table (a file offset, not an RVA).
    pub const SECURITY: usize = 4;
}

/// `IMAGE_FILE_MACHINE_*` values.
pub mod machine {
    /// x86.
    pub const I386: u16 = 0x14c;
    /// x64.
    pub const AMD64: u16 = 0x8664;
    /// Arm64.
    pub const ARM64: u16 = 0xaa64;
}

/// A section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Name (up to 8 bytes).
    pub name: String,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `VirtualAddress` (RVA).
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `Characteristics`.
    pub characteristics: u32,
}

/// A parsed PE image (the bytes are kept and edited in place).
#[derive(Debug, Clone)]
pub struct Image {
    data: Vec<u8>,
    coff: usize,
    opt: usize,
    pe32_plus: bool,
    /// Sections in header order.
    pub sections: Vec<Section>,
}

impl Image {
    /// Parses a PE file.
    pub fn parse(data: Vec<u8>) -> Result<Image> {
        if data.get(..2) != Some(b"MZ") {
            return Err(bad("no MZ header"));
        }
        let pe = le32(&data, 0x3c)? as usize;
        if data.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(bad("no PE signature"));
        }
        let coff = pe + 4;
        let nsec = le16(&data, coff + 2)? as usize;
        let opt_size = le16(&data, coff + 16)? as usize;
        let opt = coff + 20;
        let pe32_plus = match le16(&data, opt)? {
            0x10b => false,
            0x20b => true,
            m => return Err(bad(format!("unknown optional header magic {m:#x}"))),
        };
        let st = opt + opt_size;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let h = st + 40 * i;
            let raw = data.get(h..h + 8).ok_or_else(|| bad("truncated section table"))?;
            let name = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
            sections.push(Section {
                name,
                virtual_size: le32(&data, h + 8)?,
                virtual_address: le32(&data, h + 12)?,
                raw_size: le32(&data, h + 16)?,
                raw_offset: le32(&data, h + 20)?,
                characteristics: le32(&data, h + 36)?,
            });
        }
        Ok(Image { data, coff, opt, pe32_plus, sections })
    }

    /// Reads and parses a file.
    pub fn read(path: impl AsRef<std::path::Path>) -> Result<Image> {
        use crate::error::IoContext;
        let p = path.as_ref();
        Image::parse(std::fs::read(p).at(p)?)
    }

    /// The file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
    /// Consumes the image, returning its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
    /// Writes the file.
    pub fn write(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        use crate::error::IoContext;
        let p = path.as_ref();
        std::fs::write(p, &self.data).at(p)
    }

    /// `IMAGE_FILE_MACHINE_*`.
    pub fn machine(&self) -> u16 {
        le16(&self.data, self.coff).unwrap_or(0)
    }
    /// Whether this is a DLL.
    pub fn is_dll(&self) -> bool {
        le16(&self.data, self.coff + 18).unwrap_or(0) & 0x2000 != 0
    }
    /// Whether the optional header is PE32+ (64-bit).
    pub fn is_pe32_plus(&self) -> bool {
        self.pe32_plus
    }
    /// File offset of the `CheckSum` field.
    pub fn checksum_offset(&self) -> usize {
        self.opt + 64
    }
    /// `SizeOfHeaders`.
    pub fn size_of_headers(&self) -> u32 {
        le32(&self.data, self.opt + 60).unwrap_or(0)
    }
    fn file_alignment(&self) -> u32 {
        le32(&self.data, self.opt + 36).unwrap_or(512)
    }
    fn section_alignment(&self) -> u32 {
        le32(&self.data, self.opt + 32).unwrap_or(4096)
    }
    fn n_dirs(&self) -> usize {
        le32(&self.data, self.opt + if self.pe32_plus { 108 } else { 92 }).unwrap_or(0) as usize
    }
    /// File offset of data directory `i`'s entry.
    pub fn dir_entry_offset(&self, i: usize) -> usize {
        self.opt + if self.pe32_plus { 112 } else { 96 } + 8 * i
    }
    /// Data directory `i` as (address, size); zeros when absent.
    pub fn data_dir(&self, i: usize) -> (u32, u32) {
        if i >= self.n_dirs() {
            return (0, 0);
        }
        let o = self.dir_entry_offset(i);
        (le32(&self.data, o).unwrap_or(0), le32(&self.data, o + 4).unwrap_or(0))
    }
    fn set_data_dir(&mut self, i: usize, addr: u32, size: u32) -> Result<()> {
        if i >= self.n_dirs() {
            return Err(bad(format!("no data directory {i}")));
        }
        let o = self.dir_entry_offset(i);
        put32(&mut self.data, o, addr);
        put32(&mut self.data, o + 4, size);
        Ok(())
    }

    /// The file offset of an RVA.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.sections
            .iter()
            .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size))
            .map(|s| (rva - s.virtual_address + s.raw_offset) as usize)
    }

    /// The certificate table (file offset, size), when signed.
    pub fn certificate_table(&self) -> Option<(usize, usize)> {
        let (off, size) = self.data_dir(dir::SECURITY);
        (off != 0 && size != 0).then_some((off as usize, size as usize))
    }

    /// Removes the certificate table (Authenticode signature) and its directory entry.
    pub fn strip_certificates(&mut self) -> Result<()> {
        if let Some((off, size)) = self.certificate_table() {
            if off + size != self.data.len() {
                return Err(bad("the certificate table isn't at the end of the file"));
            }
            self.data.truncate(off);
            self.set_data_dir(dir::SECURITY, 0, 0)?;
        }
        Ok(())
    }

    /// Sets the certificate table to `table` (already 8-byte aligned), appended at the end.
    pub(crate) fn set_certificate_table(&mut self, table: &[u8]) -> Result<()> {
        self.strip_certificates()?;
        let off = self.data.len();
        if off % 8 != 0 {
            return Err(bad("the file must be 8-byte aligned before the certificate table"));
        }
        self.data.extend_from_slice(table);
        self.set_data_dir(dir::SECURITY, off as u32, table.len() as u32)
    }

    /// Pads the file to a multiple of 8 bytes (needed before a certificate table).
    pub(crate) fn pad_to_8(&mut self) {
        while self.data.len() % 8 != 0 {
            self.data.push(0);
        }
    }

    /// Computes the PE checksum (what `CheckSumMappedFile` does).
    pub fn compute_checksum(&self) -> u32 {
        let skip = self.checksum_offset();
        let mut sum: u64 = 0;
        let mut i = 0;
        while i < self.data.len() {
            if i == skip {
                i += 4;
                continue;
            }
            let w = if i + 1 < self.data.len() { u16::from_le_bytes([self.data[i], self.data[i + 1]]) } else { u16::from(self.data[i]) };
            sum += u64::from(w);
            sum = (sum & 0xffff) + (sum >> 16);
            i += 2;
        }
        sum = (sum & 0xffff) + (sum >> 16);
        (sum as u32).wrapping_add(self.data.len() as u32)
    }

    /// Writes the correct checksum into the header.
    pub fn update_checksum(&mut self) {
        let c = self.compute_checksum();
        let o = self.checksum_offset();
        put32(&mut self.data, o, c);
    }

    /// The resource tree.
    pub fn resources(&self) -> Result<Resources> {
        let (rva, size) = self.data_dir(dir::RESOURCE);
        if rva == 0 || size == 0 {
            return Ok(Resources::default());
        }
        let base = self.rva_to_offset(rva).ok_or_else(|| bad("resource directory outside every section"))?;
        let mut out = Resources::default();
        let d = &self.data;
        let entries = |off: usize| -> Result<Vec<(ResId, u32)>> {
            let named = le16(d, off + 12)? as usize;
            let ids = le16(d, off + 14)? as usize;
            let mut v = Vec::new();
            for k in 0..named + ids {
                let e = off + 16 + 8 * k;
                let name = le32(d, e)?;
                let target = le32(d, e + 4)?;
                let id = if name & 0x8000_0000 != 0 {
                    let so = base + (name & 0x7fff_ffff) as usize;
                    let n = le16(d, so)? as usize;
                    let units: Vec<u16> = (0..n).map(|j| le16(d, so + 2 + 2 * j)).collect::<Result<_>>()?;
                    ResId::Name(String::from_utf16_lossy(&units))
                } else {
                    ResId::Id(name as u16)
                };
                v.push((id, target));
            }
            Ok(v)
        };
        for (ty, t) in entries(base)? {
            if t & 0x8000_0000 == 0 {
                return Err(bad("resource type entry isn't a directory"));
            }
            for (name, n) in entries(base + (t & 0x7fff_ffff) as usize)? {
                if n & 0x8000_0000 == 0 {
                    return Err(bad("resource name entry isn't a directory"));
                }
                for (lang, l) in entries(base + (n & 0x7fff_ffff) as usize)? {
                    let de = base + (l & 0x7fff_ffff) as usize;
                    let (drva, dsize) = (le32(d, de)?, le32(d, de + 4)? as usize);
                    let doff = self.rva_to_offset(drva).ok_or_else(|| bad("resource data outside every section"))?;
                    let bytes = d.get(doff..doff + dsize).ok_or_else(|| bad("resource data out of range"))?;
                    let lang = match lang {
                        ResId::Id(v) => v,
                        ResId::Name(_) => return Err(bad("named language")),
                    };
                    out.entries.insert((ty.clone(), name.clone(), lang), bytes.to_vec());
                }
            }
        }
        Ok(out)
    }

    /// Replaces the resource tree. Drops any certificate table first (re-sign afterwards).
    pub fn set_resources(&mut self, res: &Resources) -> Result<()> {
        self.strip_certificates()?;
        let fa = self.file_alignment();
        let sa = self.section_alignment();
        let last = self.sections.iter().max_by_key(|s| s.virtual_address).ok_or_else(|| bad("no sections"))?.clone();
        let raw_end = self.sections.iter().map(|s| s.raw_offset + s.raw_size).max().unwrap_or(0) as usize;
        if raw_end < self.data.len() {
            return Err(bad("the file has data after its last section (an installer stub?); can't add resources safely"));
        }
        // Reuse the last section when it is the resource section; otherwise append one.
        let (rva, idx) = if last.name == ".rsrc" && self.data_dir(dir::RESOURCE).0 == last.virtual_address {
            (last.virtual_address, self.sections.iter().position(|s| *s == last))
        } else {
            (align(last.virtual_address + last.virtual_size.max(1), sa), None)
        };
        let tree = res.build(rva);
        let raw_size = align(tree.len() as u32, fa);
        let mut body = tree.clone();
        body.resize(raw_size as usize, 0);
        let st = self.opt + le16(&self.data, self.coff + 16)? as usize;
        let header = match idx {
            Some(i) => {
                let s = &self.sections[i];
                self.data.truncate(s.raw_offset as usize);
                st + 40 * i
            }
            None => {
                let n = self.sections.len();
                let h = st + 40 * n;
                let first_raw = self.sections.iter().filter(|s| s.raw_size > 0).map(|s| s.raw_offset).min().unwrap_or(0) as usize;
                if h + 40 > first_raw.min(self.size_of_headers() as usize) {
                    return Err(bad("no room in the header for another section"));
                }
                if let Some(old) = self.sections.iter().position(|s| s.name == ".rsrc") {
                    // Keep the old bytes, under another name, so the new one is the only .rsrc.
                    let oh = st + 40 * old;
                    self.data[oh..oh + 8].copy_from_slice(b".rsrc_o\0");
                    self.sections[old].name = ".rsrc_o".into();
                }
                self.data[self.coff + 2..self.coff + 4].copy_from_slice(&((n + 1) as u16).to_le_bytes());
                h
            }
        };
        let raw_offset = align(self.data.len() as u32, fa);
        self.data.resize(raw_offset as usize, 0);
        self.data.extend_from_slice(&body);
        let mut sh = [0u8; 40];
        sh[..5].copy_from_slice(b".rsrc");
        sh[8..12].copy_from_slice(&(tree.len() as u32).to_le_bytes());
        sh[12..16].copy_from_slice(&rva.to_le_bytes());
        sh[16..20].copy_from_slice(&raw_size.to_le_bytes());
        sh[20..24].copy_from_slice(&raw_offset.to_le_bytes());
        sh[36..40].copy_from_slice(&0x4000_0040u32.to_le_bytes()); // initialized data, read
        self.data[header..header + 40].copy_from_slice(&sh);
        let sec = Section { name: ".rsrc".into(), virtual_size: tree.len() as u32, virtual_address: rva, raw_size, raw_offset, characteristics: 0x4000_0040 };
        match idx {
            Some(i) => self.sections[i] = sec,
            None => self.sections.push(sec),
        }
        let image_end = self.sections.iter().map(|s| align(s.virtual_address + s.virtual_size.max(s.raw_size), sa)).max().unwrap_or(0);
        put32(&mut self.data, self.opt + 56, image_end);
        self.set_data_dir(dir::RESOURCE, rva, tree.len() as u32)?;
        self.update_checksum();
        Ok(())
    }

    /// Sets the icon (replacing every icon and icon group) from an `.ico` file's bytes.
    pub fn set_icon(&mut self, ico_file: &[u8]) -> Result<()> {
        let mut r = self.resources()?;
        r.set_icon(&ico::read(ico_file)?);
        self.set_resources(&r)
    }

    /// Sets the version information.
    pub fn set_version_info(&mut self, v: &VersionInfo) -> Result<()> {
        let mut r = self.resources()?;
        r.remove_type(rt::VERSION);
        r.entries.insert((ResId::Id(rt::VERSION), ResId::Id(1), LANG_EN_US), v.to_bytes(self.is_dll()));
        self.set_resources(&r)
    }

    /// Sets the application manifest (resource 1).
    pub fn set_manifest(&mut self, xml: &[u8]) -> Result<()> {
        let mut r = self.resources()?;
        r.remove_type(rt::MANIFEST);
        r.entries.insert((ResId::Id(rt::MANIFEST), ResId::Id(1), LANG_EN_US), xml.to_vec());
        self.set_resources(&r)
    }
}

/// Resource types (`RT_*`).
pub mod rt {
    /// `RT_ICON`.
    pub const ICON: u16 = 3;
    /// `RT_GROUP_ICON`.
    pub const GROUP_ICON: u16 = 14;
    /// `RT_VERSION`.
    pub const VERSION: u16 = 16;
    /// `RT_MANIFEST`.
    pub const MANIFEST: u16 = 24;
}

/// English (United States).
pub const LANG_EN_US: u16 = 0x0409;

/// A resource type or name: a number or a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResId {
    /// A string name (sorted before numbers, case-insensitively).
    Name(String),
    /// A number.
    Id(u16),
}

impl PartialOrd for ResId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ResId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self, other) {
            (ResId::Name(a), ResId::Name(b)) => a.to_uppercase().cmp(&b.to_uppercase()).then(a.cmp(b)),
            (ResId::Name(_), ResId::Id(_)) => Less,
            (ResId::Id(_), ResId::Name(_)) => Greater,
            (ResId::Id(a), ResId::Id(b)) => a.cmp(b),
        }
    }
}

/// A resource tree: (type, name, language) → data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resources {
    /// Every resource.
    pub entries: BTreeMap<(ResId, ResId, u16), Vec<u8>>,
}

impl Resources {
    /// Removes every resource of a type.
    pub fn remove_type(&mut self, ty: u16) {
        self.entries.retain(|(t, _, _), _| *t != ResId::Id(ty));
    }

    /// Replaces every icon and icon group with one group (id 1) of `images`.
    pub fn set_icon(&mut self, images: &[IconImage]) {
        self.remove_type(rt::ICON);
        self.remove_type(rt::GROUP_ICON);
        for (k, i) in images.iter().enumerate() {
            self.entries.insert((ResId::Id(rt::ICON), ResId::Id(1 + k as u16), LANG_EN_US), i.data.clone());
        }
        self.entries.insert((ResId::Id(rt::GROUP_ICON), ResId::Id(1), LANG_EN_US), ico::group_directory(images, 1));
    }

    /// Lays the tree out for a section at `rva`: directories, then data entries, then names,
    /// then data (8-byte aligned).
    fn build(&self, rva: u32) -> Vec<u8> {
        type Langs = BTreeMap<u16, Vec<u8>>;
        let mut tree: BTreeMap<ResId, BTreeMap<ResId, Langs>> = BTreeMap::new();
        for ((t, n, l), d) in &self.entries {
            tree.entry(t.clone()).or_default().entry(n.clone()).or_default().insert(*l, d.clone());
        }
        let dir_len = |n: usize| 16 + 8 * n;
        // Offsets: root, type directories, name directories, data entries.
        let mut off = dir_len(tree.len());
        let mut type_dirs = Vec::new();
        for names in tree.values() {
            type_dirs.push(off);
            off += dir_len(names.len());
        }
        let mut name_dirs = Vec::new();
        for names in tree.values() {
            for langs in names.values() {
                name_dirs.push(off);
                off += dir_len(langs.len());
            }
        }
        let n_leaves: usize = tree.values().flat_map(|n| n.values()).map(|l| l.len()).sum();
        let data_entries = off;
        off += 16 * n_leaves;
        // Names.
        let mut strings = Vec::new();
        let mut string_off: BTreeMap<String, usize> = BTreeMap::new();
        for (t, names) in &tree {
            for n in std::iter::once(t).chain(names.keys()) {
                if let ResId::Name(s) = n
                    && !string_off.contains_key(s)
                {
                    string_off.insert(s.clone(), off + strings.len());
                    let units: Vec<u16> = s.encode_utf16().collect();
                    strings.extend_from_slice(&(units.len() as u16).to_le_bytes());
                    for u in units {
                        strings.extend_from_slice(&u.to_le_bytes());
                    }
                }
            }
        }
        off += strings.len();
        let mut data_at = align(off as u32, 8) as usize;

        let mut out = vec![0u8; data_at];
        let write_dir = |out: &mut Vec<u8>, at: usize, ids: &[(ResId, u32)]| {
            let named = ids.iter().filter(|(i, _)| matches!(i, ResId::Name(_))).count();
            out[at + 12..at + 14].copy_from_slice(&(named as u16).to_le_bytes());
            out[at + 14..at + 16].copy_from_slice(&((ids.len() - named) as u16).to_le_bytes());
            for (k, (id, target)) in ids.iter().enumerate() {
                let e = at + 16 + 8 * k;
                let name = match id {
                    ResId::Id(v) => u32::from(*v),
                    ResId::Name(s) => 0x8000_0000 | string_off[s] as u32,
                };
                out[e..e + 4].copy_from_slice(&name.to_le_bytes());
                out[e + 4..e + 8].copy_from_slice(&target.to_le_bytes());
            }
        };
        let root: Vec<(ResId, u32)> = tree.keys().zip(&type_dirs).map(|(t, &o)| (t.clone(), 0x8000_0000 | o as u32)).collect();
        write_dir(&mut out, 0, &root);
        let (mut ni, mut li) = (0, 0);
        let mut blobs = Vec::new();
        for (ti, names) in tree.values().enumerate() {
            let mut entries = Vec::new();
            for (name, langs) in names {
                entries.push((name.clone(), 0x8000_0000 | name_dirs[ni] as u32));
                let mut le = Vec::new();
                for (lang, d) in langs {
                    let de = data_entries + 16 * li;
                    le.push((ResId::Id(*lang), de as u32));
                    out[de..de + 4].copy_from_slice(&(rva + data_at as u32).to_le_bytes());
                    out[de + 4..de + 8].copy_from_slice(&(d.len() as u32).to_le_bytes());
                    blobs.push((data_at, d));
                    data_at = align((data_at + d.len()) as u32, 8) as usize;
                    li += 1;
                }
                write_dir(&mut out, name_dirs[ni], &le);
                ni += 1;
            }
            write_dir(&mut out, type_dirs[ti], &entries);
        }
        let s0 = data_entries + 16 * n_leaves;
        out[s0..s0 + strings.len()].copy_from_slice(&strings);
        out.resize(data_at, 0);
        for (at, d) in blobs {
            out[at..at + d.len()].copy_from_slice(d);
        }
        out
    }
}

/// `VS_VERSIONINFO`: what Explorer's Details tab and Add/Remove Programs show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// File and product version, up to four parts (`1.4.0` → 1.4.0.0).
    pub version: [u16; 4],
    /// Display version string (`1.4.0`).
    pub version_string: String,
    /// `StringFileInfo` values (`ProductName`, `CompanyName`, `FileDescription`…).
    pub strings: Vec<(String, String)>,
}

impl VersionInfo {
    /// Version information for `version` (`major.minor.patch[.build]`).
    pub fn new(version: &str) -> Result<VersionInfo> {
        let core = version.split(['-', '+']).next().unwrap_or_default();
        let mut parts = [0u16; 4];
        for (i, p) in core.split('.').enumerate() {
            if i >= 4 {
                return Err(Error::invalid("version info", "version", format!("`{version}` has more than four parts")));
            }
            parts[i] = p.parse().map_err(|_| Error::invalid("version info", "version", format!("`{version}`: each part must be 0–65535")))?;
        }
        let s = version.to_string();
        Ok(VersionInfo { version: parts, version_string: s.clone(), strings: vec![("FileVersion".into(), s.clone()), ("ProductVersion".into(), s)] })
    }
    /// Sets a `StringFileInfo` value.
    pub fn string(mut self, key: &str, value: impl Into<String>) -> Self {
        self.strings.retain(|(k, _)| k != key);
        self.strings.push((key.to_string(), value.into()));
        self
    }
    /// Sets `ProductName` and `FileDescription`.
    pub fn product(self, name: &str) -> Self {
        self.string("ProductName", name).string("FileDescription", name)
    }

    /// The resource bytes.
    pub fn to_bytes(&self, dll: bool) -> Vec<u8> {
        fn utf16z(s: &str) -> Vec<u8> {
            s.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
        }
        fn pad4(b: &mut Vec<u8>) {
            while b.len() % 4 != 0 {
                b.push(0);
            }
        }
        // One node: wLength, wValueLength, wType, key, padding, value, padding, children.
        fn node(key: &str, value: &[u8], value_len: u16, text: bool, children: &[Vec<u8>]) -> Vec<u8> {
            let mut b = vec![0u8; 6];
            b[2..4].copy_from_slice(&value_len.to_le_bytes());
            b[4..6].copy_from_slice(&u16::from(text).to_le_bytes());
            b.extend_from_slice(&utf16z(key));
            pad4(&mut b);
            b.extend_from_slice(value);
            for c in children {
                pad4(&mut b);
                b.extend_from_slice(c);
            }
            let len = b.len() as u16;
            b[0..2].copy_from_slice(&len.to_le_bytes());
            b
        }
        let v = self.version;
        let ms = (u32::from(v[0]) << 16) | u32::from(v[1]);
        let ls = (u32::from(v[2]) << 16) | u32::from(v[3]);
        let mut fixed = Vec::with_capacity(52);
        for x in [0xfeef_04bd, 0x0001_0000, ms, ls, ms, ls, 0x3f, 0, 0x0004_0004, if dll { 2 } else { 1 }, 0, 0, 0] {
            fixed.extend_from_slice(&u32::to_le_bytes(x));
        }
        let strings: Vec<Vec<u8>> = self
            .strings
            .iter()
            .map(|(k, val)| {
                let mut b = utf16z(val);
                let chars = (b.len() / 2) as u16;
                pad4(&mut b);
                node(k, &b, chars, true, &[])
            })
            .collect();
        let table = node("040904b0", &[], 0, true, &strings);
        let sfi = node("StringFileInfo", &[], 0, true, &[table]);
        let translation = [0x09u8, 0x04, 0xb0, 0x04];
        let var = node("Translation", &translation, 4, false, &[]);
        let vfi = node("VarFileInfo", &[], 0, true, &[var]);
        node("VS_VERSION_INFO", &fixed, 52, false, &[sfi, vfi])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal valid PE32+ executable: headers and one code section (`ret`).
    pub(crate) fn tiny_exe() -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let c = 0x84;
        d[c..c + 2].copy_from_slice(&machine::AMD64.to_le_bytes());
        d[c + 2..c + 4].copy_from_slice(&1u16.to_le_bytes());
        d[c + 16..c + 18].copy_from_slice(&240u16.to_le_bytes());
        d[c + 18..c + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let o = c + 20;
        d[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        put32(&mut d, o + 16, 0x1000); // entry point
        d[o + 24..o + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        put32(&mut d, o + 32, 0x1000);
        put32(&mut d, o + 36, 0x200);
        d[o + 40..o + 42].copy_from_slice(&6u16.to_le_bytes());
        d[o + 48..o + 50].copy_from_slice(&6u16.to_le_bytes());
        put32(&mut d, o + 56, 0x2000);
        put32(&mut d, o + 60, 0x200);
        d[o + 68..o + 70].copy_from_slice(&3u16.to_le_bytes()); // console
        put32(&mut d, o + 108, 16);
        let s = o + 240;
        d[s..s + 5].copy_from_slice(b".text");
        put32(&mut d, s + 8, 1);
        put32(&mut d, s + 12, 0x1000);
        put32(&mut d, s + 16, 0x200);
        put32(&mut d, s + 20, 0x200);
        put32(&mut d, s + 36, 0x6000_0020);
        d[0x200] = 0xc3;
        d
    }

    #[test]
    fn resources_round_trip_and_icon() {
        let mut img = Image::parse(tiny_exe()).unwrap();
        assert_eq!(img.machine(), machine::AMD64);
        assert!(img.resources().unwrap().entries.is_empty());
        let mut pic = crate::image::Image::new(32, 32);
        pic.rgba.fill(200);
        img.set_icon(&ico::from_image(&pic)).unwrap();
        img.set_version_info(&VersionInfo::new("1.4.0").unwrap().product("My App").string("CompanyName", "Example Ltd")).unwrap();
        img.set_manifest(b"<assembly/>").unwrap();
        let r = img.resources().unwrap();
        assert_eq!(r.entries.keys().filter(|k| k.0 == ResId::Id(rt::ICON)).count(), ico::SIZES.len());
        let v = &r.entries[&(ResId::Id(rt::VERSION), ResId::Id(1), LANG_EN_US)];
        assert_eq!(u16::from_le_bytes([v[0], v[1]]) as usize, v.len());
        assert_eq!(&r.entries[&(ResId::Id(rt::MANIFEST), ResId::Id(1), LANG_EN_US)], b"<assembly/>");
        // Edits reuse the trailing .rsrc section instead of stacking new ones.
        assert_eq!(img.sections.len(), 2);
        assert_eq!(img.compute_checksum(), u32::from_le_bytes(img.bytes()[img.checksum_offset()..img.checksum_offset() + 4].try_into().unwrap()));
        // Named entries survive.
        let mut r2 = r.clone();
        r2.entries.insert((ResId::Name("CUSTOM".into()), ResId::Name("thing".into()), 0), vec![1, 2, 3]);
        img.set_resources(&r2).unwrap();
        assert_eq!(img.resources().unwrap(), r2);
    }
}
