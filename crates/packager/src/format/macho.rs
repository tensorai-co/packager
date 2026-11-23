//! Mach-O: reading 64-bit images and universal (fat) files, merging slices into a universal
//! binary (what `lipo -create` does), and reserving space for `LC_CODE_SIGNATURE`.

use crate::util::{le32, le64, put_le32, put_le64};
use crate::{Error, Result};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_MAGIC_32: u32 = 0xfeed_face;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_BUILD_VERSION: u32 = 0x32;

/// `MH_EXECUTE`.
pub const MH_EXECUTE: u32 = 2;
/// `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM64`.
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("mach-o", m)
}

/// Whether `data` starts like a Mach-O image or a universal binary.
pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let le = le32(data, 0);
    let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if le == MH_MAGIC_64 || le == MH_MAGIC_32 {
        return true;
    }
    // Java class files share 0xcafebabe; a fat header has a small arch count there.
    (be == FAT_MAGIC || be == FAT_MAGIC_64) && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) < 32
}

/// A segment load command.
#[derive(Debug, Clone)]
pub struct Segment {
    /// `segname`.
    pub name: String,
    /// Offset of the load command in the image.
    pub cmd_offset: usize,
    /// `vmaddr`.
    pub vmaddr: u64,
    /// `vmsize`.
    pub vmsize: u64,
    /// `fileoff`.
    pub fileoff: u64,
    /// `filesize`.
    pub filesize: u64,
}

/// A parsed 64-bit, little-endian Mach-O image (one architecture).
#[derive(Debug, Clone)]
pub struct Image {
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype`.
    pub cpusubtype: u32,
    /// `filetype` (`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`…).
    pub filetype: u32,
    /// `ncmds`.
    pub ncmds: u32,
    /// `sizeofcmds`.
    pub sizeofcmds: u32,
    /// Segments in load-command order.
    pub segments: Vec<Segment>,
    /// `LC_CODE_SIGNATURE` as (command offset, dataoff, datasize).
    pub code_signature: Option<(usize, u32, u32)>,
    /// Offset of the first byte of section data: load commands must end before it.
    pub first_section_offset: u64,
    /// The SDK version from `LC_BUILD_VERSION` / `LC_VERSION_MIN_MACOSX` (`xxxx.yy.zz` nibbles).
    pub sdk_version: Option<u32>,
}

impl Image {
    /// Parses a thin 64-bit image.
    pub fn parse(data: &[u8]) -> Result<Image> {
        if data.len() < 32 {
            return Err(bad("too short"));
        }
        match le32(data, 0) {
            MH_MAGIC_64 => {}
            MH_MAGIC_32 => return Err(bad("32-bit Mach-O isn't supported")),
            _ => return Err(bad("not a 64-bit little-endian Mach-O image")),
        }
        let ncmds = le32(data, 16);
        let sizeofcmds = le32(data, 20);
        let mut img = Image {
            cputype: le32(data, 4),
            cpusubtype: le32(data, 8),
            filetype: le32(data, 12),
            ncmds,
            sizeofcmds,
            segments: Vec::new(),
            code_signature: None,
            first_section_offset: data.len() as u64,
            sdk_version: None,
        };
        let end = 32 + sizeofcmds as usize;
        if end > data.len() {
            return Err(bad("load commands run past the end"));
        }
        let mut p = 32;
        for _ in 0..ncmds {
            if p + 8 > end {
                return Err(bad("truncated load command"));
            }
            let cmd = le32(data, p);
            let size = le32(data, p + 4) as usize;
            if size < 8 || p + size > end {
                return Err(bad("bad load command size"));
            }
            match cmd {
                LC_SEGMENT_64 if size >= 72 => {
                    let name = String::from_utf8_lossy(&data[p + 8..p + 24]).trim_end_matches('\0').to_string();
                    let seg = Segment {
                        name,
                        cmd_offset: p,
                        vmaddr: le64(data, p + 24),
                        vmsize: le64(data, p + 32),
                        fileoff: le64(data, p + 40),
                        filesize: le64(data, p + 48),
                    };
                    let nsects = le32(data, p + 64) as usize;
                    for s in 0..nsects {
                        let sp = p + 72 + s * 80;
                        if sp + 80 > p + size {
                            break;
                        }
                        let offset = le32(data, sp + 48) as u64;
                        let flags = le32(data, sp + 64);
                        let zerofill = matches!(flags & 0xff, 0x1 | 0xc | 0x12);
                        if offset != 0 && !zerofill && le64(data, sp + 40) != 0 {
                            img.first_section_offset = img.first_section_offset.min(offset);
                        }
                    }
                    img.segments.push(seg);
                }
                LC_BUILD_VERSION if size >= 24 => img.sdk_version = Some(le32(data, p + 16)),
                LC_VERSION_MIN_MACOSX if size >= 16 => img.sdk_version = Some(le32(data, p + 12)),
                LC_CODE_SIGNATURE if size >= 16 => {
                    img.code_signature = Some((p, le32(data, p + 8), le32(data, p + 12)));
                }
                _ => {}
            }
            p += size;
        }
        Ok(img)
    }

    /// A segment by name.
    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    /// The architecture name `lipo` uses.
    pub fn arch_name(&self) -> &'static str {
        match self.cputype {
            CPU_TYPE_ARM64 if self.cpusubtype & 0xff == 2 => "arm64e",
            CPU_TYPE_ARM64 => "arm64",
            CPU_TYPE_X86_64 => "x86_64",
            _ => "unknown",
        }
    }
}

/// Removes any existing signature and reserves `sig_size` bytes for a new one at the end of
/// `__LINKEDIT`, updating the load commands. Returns the code limit (where the signature starts).
pub fn reserve_signature(data: &mut Vec<u8>, sig_size: u32) -> Result<u32> {
    let img = Image::parse(data)?;
    let linkedit = img.segment("__LINKEDIT").ok_or_else(|| bad("no __LINKEDIT segment"))?.clone();
    let (cs_cmd, dataoff) = match img.code_signature {
        Some((cmd, off, _)) => (cmd, off as usize),
        None => {
            // Append a new LC_CODE_SIGNATURE after the existing load commands.
            let cmd = 32 + img.sizeofcmds as usize;
            if (cmd + 16) as u64 > img.first_section_offset {
                return Err(bad("no room for LC_CODE_SIGNATURE; relink with -headerpad"));
            }
            if data[cmd..cmd + 16].iter().any(|&b| b != 0) {
                return Err(bad("header padding isn't empty"));
            }
            put_le32(data, cmd, LC_CODE_SIGNATURE);
            put_le32(data, cmd + 4, 16);
            put_le32(data, 16, img.ncmds + 1);
            put_le32(data, 20, img.sizeofcmds + 16);
            let end = (linkedit.fileoff + linkedit.filesize) as usize;
            if end != data.len() {
                return Err(bad("__LINKEDIT doesn't end the file"));
            }
            (cmd, (end + 15) & !15)
        }
    };
    if dataoff < linkedit.fileoff as usize {
        return Err(bad("code signature before __LINKEDIT"));
    }
    data.truncate(dataoff);
    data.resize(dataoff, 0);
    put_le32(data, cs_cmd + 8, dataoff as u32);
    put_le32(data, cs_cmd + 12, sig_size);
    let filesize = dataoff as u64 + sig_size as u64 - linkedit.fileoff;
    let page = if img.cputype == CPU_TYPE_ARM64 { 0x4000 } else { 0x1000 };
    let vmsize = filesize.div_ceil(page) * page;
    put_le64(data, linkedit.cmd_offset + 32, vmsize);
    put_le64(data, linkedit.cmd_offset + 48, filesize);
    Ok(dataoff as u32)
}

/// One architecture slice of a (possibly universal) file.
#[derive(Debug, Clone)]
pub struct Slice {
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype`.
    pub cpusubtype: u32,
    /// Alignment as a power of two.
    pub align: u32,
    /// The slice bytes.
    pub data: Vec<u8>,
}

/// Splits a file into slices: one for a thin image, several for a universal binary.
pub fn slices(data: &[u8]) -> Result<Vec<Slice>> {
    if data.len() < 8 {
        return Err(bad("too short"));
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
        let img = Image::parse(data)?;
        return Ok(vec![Slice { cputype: img.cputype, cpusubtype: img.cpusubtype, align: default_align(img.cputype), data: data.to_vec() }]);
    }
    let be = |p: usize| u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
    let n = be(4) as usize;
    let entry = if magic == FAT_MAGIC_64 { 32 } else { 20 };
    if 8 + n * entry > data.len() {
        return Err(bad("truncated fat header"));
    }
    let mut out = Vec::new();
    for i in 0..n {
        let p = 8 + i * entry;
        let (offset, size, align) = if magic == FAT_MAGIC_64 {
            let o = (be(p + 8) as u64) << 32 | be(p + 12) as u64;
            let s = (be(p + 16) as u64) << 32 | be(p + 20) as u64;
            (o as usize, s as usize, be(p + 24))
        } else {
            (be(p + 8) as usize, be(p + 12) as usize, be(p + 16))
        };
        let bytes = data.get(offset..offset + size).ok_or_else(|| bad("slice out of range"))?;
        out.push(Slice { cputype: be(p), cpusubtype: be(p + 4), align, data: bytes.to_vec() });
    }
    Ok(out)
}

fn default_align(cputype: u32) -> u32 {
    if cputype == CPU_TYPE_ARM64 || cputype == CPU_TYPE_X86_64 { 14 } else { 12 }
}

/// Writes slices back out: the single image when there's one, else a universal binary with
/// slices sorted by CPU type (x86_64 before arm64, like `lipo`).
pub fn join(mut slices: Vec<Slice>) -> Result<Vec<u8>> {
    slices.sort_by_key(|s| (s.cputype == CPU_TYPE_ARM64, s.cputype, s.cpusubtype));
    for w in slices.windows(2) {
        if w[0].cputype == w[1].cputype && w[0].cpusubtype == w[1].cpusubtype {
            return Err(bad("two slices for the same architecture"));
        }
    }
    join_in_order(slices)
}

/// Like [`join`], keeping the slices in the order given.
pub fn join_in_order(mut slices: Vec<Slice>) -> Result<Vec<u8>> {
    match slices.len() {
        0 => return Err(bad("no slices")),
        1 => return Ok(slices.remove(0).data),
        _ => {}
    }
    let mut out = Vec::new();
    out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut offset = 8 + 20 * slices.len();
    let mut placed = Vec::new();
    for s in &slices {
        let a = 1usize << s.align;
        offset = offset.div_ceil(a) * a;
        if offset + s.data.len() > u32::MAX as usize {
            return Err(bad("universal binary over 4 GB"));
        }
        out.extend_from_slice(&s.cputype.to_be_bytes());
        out.extend_from_slice(&s.cpusubtype.to_be_bytes());
        out.extend_from_slice(&(offset as u32).to_be_bytes());
        out.extend_from_slice(&(s.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&s.align.to_be_bytes());
        placed.push(offset);
        offset += s.data.len();
    }
    for (s, off) in slices.iter().zip(placed) {
        out.resize(off, 0);
        out.extend_from_slice(&s.data);
    }
    Ok(out)
}

/// Merges thin or universal inputs into one universal binary.
pub fn merge_universal(inputs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut all = Vec::new();
    for i in inputs {
        all.extend(slices(i)?);
    }
    join(all)
}
