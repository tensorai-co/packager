//! ELF executables: enough to check a binary's architecture and list what it links against
//! (`DT_NEEDED`, the interpreter), as `.deb` and `.snap` building needs.

use crate::{Error, Result};

/// `e_machine` values.
pub mod machine {
    /// x86 (32-bit).
    pub const X86: u16 = 3;
    /// 32-bit Arm.
    pub const ARM: u16 = 40;
    /// x86-64.
    pub const X86_64: u16 = 62;
    /// 64-bit Arm.
    pub const AARCH64: u16 = 183;
    /// RISC-V.
    pub const RISCV: u16 = 243;
}

/// What a parsed ELF file says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf {
    /// 64-bit (`ELFCLASS64`).
    pub is_64: bool,
    /// Little-endian.
    pub little_endian: bool,
    /// `e_type`: 2 executable, 3 shared object (also position-independent executables).
    pub kind: u16,
    /// `e_machine` (see [`machine`]).
    pub machine: u16,
    /// The program interpreter (`/lib64/ld-linux-x86-64.so.2`), `None` for static binaries.
    pub interpreter: Option<String>,
    /// Libraries from `DT_NEEDED`, in order.
    pub needed: Vec<String>,
    /// `DT_SONAME`, for shared libraries.
    pub soname: Option<String>,
    /// Symbol versions needed from each library (`DT_VERNEED`): (`libc.so.6`, [`GLIBC_2.34`, …]).
    pub version_needs: Vec<(String, Vec<String>)>,
}

/// Whether `data` starts with the ELF magic.
pub fn is_elf(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF")
}

impl Elf {
    /// Parses the headers, program headers and dynamic section.
    pub fn parse(data: &[u8]) -> Result<Elf> {
        let bad = |m: &str| Error::malformed("elf", m);
        if !is_elf(data) || data.len() < 52 {
            return Err(bad("not an ELF file"));
        }
        let is_64 = match data[4] {
            1 => false,
            2 => true,
            _ => return Err(bad("unknown class")),
        };
        let le = match data[5] {
            1 => true,
            2 => false,
            _ => return Err(bad("unknown byte order")),
        };
        let u16_at = |at: usize| -> Result<u16> {
            let b = data.get(at..at + 2).ok_or_else(|| bad("truncated"))?;
            Ok(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
        };
        let u32_at = |at: usize| -> Result<u32> {
            let b: [u8; 4] = data.get(at..at + 4).ok_or_else(|| bad("truncated"))?.try_into().map_err(|_| bad("truncated"))?;
            Ok(if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
        };
        let u64_at = |at: usize| -> Result<u64> {
            let b: [u8; 8] = data.get(at..at + 8).ok_or_else(|| bad("truncated"))?.try_into().map_err(|_| bad("truncated"))?;
            Ok(if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
        };
        let word = |at: usize| -> Result<u64> { if is_64 { u64_at(at) } else { u32_at(at).map(u64::from) } };
        let kind = u16_at(16)?;
        let machine = u16_at(18)?;
        let (phoff, phentsize, phnum) = if is_64 { (u64_at(32)?, u16_at(54)?, u16_at(56)?) } else { (u64::from(u32_at(28)?), u16_at(42)?, u16_at(44)?) };

        struct Ph {
            kind: u32,
            offset: u64,
            vaddr: u64,
            filesz: u64,
        }
        let mut phs = Vec::new();
        for i in 0..u64::from(phnum) {
            let at = usize::try_from(phoff + i * u64::from(phentsize)).map_err(|_| bad("bad program header offset"))?;
            let ph = if is_64 {
                Ph { kind: u32_at(at)?, offset: u64_at(at + 8)?, vaddr: u64_at(at + 16)?, filesz: u64_at(at + 32)? }
            } else {
                Ph { kind: u32_at(at)?, offset: u64::from(u32_at(at + 4)?), vaddr: u64::from(u32_at(at + 8)?), filesz: u64::from(u32_at(at + 16)?) }
            };
            phs.push(ph);
        }
        let slice = |off: u64, len: u64| -> Result<&[u8]> {
            let s = usize::try_from(off).map_err(|_| bad("offset too large"))?;
            let e = s.checked_add(usize::try_from(len).map_err(|_| bad("size too large"))?).ok_or_else(|| bad("overflow"))?;
            data.get(s..e).ok_or_else(|| bad("segment past end of file"))
        };
        let mut interpreter = None;
        let mut needed = Vec::new();
        let mut soname = None;
        let mut version_needs = Vec::new();
        if let Some(ph) = phs.iter().find(|p| p.kind == 3) {
            let raw = slice(ph.offset, ph.filesz)?;
            interpreter = Some(String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or_default()).into_owned());
        }
        if let Some(dynamic) = phs.iter().find(|p| p.kind == 2) {
            let ent = if is_64 { 16 } else { 8 };
            let mut entries = Vec::new();
            let start = usize::try_from(dynamic.offset).map_err(|_| bad("bad dynamic offset"))?;
            for i in 0..(dynamic.filesz as usize / ent) {
                let at = start + i * ent;
                let tag = word(at)?;
                let val = word(at + ent / 2)?;
                if tag == 0 {
                    break;
                }
                entries.push((tag, val));
            }
            // Dynamic-section addresses are virtual; map them through the PT_LOAD segments.
            let file_offset = |addr: u64| -> Result<u64> {
                let load = phs.iter().find(|p| p.kind == 1 && addr >= p.vaddr && addr < p.vaddr + p.filesz).ok_or_else(|| bad("dynamic address outside every segment"))?;
                Ok(load.offset + (addr - load.vaddr))
            };
            let tag = |t: u64| entries.iter().find(|e| e.0 == t).map(|e| e.1);
            let strtab = tag(5);
            let strsz = tag(10).unwrap_or(0);
            if let Some(addr) = strtab {
                let table = slice(file_offset(addr)?, strsz)?;
                let string = |off: u64| -> String {
                    let s = table.get(off as usize..).unwrap_or_default();
                    String::from_utf8_lossy(s.split(|&b| b == 0).next().unwrap_or_default()).into_owned()
                };
                for &(t, val) in &entries {
                    match t {
                        1 => needed.push(string(val)),
                        14 => soname = Some(string(val)),
                        _ => {}
                    }
                }
                // DT_VERNEED / DT_VERNEEDNUM: Elf_Verneed records, each with Elf_Vernaux entries.
                if let (Some(addr), Some(num)) = (tag(0x6fff_fffe), tag(0x6fff_ffff)) {
                    let mut at = usize::try_from(file_offset(addr)?).map_err(|_| bad("bad DT_VERNEED"))?;
                    for _ in 0..num.min(1024) {
                        let (cnt, file, aux, next) = (u16_at(at + 2)?, u32_at(at + 4)?, u32_at(at + 8)?, u32_at(at + 12)?);
                        let mut versions = Vec::new();
                        let mut a = at + aux as usize;
                        for _ in 0..cnt.min(1024) {
                            versions.push(string(u64::from(u32_at(a + 8)?)));
                            let anext = u32_at(a + 12)?;
                            if anext == 0 {
                                break;
                            }
                            a += anext as usize;
                        }
                        version_needs.push((string(u64::from(file)), versions));
                        if next == 0 {
                            break;
                        }
                        at += next as usize;
                    }
                }
            }
        }
        Ok(Elf { is_64, little_endian: le, kind, machine, interpreter, needed, soname, version_needs })
    }

    /// The newest glibc symbol version the binary needs (`(2, 34)` for `GLIBC_2.34`), if it
    /// links against glibc.
    pub fn min_glibc(&self) -> Option<(u32, u32, u32)> {
        let mut best = None;
        for (file, versions) in &self.version_needs {
            if !file.starts_with("libc.so") && !file.starts_with("libm.so") && !file.starts_with("libpthread.so") && !file.starts_with("libdl.so") && !file.starts_with("librt.so") {
                continue;
            }
            for v in versions {
                let Some(rest) = v.strip_prefix("GLIBC_") else { continue };
                let mut it = rest.split('.').map(|x| x.parse::<u32>().ok());
                let (Some(Some(a)), Some(Some(b))) = (it.next(), it.next()) else { continue };
                let c = it.next().flatten().unwrap_or(0);
                if best.is_none_or(|x| (a, b, c) > x) {
                    best = Some((a, b, c));
                }
            }
        }
        best
    }

    /// Whether it's dynamically linked against glibc (`libc.so.6` in `DT_NEEDED`).
    pub fn links_glibc(&self) -> bool {
        self.needed.iter().any(|n| n == "libc.so.6")
    }

    /// The Debian architecture name (`amd64`, `arm64`…), if it's one packager knows.
    pub fn debian_arch(&self) -> Option<&'static str> {
        Some(match (self.machine, self.is_64) {
            (machine::X86_64, true) => "amd64",
            (machine::AARCH64, true) => "arm64",
            (machine::X86, false) => "i386",
            (machine::ARM, false) => "armhf",
            (machine::RISCV, true) => "riscv64",
            _ => return None,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal 64-bit little-endian ELF executable header for `machine` (no segments).
    pub(crate) fn stub(machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[6] = 1;
        h[16..18].copy_from_slice(&3u16.to_le_bytes());
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        h[52..54].copy_from_slice(&64u16.to_le_bytes());
        h[54..56].copy_from_slice(&56u16.to_le_bytes());
        h
    }

    #[test]
    fn headers() {
        let e = Elf::parse(&stub(machine::X86_64)).unwrap();
        assert_eq!(e.debian_arch(), Some("amd64"));
        assert!(e.needed.is_empty() && e.interpreter.is_none());
        assert_eq!(Elf::parse(&stub(machine::AARCH64)).unwrap().debian_arch(), Some("arm64"));
        assert!(Elf::parse(b"MZ\0\0").is_err());
    }

    #[test]
    fn dynamic_section() {
        // One PT_LOAD covering the file, PT_INTERP and PT_DYNAMIC pointing into it.
        let mut f = stub(machine::X86_64);
        f[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        f[56..58].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
        let ph = |kind: u32, off: u64, size: u64| {
            let mut p = vec![0u8; 56];
            p[..4].copy_from_slice(&kind.to_le_bytes());
            p[8..16].copy_from_slice(&off.to_le_bytes());
            p[16..24].copy_from_slice(&(0x400000 + off).to_le_bytes());
            p[32..40].copy_from_slice(&size.to_le_bytes());
            p
        };
        let interp_at = 64 + 56 * 3;
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let str_at = interp_at + interp.len();
        let strs = b"\0libc.so.6\0libm.so.6\0";
        let dyn_at = str_at + strs.len();
        let dyns: Vec<(u64, u64)> = vec![(1, 1), (1, 11), (5, 0x400000 + str_at as u64), (10, strs.len() as u64), (0, 0)];
        f.extend(ph(1, 0, 4096));
        f.extend(ph(3, interp_at as u64, interp.len() as u64));
        f.extend(ph(2, dyn_at as u64, (dyns.len() * 16) as u64));
        f.extend_from_slice(interp);
        f.extend_from_slice(strs);
        for (t, v) in dyns {
            f.extend(t.to_le_bytes());
            f.extend(v.to_le_bytes());
        }
        f.resize(4096, 0);
        let e = Elf::parse(&f).unwrap();
        assert_eq!(e.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
        assert_eq!(e.needed, ["libc.so.6", "libm.so.6"]);
    }
}
