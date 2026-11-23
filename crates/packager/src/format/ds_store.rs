//! `.DS_Store`: Finder's per-folder view settings, stored as a B-tree of records inside a buddy
//! allocator ("Bud1"), and Finder aliases (alias record v2) used to point at a background image.
//!
//! Only what a disk-image window needs is written: window bounds and chrome (`bwsp`), icon-view
//! settings with an optional background picture (`icvp`), the view style, and icon positions.

use crate::format::plist::{Dict, Value};
use crate::util::PutBe;
use crate::{Error, Result};

/// Where the background picture lives, for its alias.
#[derive(Debug, Clone)]
pub struct Background {
    /// Volume name.
    pub volume_name: String,
    /// The volume's creation date (HFS seconds), which aliases match against.
    pub volume_created: u32,
    /// Folder holding the picture (`.background`) and its catalog node ID.
    pub folder: (String, u32),
    /// Picture file name and its catalog node ID.
    pub file: (String, u32),
}

/// A disk-image window layout.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Content size in points.
    pub window: (u32, u32),
    /// Icon size in points.
    pub icon_size: u32,
    /// Icon centers by item name.
    pub positions: Vec<(String, (u32, u32))>,
    /// Background picture, if any.
    pub background: Option<Background>,
}

enum Data {
    Long(u32),
    Type([u8; 4]),
    Blob(Vec<u8>),
}

struct Record {
    name: String,
    code: [u8; 4],
    data: Data,
}

impl Record {
    fn encode(&self, out: &mut Vec<u8>) {
        let units: Vec<u16> = self.name.encode_utf16().collect();
        out.u32(units.len() as u32);
        for u in units {
            out.u16(u);
        }
        out.extend_from_slice(&self.code);
        match &self.data {
            Data::Long(v) => {
                out.extend_from_slice(b"long");
                out.u32(*v);
            }
            Data::Type(t) => {
                out.extend_from_slice(b"type");
                out.extend_from_slice(t);
            }
            Data::Blob(b) => {
                out.extend_from_slice(b"blob");
                out.u32(b.len() as u32);
                out.extend_from_slice(b);
            }
        }
    }
}

/// Writes a `.DS_Store` for the volume root.
pub fn write(layout: &Layout) -> Result<Vec<u8>> {
    let (w, h) = layout.window;
    let bwsp = Dict::new()
        .with("ContainerShowSidebar", false)
        .with("PreviewPaneVisibility", false)
        .with("ShowPathbar", false)
        .with("ShowSidebar", false)
        .with("ShowStatusBar", false)
        .with("ShowTabView", false)
        .with("ShowToolbar", false)
        .with("SidebarWidth", 0i64)
        // Window frame: content plus the title bar.
        .with("WindowBounds", format!("{{{{200, 120}}, {{{w}, {}}}}}", h + 28));
    let mut icvp = Dict::new()
        .with("arrangeBy", "none")
        .with("backgroundColorBlue", Value::Real(1.0))
        .with("backgroundColorGreen", Value::Real(1.0))
        .with("backgroundColorRed", Value::Real(1.0))
        .with("backgroundType", if layout.background.is_some() { 2i64 } else { 0i64 })
        .with("gridOffsetX", Value::Real(0.0))
        .with("gridOffsetY", Value::Real(0.0))
        .with("gridSpacing", Value::Real(100.0))
        .with("iconSize", Value::Real(layout.icon_size as f64))
        .with("labelOnBottom", true)
        .with("showIconPreview", true)
        .with("showItemInfo", false)
        .with("textSize", Value::Real(12.0))
        .with("viewOptionsVersion", 1i64);
    if let Some(bg) = &layout.background {
        icvp.insert("backgroundImageAlias", Value::Data(alias(bg)?));
    }
    let mut records = vec![
        Record { name: ".".into(), code: *b"bwsp", data: Data::Blob(Value::Dict(bwsp).to_binary()) },
        Record { name: ".".into(), code: *b"icvp", data: Data::Blob(Value::Dict(icvp).to_binary()) },
        Record { name: ".".into(), code: *b"vSrn", data: Data::Long(1) },
        Record { name: ".".into(), code: *b"vstl", data: Data::Type(*b"icnv") },
    ];
    for (name, (x, y)) in &layout.positions {
        let mut b = Vec::with_capacity(16);
        b.u32(*x);
        b.u32(*y);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]);
        records.push(Record { name: name.clone(), code: *b"Iloc", data: Data::Blob(b) });
    }
    // Finder orders records by name (case-insensitively), then structure code.
    records.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.code.cmp(&b.code)));

    // One leaf node holds everything a disk-image window needs.
    let mut leaf = Vec::new();
    leaf.u32(0);
    leaf.u32(records.len() as u32);
    for r in &records {
        r.encode(&mut leaf);
    }
    if leaf.len() > 4096 {
        return Err(Error::Other("ds_store: records exceed one node".into()));
    }
    let mut dsdb = Vec::new();
    dsdb.u32(2); // root node block id
    dsdb.u32(0); // internal levels
    dsdb.u32(records.len() as u32);
    dsdb.u32(1); // nodes
    dsdb.u32(0x1000); // page size

    // Buddy allocator, offsets relative to byte 4: header [0,32), DSDB [32,64),
    // allocator info [2048,4096), leaf [4096,8192).
    let allocated: [(u32, u32); 4] = [(0, 32), (32, 32), (2048, 2048), (4096, 4096)];
    let addr = |off: u32, size: u32| off | size.trailing_zeros();
    let mut info = Vec::new();
    let blocks = [addr(2048, 2048), addr(32, 32), addr(4096, 4096)];
    info.u32(blocks.len() as u32);
    info.u32(0);
    for b in blocks {
        info.u32(b);
    }
    info.resize(8 + 256 * 4, 0);
    info.u32(1);
    info.u8(4);
    info.extend_from_slice(b"DSDB");
    info.u32(1);
    let mut free: Vec<Vec<u32>> = vec![Vec::new(); 32];
    free_blocks(0, 1 << 31, &allocated, &mut free);
    for list in &free {
        info.u32(list.len() as u32);
        for &o in list {
            info.u32(o);
        }
    }
    if info.len() > 2048 {
        return Err(Error::Other("ds_store: allocator info too large".into()));
    }

    let mut body = vec![0u8; 8192];
    body[0..4].copy_from_slice(b"Bud1");
    body[4..8].copy_from_slice(&2048u32.to_be_bytes());
    body[8..12].copy_from_slice(&2048u32.to_be_bytes());
    body[12..16].copy_from_slice(&2048u32.to_be_bytes());
    body[16..32].copy_from_slice(&[0, 0, 0x10, 0x0c, 0, 0, 0, 0x87, 0, 0, 0x20, 0x0b, 0, 0, 0, 0]);
    body[32..32 + dsdb.len()].copy_from_slice(&dsdb);
    body[2048..2048 + info.len()].copy_from_slice(&info);
    body[4096..4096 + leaf.len()].copy_from_slice(&leaf);
    let mut out = vec![0, 0, 0, 1];
    out.extend_from_slice(&body);
    Ok(out)
}

/// Splits `[off, off+size)` into the largest buddy blocks not overlapping `allocated`.
fn free_blocks(off: u32, size: u32, allocated: &[(u32, u32)], free: &mut [Vec<u32>]) {
    let end = off as u64 + size as u64;
    if allocated.iter().any(|&(o, s)| o == off && s == size) {
        return;
    }
    let overlaps = allocated.iter().any(|&(o, s)| (o as u64) < end && (o as u64 + s as u64) > off as u64);
    if !overlaps {
        free[size.trailing_zeros() as usize].push(off);
        return;
    }
    let half = size / 2;
    free_blocks(off, half, allocated, free);
    free_blocks(off + half, half, allocated, free);
}

fn mac_roman(s: &str) -> Vec<u8> {
    s.chars().map(|c| if c.is_ascii() && c != ':' { c as u8 } else { b'?' }).collect()
}

fn pascal(out: &mut Vec<u8>, s: &[u8], field: usize) {
    let n = s.len().min(field - 1);
    out.u8(n as u8);
    out.extend_from_slice(&s[..n]);
    out.resize(out.len() + field - 1 - n, 0);
}

fn utf16_field(s: &str) -> Vec<u8> {
    let u: Vec<u16> = s.encode_utf16().collect();
    let mut b = Vec::with_capacity(2 + u.len() * 2);
    b.u16(u.len() as u16);
    for x in u {
        b.u16(x);
    }
    b
}

/// An alias record (version 2) to a file on a mounted disk image.
pub fn alias(bg: &Background) -> Result<Vec<u8>> {
    if bg.volume_name.chars().count() > 27 {
        return Err(Error::invalid("dmg", "volume_name", "must be at most 27 characters for Finder aliases"));
    }
    let mut a = Vec::with_capacity(512);
    a.u32(0); // creator code
    a.u16(0); // record size, patched below
    a.u16(2); // version
    a.u16(0); // kind: file
    pascal(&mut a, &mac_roman(&bg.volume_name), 28);
    a.u32(bg.volume_created);
    a.extend_from_slice(b"H+");
    a.u16(5); // disk type: ejectable
    a.u32(bg.folder.1);
    pascal(&mut a, &mac_roman(&bg.file.0), 64);
    a.u32(bg.file.1);
    a.u32(bg.volume_created); // file creation date
    a.extend_from_slice(&[0u8; 8]); // type, creator
    a.u16(0xffff); // nlvlFrom
    a.u16(0xffff); // nlvlTo
    a.u32(0); // volume attributes
    a.u16(0); // volume file system ID
    a.extend_from_slice(&[0u8; 10]);
    debug_assert_eq!(a.len(), 150);
    let mut tag = |t: i16, data: &[u8]| {
        a.u16(t as u16);
        a.u16(data.len() as u16);
        a.extend_from_slice(data);
        if data.len() % 2 == 1 {
            a.u8(0);
        }
    };
    tag(0, &mac_roman(&bg.folder.0));
    tag(1, &bg.folder.1.to_be_bytes());
    tag(2, &mac_roman(&format!("{}:{}:{}", bg.volume_name, bg.folder.0, bg.file.0)));
    tag(14, &utf16_field(&bg.file.0));
    tag(15, &utf16_field(&bg.volume_name));
    tag(18, format!("/{}/{}", bg.folder.0, bg.file.0).as_bytes());
    tag(19, format!("/Volumes/{}", bg.volume_name).as_bytes());
    a.u16(0xffff);
    a.u16(0);
    let len = a.len() as u16;
    a[4..6].copy_from_slice(&len.to_be_bytes());
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes() {
        let l = Layout {
            window: (540, 380),
            icon_size: 128,
            positions: vec![("My App.app".into(), (140, 180)), ("Applications".into(), (400, 180))],
            background: Some(Background { volume_name: "My App".into(), volume_created: 1, folder: (".background".into(), 17), file: ("background.png".into(), 18) }),
        };
        let d = write(&l).unwrap();
        assert_eq!(&d[4..8], b"Bud1");
        assert_eq!(d.len(), 8196);
    }
}
