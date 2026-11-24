//! XAR archives: the container of flat `.pkg` installers. A 28-byte header, a zlib-compressed
//! XML table of contents, then the heap (the TOC's SHA-1 first, then file data).

use crate::compress::{unzlib, zlib, Level};
use crate::crypto::sha1;
use crate::format::xml::{self, Element};
use crate::util::{be16, be32, iso8601};
use crate::{Error, Result};

/// How a file's data is stored in the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Stored as is (`application/octet-stream`); used for already-compressed payloads.
    Raw,
    /// zlib-compressed (`application/x-gzip`, which in XAR means zlib).
    Zlib,
}

/// An entry to archive.
#[derive(Debug, Clone)]
pub enum XarEntry {
    /// A directory and its children.
    Dir {
        /// Name.
        name: String,
        /// Children.
        children: Vec<XarEntry>,
    },
    /// A file.
    File {
        /// Name.
        name: String,
        /// Contents.
        data: Vec<u8>,
        /// Storage encoding.
        encoding: Encoding,
    },
}

impl XarEntry {
    /// A zlib-compressed file.
    pub fn file(name: impl Into<String>, data: Vec<u8>) -> Self {
        XarEntry::File { name: name.into(), data, encoding: Encoding::Zlib }
    }
    /// A file stored raw.
    pub fn raw(name: impl Into<String>, data: Vec<u8>) -> Self {
        XarEntry::File { name: name.into(), data, encoding: Encoding::Raw }
    }
    /// A directory.
    pub fn dir(name: impl Into<String>, children: Vec<XarEntry>) -> Self {
        XarEntry::Dir { name: name.into(), children }
    }
}

/// Writes a XAR archive with SHA-1 checksums and a fixed creation time.
pub fn write(entries: &[XarEntry], mtime: i64) -> Result<Vec<u8>> {
    let mut heap = vec![0u8; 20]; // the TOC checksum goes first
    let mut next_id = 1;
    let mut files = Vec::new();
    for e in entries {
        files.push(entry_element(e, &mut heap, &mut next_id, mtime));
    }
    let checksum = Element::new("checksum").attr("style", "sha1").child(Element::new("offset").text("0")).child(Element::new("size").text("20"));
    let mut toc = Element::new("toc").child(checksum).child(Element::new("creation-time").text(iso8601(mtime).trim_end_matches('Z').to_string()));
    for f in files {
        toc = toc.child(f);
    }
    let toc_xml = Element::new("xar").child(toc).to_document(1);
    let toc_z = zlib(toc_xml.as_bytes(), Level::BEST);
    heap[..20].copy_from_slice(&sha1(&toc_z));

    let mut out = Vec::with_capacity(28 + toc_z.len() + heap.len());
    out.extend_from_slice(b"xar!");
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(toc_z.len() as u64).to_be_bytes());
    out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes()); // SHA-1
    out.extend_from_slice(&toc_z);
    out.extend_from_slice(&heap);
    Ok(out)
}

fn common(el: Element, id: u32, name: &str, ty: &str, mode: &str, mtime: i64) -> Element {
    let t = iso8601(mtime);
    let mut el = el.attr("id", id.to_string());
    for (k, v) in [("name", name), ("type", ty), ("mode", mode), ("uid", "0"), ("user", "root"), ("gid", "0"), ("group", "wheel"), ("mtime", &t)] {
        el = el.child(Element::new(k).text(v));
    }
    el
}

fn entry_element(e: &XarEntry, heap: &mut Vec<u8>, next_id: &mut u32, mtime: i64) -> Element {
    let id = *next_id;
    *next_id += 1;
    match e {
        XarEntry::Dir { name, children } => {
            let mut el = common(Element::new("file"), id, name, "directory", "0755", mtime);
            for c in children {
                el = el.child(entry_element(c, heap, next_id, mtime));
            }
            el
        }
        XarEntry::File { name, data, encoding } => {
            let stored = match encoding {
                Encoding::Raw => data.clone(),
                Encoding::Zlib => zlib(data, Level::BEST),
            };
            let offset = heap.len();
            heap.extend_from_slice(&stored);
            let style = match encoding {
                Encoding::Raw => "application/octet-stream",
                Encoding::Zlib => "application/x-gzip",
            };
            let d = Element::new("data")
                .child(Element::new("length").text(stored.len().to_string()))
                .child(Element::new("offset").text(offset.to_string()))
                .child(Element::new("size").text(data.len().to_string()))
                .child(Element::new("encoding").attr("style", style))
                .child(Element::new("archived-checksum").attr("style", "sha1").text(crate::crypto::hex(&sha1(&stored))))
                .child(Element::new("extracted-checksum").attr("style", "sha1").text(crate::crypto::hex(&sha1(data))));
            common(Element::new("file"), id, name, "file", "0644", mtime).child(d)
        }
    }
}

/// The raw parts of an archive: header length, compressed TOC, parsed `<xar>` root and heap
/// (which ends before any stapled notarization ticket).
#[derive(Debug, Clone)]
pub struct Parts<'a> {
    /// The compressed table of contents, as stored.
    pub toc_compressed: &'a [u8],
    /// The `<xar>` root element.
    pub root: Element,
    /// The heap.
    pub heap: &'a [u8],
}

/// Splits an archive into its parts, checking the header and the TOC checksum.
pub fn parts(data: &[u8]) -> Result<Parts<'_>> {
    let bad = |m: &str| Error::malformed("xar", m);
    let data = without_ticket(data);
    if data.len() < 28 || &data[..4] != b"xar!" {
        return Err(bad("missing `xar!` header"));
    }
    let hsize = be16(data, 4) as usize;
    let toc_len = u64::from_be_bytes(data[8..16].try_into().unwrap_or_default()) as usize;
    if be32(data, 24) != 1 {
        return Err(bad("only SHA-1 checksums are supported"));
    }
    let toc_compressed = data.get(hsize..hsize.saturating_add(toc_len)).ok_or_else(|| bad("truncated TOC"))?;
    let heap = &data[hsize + toc_len..];
    let toc_xml = String::from_utf8(unzlib(toc_compressed)?).map_err(|_| bad("TOC isn't UTF-8"))?;
    let root = xml::parse(&toc_xml)?;
    let toc = root.find("toc").ok_or_else(|| bad("no <toc>"))?;
    let num = |e: Option<&Element>, k: &str| e.and_then(|e| e.find(k)).and_then(|x| x.text_content().trim().parse::<usize>().ok());
    let ck = toc.find("checksum");
    let (off, size) = (num(ck, "offset").unwrap_or(0), num(ck, "size").unwrap_or(20));
    if heap.get(off..off + size) != Some(&sha1(toc_compressed)[..]) {
        return Err(bad("TOC checksum mismatch"));
    }
    Ok(Parts { toc_compressed, root, heap })
}

/// The TOC checksum (SHA-1 of the compressed TOC): what installer signatures sign and what a
/// notarization ticket for the archive is filed under.
pub fn toc_checksum(data: &[u8]) -> Result<[u8; 20]> {
    Ok(sha1(parts(data)?.toc_compressed))
}

const TICKET_TRAILER: &[u8; 4] = b"t8lr";

/// The archive without a stapled notarization ticket (see [`crate::staple`]): a `t8lr`
/// terminator record, the ticket, then a `t8lr` ticket record (16 bytes each, little-endian).
pub fn without_ticket(data: &[u8]) -> &[u8] {
    match ticket_span(data) {
        Some((start, _)) => &data[..start],
        None => data,
    }
}

/// (start of the stapled records, ticket range) when a ticket is stapled.
pub(crate) fn ticket_span(data: &[u8]) -> Option<(usize, std::ops::Range<usize>)> {
    let le16 = |b: &[u8], p: usize| u16::from_le_bytes([b[p], b[p + 1]]);
    let t = data.get(data.len().checked_sub(16)?..)?;
    if &t[..4] != TICKET_TRAILER || le16(t, 6) != 2 {
        return None;
    }
    let len = u32::from_le_bytes(t[8..12].try_into().ok()?) as usize;
    let ticket_start = data.len().checked_sub(16)?.checked_sub(len)?;
    let term = data.get(ticket_start.checked_sub(16)?..ticket_start)?;
    if &term[..4] != TICKET_TRAILER || le16(term, 6) != 1 {
        return None;
    }
    Some((ticket_start - 16, ticket_start..ticket_start + len))
}

/// The 16-byte `t8lr` record: magic, version 1, `kind` (1 terminator, 2 ticket), length, unused.
pub(crate) fn ticket_record(kind: u16, len: u32) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..4].copy_from_slice(TICKET_TRAILER);
    r[4..6].copy_from_slice(&1u16.to_le_bytes());
    r[6..8].copy_from_slice(&kind.to_le_bytes());
    r[8..12].copy_from_slice(&len.to_le_bytes());
    r
}

/// A file read back from an archive.
#[derive(Debug, Clone)]
pub struct XarFile {
    /// Path with `/` separators.
    pub path: String,
    /// Decoded contents.
    pub data: Vec<u8>,
}

/// Reads every file of a XAR archive, verifying the TOC and data checksums.
pub fn read(data: &[u8]) -> Result<(Element, Vec<XarFile>)> {
    let bad = |m: &str| Error::malformed("xar", m);
    let data = without_ticket(data);
    if data.len() < 28 || &data[..4] != b"xar!" {
        return Err(bad("missing `xar!` header"));
    }
    let hsize = be16(data, 4) as usize;
    let toc_len = u64::from_be_bytes(data[8..16].try_into().unwrap_or_default()) as usize;
    if be32(data, 24) != 1 {
        return Err(bad("only SHA-1 checksums are supported"));
    }
    let toc_z = data.get(hsize..hsize + toc_len).ok_or_else(|| bad("truncated TOC"))?;
    let heap = &data[hsize + toc_len..];
    if heap.get(..20) != Some(&sha1(toc_z)[..]) {
        return Err(bad("TOC checksum mismatch"));
    }
    let toc_xml = String::from_utf8(unzlib(toc_z)?).map_err(|_| bad("TOC isn't UTF-8"))?;
    let root = xml::parse(&toc_xml)?;
    let toc = root.find("toc").ok_or_else(|| bad("no <toc>"))?.clone();
    let mut out = Vec::new();
    fn walk(el: &Element, prefix: &str, heap: &[u8], out: &mut Vec<XarFile>) -> Result<()> {
        let bad = |m: &str| Error::malformed("xar", m);
        for f in el.elements().filter(|e| e.name == "file") {
            let name = f.find("name").map(|n| n.text_content()).unwrap_or_default();
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            if let Some(d) = f.find("data") {
                let num = |k: &str| d.find(k).and_then(|x| x.text_content().trim().parse::<usize>().ok()).ok_or_else(|| bad("bad <data>"));
                let (off, len) = (num("offset")?, num("length")?);
                let stored = heap.get(off..off + len).ok_or_else(|| bad("data out of range"))?;
                if let Some(c) = d.find("archived-checksum")
                    && c.text_content().trim() != crate::crypto::hex(&sha1(stored))
                {
                    return Err(bad("archived checksum mismatch"));
                }
                let style = d.find("encoding").and_then(|e| e.get_attr("style")).unwrap_or("application/octet-stream");
                let data = if style == "application/x-gzip" { unzlib(stored)? } else { stored.to_vec() };
                out.push(XarFile { path: path.clone(), data });
            }
            walk(f, &path, heap, out)?;
        }
        Ok(())
    }
    walk(&toc, "", heap, &mut out)?;
    Ok((toc, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let x = write(&[XarEntry::file("Distribution", b"<d/>".to_vec()), XarEntry::dir("a.pkg", vec![XarEntry::raw("Payload", vec![9; 1000])])], 0).unwrap();
        let (_, files) = read(&x).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "Distribution");
        assert_eq!(files[1].path, "a.pkg/Payload");
        assert_eq!(files[1].data, vec![9; 1000]);
    }
}
