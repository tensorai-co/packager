//! tar archives: POSIX ustar, with pax extended headers for long paths, long link targets and
//! sizes over 8 GiB (what `dpkg-deb` and GNU tar read). Entries use the [`cpio::Node`] tree model.
//!
//! [`cpio::Node`]: crate::format::cpio::Node

use crate::format::cpio::{Node, NodeKind};
use crate::{Error, Result};

const BLOCK: usize = 512;

/// Writes `nodes` in order as a tar archive (ending with the two zero blocks).
///
/// Directories get a trailing `/`, as GNU tar writes them. Owners are written as numbers plus
/// `root` names for id 0.
pub fn write(nodes: &[Node]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for n in nodes {
        let mut name = n.path.clone();
        if matches!(n.kind, NodeKind::Dir) && !name.ends_with('/') {
            name.push('/');
        }
        let (link, typeflag) = match &n.kind {
            NodeKind::Dir => (String::new(), b'5'),
            NodeKind::File(_) => (String::new(), b'0'),
            NodeKind::Symlink(t) => (t.clone(), b'2'),
        };
        let size = if let NodeKind::File(d) = &n.kind { d.len() as u64 } else { 0 };
        let split = split_ustar(&name);
        let mut pax = String::new();
        if split.is_none() {
            pax_record(&mut pax, "path", &name);
        }
        if link.len() > 100 {
            pax_record(&mut pax, "linkpath", &link);
        }
        if size > 0o77777777777 {
            pax_record(&mut pax, "size", &size.to_string());
        }
        if !pax.is_empty() {
            let base = name.trim_end_matches('/').rsplit('/').next().unwrap_or("x");
            let pax_name: String = format!("./PaxHeaders/{base}").chars().take(100).collect();
            let hdr = header(&pax_name, "", 0o644, 0, 0, pax.len() as u64, n.mtime, b'x', "")?;
            out.extend_from_slice(&hdr);
            out.extend_from_slice(pax.as_bytes());
            pad(&mut out);
        }
        let (prefix, short) = split.unwrap_or_else(|| (String::new(), truncate_utf8(&name, 100)));
        let link_short = truncate_utf8(&link, 100);
        let hdr = header(&short, &prefix, n.perm, n.uid, n.gid, size, n.mtime, typeflag, &link_short)?;
        out.extend_from_slice(&hdr);
        if let NodeKind::File(d) = &n.kind {
            out.extend_from_slice(d);
            pad(&mut out);
        }
    }
    out.extend_from_slice(&[0u8; BLOCK * 2]);
    Ok(out)
}

fn pad(out: &mut Vec<u8>) {
    let rem = out.len() % BLOCK;
    if rem != 0 {
        out.resize(out.len() + BLOCK - rem, 0);
    }
}

fn truncate_utf8(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Splits a path into ustar `prefix` (≤155 bytes) and `name` (≤100 bytes) at a `/`.
fn split_ustar(path: &str) -> Option<(String, String)> {
    if path.len() <= 100 {
        return Some((String::new(), path.to_string()));
    }
    // Keep a directory's trailing slash in the name part.
    let body = path.trim_end_matches('/');
    let trail = &path[body.len()..];
    for (i, _) in body.match_indices('/') {
        let (pre, rest) = (&body[..i], &body[i + 1..]);
        if pre.len() <= 155 && rest.len() + trail.len() <= 100 && !rest.is_empty() {
            return Some((pre.to_string(), format!("{rest}{trail}")));
        }
    }
    None
}

fn pax_record(out: &mut String, key: &str, value: &str) {
    // "<len> <key>=<value>\n", where <len> counts itself.
    let body = key.len() + value.len() + 3;
    let mut len = body + 1;
    while body + len.to_string().len() != len {
        len = body + len.to_string().len();
    }
    out.push_str(&format!("{len} {key}={value}\n"));
}

fn octal(field: &mut [u8], v: u64) -> Result<()> {
    let digits = field.len() - 1;
    let s = format!("{v:0digits$o}");
    if s.len() > digits {
        return Err(Error::Other(format!("tar: {v} doesn't fit a {digits}-digit field")));
    }
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn header(name: &str, prefix: &str, perm: u32, uid: u32, gid: u32, size: u64, mtime: i64, typeflag: u8, link: &str) -> Result<[u8; BLOCK]> {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], u64::from(perm & 0o7777))?;
    octal(&mut h[108..116], u64::from(uid))?;
    octal(&mut h[116..124], u64::from(gid))?;
    octal(&mut h[124..136], size.min(0o77777777777))?;
    octal(&mut h[136..148], mtime.max(0) as u64)?;
    h[156] = typeflag;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    for (at, id) in [(265usize, uid), (297, gid)] {
        if id == 0 {
            h[at..at + 4].copy_from_slice(b"root");
        }
    }
    octal(&mut h[329..337], 0)?;
    octal(&mut h[337..345], 0)?;
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let s = format!("{sum:06o}");
    h[148..154].copy_from_slice(s.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

fn parse_octal(field: &[u8]) -> Result<u64> {
    // GNU base-256 for large values.
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = u64::from(field[0] & 0x7f);
        for &b in &field[1..] {
            v = v.checked_mul(256).ok_or_else(|| Error::malformed("tar", "number too large"))? | u64::from(b);
        }
        return Ok(v);
    }
    let s: String = field.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| Error::malformed("tar", format!("bad number `{s}`")))
}

fn cstr(field: &[u8]) -> String {
    String::from_utf8_lossy(&field[..field.iter().position(|&b| b == 0).unwrap_or(field.len())]).into_owned()
}

/// Reads a tar archive into nodes (paths as stored, trailing `/` of directories removed).
/// Understands ustar, pax `path` / `linkpath` / `size` records and GNU long names.
pub fn read(data: &[u8]) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    let mut p = 0;
    let mut pax_path: Option<String> = None;
    let mut pax_link: Option<String> = None;
    let mut pax_size: Option<u64> = None;
    while p + BLOCK <= data.len() {
        let h = &data[p..p + BLOCK];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let stored: u32 = parse_octal(&h[148..156])? as u32;
        let sum: u32 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u32::from(b) }).sum();
        if stored != sum {
            return Err(Error::malformed("tar", format!("header checksum mismatch at offset {p}")));
        }
        let size = pax_size.take().map_or_else(|| parse_octal(&h[124..136]), Ok)? as usize;
        let body_start = p + BLOCK;
        let body = data.get(body_start..body_start + size).ok_or_else(|| Error::malformed("tar", "truncated entry"))?;
        p = body_start + size.div_ceil(BLOCK) * BLOCK;
        let typeflag = h[156];
        match typeflag {
            b'x' => {
                let mut rest = body;
                while !rest.is_empty() {
                    let sp = rest.iter().position(|&b| b == b' ').ok_or_else(|| Error::malformed("tar", "bad pax record"))?;
                    let len: usize = std::str::from_utf8(&rest[..sp]).ok().and_then(|s| s.parse().ok()).ok_or_else(|| Error::malformed("tar", "bad pax length"))?;
                    let rec = rest.get(sp + 1..len.saturating_sub(1)).ok_or_else(|| Error::malformed("tar", "bad pax record"))?;
                    let rec = String::from_utf8_lossy(rec);
                    if let Some((k, v)) = rec.split_once('=') {
                        match k {
                            "path" => pax_path = Some(v.to_string()),
                            "linkpath" => pax_link = Some(v.to_string()),
                            "size" => pax_size = v.parse().ok(),
                            _ => {}
                        }
                    }
                    rest = rest.get(len..).ok_or_else(|| Error::malformed("tar", "bad pax record"))?;
                }
                continue;
            }
            b'g' => continue,
            b'L' => {
                pax_path = Some(cstr(body));
                continue;
            }
            b'K' => {
                pax_link = Some(cstr(body));
                continue;
            }
            _ => {}
        }
        let mut name = cstr(&h[..100]);
        let prefix = if &h[257..262] == b"ustar" { cstr(&h[345..500]) } else { String::new() };
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let name = pax_path.take().unwrap_or(name);
        let link = pax_link.take().unwrap_or_else(|| cstr(&h[157..257]));
        let kind = match typeflag {
            b'5' => NodeKind::Dir,
            b'2' => NodeKind::Symlink(link),
            b'0' | 0 | b'7' => NodeKind::File(body.to_vec()),
            other => return Err(Error::malformed("tar", format!("unsupported entry type `{}` for {name}", other as char))),
        };
        let path = if name.len() > 1 { name.trim_end_matches('/').to_string() } else { name };
        out.push(Node {
            path,
            kind,
            perm: parse_octal(&h[100..108])? as u32 & 0o7777,
            uid: parse_octal(&h[108..116])? as u32,
            gid: parse_octal(&h[116..124])? as u32,
            mtime: parse_octal(&h[136..148])? as i64,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, kind: NodeKind, perm: u32) -> Node {
        Node { path: path.into(), kind, perm, uid: 0, gid: 0, mtime: 315_532_800 }
    }

    #[test]
    fn round_trip() {
        let long_dir = format!("./usr/share/{}", "d".repeat(120));
        let very_long = format!("./{}/{}", "a".repeat(160), "b".repeat(120));
        let nodes = vec![
            node("./", NodeKind::Dir, 0o755),
            node("./usr", NodeKind::Dir, 0o755),
            node("./usr/bin/tool", NodeKind::File(b"#!/bin/sh\necho hi\n".to_vec()), 0o755),
            node("./usr/bin/link", NodeKind::Symlink("../lib/x/tool".into()), 0o777),
            node(&long_dir, NodeKind::Dir, 0o755),
            node(&format!("{long_dir}/file.txt"), NodeKind::File(vec![7; 1000]), 0o644),
            node(&very_long, NodeKind::File(vec![]), 0o644),
            node("./l2", NodeKind::Symlink("t".repeat(150)), 0o777),
        ];
        let t = write(&nodes).unwrap();
        assert_eq!(t.len() % 512, 0);
        let back = read(&t).unwrap();
        assert_eq!(back.len(), nodes.len());
        for (a, b) in nodes.iter().zip(&back) {
            let want = if a.path.len() > 1 { a.path.trim_end_matches('/') } else { &a.path };
            assert_eq!(b.path, want);
            assert_eq!(b.kind, a.kind, "{}", a.path);
            assert_eq!(b.perm, a.perm);
            assert_eq!(b.mtime, a.mtime);
        }
        // Owner names as dpkg-deb writes them.
        assert_eq!(&t[265..269], b"root");
    }

    #[test]
    fn pax_lengths() {
        let mut s = String::new();
        pax_record(&mut s, "path", "x");
        assert_eq!(s, "9 path=x\n");
        let mut s = String::new();
        pax_record(&mut s, "path", &"y".repeat(93));
        assert_eq!(s.len(), s.split(' ').next().unwrap().parse::<usize>().unwrap());
    }
}
