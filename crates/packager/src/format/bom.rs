//! `Bom` (bill of materials) files: the `BOMStore` block store `.pkg` installers carry to list
//! every installed path with its mode, owner, size and checksum.
//!
//! The format is undocumented. The layout here follows `pkgbuild`'s output (checked with
//! `lsbom`) and the open `bomutils` implementation for multi-page trees.

use crate::crypto::crc::posix_cksum;
use crate::format::cpio::{Node, NodeKind};
use crate::format::macho;
use crate::util::{be32, PutBe};
use crate::{Error, Result};

const LEAF_CAPACITY: usize = 256;
const PAGE: usize = 4096;

struct Store {
    blocks: Vec<Vec<u8>>, // block 0 is the null block
}

impl Store {
    fn add(&mut self, b: Vec<u8>) -> u32 {
        self.blocks.push(b);
        (self.blocks.len() - 1) as u32
    }
}

fn tree_block(child: u32, block_size: u32, count: u32) -> Vec<u8> {
    let mut b = b"tree".to_vec();
    b.u32(1);
    b.u32(child);
    b.u32(block_size);
    b.u32(count);
    b.u8(0);
    b
}

fn paths_block(leaf: bool, entries: &[(u32, u32)], forward: u32, backward: u32, pad_to: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(pad_to);
    b.u16(leaf as u16);
    b.u16(entries.len() as u16);
    b.u32(forward);
    b.u32(backward);
    for &(i0, i1) in entries {
        b.u32(i0);
        b.u32(i1);
    }
    if b.len() < pad_to {
        b.resize(pad_to, 0);
    }
    b
}

/// Builds a `Bom` for `nodes` (paths starting at `.`, as in the payload).
pub fn write(nodes: &[Node]) -> Result<Vec<u8>> {
    // Index nodes by path and give each its parent's index.
    let mut by_path = std::collections::HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        if by_path.insert(n.path.as_str(), i).is_some() {
            return Err(Error::invalid("pkg", n.path.clone(), "appears twice in the payload"));
        }
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut root = None;
    for (i, n) in nodes.iter().enumerate() {
        if n.path == "." {
            root = Some(i);
            continue;
        }
        let parent = n.path.rsplit_once('/').map(|(p, _)| p).unwrap_or(".");
        let pi = *by_path.get(parent).ok_or_else(|| Error::invalid("pkg", n.path.clone(), "has no parent directory in the payload"))?;
        children[pi].push(i);
    }
    let root = root.ok_or_else(|| Error::invalid("pkg", ".", "the payload has no root entry"))?;
    for c in &mut children {
        c.sort_by(|&a, &b| nodes[a].name().as_bytes().cmp(nodes[b].name().as_bytes()));
    }
    // Breadth-first order with ids 1.., so entries come sorted by (parent id, name).
    let mut order = vec![(root, 0u32)];
    let mut ids = vec![0u32; nodes.len()];
    let mut q = 0;
    while q < order.len() {
        let (i, _) = order[q];
        ids[i] = q as u32 + 1;
        for &c in &children[i] {
            order.push((c, q as u32 + 1));
        }
        q += 1;
    }

    let mut st = Store { blocks: vec![Vec::new()] };
    let mut arch_sizes: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut plain_size = 0u64;
    let mut leaf_entries: Vec<(u32, u32)> = Vec::with_capacity(order.len());
    for &(i, parent_id) in &order {
        let n = &nodes[i];
        let mut info = Vec::with_capacity(48);
        let (ty, slices) = match &n.kind {
            NodeKind::Dir => (2u8, Vec::new()),
            NodeKind::File(d) if macho::is_macho(d) => (1, macho::slices(d).unwrap_or_default()),
            NodeKind::File(_) => (1, Vec::new()),
            NodeKind::Symlink(_) => (3, Vec::new()),
        };
        info.u8(ty);
        info.u8(1);
        info.u16(((slices.len() as u16) << 12) | 0xf);
        info.u16(n.mode() as u16);
        info.u32(n.uid);
        info.u32(n.gid);
        info.u32(n.mtime.clamp(0, u32::MAX as i64) as u32);
        info.u32(n.size() as u32);
        info.u8(1);
        match &n.kind {
            NodeKind::Dir => {
                info.u32(0);
                info.u32(0);
            }
            NodeKind::Symlink(t) => {
                info.u32(posix_cksum(t.as_bytes()));
                info.u32(t.len() as u32 + 1);
                info.extend_from_slice(t.as_bytes());
                info.u8(0);
                info.u64(0);
            }
            NodeKind::File(d) => {
                info.u32(posix_cksum(d));
                if slices.is_empty() {
                    plain_size += d.len() as u64;
                    info.u32(0);
                    info.u32(0);
                } else {
                    info.u32(0x0100_0000);
                    info.u8(slices.len() as u8);
                    for s in &slices {
                        *arch_sizes.entry(s.cputype).or_default() += s.data.len() as u64;
                        info.u32(s.cputype);
                        info.u32(s.cpusubtype & 0x00ff_ffff);
                        info.u32(s.data.len() as u32);
                        info.u32(posix_cksum(&s.data));
                    }
                    info.u64(0);
                }
            }
        }
        let info_id = st.add(info);
        let mut p1 = Vec::with_capacity(8);
        p1.u32(ids[i]);
        p1.u32(info_id);
        let p1_id = st.add(p1);
        let mut f = Vec::with_capacity(n.name().len() + 5);
        f.u32(parent_id);
        f.extend_from_slice(if n.path == "." { b"." } else { n.name().as_bytes() });
        f.u8(0);
        let f_id = st.add(f);
        leaf_entries.push((p1_id, f_id));
    }

    // Leaves of up to 256 entries, linked both ways; an index root when there's more than one.
    let leaves: Vec<&[(u32, u32)]> = leaf_entries.chunks(LEAF_CAPACITY).collect();
    let paths_root = if leaves.len() <= 1 {
        st.add(paths_block(true, leaves.first().copied().unwrap_or(&[]), 0, 0, PAGE))
    } else {
        let mut ids_: Vec<u32> = Vec::new();
        for (k, chunk) in leaves.iter().enumerate() {
            let back = if k == 0 { 0 } else { ids_[k - 1] };
            ids_.push(st.add(paths_block(true, chunk, 0, back, PAGE)));
        }
        for k in 0..ids_.len().saturating_sub(1) {
            let next = ids_[k + 1];
            let b = &mut st.blocks[ids_[k] as usize];
            b[4..8].copy_from_slice(&next.to_be_bytes());
        }
        let index: Vec<(u32, u32)> = leaves.iter().zip(&ids_).map(|(chunk, &id)| (id, chunk[chunk.len() - 1].1)).collect();
        st.add(paths_block(false, &index, 0, 0, PAGE))
    };
    let paths = st.add(tree_block(paths_root, PAGE as u32, order.len() as u32));
    let hl_leaf = st.add(paths_block(true, &[], 0, 0, PAGE));
    let hlindex = st.add(tree_block(hl_leaf, PAGE as u32, 0));
    let v_leaf = st.add(paths_block(true, &[], 0, 0, 128));
    let v_tree = st.add(tree_block(v_leaf, 128, 0));
    let mut vindex = Vec::new();
    vindex.u32(1);
    vindex.u32(v_tree);
    vindex.u32(0);
    vindex.u8(0);
    let vindex = st.add(vindex);
    let s_leaf = st.add(paths_block(true, &[], 0, 0, PAGE));
    let size64 = st.add(tree_block(s_leaf, PAGE as u32, 0));

    let mut info = Vec::new();
    info.u32(1);
    info.u32(order.len() as u32 + 1);
    info.u32(1 + arch_sizes.len() as u32);
    for (cpu, size) in std::iter::once((0u32, plain_size)).chain(arch_sizes) {
        info.u32(cpu);
        info.u32(0);
        info.u32(size.min(u32::MAX as u64) as u32);
        info.u32(0);
    }
    let bominfo = st.add(info);

    // Layout: header (512), vars, block data, index table, free list.
    let mut vars = Vec::new();
    let names: [(&str, u32); 5] = [("BomInfo", bominfo), ("Paths", paths), ("HLIndex", hlindex), ("VIndex", vindex), ("Size64", size64)];
    vars.u32(names.len() as u32);
    for (n, b) in names {
        vars.u32(b);
        vars.u8(n.len() as u8);
        vars.extend_from_slice(n.as_bytes());
    }
    let mut out = vec![0u8; 512];
    out.extend_from_slice(&vars);
    let mut addrs = vec![(0u32, 0u32)];
    for b in &st.blocks[1..] {
        addrs.push((out.len() as u32, b.len() as u32));
        out.extend_from_slice(b);
    }
    let index_off = out.len();
    out.u32(addrs.len() as u32);
    for (a, l) in &addrs {
        out.u32(*a);
        out.u32(*l);
    }
    out.u32(0); // free list: no entries…
    out.extend_from_slice(&[0u8; 16]); // …and two empty pointers, as bomutils writes
    let index_len = out.len() - index_off;

    out[..8].copy_from_slice(b"BOMStore");
    let header = [1u32, (st.blocks.len() - 1) as u32, index_off as u32, index_len as u32, 512, vars.len() as u32];
    for (k, v) in header.iter().enumerate() {
        out[8 + k * 4..12 + k * 4].copy_from_slice(&v.to_be_bytes());
    }
    Ok(out)
}

/// One path read back from a `Bom`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BomPath {
    /// Path from the root (`.`, `./My App.app`…).
    pub path: String,
    /// Mode with type bits.
    pub mode: u16,
    /// Size.
    pub size: u32,
    /// POSIX cksum (0 for directories).
    pub checksum: u32,
}

/// Reads the paths of a `Bom`, following leaf links, in tree order.
pub fn read(data: &[u8]) -> Result<Vec<BomPath>> {
    let bad = |m: &str| Error::malformed("bom", m);
    if data.len() < 32 || &data[..8] != b"BOMStore" {
        return Err(bad("missing BOMStore header"));
    }
    let (index_off, vars_off) = (be32(data, 16) as usize, be32(data, 24) as usize);
    let nblocks = be32(data, index_off) as usize;
    let block = |i: u32| -> Result<&[u8]> {
        let i = i as usize;
        if i >= nblocks {
            return Err(bad("block index out of range"));
        }
        let p = index_off + 4 + i * 8;
        let (a, l) = (be32(data, p) as usize, be32(data, p + 4) as usize);
        data.get(a..a + l).ok_or_else(|| bad("block out of range"))
    };
    let nvars = be32(data, vars_off) as usize;
    let mut p = vars_off + 4;
    let mut paths_tree = None;
    for _ in 0..nvars {
        let b = be32(data, p);
        let len = data[p + 4] as usize;
        if &data[p + 5..p + 5 + len] == b"Paths" {
            paths_tree = Some(b);
        }
        p += 5 + len;
    }
    let tree = block(paths_tree.ok_or_else(|| bad("no Paths variable"))?)?;
    let mut node = be32(tree, 8);
    // Descend to the first leaf.
    loop {
        let b = block(node)?;
        if u16::from_be_bytes([b[0], b[1]]) == 1 {
            break;
        }
        node = be32(b, 12);
    }
    let mut names: std::collections::HashMap<u32, (u32, String)> = std::collections::HashMap::new();
    let mut raw = Vec::new();
    while node != 0 {
        let b = block(node)?;
        let count = u16::from_be_bytes([b[2], b[3]]) as usize;
        for k in 0..count {
            let p1 = block(be32(b, 12 + k * 8))?;
            let f = block(be32(b, 16 + k * 8))?;
            let (id, info) = (be32(p1, 0), block(be32(p1, 4))?);
            let parent = be32(f, 0);
            let name = String::from_utf8_lossy(&f[4..]).trim_end_matches('\0').to_string();
            names.insert(id, (parent, name));
            raw.push((id, u16::from_be_bytes([info[4], info[5]]), be32(info, 18), be32(info, 23)));
        }
        node = be32(b, 4);
    }
    let full = |mut id: u32| -> String {
        let mut parts = Vec::new();
        while let Some((parent, name)) = names.get(&id) {
            parts.push(name.clone());
            id = *parent;
            if parts.len() > 4096 {
                break;
            }
        }
        parts.reverse();
        parts.join("/")
    };
    Ok(raw.into_iter().map(|(id, mode, size, checksum)| BomPath { path: full(id), mode, size, checksum }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, kind: NodeKind) -> Node {
        Node { path: path.into(), kind, perm: 0o755, uid: 0, gid: 0, mtime: 0 }
    }

    #[test]
    fn round_trip_many() {
        let mut nodes = vec![node(".", NodeKind::Dir), node("./d", NodeKind::Dir)];
        for i in 0..700 {
            nodes.push(node(&format!("./d/f{i:04}"), NodeKind::File(vec![i as u8; i % 7])));
        }
        nodes.push(node("./d/link", NodeKind::Symlink("f0001".into())));
        let back = read(&write(&nodes).unwrap()).unwrap();
        assert_eq!(back.len(), nodes.len());
        assert_eq!(back[0].path, ".");
        assert_eq!(back[1].path, "./d");
        assert_eq!(back[2].path, "./d/f0000");
        assert!(back.iter().any(|p| p.path == "./d/link" && p.mode == 0o120755));
    }
}
