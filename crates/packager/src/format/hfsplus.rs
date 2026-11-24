//! A writer for HFS+ volumes, sized to fit their content: the volume header and its alternate,
//! the allocation bitmap, an empty extents-overflow B-tree and the catalog B-tree, with each
//! file stored contiguously (one extent).
//!
//! Volumes are written as HFSX (case-sensitive HFS+, binary key comparison), so catalog order is
//! plain UTF-16 order and needs no case-folding tables. Names are stored decomposed (NFD), as
//! HFS+ requires. Every macOS since 10.3 mounts HFSX.

use crate::crypto::sha256;
use crate::format::cpio::{Node, NodeKind};
use crate::format::nfd_table::DECOMPOSITIONS;
use crate::util::PutBe;
use crate::{Error, Result};

const BLOCK: u64 = 4096;
const NODE: usize = 4096;
const HFS_EPOCH_OFFSET: i64 = 2_082_844_800;
const ROOT_PARENT_ID: u32 = 1;
const ROOT_FOLDER_ID: u32 = 2;
const FIRST_USER_ID: u32 = 16;

/// Finder flag: the item is hidden.
pub const FINDER_INVISIBLE: u16 = 0x4000;
/// Finder flag: a folder (or the volume root) has a custom icon.
pub const FINDER_HAS_CUSTOM_ICON: u16 = 0x0400;

/// Volume settings.
#[derive(Debug, Clone)]
pub struct VolumeOptions {
    /// Volume name (shown in Finder and as the mount point).
    pub name: String,
    /// Owner of every item. 99 ("unknown") maps to whoever mounts the image.
    pub uid: u32,
    /// Group of every item.
    pub gid: u32,
    /// Creation/modification time (Unix seconds) for the volume and every item.
    pub time: i64,
    /// Extra free blocks beyond what the content needs.
    pub free_blocks: u32,
    /// Set the root's custom-icon flag (pair with a `.VolumeIcon.icns` at the root).
    pub custom_icon: bool,
    /// Paths (as in the node list, `./.background`) to mark invisible in Finder.
    pub invisible: Vec<String>,
}

impl VolumeOptions {
    /// Defaults for `name`.
    pub fn new(name: impl Into<String>) -> Self {
        VolumeOptions { name: name.into(), uid: 99, gid: 99, time: 0, free_blocks: 16, custom_icon: false, invisible: Vec::new() }
    }
}

/// UTF-16 in the decomposed form HFS+ stores, with `:` swapped for `/` (HFS+'s own separator).
pub fn hfs_name(s: &str) -> Vec<u16> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let c = if c == ':' { '/' } else { c };
        let cp = c as u32;
        if (0xAC00..=0xD7A3).contains(&cp) {
            let s_index = cp - 0xAC00;
            out.push((0x1100 + s_index / 588) as u16);
            out.push((0x1161 + (s_index % 588) / 28) as u16);
            if !s_index.is_multiple_of(28) {
                out.push((0x11A7 + s_index % 28) as u16);
            }
            continue;
        }
        if (0x80..0x10000).contains(&cp)
            && let Ok(i) = DECOMPOSITIONS.binary_search_by_key(&(cp as u16), |r| r.0)
        {
            out.extend(DECOMPOSITIONS[i].1.iter().copied().filter(|&u| u != 0));
            continue;
        }
        let mut buf = [0u16; 2];
        out.extend_from_slice(c.encode_utf16(&mut buf));
    }
    out
}

fn catalog_key(parent: u32, name: &[u16]) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + name.len() * 2);
    k.u16((6 + name.len() * 2) as u16);
    k.u32(parent);
    k.u16(name.len() as u16);
    for &u in name {
        k.u16(u);
    }
    k
}

fn bsd_info(out: &mut Vec<u8>, uid: u32, gid: u32, mode: u16, special: u32) {
    out.u32(uid);
    out.u32(gid);
    out.u8(0);
    out.u8(0);
    out.u16(mode);
    out.u32(special);
}

fn fork_data(out: &mut Vec<u8>, size: u64, start: u32, blocks: u32) {
    out.u64(size);
    out.u32(0);
    out.u32(blocks);
    out.u32(if blocks > 0 { start } else { 0 });
    out.u32(blocks);
    out.extend_from_slice(&[0u8; 56]);
}

struct Item<'a> {
    node: &'a Node,
    cnid: u32,
    parent: u32,
    name: Vec<u16>,
    valence: u32,
    subfolders: u32,
    start: u32,
    blocks: u32,
}

/// CNIDs in path order, so they depend only on the set of paths (deterministic, and known before
/// the volume is written — Finder aliases need them).
fn assign_ids(nodes: &[Node], root: usize) -> (Vec<usize>, Vec<u32>) {
    let mut order: Vec<usize> = (0..nodes.len()).filter(|&i| i != root).collect();
    order.sort_by(|&a, &b| nodes[a].path.cmp(&nodes[b].path));
    let mut cnids = vec![0u32; nodes.len()];
    cnids[root] = ROOT_FOLDER_ID;
    for (k, &i) in order.iter().enumerate() {
        cnids[i] = FIRST_USER_ID + k as u32;
    }
    (order, cnids)
}

/// The catalog node ID [`build`] will give `path` in a volume made of `nodes`.
pub fn catalog_id(nodes: &[Node], path: &str) -> Option<u32> {
    let root = nodes.iter().position(|n| n.path == ".")?;
    let i = nodes.iter().position(|n| n.path == path)?;
    Some(assign_ids(nodes, root).1[i])
}

/// The HFS timestamp (seconds since 1904) for Unix seconds.
pub fn hfs_time(unix: i64) -> u32 {
    (unix + HFS_EPOCH_OFFSET).clamp(0, u32::MAX as i64) as u32
}

/// Builds a whole volume image from a tree whose root is `.`.
pub fn build(nodes: &[Node], opts: &VolumeOptions) -> Result<Vec<u8>> {
    if opts.name.is_empty() || opts.name.chars().count() > 255 {
        return Err(Error::invalid("dmg", "volume name", "must be 1 to 255 characters"));
    }
    let mut index = std::collections::HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        index.insert(n.path.as_str(), i);
    }
    let root = *index.get(".").ok_or_else(|| Error::invalid("dmg", ".", "the tree has no root"))?;
    if nodes[root].kind != NodeKind::Dir {
        return Err(Error::invalid("dmg", ".", "the root must be a directory"));
    }

    let (order, cnids) = assign_ids(nodes, root);
    let mut items: Vec<Item> = Vec::with_capacity(nodes.len());
    let mut valence = vec![0u32; nodes.len()];
    let mut subfolders = vec![0u32; nodes.len()];
    let mut parents = vec![0usize; nodes.len()];
    for &i in &order {
        let n = &nodes[i];
        let parent = n.path.rsplit_once('/').map(|(p, _)| p).unwrap_or(".");
        let pi = *index.get(parent).ok_or_else(|| Error::invalid("dmg", n.path.clone(), "has no parent directory"))?;
        if nodes[pi].kind != NodeKind::Dir {
            return Err(Error::invalid("dmg", n.path.clone(), "parent isn't a directory"));
        }
        valence[pi] += 1;
        if n.kind == NodeKind::Dir {
            subfolders[pi] += 1;
        }
        parents[i] = pi;
        let name = hfs_name(n.name());
        if name.len() > 255 {
            return Err(Error::invalid("dmg", n.path.clone(), "name is longer than 255 UTF-16 units"));
        }
    }

    // Catalog records (sizes don't depend on allocation, so the catalog size is known up front).
    let vol_name = hfs_name(&opts.name);
    let mut n_files = 0u32;
    let mut n_folders = 0u32;
    let mut data_blocks = 0u64;
    for &i in &order {
        let n = &nodes[i];
        let blocks = (n.size() as u64).div_ceil(BLOCK);
        match n.kind {
            NodeKind::Dir => n_folders += 1,
            _ => n_files += 1,
        }
        data_blocks += if n.kind == NodeKind::Dir { 0 } else { blocks };
        items.push(Item { node: n, cnid: cnids[i], parent: cnids[parents[i]], name: hfs_name(n.name()), valence: valence[i], subfolders: subfolders[i], start: 0, blocks: blocks as u32 });
    }
    let record_count = 2 * (items.len() + 1);
    // Sizes in catalog order, since node packing depends on order.
    let mut keyed: Vec<(Vec<u8>, usize)> = Vec::with_capacity(record_count);
    keyed.push((catalog_key(ROOT_PARENT_ID, &vol_name), 88));
    keyed.push((catalog_key(ROOT_FOLDER_ID, &[]), 10 + 2 * vol_name.len()));
    for it in &items {
        keyed.push((catalog_key(it.parent, &it.name), if it.node.kind == NodeKind::Dir { 88 } else { 248 }));
        keyed.push((catalog_key(it.cnid, &[]), 10 + 2 * it.name.len()));
    }
    keyed.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let record_sizes: Vec<usize> = keyed.iter().map(|(k, d)| k.len() + d).collect();
    let catalog_nodes = btree_node_count(&record_sizes) as u64;

    // Layout: [0] header block, bitmap, extents tree (1 node), catalog, file data, slack, [last] alt header.
    let mut total = 0u64;
    let mut bitmap_blocks = 1u64;
    for _ in 0..4 {
        total = 1 + bitmap_blocks + 1 + catalog_nodes + data_blocks + opts.free_blocks as u64 + 1;
        bitmap_blocks = total.div_ceil(8 * BLOCK);
    }
    if total > u32::MAX as u64 {
        return Err(Error::invalid("dmg", "size", "volume is too large for HFS+"));
    }
    let bitmap_start = 1u64;
    let extents_start = bitmap_start + bitmap_blocks;
    let catalog_start = extents_start + 1;
    let mut next = catalog_start + catalog_nodes;
    for it in items.iter_mut() {
        if it.node.kind != NodeKind::Dir && it.blocks > 0 {
            it.start = next as u32;
            next += it.blocks as u64;
        }
    }
    let used_end = next;

    let mut img = vec![0u8; (total * BLOCK) as usize];
    let t = hfs_time(opts.time);

    // File data.
    for it in &items {
        if it.node.kind != NodeKind::Dir && it.blocks > 0 {
            let off = it.start as usize * BLOCK as usize;
            let d = it.node.data();
            img[off..off + d.len()].copy_from_slice(d);
        }
    }

    // Catalog records, sorted by (parent, name).
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(record_count);
    let folder_record = |cnid: u32, valence: u32, subfolders: u32, mode: u16, finder_flags: u16| {
        let mut r = Vec::with_capacity(88);
        r.u16(1);
        r.u16(0x0010); // kHFSHasFolderCountMask
        r.u32(valence);
        r.u32(cnid);
        for _ in 0..5 {
            r.u32(t);
        }
        bsd_info(&mut r, opts.uid, opts.gid, mode, 0);
        r.extend_from_slice(&[0u8; 8]); // frRect
        r.u16(finder_flags);
        r.extend_from_slice(&[0u8; 6]); // frLocation, frView
        r.extend_from_slice(&[0u8; 16]); // extended folder info
        r.u32(0); // textEncoding
        r.u32(subfolders); // folderCount
        r
    };
    let thread_record = |ty: u16, parent: u32, name: &[u16]| {
        let mut r = Vec::with_capacity(10 + name.len() * 2);
        r.u16(ty);
        r.u16(0);
        r.u32(parent);
        r.u16(name.len() as u16);
        for &u in name {
            r.u16(u);
        }
        r
    };
    let root_flags = if opts.custom_icon { FINDER_HAS_CUSTOM_ICON } else { 0 };
    records.push((catalog_key(ROOT_PARENT_ID, &vol_name), folder_record(ROOT_FOLDER_ID, valence[root], subfolders[root], 0o040755, root_flags)));
    records.push((catalog_key(ROOT_FOLDER_ID, &[]), thread_record(3, ROOT_PARENT_ID, &vol_name)));
    for it in &items {
        let invisible = opts.invisible.contains(&it.node.path);
        let fflags = if invisible { FINDER_INVISIBLE } else { 0 };
        let mode = it.node.mode() as u16;
        let rec = match &it.node.kind {
            NodeKind::Dir => folder_record(it.cnid, it.valence, it.subfolders, mode, fflags),
            kind => {
                let mut r = Vec::with_capacity(248);
                r.u16(2);
                r.u16(0x0002); // kHFSThreadExistsMask
                r.u32(0);
                r.u32(it.cnid);
                for _ in 0..5 {
                    r.u32(t);
                }
                bsd_info(&mut r, opts.uid, opts.gid, mode, 1);
                if let NodeKind::Symlink(_) = kind {
                    r.extend_from_slice(b"slnkrhap");
                } else {
                    r.extend_from_slice(&[0u8; 8]);
                }
                r.u16(fflags);
                r.extend_from_slice(&[0u8; 6]);
                r.extend_from_slice(&[0u8; 16]);
                r.u32(0);
                r.u32(0);
                fork_data(&mut r, it.node.size() as u64, it.start, it.blocks);
                fork_data(&mut r, 0, 0, 0);
                r
            }
        };
        records.push((catalog_key(it.parent, &it.name), rec));
        let ty = if it.node.kind == NodeKind::Dir { 3 } else { 4 };
        records.push((catalog_key(it.cnid, &[]), thread_record(ty, it.parent, &it.name)));
    }
    records.sort_by(|a, b| key_cmp(&a.0, &b.0));
    for w in records.windows(2) {
        if key_cmp(&w[0].0, &w[1].0) == std::cmp::Ordering::Equal {
            return Err(Error::invalid("dmg", "names", "two items in one folder have the same name"));
        }
    }
    let catalog = build_btree(&records, catalog_nodes as usize, 516, 0xBC, 6, true)?;
    let cat_off = (catalog_start * BLOCK) as usize;
    img[cat_off..cat_off + catalog.len()].copy_from_slice(&catalog);
    let extents = build_btree(&[], 1, 10, 0, 2, false)?;
    let ext_off = (extents_start * BLOCK) as usize;
    img[ext_off..ext_off + extents.len()].copy_from_slice(&extents);

    // Allocation bitmap: everything up to the data end, plus the last block (alternate header).
    let bm_off = (bitmap_start * BLOCK) as usize;
    let mut set = |b: u64| img[bm_off + (b / 8) as usize] |= 0x80 >> (b % 8);
    for b in 0..used_end {
        set(b);
    }
    set(total - 1);
    let free = total - used_end - 1;

    // Volume header and its alternate copy 1024 bytes before the end.
    let uuid = sha256(&catalog);
    let mut vh = Vec::with_capacity(512);
    vh.extend_from_slice(b"HX");
    vh.u16(5);
    vh.u32(0x8000_0100); // unmounted cleanly; unused nodes zeroed
    vh.extend_from_slice(b"10.0");
    vh.u32(0); // journalInfoBlock
    for _ in 0..2 {
        vh.u32(t); // create, modify
    }
    vh.u32(0); // backup
    vh.u32(t); // checked
    vh.u32(n_files);
    vh.u32(n_folders);
    vh.u32(BLOCK as u32);
    vh.u32(total as u32);
    vh.u32(free as u32);
    vh.u32(used_end as u32); // nextAllocation
    vh.u32(65536);
    vh.u32(65536);
    vh.u32(FIRST_USER_ID + items.len() as u32); // nextCatalogID
    vh.u32(1); // writeCount
    vh.u64(1); // encodingsBitmap: MacRoman
    for _ in 0..6 {
        vh.u32(0);
    }
    vh.extend_from_slice(&uuid[..8]); // finderInfo[6..7]: volume UUID
    let bm_bytes = bitmap_blocks * BLOCK;
    fork_data(&mut vh, bm_bytes, bitmap_start as u32, bitmap_blocks as u32);
    patch_clump(&mut vh, bm_bytes as u32);
    fork_data(&mut vh, BLOCK, extents_start as u32, 1);
    patch_clump(&mut vh, BLOCK as u32);
    fork_data(&mut vh, catalog_nodes * BLOCK, catalog_start as u32, catalog_nodes as u32);
    patch_clump(&mut vh, BLOCK as u32);
    fork_data(&mut vh, 0, 0, 0); // attributes
    fork_data(&mut vh, 0, 0, 0); // startup
    debug_assert_eq!(vh.len(), 512);
    img[1024..1536].copy_from_slice(&vh);
    let alt = img.len() - 1024;
    img[alt..alt + 512].copy_from_slice(&vh);
    Ok(img)
}

/// Sets the clump size of the fork record just appended.
fn patch_clump(vh: &mut [u8], clump: u32) {
    let at = vh.len() - 80 + 8;
    vh[at..at + 4].copy_from_slice(&clump.to_be_bytes());
}

/// Compares catalog keys: parent ID, then name as unsigned UTF-16 units (HFSX binary compare).
fn key_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let pa = u32::from_be_bytes([a[2], a[3], a[4], a[5]]);
    let pb = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
    pa.cmp(&pb).then_with(|| a[8..].cmp(&b[8..]))
}

/// How many nodes a catalog with these record sizes needs (header + leaves + index levels).
fn btree_node_count(sizes: &[usize]) -> usize {
    let leaves = pack(sizes).len();
    let mut total = 1 + leaves;
    let mut level = leaves;
    // Index records hold the first key of each child: at most a max-size key (518) + 4.
    while level > 1 {
        let per = (NODE - 14 - 2) / (518 + 4 + 2);
        level = level.div_ceil(per.max(1));
        total += level;
    }
    total
}

/// Greedy packing of record sizes into nodes; returns the record ranges per node.
fn pack(sizes: &[usize]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut used = 14 + 2;
    for (i, &s) in sizes.iter().enumerate() {
        if used + s + 2 > NODE && i > start {
            out.push(start..i);
            start = i;
            used = 14 + 2;
        }
        used += s + 2;
    }
    if start < sizes.len() || out.is_empty() {
        out.push(start..sizes.len());
    }
    out
}

fn node_bytes(kind: i8, height: u8, flink: u32, blink: u32, recs: &[Vec<u8>]) -> Vec<u8> {
    let mut n = Vec::with_capacity(NODE);
    n.u32(flink);
    n.u32(blink);
    n.u8(kind as u8);
    n.u8(height);
    n.u16(recs.len() as u16);
    n.u16(0);
    let mut offsets = Vec::with_capacity(recs.len() + 1);
    for r in recs {
        offsets.push(n.len() as u16);
        n.extend_from_slice(r);
    }
    offsets.push(n.len() as u16);
    n.resize(NODE, 0);
    for (k, off) in offsets.iter().enumerate() {
        let at = NODE - 2 * (k + 1);
        n[at..at + 2].copy_from_slice(&off.to_be_bytes());
    }
    n
}

/// Builds a B-tree of `total_nodes` nodes from sorted (key, data) records. Index keys keep their
/// real length when `variable_index_keys`.
fn build_btree(records: &[(Vec<u8>, Vec<u8>)], total_nodes: usize, max_key: u16, compare: u8, attrs: u32, variable_index_keys: bool) -> Result<Vec<u8>> {
    let mut nodes: Vec<Vec<u8>> = vec![Vec::new()]; // header placeholder
    let sizes: Vec<usize> = records.iter().map(|(k, d)| k.len() + d.len()).collect();
    let mut leaf_count = 0;
    let mut depth = 0u16;
    let mut root = 0u32;
    let (mut first_leaf, mut last_leaf) = (0u32, 0u32);
    if !records.is_empty() {
        let ranges = pack(&sizes);
        leaf_count = ranges.len();
        let base = 1u32;
        let mut level: Vec<(u32, Vec<u8>)> = Vec::new(); // (node number, first key)
        for (k, r) in ranges.iter().enumerate() {
            let recs: Vec<Vec<u8>> = records[r.clone()].iter().map(|(key, d)| [key.as_slice(), d.as_slice()].concat()).collect();
            let num = base + k as u32;
            let flink = if k + 1 < ranges.len() { num + 1 } else { 0 };
            let blink = if k > 0 { num - 1 } else { 0 };
            nodes.push(node_bytes(-1, 1, flink, blink, &recs));
            level.push((num, records[r.start].0.clone()));
        }
        first_leaf = base;
        last_leaf = base + leaf_count as u32 - 1;
        depth = 1;
        while level.len() > 1 {
            depth += 1;
            let idx_sizes: Vec<usize> = level.iter().map(|(_, key)| index_key(key, max_key, variable_index_keys).len() + 4).collect();
            let ranges = pack(&idx_sizes);
            let base = nodes.len() as u32;
            let mut up = Vec::new();
            for (k, r) in ranges.iter().enumerate() {
                let recs: Vec<Vec<u8>> = level[r.clone()]
                    .iter()
                    .map(|(child, key)| {
                        let mut rec = index_key(key, max_key, variable_index_keys);
                        rec.u32(*child);
                        rec
                    })
                    .collect();
                let num = base + k as u32;
                let flink = if k + 1 < ranges.len() { num + 1 } else { 0 };
                let blink = if k > 0 { num - 1 } else { 0 };
                nodes.push(node_bytes(0, depth as u8, flink, blink, &recs));
                up.push((num, level[r.start].1.clone()));
            }
            level = up;
        }
        root = level[0].0;
    }
    let used = nodes.len();
    if used > total_nodes {
        return Err(Error::Other(format!("hfs+: B-tree needs {used} nodes, {total_nodes} reserved")));
    }
    let map_bytes = NODE - 14 - 106 - 128 - 8;
    if total_nodes > map_bytes * 8 {
        return Err(Error::Other("hfs+: catalog too large for a single map record".into()));
    }
    let mut hdr = Vec::with_capacity(106);
    hdr.u16(depth);
    hdr.u32(root);
    hdr.u32(records.len() as u32);
    hdr.u32(first_leaf);
    hdr.u32(last_leaf);
    hdr.u16(NODE as u16);
    hdr.u16(max_key);
    hdr.u32(total_nodes as u32);
    hdr.u32((total_nodes - used) as u32);
    hdr.u16(0);
    hdr.u32(NODE as u32); // clumpSize
    hdr.u8(0); // btreeType
    hdr.u8(compare);
    hdr.u32(attrs);
    hdr.extend_from_slice(&[0u8; 64]);
    let mut map = vec![0u8; map_bytes];
    for i in 0..used {
        map[i / 8] |= 0x80 >> (i % 8);
    }
    nodes[0] = node_bytes(1, 0, 0, 0, &[hdr, vec![0u8; 128], map]);
    let mut out = Vec::with_capacity(total_nodes * NODE);
    for n in &nodes {
        out.extend_from_slice(n);
    }
    out.resize(total_nodes * NODE, 0);
    let _ = leaf_count;
    Ok(out)
}

fn index_key(key: &[u8], max_key: u16, variable: bool) -> Vec<u8> {
    if variable {
        key.to_vec()
    } else {
        let mut k = key.to_vec();
        k.resize(max_key as usize + 2, 0);
        k[0..2].copy_from_slice(&max_key.to_be_bytes());
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_decompose() {
        assert_eq!(hfs_name("é"), vec![0x65, 0x301]);
        assert_eq!(hfs_name("a:b"), vec![0x61, 0x2f, 0x62]);
        assert_eq!(hfs_name("한"), vec![0x1112, 0x1161, 0x11AB]);
    }

    #[test]
    fn builds() {
        let n = |p: &str, kind| Node { path: p.into(), kind, perm: 0o755, uid: 0, gid: 0, mtime: 0 };
        let mut nodes = vec![n(".", NodeKind::Dir), n("./A.app", NodeKind::Dir)];
        for i in 0..300 {
            nodes.push(n(&format!("./A.app/file-with-a-long-name-{i:04}"), NodeKind::File(vec![i as u8; i * 10])));
        }
        nodes.push(n("./Applications", NodeKind::Symlink("/Applications".into())));
        let img = build(&nodes, &VolumeOptions::new("Test")).unwrap();
        assert_eq!(&img[1024..1026], b"HX");
        assert_eq!(&img[img.len() - 1024..img.len() - 1022], b"HX");
    }
}
