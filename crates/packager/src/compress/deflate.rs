//! A DEFLATE compressor (RFC 1951): LZ77 with hash chains and lazy matching, then for each
//! block whichever of dynamic Huffman, fixed Huffman or stored is smallest.

const WINDOW: usize = 32 * 1024;
const WMASK: usize = WINDOW - 1;
const HASH_BITS: usize = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const BLOCK_TOKENS: usize = 1 << 15;

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
    227, 258,
];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// The order code-length code lengths are transmitted in.
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// How hard the compressor searches for matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Level {
    max_chain: usize,
    nice: usize,
    lazy: bool,
}

impl Level {
    /// Stored blocks only (no compression), still a valid stream.
    pub const STORE: Level = Level { max_chain: 0, nice: 0, lazy: false };
    /// Quick: short chains, greedy matching.
    pub const FAST: Level = Level { max_chain: 8, nice: 32, lazy: false };
    /// The default balance.
    pub const DEFAULT: Level = Level { max_chain: 128, nice: 128, lazy: true };
    /// Slowest, smallest.
    pub const BEST: Level = Level { max_chain: 1024, nice: 258, lazy: true };
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// Little-endian-bit-order writer used by DEFLATE.
pub(crate) struct BitWriter {
    pub(crate) out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    pub(crate) fn new(out: Vec<u8>) -> Self {
        BitWriter { out, acc: 0, n: 0 }
    }
    #[inline]
    pub(crate) fn bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32);
        self.acc |= (value as u64) << self.n;
        self.n += count;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    pub(crate) fn align(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.n = 0;
        }
    }
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

#[derive(Clone, Copy)]
enum Token {
    Lit(u8),
    Match { len: u16, dist: u16 },
}

/// Compresses `data` into a raw DEFLATE stream.
pub fn deflate(data: &[u8], level: Level) -> Vec<u8> {
    let mut w = BitWriter::new(Vec::with_capacity(data.len() / 2 + 64));
    deflate_into(&mut w, data, level);
    w.finish()
}

pub(crate) fn deflate_into(w: &mut BitWriter, data: &[u8], level: Level) {
    if data.is_empty() {
        // One final fixed block holding only end-of-block.
        w.bits(1, 1);
        w.bits(1, 2);
        let (codes, lens) = fixed_lit_codes();
        w.bits(codes[256] as u32, lens[256] as u32);
        return;
    }
    if level.max_chain == 0 {
        let mut pos = 0;
        while pos < data.len() {
            let end = (pos + 65535).min(data.len());
            write_stored(w, &data[pos..end], end == data.len());
            pos = end;
        }
        return;
    }

    let mut head = vec![u32::MAX; HASH_SIZE];
    let mut prev = vec![u32::MAX; WINDOW];
    let mut tokens: Vec<Token> = Vec::with_capacity(BLOCK_TOKENS + 2);
    let mut block_start = 0usize;
    let mut pos = 0usize;

    let hash = |p: usize| -> usize {
        let v = (data[p] as u32) << 16 | (data[p + 1] as u32) << 8 | data[p + 2] as u32;
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    };
    let insert = |head: &mut [u32], prev: &mut [u32], p: usize| {
        if p + MIN_MATCH <= data.len() {
            let h = hash(p);
            prev[p & WMASK] = head[h];
            head[h] = p as u32;
        }
    };
    let find = |head: &[u32], prev: &[u32], p: usize, min_len: usize| -> (usize, usize) {
        if p + MIN_MATCH > data.len() {
            return (0, 0);
        }
        let max_len = MAX_MATCH.min(data.len() - p);
        let mut best_len = min_len;
        let mut best_dist = 0;
        let mut cand = head[hash(p)];
        let mut chain = level.max_chain;
        while cand != u32::MAX && chain > 0 {
            let c = cand as usize;
            if c >= p || p - c > WINDOW {
                break;
            }
            if data[c + best_len.min(max_len - 1)] == data[p + best_len.min(max_len - 1)] {
                let mut l = 0;
                while l < max_len && data[c + l] == data[p + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = p - c;
                    if l >= level.nice || l == max_len {
                        break;
                    }
                }
            }
            let next = prev[c & WMASK];
            if next != u32::MAX && next as usize >= c {
                break;
            }
            cand = next;
            chain -= 1;
        }
        if best_dist == 0 { (0, 0) } else { (best_len, best_dist) }
    };

    while pos < data.len() {
        let (mut len, mut dist) = find(&head, &prev, pos, MIN_MATCH - 1);
        if len >= MIN_MATCH && level.lazy && len < level.nice && pos + 1 < data.len() {
            insert(&mut head, &mut prev, pos);
            let (l2, d2) = find(&head, &prev, pos + 1, len);
            if l2 > len {
                tokens.push(Token::Lit(data[pos]));
                pos += 1;
                len = l2;
                dist = d2;
            } else {
                // Already inserted `pos`; insert the rest of the match below.
                tokens.push(Token::Match { len: len as u16, dist: dist as u16 });
                for p in pos + 1..pos + len {
                    insert(&mut head, &mut prev, p);
                }
                pos += len;
                maybe_flush(w, data, &mut tokens, &mut block_start, pos, false);
                continue;
            }
        }
        if len >= MIN_MATCH {
            tokens.push(Token::Match { len: len as u16, dist: dist as u16 });
            for p in pos..pos + len {
                insert(&mut head, &mut prev, p);
            }
            pos += len;
        } else {
            tokens.push(Token::Lit(data[pos]));
            insert(&mut head, &mut prev, pos);
            pos += 1;
        }
        maybe_flush(w, data, &mut tokens, &mut block_start, pos, false);
    }
    maybe_flush(w, data, &mut tokens, &mut block_start, pos, true);
}

fn maybe_flush(w: &mut BitWriter, data: &[u8], tokens: &mut Vec<Token>, start: &mut usize, pos: usize, last: bool) {
    if tokens.len() >= BLOCK_TOKENS || last {
        write_block(w, &data[*start..pos], tokens, last);
        tokens.clear();
        *start = pos;
    }
}

fn len_code(len: u16) -> usize {
    match LEN_BASE.binary_search(&len) {
        Ok(i) => i,
        Err(i) => i - 1,
    }
}
fn dist_code(dist: u16) -> usize {
    match DIST_BASE.binary_search(&dist) {
        Ok(i) => i,
        Err(i) => i - 1,
    }
}

fn write_stored(w: &mut BitWriter, raw: &[u8], last: bool) {
    w.bits(last as u32, 1);
    w.bits(0, 2);
    w.align();
    let n = raw.len() as u16;
    w.out.extend_from_slice(&n.to_le_bytes());
    w.out.extend_from_slice(&(!n).to_le_bytes());
    w.out.extend_from_slice(raw);
}

fn write_block(w: &mut BitWriter, raw: &[u8], tokens: &[Token], last: bool) {
    let mut lit_freq = [0u32; 286];
    let mut dist_freq = [0u32; 30];
    for t in tokens {
        match *t {
            Token::Lit(b) => lit_freq[b as usize] += 1,
            Token::Match { len, dist } => {
                lit_freq[257 + len_code(len)] += 1;
                dist_freq[dist_code(dist)] += 1;
            }
        }
    }
    lit_freq[256] = 1;

    let mut lit_lens = huffman_lengths(&lit_freq, 15);
    let mut dist_lens = huffman_lengths(&dist_freq, 15);
    if dist_lens.iter().all(|&l| l == 0) {
        dist_lens[0] = 1;
    }
    // Trim trailing zeros, keeping the minimum counts.
    let hlit = (257..=286).rev().find(|&n| lit_lens[n - 1] != 0).unwrap_or(257).max(257);
    let hdist = (1..=30).rev().find(|&n| dist_lens[n - 1] != 0).unwrap_or(1).max(1);
    lit_lens.truncate(hlit);
    dist_lens.truncate(hdist);

    // Code-length alphabet: RLE of the concatenated lengths.
    let mut all = lit_lens.clone();
    all.extend_from_slice(&dist_lens);
    let rle = rle_lengths(&all);
    let mut cl_freq = [0u32; 19];
    for &(sym, _) in &rle {
        cl_freq[sym as usize] += 1;
    }
    let cl_lens = huffman_lengths(&cl_freq, 7);
    let hclen = (4..=19).rev().find(|&n| cl_lens[CL_ORDER[n - 1]] != 0).unwrap_or(4).max(4);

    // Cost each option in bits.
    let extra_bits = |t: &Token| match *t {
        Token::Lit(_) => 0,
        Token::Match { len, dist } => LEN_EXTRA[len_code(len)] as u64 + DIST_EXTRA[dist_code(dist)] as u64,
    };
    let body_cost = |ll: &[u8], dl: &[u8]| -> u64 {
        let mut bits = ll[256] as u64;
        for t in tokens {
            bits += extra_bits(t);
            match *t {
                Token::Lit(b) => bits += ll[b as usize] as u64,
                Token::Match { len, dist } => {
                    bits += ll[257 + len_code(len)] as u64 + dl[dist_code(dist)] as u64;
                }
            }
        }
        bits
    };
    let mut dyn_cost = 3 + 5 + 5 + 4 + 3 * hclen as u64;
    for &(sym, _) in &rle {
        dyn_cost += cl_lens[sym as usize] as u64
            + match sym {
                16 => 2,
                17 => 3,
                18 => 7,
                _ => 0,
            };
    }
    let mut full_lit = lit_lens.clone();
    full_lit.resize(286, 0);
    let mut full_dist = dist_lens.clone();
    full_dist.resize(30, 0);
    dyn_cost += body_cost(&full_lit, &full_dist);
    let (_, fixed_lens) = fixed_lit_codes();
    let fixed_cost = 3 + body_cost(&fixed_lens, &[5u8; 30]);
    let stored_cost = (raw.len() as u64).div_ceil(65535).max(1) * 40 + raw.len() as u64 * 8;

    if stored_cost < dyn_cost && stored_cost < fixed_cost {
        let chunks: Vec<&[u8]> = if raw.is_empty() { vec![&[][..]] } else { raw.chunks(65535).collect() };
        let n = chunks.len();
        for (i, c) in chunks.into_iter().enumerate() {
            write_stored(w, c, last && i + 1 == n);
        }
        return;
    }

    w.bits(last as u32, 1);
    let (lit_codes, lit_l, dist_codes, dist_l): (Vec<u16>, Vec<u8>, Vec<u16>, Vec<u8>);
    if fixed_cost <= dyn_cost {
        w.bits(1, 2);
        let (c, l) = fixed_lit_codes();
        lit_codes = c.to_vec();
        lit_l = l.to_vec();
        dist_l = vec![5; 30];
        dist_codes = canonical_codes(&dist_l);
    } else {
        w.bits(2, 2);
        w.bits((hlit - 257) as u32, 5);
        w.bits((hdist - 1) as u32, 5);
        w.bits((hclen - 4) as u32, 4);
        for &i in CL_ORDER.iter().take(hclen) {
            w.bits(cl_lens[i] as u32, 3);
        }
        let cl_codes = canonical_codes(&cl_lens);
        for &(sym, extra) in &rle {
            w.bits(cl_codes[sym as usize] as u32, cl_lens[sym as usize] as u32);
            match sym {
                16 => w.bits(extra as u32, 2),
                17 => w.bits(extra as u32, 3),
                18 => w.bits(extra as u32, 7),
                _ => {}
            }
        }
        lit_codes = canonical_codes(&full_lit);
        lit_l = full_lit;
        dist_codes = canonical_codes(&full_dist);
        dist_l = full_dist;
    }
    for t in tokens {
        match *t {
            Token::Lit(b) => w.bits(lit_codes[b as usize] as u32, lit_l[b as usize] as u32),
            Token::Match { len, dist } => {
                let lc = len_code(len);
                w.bits(lit_codes[257 + lc] as u32, lit_l[257 + lc] as u32);
                w.bits((len - LEN_BASE[lc]) as u32, LEN_EXTRA[lc] as u32);
                let dc = dist_code(dist);
                w.bits(dist_codes[dc] as u32, dist_l[dc] as u32);
                w.bits((dist - DIST_BASE[dc]) as u32, DIST_EXTRA[dc] as u32);
            }
        }
    }
    w.bits(lit_codes[256] as u32, lit_l[256] as u32);
}

/// Run-length encodes code lengths into (symbol, extra-bits value) pairs.
fn rle_lengths(lens: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let l = lens[i];
        let mut run = 1;
        while i + run < lens.len() && lens[i + run] == l {
            run += 1;
        }
        i += run;
        if l == 0 {
            while run >= 11 {
                let n = run.min(138);
                out.push((18, (n - 11) as u8));
                run -= n;
            }
            if run >= 3 {
                out.push((17, (run - 3) as u8));
                run = 0;
            }
            for _ in 0..run {
                out.push((0, 0));
            }
        } else {
            out.push((l, 0));
            run -= 1;
            while run >= 3 {
                let n = run.min(6);
                out.push((16, (n - 3) as u8));
                run -= n;
            }
            for _ in 0..run {
                out.push((l, 0));
            }
        }
    }
    out
}

/// The fixed literal/length code (RFC 1951 §3.2.6), bit-reversed for output.
fn fixed_lit_codes() -> ([u16; 288], [u8; 288]) {
    let mut lens = [0u8; 288];
    for (i, l) in lens.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let codes = canonical_codes(&lens);
    let mut out = [0u16; 288];
    out.copy_from_slice(&codes);
    (out, lens)
}

/// Canonical Huffman codes for `lens`, bit-reversed so they can be written LSB first.
pub(crate) fn canonical_codes(lens: &[u8]) -> Vec<u16> {
    let mut bl_count = [0u16; 16];
    for &l in lens {
        bl_count[l as usize] += 1;
    }
    bl_count[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..16 {
        code = (code + bl_count[bits - 1]) << 1;
        next[bits] = code;
    }
    lens.iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let c = next[l as usize];
            next[l as usize] += 1;
            c.reverse_bits() >> (16 - l)
        })
        .collect()
}

/// Huffman code lengths for `freq`, no longer than `max_bits`.
pub(crate) fn huffman_lengths(freq: &[u32], max_bits: u8) -> Vec<u8> {
    let mut f: Vec<u64> = freq.iter().map(|&x| x as u64).collect();
    loop {
        let lens = huffman_unlimited(&f);
        if lens.iter().all(|&l| l <= max_bits) {
            return lens;
        }
        for x in f.iter_mut() {
            if *x > 0 {
                *x = (*x >> 1).max(1);
            }
        }
    }
}

fn huffman_unlimited(freq: &[u64]) -> Vec<u8> {
    let mut lens = vec![0u8; freq.len()];
    let mut leaves: Vec<(u64, usize)> = freq.iter().enumerate().filter(|(_, f)| **f > 0).map(|(i, f)| (*f, i)).collect();
    match leaves.len() {
        0 => return lens,
        1 => {
            lens[leaves[0].1] = 1;
            return lens;
        }
        _ => {}
    }
    leaves.sort();
    // Two-queue construction: nodes are leaves 0..n then internal nodes.
    let n = leaves.len();
    let mut weight: Vec<u64> = leaves.iter().map(|l| l.0).collect();
    let mut parent = vec![usize::MAX; 2 * n - 1];
    let (mut li, mut ii) = (0usize, n);
    let pick = |weight: &Vec<u64>, li: &mut usize, ii: &mut usize, end: usize| -> usize {
        if *li < n && (*ii >= end || weight[*li] <= weight[*ii]) {
            *li += 1;
            *li - 1
        } else {
            *ii += 1;
            *ii - 1
        }
    };
    for k in n..2 * n - 1 {
        let a = pick(&weight, &mut li, &mut ii, k);
        let b = pick(&weight, &mut li, &mut ii, k);
        weight.push(weight[a] + weight[b]);
        parent[a] = k;
        parent[b] = k;
    }
    let mut depth = vec![0u8; 2 * n - 1];
    for k in (0..2 * n - 2).rev() {
        depth[k] = depth[parent[k]].saturating_add(1);
    }
    for (i, &(_, sym)) in leaves.iter().enumerate() {
        lens[sym] = depth[i];
    }
    lens
}
