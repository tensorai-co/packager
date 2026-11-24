//! LZMA with LZMA2 framing, the codec inside `.xz` files (and so inside SquashFS images and
//! `.deb` `data.tar.xz` members): an encoder (hash-chain match finder, lazy parsing that prefers
//! repeated distances, adaptive range coding) and a decoder. Literal context lc=3, lp=0, pb=2,
//! like xz's presets.

use crate::{Error, Result};

const LC: u32 = 3;
const LP: u32 = 0;
const PB: u32 = 2;
const PB_MASK: usize = (1 << PB) - 1;
/// The LZMA2 properties byte for lc=3, lp=0, pb=2.
const PROPS: u8 = ((PB * 5 + LP) * 9 + LC) as u8;

const STATES: usize = 12;
const POS_STATES: usize = 1 << PB;
const MATCH_LEN_MIN: usize = 2;
/// The longest match LZMA can code.
pub const MATCH_LEN_MAX: usize = 273;
const DIST_STATES: usize = 4;
const DIST_MODEL_END: u32 = 14;
const FULL_DISTANCES: usize = 1 << (DIST_MODEL_END / 2);
const ALIGN_BITS: u32 = 4;
/// Uncompressed bytes per LZMA2 chunk: small enough that an incompressible chunk can always be
/// stored as an uncompressed chunk (at most 64 KiB).
const CHUNK: usize = 1 << 16;

const PROB_INIT: u16 = 1024;
const MOVE_BITS: u32 = 5;
const TOP: u32 = 1 << 24;

/// Encoder settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Dictionary (window) size: the farthest a match may reach back.
    pub dict_size: u32,
    /// A match at least this long is taken without looking further.
    pub nice_len: usize,
    /// How many hash-chain candidates are compared per position.
    pub max_chain: usize,
}

impl Options {
    /// Quick, for large inputs.
    pub const FAST: Options = Options { dict_size: 1 << 22, nice_len: 32, max_chain: 8 };
    /// A good balance (the default).
    pub const DEFAULT: Options = Options { dict_size: 1 << 23, nice_len: 64, max_chain: 48 };
    /// Smallest output.
    pub const BEST: Options = Options { dict_size: 1 << 25, nice_len: MATCH_LEN_MAX, max_chain: 256 };

    /// The same settings with another dictionary size.
    pub fn dict_size(self, dict_size: u32) -> Options {
        Options { dict_size, ..self }
    }
}

impl Default for Options {
    fn default() -> Self {
        Options::DEFAULT
    }
}

/// The LZMA2 filter-properties byte for a dictionary of at least `dict_size` bytes, and the
/// dictionary size it stands for: `(2 | (b & 1)) << (b / 2 + 11)`, 4 KiB minimum.
pub fn dict_size_byte(dict_size: u32) -> (u8, u32) {
    for b in 0u8..40 {
        let size = (2u64 | u64::from(b & 1)) << (u32::from(b) / 2 + 11);
        if size >= u64::from(dict_size) {
            return (b, size as u32);
        }
    }
    (40, u32::MAX)
}

/// Decodes a dictionary-size byte.
pub fn dict_size_from_byte(b: u8) -> Result<u32> {
    match b {
        40 => Ok(u32::MAX),
        0..40 => Ok(((2u64 | u64::from(b & 1)) << (u32::from(b) / 2 + 11)) as u32),
        _ => Err(Error::malformed("lzma2", "bad dictionary size")),
    }
}

// ---------------------------------------------------------------------------------------------
// The probability model, shared by the encoder and decoder.

#[derive(Clone)]
struct LenModel {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES],
    mid: [[u16; 8]; POS_STATES],
    high: [u16; 256],
}

impl LenModel {
    fn new() -> Self {
        LenModel { choice: PROB_INIT, choice2: PROB_INIT, low: [[PROB_INIT; 8]; POS_STATES], mid: [[PROB_INIT; 8]; POS_STATES], high: [PROB_INIT; 256] }
    }
}

#[derive(Clone)]
struct Model {
    literal: Vec<u16>,
    is_match: [[u16; POS_STATES]; STATES],
    is_rep: [u16; STATES],
    is_rep_g0: [u16; STATES],
    is_rep_g1: [u16; STATES],
    is_rep_g2: [u16; STATES],
    is_rep0_long: [[u16; POS_STATES]; STATES],
    dist_slot: [[u16; 64]; DIST_STATES],
    dist_special: [u16; FULL_DISTANCES - DIST_MODEL_END as usize],
    dist_align: [u16; 1 << ALIGN_BITS],
    len: LenModel,
    rep_len: LenModel,
}

impl Model {
    fn new() -> Self {
        Model {
            literal: vec![PROB_INIT; 0x300 << (LC + LP)],
            is_match: [[PROB_INIT; POS_STATES]; STATES],
            is_rep: [PROB_INIT; STATES],
            is_rep_g0: [PROB_INIT; STATES],
            is_rep_g1: [PROB_INIT; STATES],
            is_rep_g2: [PROB_INIT; STATES],
            is_rep0_long: [[PROB_INIT; POS_STATES]; STATES],
            dist_slot: [[PROB_INIT; 64]; DIST_STATES],
            dist_special: [PROB_INIT; FULL_DISTANCES - DIST_MODEL_END as usize],
            dist_align: [PROB_INIT; 1 << ALIGN_BITS],
            len: LenModel::new(),
            rep_len: LenModel::new(),
        }
    }
}

fn literal_base(prev: u8) -> usize {
    0x300 * (usize::from(prev) >> (8 - LC))
}

fn after_literal(s: usize) -> usize {
    if s < 4 {
        0
    } else if s < 10 {
        s - 3
    } else {
        s - 6
    }
}
fn after_match(s: usize) -> usize {
    if s < 7 { 7 } else { 10 }
}
fn after_rep(s: usize) -> usize {
    if s < 7 { 8 } else { 11 }
}
fn after_short_rep(s: usize) -> usize {
    if s < 7 { 9 } else { 11 }
}

fn dist_slot(d: u32) -> u32 {
    if d < 4 {
        d
    } else {
        let n = 31 - d.leading_zeros();
        (n << 1) | ((d >> (n - 1)) & 1)
    }
}

// ---------------------------------------------------------------------------------------------
// Range coder.

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out: Vec::new() }
    }

    #[inline]
    fn bit(&mut self, p: &mut u16, bit: u32) {
        let bound = (self.range >> 11) * u32::from(*p);
        if bit == 0 {
            self.range = bound;
            *p += (2048 - *p) >> MOVE_BITS;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
            *p -= *p >> MOVE_BITS;
        }
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn direct(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.range >>= 1;
            if (value >> i) & 1 == 1 {
                self.low += u64::from(self.range);
            }
            while self.range < TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32, symbol: u32) {
        let mut m = 1usize;
        for i in (0..bits).rev() {
            let b = (symbol >> i) & 1;
            self.bit(&mut probs[m], b);
            m = (m << 1) | b as usize;
        }
    }

    fn reverse_tree(&mut self, probs: &mut [u16], offset: usize, bits: u32, mut symbol: u32) {
        // `offset + m - 1` with m starting at 1, so negative-looking offsets stay in range.
        let mut m = 1usize;
        for _ in 0..bits {
            let b = symbol & 1;
            self.bit(&mut probs[offset + m - 1], b);
            m = (m << 1) | b as usize;
            symbol >>= 1;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 5 || data[0] != 0 {
            return Err(Error::malformed("lzma2", "bad range coder start"));
        }
        let code = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok(RangeDecoder { data, pos: 5, range: 0xFFFF_FFFF, code })
    }

    #[inline]
    fn normalize(&mut self) -> Result<()> {
        if self.range < TOP {
            let b = *self.data.get(self.pos).ok_or_else(|| Error::malformed("lzma2", "compressed chunk ends early"))?;
            self.pos += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(b);
        }
        Ok(())
    }

    #[inline]
    fn bit(&mut self, p: &mut u16) -> Result<u32> {
        let bound = (self.range >> 11) * u32::from(*p);
        let b = if self.code < bound {
            self.range = bound;
            *p += (2048 - *p) >> MOVE_BITS;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *p -= *p >> MOVE_BITS;
            1
        };
        self.normalize()?;
        Ok(b)
    }

    fn direct(&mut self, count: u32) -> Result<u32> {
        let mut v = 0;
        for _ in 0..count {
            self.range >>= 1;
            let b = if self.code >= self.range {
                self.code -= self.range;
                1
            } else {
                0
            };
            v = (v << 1) | b;
            self.normalize()?;
        }
        Ok(v)
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> Result<u32> {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) | self.bit(&mut probs[m])? as usize;
        }
        Ok((m - (1 << bits)) as u32)
    }

    fn reverse_tree(&mut self, probs: &mut [u16], offset: usize, bits: u32) -> Result<u32> {
        let mut m = 1usize;
        let mut sym = 0;
        for i in 0..bits {
            let b = self.bit(&mut probs[offset + m - 1])?;
            m = (m << 1) | b as usize;
            sym |= b << i;
        }
        Ok(sym)
    }
}

// ---------------------------------------------------------------------------------------------
// Encoder.

struct MatchFinder {
    head: Vec<i32>,
    prev: Vec<i32>,
    hash_bits: u32,
    inserted: usize,
    dict_size: usize,
    max_chain: usize,
}

impl MatchFinder {
    fn new(len: usize, opts: &Options) -> Self {
        let hash_bits = (usize::BITS - len.max(1).leading_zeros()).clamp(10, 18);
        MatchFinder { head: vec![-1; 1 << hash_bits], prev: vec![-1; len], hash_bits, inserted: 0, dict_size: opts.dict_size as usize, max_chain: opts.max_chain.max(1) }
    }

    #[inline]
    fn hash(&self, d: &[u8], p: usize) -> usize {
        let v = (u32::from(d[p]) << 16) | (u32::from(d[p + 1]) << 8) | u32::from(d[p + 2]);
        (v.wrapping_mul(2_654_435_761) >> (32 - self.hash_bits)) as usize
    }

    /// Adds every position before `upto` to the chains.
    fn insert_upto(&mut self, d: &[u8], upto: usize) {
        while self.inserted < upto {
            let p = self.inserted;
            if p + 2 < d.len() {
                let h = self.hash(d, p);
                self.prev[p] = self.head[h];
                self.head[h] = p as i32;
            }
            self.inserted += 1;
        }
    }

    /// The longest earlier match for position `p` (length ≤ `limit`): (length, distance − 1).
    fn find(&mut self, d: &[u8], p: usize, limit: usize, nice: usize) -> (usize, u32) {
        self.insert_upto(d, p);
        if limit < 3 || p + 2 >= d.len() {
            return (0, 0);
        }
        let mut cand = self.head[self.hash(d, p)];
        let (mut best_len, mut best_back) = (0usize, 0u32);
        let mut chain = self.max_chain;
        while cand >= 0 && chain > 0 {
            let c = cand as usize;
            let dist = p - c;
            if dist > self.dict_size {
                break;
            }
            if d[c + best_len.min(limit - 1)] == d[p + best_len.min(limit - 1)] {
                let l = match_len(d, p, c, limit);
                if l > best_len {
                    best_len = l;
                    best_back = (dist - 1) as u32;
                    if l >= nice || l == limit {
                        break;
                    }
                }
            }
            cand = self.prev[c];
            chain -= 1;
        }
        if best_len < 3 { (0, 0) } else { (best_len, best_back) }
    }
}

#[inline]
fn match_len(d: &[u8], a: usize, b: usize, limit: usize) -> usize {
    let mut l = 0;
    while l < limit && d[a + l] == d[b + l] {
        l += 1;
    }
    l
}

enum Choice {
    Literal,
    Match { len: usize, back: u32 },
    Rep { idx: usize, len: usize },
}

struct Encoder {
    model: Model,
    state: usize,
    reps: [u32; 4],
    nice: usize,
    /// A match-finder result for the next position, from lazy evaluation.
    next: Option<(usize, usize, u32)>,
}

impl Encoder {
    fn reset(&mut self) {
        self.model = Model::new();
        self.state = 0;
        self.reps = [0; 4];
    }

    fn find(&mut self, mf: &mut MatchFinder, d: &[u8], p: usize, limit: usize) -> (usize, u32) {
        if let Some((at, len, back)) = self.next.take()
            && at == p
        {
            return (len.min(limit), back);
        }
        mf.find(d, p, limit, self.nice)
    }

    fn best_rep(&self, d: &[u8], p: usize, limit: usize) -> (usize, usize) {
        let (mut len, mut idx) = (0, 0);
        for (i, &r) in self.reps.iter().enumerate() {
            let dist = r as usize + 1;
            if dist > p {
                continue;
            }
            let l = match_len(d, p, p - dist, limit);
            if l > len {
                len = l;
                idx = i;
            }
        }
        (len, idx)
    }

    fn decide(&mut self, mf: &mut MatchFinder, d: &[u8], p: usize, end: usize) -> Choice {
        let limit = (end - p).min(MATCH_LEN_MAX);
        if limit < MATCH_LEN_MIN {
            return Choice::Literal;
        }
        let (rep_len, rep_idx) = self.best_rep(d, p, limit);
        if rep_len >= self.nice.min(limit) {
            return Choice::Rep { idx: rep_idx, len: rep_len };
        }
        let (main_len, main_back) = self.find(mf, d, p, limit);
        if main_len >= self.nice.min(limit) {
            return Choice::Match { len: main_len, back: main_back };
        }
        if rep_len >= 2 && (rep_len + 1 >= main_len || (rep_len + 2 >= main_len && main_back >= 1 << 9) || (rep_len + 3 >= main_len && main_back >= 1 << 15)) {
            return Choice::Rep { idx: rep_idx, len: rep_len };
        }
        if main_len < 3 {
            return Choice::Literal;
        }
        // Lazy evaluation: would starting one byte later find something clearly better?
        if p + 1 < end {
            let nlimit = (end - p - 1).min(MATCH_LEN_MAX);
            let (nlen, nback) = mf.find(d, p + 1, nlimit, self.nice);
            self.next = Some((p + 1, nlen, nback));
            let change = |small: u32, big: u32| (big >> 7) > small;
            if nlen >= 3
                && ((nlen >= main_len && nback < main_back)
                    || (nlen == main_len + 1 && !change(main_back, nback))
                    || nlen > main_len + 1
                    || (nlen + 1 >= main_len && main_len >= 3 && change(nback, main_back)))
            {
                return Choice::Literal;
            }
            let want = main_len - 1;
            if want >= 2 && nlimit >= want {
                for &r in &self.reps {
                    let dist = r as usize + 1;
                    if dist <= p + 1 && match_len(d, p + 1, p + 1 - dist, want) == want {
                        return Choice::Literal;
                    }
                }
            }
        }
        Choice::Match { len: main_len, back: main_back }
    }

    fn literal(&mut self, rc: &mut RangeEncoder, d: &[u8], p: usize) {
        let ps = p & PB_MASK;
        rc.bit(&mut self.model.is_match[self.state][ps], 0);
        let prev = if p > 0 { d[p - 1] } else { 0 };
        let base = literal_base(prev);
        let probs = &mut self.model.literal[base..base + 0x300];
        let mut symbol = u32::from(d[p]) | 0x100;
        if self.state < 7 {
            while symbol < 0x10000 {
                rc.bit(&mut probs[(symbol >> 8) as usize], (symbol >> 7) & 1);
                symbol <<= 1;
            }
        } else {
            let mut match_byte = u32::from(d[p - self.reps[0] as usize - 1]);
            let mut offs = 0x100u32;
            while symbol < 0x10000 {
                match_byte <<= 1;
                rc.bit(&mut probs[(offs + (match_byte & offs) + (symbol >> 8)) as usize], (symbol >> 7) & 1);
                symbol <<= 1;
                offs &= !(match_byte ^ symbol);
            }
        }
        self.state = after_literal(self.state);
    }

    fn length(rc: &mut RangeEncoder, m: &mut LenModel, len: usize, ps: usize) {
        let s = (len - MATCH_LEN_MIN) as u32;
        if s < 8 {
            rc.bit(&mut m.choice, 0);
            rc.tree(&mut m.low[ps], 3, s);
        } else if s < 16 {
            rc.bit(&mut m.choice, 1);
            rc.bit(&mut m.choice2, 0);
            rc.tree(&mut m.mid[ps], 3, s - 8);
        } else {
            rc.bit(&mut m.choice, 1);
            rc.bit(&mut m.choice2, 1);
            rc.tree(&mut m.high, 8, s - 16);
        }
    }

    fn matched(&mut self, rc: &mut RangeEncoder, p: usize, len: usize, back: u32) {
        let ps = p & PB_MASK;
        rc.bit(&mut self.model.is_match[self.state][ps], 1);
        rc.bit(&mut self.model.is_rep[self.state], 0);
        Self::length(rc, &mut self.model.len, len, ps);
        let ls = (len - MATCH_LEN_MIN).min(DIST_STATES - 1);
        let slot = dist_slot(back);
        rc.tree(&mut self.model.dist_slot[ls], 6, slot);
        if slot >= 4 {
            let footer = (slot >> 1) - 1;
            let base = (2 | (slot & 1)) << footer;
            let reduced = back - base;
            if slot < DIST_MODEL_END {
                rc.reverse_tree(&mut self.model.dist_special, (base - slot) as usize, footer, reduced);
            } else {
                rc.direct(reduced >> ALIGN_BITS, footer - ALIGN_BITS);
                rc.reverse_tree(&mut self.model.dist_align, 1, ALIGN_BITS, reduced & ((1 << ALIGN_BITS) - 1));
            }
        }
        self.reps = [back, self.reps[0], self.reps[1], self.reps[2]];
        self.state = after_match(self.state);
    }

    fn rep(&mut self, rc: &mut RangeEncoder, p: usize, idx: usize, len: usize) {
        let ps = p & PB_MASK;
        let s = self.state;
        rc.bit(&mut self.model.is_match[s][ps], 1);
        rc.bit(&mut self.model.is_rep[s], 1);
        if idx == 0 {
            rc.bit(&mut self.model.is_rep_g0[s], 0);
            rc.bit(&mut self.model.is_rep0_long[s][ps], 1);
        } else {
            rc.bit(&mut self.model.is_rep_g0[s], 1);
            if idx == 1 {
                rc.bit(&mut self.model.is_rep_g1[s], 0);
            } else {
                rc.bit(&mut self.model.is_rep_g1[s], 1);
                rc.bit(&mut self.model.is_rep_g2[s], (idx - 2) as u32);
            }
            let d = self.reps[idx];
            for i in (1..=idx).rev() {
                self.reps[i] = self.reps[i - 1];
            }
            self.reps[0] = d;
        }
        Self::length(rc, &mut self.model.rep_len, len, ps);
        self.state = after_rep(s);
    }
}

/// Encodes `data` as a complete LZMA2 stream (ending with the end marker), as an `.xz` block's
/// payload. Matches never reach further back than `opts.dict_size`.
pub fn lzma2_encode(data: &[u8], opts: &Options) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 16);
    let mut mf = MatchFinder::new(data.len(), opts);
    let mut enc = Encoder { model: Model::new(), state: 0, reps: [0; 4], nice: opts.nice_len.clamp(MATCH_LEN_MIN, MATCH_LEN_MAX), next: None };
    let (mut first, mut props_sent, mut need_reset) = (true, false, true);
    let mut start = 0;
    while start < data.len() {
        let end = (start + CHUNK).min(data.len());
        if need_reset {
            enc.reset();
        }
        let mut rc = RangeEncoder::new();
        let mut p = start;
        while p < end {
            match enc.decide(&mut mf, data, p, end) {
                Choice::Literal => {
                    enc.literal(&mut rc, data, p);
                    p += 1;
                }
                Choice::Match { len, back } => {
                    enc.matched(&mut rc, p, len, back);
                    p += len;
                }
                Choice::Rep { idx, len } => {
                    enc.rep(&mut rc, p, idx, len);
                    p += len;
                }
            }
        }
        let packed = rc.finish();
        let unpacked = end - start;
        if packed.len() <= 1 << 16 && packed.len() < unpacked {
            let reset: u8 = if first {
                3
            } else if !props_sent {
                2
            } else if need_reset {
                1
            } else {
                0
            };
            out.push(0x80 | (reset << 5) | ((unpacked - 1) >> 16) as u8);
            out.extend_from_slice(&((unpacked - 1) as u16).to_be_bytes());
            out.extend_from_slice(&((packed.len() - 1) as u16).to_be_bytes());
            if reset >= 2 {
                out.push(PROPS);
            }
            out.extend_from_slice(&packed);
            props_sent = true;
            need_reset = false;
        } else {
            out.push(if first { 1 } else { 2 });
            out.extend_from_slice(&((unpacked - 1) as u16).to_be_bytes());
            out.extend_from_slice(&data[start..end]);
            // The decoder didn't run the model over these bytes.
            need_reset = true;
        }
        first = false;
        start = end;
    }
    out.push(0);
    out
}

// ---------------------------------------------------------------------------------------------
// Decoder.

/// Decodes an LZMA2 stream; returns the data and how many input bytes it used (through the end
/// marker). `max_out` bounds the output, against decompression bombs.
pub fn lzma2_decode(data: &[u8], max_out: usize) -> Result<(Vec<u8>, usize)> {
    let bad = |m: &str| Error::malformed("lzma2", m);
    let mut out: Vec<u8> = Vec::new();
    let mut model = Model::new();
    let mut state = 0usize;
    let mut reps = [0u32; 4];
    let (mut need_dict_reset, mut need_props) = (true, true);
    let mut dict_start = 0usize;
    let (mut lc, mut lp, mut pb) = (LC, LP, PB);
    let mut p = 0;
    loop {
        let control = *data.get(p).ok_or_else(|| bad("missing end marker"))?;
        p += 1;
        if control == 0 {
            return Ok((out, p));
        }
        let be16 = |at: usize| -> Result<usize> { data.get(at..at + 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))).ok_or_else(|| bad("truncated chunk header")) };
        if control == 1 || control == 2 {
            if control == 1 {
                dict_start = out.len();
                need_dict_reset = false;
                need_props = true;
            } else if need_dict_reset {
                return Err(bad("first chunk doesn't reset the dictionary"));
            }
            let size = be16(p)? + 1;
            p += 2;
            let raw = data.get(p..p + size).ok_or_else(|| bad("truncated uncompressed chunk"))?;
            if out.len() + size > max_out {
                return Err(bad("output larger than allowed"));
            }
            out.extend_from_slice(raw);
            p += size;
            continue;
        }
        if control < 0x80 {
            return Err(bad("bad control byte"));
        }
        let unpacked = ((usize::from(control & 0x1F) << 16) | be16(p)?) + 1;
        let packed = be16(p + 2)? + 1;
        p += 4;
        let reset = (control >> 5) & 3;
        if reset == 3 {
            dict_start = out.len();
            need_dict_reset = false;
        } else if need_dict_reset {
            return Err(bad("first chunk doesn't reset the dictionary"));
        }
        if reset >= 2 {
            let mut d = u32::from(*data.get(p).ok_or_else(|| bad("missing properties"))?);
            p += 1;
            if d >= 9 * 5 * 5 {
                return Err(bad("bad properties"));
            }
            lc = d % 9;
            d /= 9;
            lp = d % 5;
            pb = d / 5;
            if lc + lp > 4 {
                return Err(bad("lc + lp over 4"));
            }
            need_props = false;
        } else if need_props {
            return Err(bad("missing properties"));
        }
        if reset >= 1 {
            model = Model::new();
            model.literal = vec![PROB_INIT; 0x300 << (lc + lp)];
            state = 0;
            reps = [0; 4];
        }
        if out.len() + unpacked > max_out {
            return Err(bad("output larger than allowed"));
        }
        let chunk = data.get(p..p + packed).ok_or_else(|| bad("truncated compressed chunk"))?;
        let mut rc = RangeDecoder::new(chunk)?;
        let target = out.len() + unpacked;
        let pb_mask = (1usize << pb) - 1;
        let lp_mask = (1usize << lp) - 1;
        while out.len() < target {
            let pos = out.len() - dict_start;
            let ps = pos & pb_mask;
            if rc.bit(&mut model.is_match[state][ps])? == 0 {
                let prev = if pos > 0 { out[out.len() - 1] } else { 0 };
                let base = 0x300 * (((pos & lp_mask) << lc) + (usize::from(prev) >> (8 - lc)));
                let probs = &mut model.literal[base..base + 0x300];
                let mut symbol = 1usize;
                if state >= 7 {
                    let mut match_byte = usize::from(out[out.len() - reps[0] as usize - 1]);
                    while symbol < 0x100 {
                        let match_bit = (match_byte >> 7) & 1;
                        match_byte <<= 1;
                        let b = rc.bit(&mut probs[((1 + match_bit) << 8) + symbol])? as usize;
                        symbol = (symbol << 1) | b;
                        if match_bit != b {
                            break;
                        }
                    }
                }
                while symbol < 0x100 {
                    symbol = (symbol << 1) | rc.bit(&mut probs[symbol])? as usize;
                }
                out.push(symbol as u8);
                state = after_literal(state);
                continue;
            }
            let len;
            if rc.bit(&mut model.is_rep[state])? == 0 {
                len = decode_len(&mut rc, &mut model.len, ps)?;
                let ls = (len - MATCH_LEN_MIN).min(DIST_STATES - 1);
                let slot = rc.tree(&mut model.dist_slot[ls], 6)?;
                let dist = if slot < 4 {
                    slot
                } else {
                    let footer = (slot >> 1) - 1;
                    let base = (2 | (slot & 1)) << footer;
                    if slot < DIST_MODEL_END {
                        base + rc.reverse_tree(&mut model.dist_special, (base - slot) as usize, footer)?
                    } else {
                        base + (rc.direct(footer - ALIGN_BITS)? << ALIGN_BITS) + rc.reverse_tree(&mut model.dist_align, 1, ALIGN_BITS)?
                    }
                };
                reps = [dist, reps[0], reps[1], reps[2]];
                state = after_match(state);
            } else {
                if rc.bit(&mut model.is_rep_g0[state])? == 0 {
                    if rc.bit(&mut model.is_rep0_long[state][ps])? == 0 {
                        if reps[0] as usize >= pos {
                            return Err(bad("distance before the dictionary start"));
                        }
                        state = after_short_rep(state);
                        let b = out[out.len() - reps[0] as usize - 1];
                        out.push(b);
                        continue;
                    }
                } else {
                    let d;
                    if rc.bit(&mut model.is_rep_g1[state])? == 0 {
                        d = reps[1];
                    } else {
                        if rc.bit(&mut model.is_rep_g2[state])? == 0 {
                            d = reps[2];
                        } else {
                            d = reps[3];
                            reps[3] = reps[2];
                        }
                        reps[2] = reps[1];
                    }
                    reps[1] = reps[0];
                    reps[0] = d;
                }
                len = decode_len(&mut rc, &mut model.rep_len, ps)?;
                state = after_rep(state);
            }
            let back = reps[0] as usize + 1;
            if back > pos {
                return Err(bad("distance before the dictionary start"));
            }
            if out.len() + len > target {
                return Err(bad("match runs past the chunk"));
            }
            let from = out.len() - back;
            for i in 0..len {
                let b = out[from + i];
                out.push(b);
            }
        }
        if rc.code != 0 || rc.pos != packed {
            return Err(bad("compressed chunk size doesn't match"));
        }
        p += packed;
    }
}

fn decode_len(rc: &mut RangeDecoder, m: &mut LenModel, ps: usize) -> Result<usize> {
    Ok(MATCH_LEN_MIN
        + if rc.bit(&mut m.choice)? == 0 {
            rc.tree(&mut m.low[ps], 3)? as usize
        } else if rc.bit(&mut m.choice2)? == 0 {
            8 + rc.tree(&mut m.mid[ps], 3)? as usize
        } else {
            16 + rc.tree(&mut m.high, 8)? as usize
        })
}

/// Test data mixing text-like repeats and noise.
#[cfg(test)]
pub(crate) fn tests_sample(n: usize) -> Vec<u8> {
    tests::sample(n, n as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        let words: [&[u8]; 7] = [b"snap ", b"squashfs ", b"/usr/lib/x86_64-linux-gnu/", b"\x00\x00\x00\x00", b"zz", b"meta/gui/", b"\x7fELF\x02\x01\x01"];
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            if x >> 28 < 3 {
                out.push((x >> 16) as u8);
            } else {
                out.extend_from_slice(words[(x >> 20) as usize % words.len()]);
            }
        }
        out.truncate(n);
        out
    }

    #[test]
    fn round_trips() {
        for &n in &[0usize, 1, 2, 3, 4, 100, 4095, 65535, 65536, 65537, 200_000, 400_000] {
            for opts in [Options::FAST, Options::DEFAULT, Options::BEST.dict_size(1 << 17)] {
                let d = sample(n, n as u32 + 3);
                let c = lzma2_encode(&d, &opts);
                let (back, used) = lzma2_decode(&c, usize::MAX).unwrap();
                assert_eq!(back.len(), d.len(), "n={n}");
                assert!(back == d, "n={n} {opts:?}");
                assert_eq!(used, c.len());
            }
        }
    }

    #[test]
    fn compresses_and_stores() {
        let d = sample(300_000, 9);
        let c = lzma2_encode(&d, &Options::DEFAULT);
        assert!(c.len() < d.len() / 3, "{} -> {}", d.len(), c.len());
        let zeros = vec![0u8; 1 << 20];
        assert!(lzma2_encode(&zeros, &Options::DEFAULT).len() < 1000);
        // Random data is stored in uncompressed chunks, with little overhead.
        let mut x = 7u32;
        let rnd: Vec<u8> = (0..150_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let c = lzma2_encode(&rnd, &Options::DEFAULT);
        assert!(c.len() < rnd.len() + 20, "{}", c.len());
        assert_eq!(lzma2_decode(&c, usize::MAX).unwrap().0, rnd);
        // Mixed: random then repetitive, so an LZMA chunk follows an uncompressed one.
        let mut mixed = rnd[..70_000].to_vec();
        mixed.extend(sample(100_000, 4));
        mixed.extend_from_slice(&rnd[..70_000]);
        assert_eq!(lzma2_decode(&lzma2_encode(&mixed, &Options::DEFAULT), usize::MAX).unwrap().0, mixed);
    }

    #[test]
    fn dict_bytes() {
        assert_eq!(dict_size_byte(1 << 17), (10, 1 << 17));
        assert_eq!(dict_size_byte(1 << 23), (22, 1 << 23));
        assert_eq!(dict_size_byte(3 << 20), (19, 3 << 20));
        assert_eq!(dict_size_byte(100), (0, 4096));
        assert_eq!(dict_size_from_byte(10).unwrap(), 1 << 17);
    }
}
