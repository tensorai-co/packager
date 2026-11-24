//! Windows Installer databases (`.msi`) at the storage level: tables kept in a compound file as
//! a shared string pool (`_StringPool`, `_StringData`), the `_Tables` and `_Columns` catalogs,
//! one column-major stream per table, binary cells in streams of their own, and the
//! `\x05SummaryInformation` property set.
//!
//! Stream names use Windows Installer's packing of `[0-9A-Za-z._]` two per code unit
//! (`0x3800` + a + b·64, singles at `0x4800` + a), with `0x4840` in front of table streams.
//! Strings are Windows-1252 (database codepage 1252).

use crate::format::cfb::{self, Stream};
use crate::{Error, Result};

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("msi", m)
}

/// The root CLSID of an installer database.
pub const CLSID_MSI: [u8; 16] = [0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
/// The database codepage.
pub const CODEPAGE: u16 = 1252;

fn mime(c: u16) -> Option<u16> {
    match c {
        0x30..=0x39 => Some(c - 0x30),
        0x41..=0x5a => Some(c - 0x41 + 10),
        0x61..=0x7a => Some(c - 0x61 + 36),
        0x2e => Some(62),
        0x5f => Some(63),
        _ => None,
    }
}

fn unmime(v: u16) -> u16 {
    match v {
        0..=9 => 0x30 + v,
        10..=35 => 0x41 + v - 10,
        36..=61 => 0x61 + v - 36,
        62 => 0x2e,
        _ => 0x5f,
    }
}

/// The stream name Windows Installer uses for `name` (a table when `table`).
pub fn encode_stream_name(name: &str, table: bool) -> Vec<u16> {
    let src: Vec<u16> = name.encode_utf16().collect();
    let mut out = Vec::new();
    if table {
        out.push(0x4840);
    }
    let mut i = 0;
    while i < src.len() {
        match mime(src[i]) {
            Some(a) => match src.get(i + 1).and_then(|&n| mime(n)) {
                Some(b) => {
                    out.push(0x3800 + a + (b << 6));
                    i += 2;
                }
                None => {
                    out.push(0x4800 + a);
                    i += 1;
                }
            },
            None => {
                out.push(src[i]);
                i += 1;
            }
        }
    }
    out
}

/// Decodes a stream name: (name, whether it's a table stream).
pub fn decode_stream_name(units: &[u16]) -> (String, bool) {
    let (table, units) = match units.first() {
        Some(0x4840) => (true, &units[1..]),
        _ => (false, units),
    };
    let mut out = Vec::new();
    for &c in units {
        match c {
            0x3800..=0x47ff => {
                let v = c - 0x3800;
                out.push(unmime(v & 0x3f));
                out.push(unmime(v >> 6));
            }
            0x4800..=0x483f => out.push(unmime(c - 0x4800)),
            _ => out.push(c),
        }
    }
    (String::from_utf16_lossy(&out), table)
}

/// Windows-1252 bytes for `s`.
pub fn cp1252(s: &str) -> Result<Vec<u8>> {
    const HIGH: [(char, u8); 27] = [
        ('€', 0x80),
        ('‚', 0x82),
        ('ƒ', 0x83),
        ('„', 0x84),
        ('…', 0x85),
        ('†', 0x86),
        ('‡', 0x87),
        ('ˆ', 0x88),
        ('‰', 0x89),
        ('Š', 0x8a),
        ('‹', 0x8b),
        ('Œ', 0x8c),
        ('Ž', 0x8e),
        ('‘', 0x91),
        ('’', 0x92),
        ('“', 0x93),
        ('”', 0x94),
        ('•', 0x95),
        ('–', 0x96),
        ('—', 0x97),
        ('˜', 0x98),
        ('™', 0x99),
        ('š', 0x9a),
        ('›', 0x9b),
        ('œ', 0x9c),
        ('ž', 0x9e),
        ('Ÿ', 0x9f),
    ];
    s.chars()
        .map(|c| match c as u32 {
            0..=0x7f | 0xa0..=0xff => Ok(c as u8),
            _ => HIGH.iter().find(|(h, _)| *h == c).map(|(_, b)| *b).ok_or_else(|| Error::invalid("msi", s.to_string(), format!("`{c}` can't be written in the database's codepage (Windows-1252)"))),
        })
        .collect()
}

fn from_cp1252(b: &[u8]) -> String {
    const HIGH: &str = "€\u{81}‚ƒ„…†‡ˆ‰Š‹Œ\u{8d}Ž\u{8f}\u{90}‘’“”•–—˜™š›œ\u{9d}žŸ";
    let high: Vec<char> = HIGH.chars().collect();
    b.iter().map(|&x| if (0x80..0xa0).contains(&x) { high[(x - 0x80) as usize] } else { x as char }).collect()
}

/// A column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A string of at most this many characters (0: unlimited).
    Str(u8),
    /// A localizable string.
    LocStr(u8),
    /// A 16-bit integer.
    Short,
    /// A 32-bit integer.
    Long,
    /// A stream (`Binary`, `Icon` data).
    Binary,
}

/// A column definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// Name.
    pub name: String,
    /// Type.
    pub kind: Kind,
    /// Allows nulls.
    pub nullable: bool,
    /// Part of the primary key.
    pub key: bool,
}

impl Column {
    /// The `_Columns.Type` value (Windows Installer's `icd*` bits).
    pub fn type_bits(&self) -> u16 {
        let base = match self.kind {
            Kind::Str(w) => 0x0d00 | u16::from(w),
            Kind::LocStr(w) => 0x0f00 | u16::from(w),
            Kind::Short => 0x0502,
            Kind::Long => 0x0104,
            Kind::Binary => 0x0900,
        };
        base | if self.nullable { 0x1000 } else { 0 } | if self.key { 0x2000 } else { 0 }
    }

    fn from_bits(name: String, t: u16) -> Column {
        let nullable = t & 0x1000 != 0;
        let key = t & 0x2000 != 0;
        let w = (t & 0xff) as u8;
        let kind = if t & 0x0800 != 0 {
            if t & 0x0400 == 0 {
                Kind::Binary
            } else if t & 0x0200 != 0 {
                Kind::LocStr(w)
            } else {
                Kind::Str(w)
            }
        } else if w <= 2 {
            Kind::Short
        } else {
            Kind::Long
        };
        Column { name, kind, nullable, key }
    }

    fn width(&self, strref: usize) -> usize {
        match self.kind {
            Kind::Binary | Kind::Short => 2,
            Kind::Long => 4,
            Kind::Str(_) | Kind::LocStr(_) => strref,
        }
    }
}

/// Shorthand for column definitions: `s72` (string), `l255` (localizable), `i2`, `i4`, `v0`
/// (binary); a `?` suffix makes it nullable, a `*` prefix a key column.
pub fn col(name: &str, spec: &str) -> Column {
    let key = spec.starts_with('*');
    let spec = spec.trim_start_matches('*');
    let nullable = spec.ends_with('?');
    let spec = spec.trim_end_matches('?');
    let w: u8 = spec[1..].parse().unwrap_or(0);
    let kind = match &spec[..1] {
        "s" => Kind::Str(w),
        "l" => Kind::LocStr(w),
        "i" if w == 2 => Kind::Short,
        "i" => Kind::Long,
        _ => Kind::Binary,
    };
    Column { name: name.into(), kind, nullable, key }
}

/// A cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Null (empty strings are null too).
    Null,
    /// An integer.
    Int(i32),
    /// A string.
    Str(String),
    /// Stream contents (binary columns).
    Binary(Vec<u8>),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        if s.is_empty() { Value::Null } else { Value::Str(s.to_string()) }
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        if s.is_empty() { Value::Null } else { Value::Str(s) }
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(v)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map(Into::into).unwrap_or(Value::Null)
    }
}

impl Value {
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        if let Value::Str(s) = self { Some(s) } else { None }
    }
    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i32> {
        if let Value::Int(v) = self { Some(*v) } else { None }
    }
}

/// A table: its schema and rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    /// Name.
    pub name: String,
    /// Columns in order.
    pub columns: Vec<Column>,
    /// Rows, one value per column.
    pub rows: Vec<Vec<Value>>,
}

impl Table {
    /// An empty table.
    pub fn new(name: &str, columns: Vec<Column>) -> Self {
        Table { name: name.into(), columns, rows: Vec::new() }
    }
    /// Adds a row.
    pub fn row(&mut self, values: Vec<Value>) -> &mut Self {
        self.rows.push(values);
        self
    }
    /// The value of `column` in each row.
    pub fn column(&self, column: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == column)
    }
}

/// `\x05SummaryInformation` values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    /// PID_TITLE.
    pub title: String,
    /// PID_SUBJECT (the product name).
    pub subject: String,
    /// PID_AUTHOR (the manufacturer).
    pub author: String,
    /// PID_KEYWORDS.
    pub keywords: String,
    /// PID_COMMENTS.
    pub comments: String,
    /// PID_TEMPLATE: `x64;1033`.
    pub template: String,
    /// PID_REVNUMBER: the package code `{GUID}`.
    pub revision: String,
    /// PID_APPNAME.
    pub app_name: String,
    /// Creation / last-save time (Unix seconds).
    pub time: i64,
    /// PID_PAGECOUNT: minimum installer version (200 for x86, 500 for x64 and Arm64).
    pub page_count: i32,
    /// PID_WORDCOUNT: source flags (2 = compressed, long names; +8 = no elevation needed).
    pub word_count: i32,
    /// PID_SECURITY (2 = read-only recommended).
    pub security: i32,
}

const FMTID_SUMMARY: [u8; 16] = [0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9];

impl Summary {
    /// The property set stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let ft = |unix: i64| ((unix.max(0) as u64 + 11_644_473_600) * 10_000_000).to_le_bytes();
        let mut props: Vec<(u32, Vec<u8>)> = vec![(1, [&2u32.to_le_bytes()[..], &CODEPAGE.to_le_bytes(), &[0, 0]].concat())];
        let mut text = |id: u32, s: &str| -> Result<()> {
            if !s.is_empty() {
                let mut b = cp1252(s)?;
                b.push(0);
                let mut v = 30u32.to_le_bytes().to_vec(); // VT_LPSTR
                v.extend_from_slice(&(b.len() as u32).to_le_bytes());
                v.extend_from_slice(&b);
                while !v.len().is_multiple_of(4) {
                    v.push(0);
                }
                props.push((id, v));
            }
            Ok(())
        };
        text(2, &self.title)?;
        text(3, &self.subject)?;
        text(4, &self.author)?;
        text(5, &self.keywords)?;
        text(6, &self.comments)?;
        text(7, &self.template)?;
        text(9, &self.revision)?;
        for id in [12u32, 13] {
            props.push((id, [&64u32.to_le_bytes()[..], &ft(self.time)].concat())); // VT_FILETIME
        }
        for (id, v) in [(14u32, self.page_count), (15, self.word_count)] {
            props.push((id, [&3u32.to_le_bytes()[..], &v.to_le_bytes()].concat())); // VT_I4
        }
        let mut t = Vec::new();
        text_into(&mut t, &self.app_name)?;
        if !t.is_empty() {
            props.push((18, t));
        }
        props.push((19, [&3u32.to_le_bytes()[..], &self.security.to_le_bytes()].concat()));
        props.sort_by_key(|p| p.0);

        let mut section = Vec::new();
        let header_len = 8 + 8 * props.len();
        let mut off = header_len;
        let mut index = Vec::new();
        for (id, v) in &props {
            index.extend_from_slice(&id.to_le_bytes());
            index.extend_from_slice(&(off as u32).to_le_bytes());
            off += v.len();
        }
        section.extend_from_slice(&(off as u32).to_le_bytes());
        section.extend_from_slice(&(props.len() as u32).to_le_bytes());
        section.extend_from_slice(&index);
        for (_, v) in &props {
            section.extend_from_slice(v);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&0xfffeu16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x0002_0006u32.to_le_bytes()); // OS version: Windows, 6.2
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&FMTID_SUMMARY);
        out.extend_from_slice(&48u32.to_le_bytes());
        out.extend_from_slice(&section);
        Ok(out)
    }

    /// Reads the property set's text and integer properties: (id, value).
    pub fn parse(data: &[u8]) -> Result<Vec<(u32, Value)>> {
        let le32 = |p: usize| data.get(p..p + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| bad("truncated summary"));
        let sec = le32(44)? as usize;
        let n = le32(sec + 4)? as usize;
        let mut out = Vec::new();
        for k in 0..n {
            let id = le32(sec + 8 + 8 * k)?;
            let at = sec + le32(sec + 12 + 8 * k)? as usize;
            let v = match le32(at)? {
                30 => {
                    let len = le32(at + 4)? as usize;
                    let b = data.get(at + 8..at + 8 + len).ok_or_else(|| bad("truncated string"))?;
                    Value::Str(from_cp1252(b.strip_suffix(&[0]).unwrap_or(b)))
                }
                3 => Value::Int(le32(at + 4)? as i32),
                2 => Value::Int(i32::from(data.get(at + 4..at + 6).map(|b| i16::from_le_bytes([b[0], b[1]])).unwrap_or(0))),
                _ => Value::Null,
            };
            out.push((id, v));
        }
        Ok(out)
    }
}

fn text_into(v: &mut Vec<u8>, s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let mut b = cp1252(s)?;
    b.push(0);
    v.extend_from_slice(&30u32.to_le_bytes());
    v.extend_from_slice(&(b.len() as u32).to_le_bytes());
    v.extend_from_slice(&b);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    Ok(())
}

/// The string pool being built: id 0 is null.
#[derive(Default)]
struct Pool {
    strings: Vec<String>,
    refs: Vec<u32>,
    ids: std::collections::HashMap<String, u32>,
}

impl Pool {
    fn id(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&i) = self.ids.get(s) {
            self.refs[i as usize - 1] += 1;
            return i;
        }
        self.strings.push(s.to_string());
        self.refs.push(1);
        let i = self.strings.len() as u32;
        self.ids.insert(s.to_string(), i);
        i
    }
}

/// A database to write: tables, extra streams (embedded cabinets) and the summary.
#[derive(Debug, Clone, Default)]
pub struct Database {
    /// The tables.
    pub tables: Vec<Table>,
    /// Streams outside the tables, by name (`data.cab` for `Media.Cabinet = "#data.cab"`).
    pub streams: Vec<(String, Vec<u8>)>,
    /// Summary information.
    pub summary: Summary,
}

impl Database {
    /// Writes the database as a compound file, with any `extra` raw streams (signatures).
    pub fn write(&self, extra: &[Stream]) -> Result<Vec<u8>> {
        let mut pool = Pool::default();
        let mut tables = self.tables.clone();
        tables.sort_by(|a, b| a.name.cmp(&b.name));
        // Validate and intern every string first: ids decide row order and widths.
        let mut streams = Vec::new();
        for t in &tables {
            if !t.columns.iter().any(|c| c.key) {
                return Err(Error::invalid("msi", t.name.clone(), "a table needs at least one key column"));
            }
            for r in &t.rows {
                if r.len() != t.columns.len() {
                    return Err(Error::invalid("msi", t.name.clone(), format!("row has {} values for {} columns", r.len(), t.columns.len())));
                }
                for (c, v) in t.columns.iter().zip(r) {
                    match (v, c.kind) {
                        (Value::Null, _) if !c.nullable => return Err(Error::invalid("msi", format!("{}.{}", t.name, c.name), "can't be null")),
                        (Value::Null, _) | (Value::Str(_), Kind::Str(_) | Kind::LocStr(_)) | (Value::Int(_), Kind::Short | Kind::Long) | (Value::Binary(_), Kind::Binary) => {}
                        _ => return Err(Error::invalid("msi", format!("{}.{}", t.name, c.name), format!("value {v:?} doesn't fit the column type"))),
                    }
                    if let (Value::Str(s), Kind::Str(w) | Kind::LocStr(w)) = (v, c.kind)
                        && w != 0
                        && s.chars().count() > usize::from(w)
                    {
                        return Err(Error::invalid("msi", format!("{}.{}", t.name, c.name), format!("`{s}` is longer than {w} characters")));
                    }
                    if let (Value::Int(i), Kind::Short) = (v, c.kind)
                        && !(-32767..=32767).contains(i)
                    {
                        return Err(Error::invalid("msi", format!("{}.{}", t.name, c.name), format!("{i} doesn't fit in 16 bits")));
                    }
                }
            }
        }
        let mut columns_rows: Vec<(String, i32, String, i32)> = Vec::new();
        for t in &tables {
            pool.id(&t.name);
            for (i, c) in t.columns.iter().enumerate() {
                columns_rows.push((t.name.clone(), i as i32 + 1, c.name.clone(), i32::from(c.type_bits())));
            }
        }
        for (t, _, n, _) in &columns_rows {
            pool.id(t);
            pool.id(n);
        }
        // Table cells: string ids (interned in row order), offset integers.
        let mut encoded: Vec<(String, Vec<Column>, Vec<Vec<u32>>)> = Vec::new();
        for t in &tables {
            let mut rows = Vec::new();
            for r in &t.rows {
                let mut cells = Vec::new();
                for (c, v) in t.columns.iter().zip(r) {
                    cells.push(match (v, c.kind) {
                        (Value::Null, _) => 0,
                        (Value::Str(s), _) => {
                            cp1252(s)?;
                            pool.id(s)
                        }
                        (Value::Int(i), Kind::Short) => (*i as i16 as u16 ^ 0x8000) as u32,
                        (Value::Int(i), _) => *i as u32 ^ 0x8000_0000,
                        (Value::Binary(_), _) => 1,
                    });
                }
                rows.push(cells);
            }
            encoded.push((t.name.clone(), t.columns.clone(), rows));
        }
        let strref = if pool.strings.len() > 0xffff { 3 } else { 2 };
        let put = |out: &mut Vec<u8>, v: u32, w: usize| out.extend_from_slice(&v.to_le_bytes()[..w]);

        // Binary cells go in `Table.key1.key2` streams.
        for t in &tables {
            for r in &t.rows {
                for (c, v) in t.columns.iter().zip(r) {
                    if let (Value::Binary(data), Kind::Binary) = (v, c.kind) {
                        let keys: Vec<String> = t
                            .columns
                            .iter()
                            .zip(r)
                            .filter(|(c, _)| c.key)
                            .map(|(_, v)| match v {
                                Value::Str(s) => s.clone(),
                                Value::Int(i) => i.to_string(),
                                _ => String::new(),
                            })
                            .collect();
                        let name = format!("{}.{}", t.name, keys.join("."));
                        streams.push(Stream { name: encode_stream_name(&name, false), data: data.clone() });
                    }
                }
            }
        }

        for (name, cols, rows) in &mut encoded {
            // Rows in primary-key order, comparing stored values.
            let key_idx: Vec<usize> = cols.iter().enumerate().filter(|(_, c)| c.key).map(|(i, _)| i).collect();
            rows.sort_by(|a, b| key_idx.iter().map(|&i| a[i]).cmp(key_idx.iter().map(|&i| b[i])));
            for w in rows.windows(2) {
                if key_idx.iter().all(|&i| w[0][i] == w[1][i]) {
                    return Err(Error::invalid("msi", name.clone(), "two rows have the same primary key"));
                }
            }
            let mut data = Vec::new();
            for (ci, c) in cols.iter().enumerate() {
                for r in rows.iter() {
                    put(&mut data, r[ci], c.width(strref));
                }
            }
            streams.push(Stream { name: encode_stream_name(name, true), data });
        }
        // _Tables and _Columns.
        let mut tdata = Vec::new();
        let mut names: Vec<u32> = tables.iter().map(|t| pool.ids[&t.name]).collect();
        names.sort();
        for id in names {
            put(&mut tdata, id, strref);
        }
        streams.push(Stream { name: encode_stream_name("_Tables", true), data: tdata });
        let mut crows: Vec<(u32, i32, u32, i32)> = columns_rows.iter().map(|(t, n, c, ty)| (pool.ids[t], *n, pool.ids[c], *ty)).collect();
        crows.sort_by_key(|r| (r.0, r.1));
        let mut cdata = Vec::new();
        for r in &crows {
            put(&mut cdata, r.0, strref);
        }
        for r in &crows {
            put(&mut cdata, (r.1 as u16 ^ 0x8000) as u32, 2);
        }
        for r in &crows {
            put(&mut cdata, r.2, strref);
        }
        for r in &crows {
            put(&mut cdata, (r.3 as u16 ^ 0x8000) as u32, 2);
        }
        streams.push(Stream { name: encode_stream_name("_Columns", true), data: cdata });
        // The string pool.
        let mut sp = Vec::new();
        sp.extend_from_slice(&CODEPAGE.to_le_bytes());
        sp.extend_from_slice(&(if strref == 3 { 0x8000u16 } else { 0 }).to_le_bytes());
        let mut sd = Vec::new();
        for (s, r) in pool.strings.iter().zip(&pool.refs) {
            let b = cp1252(s)?;
            if b.len() >= 0x10000 {
                return Err(Error::invalid("msi", s.chars().take(40).collect::<String>(), "strings over 64 KB aren't supported"));
            }
            sp.extend_from_slice(&(b.len() as u16).to_le_bytes());
            sp.extend_from_slice(&(*r.min(&0xffff) as u16).to_le_bytes());
            sd.extend_from_slice(&b);
        }
        streams.push(Stream { name: encode_stream_name("_StringPool", true), data: sp });
        streams.push(Stream { name: encode_stream_name("_StringData", true), data: sd });
        for (n, d) in &self.streams {
            streams.push(Stream { name: encode_stream_name(n, false), data: d.clone() });
        }
        streams.push(Stream::new("\u{5}SummaryInformation", self.summary.to_bytes()?));
        streams.extend(extra.iter().cloned());
        cfb::write(&streams, CLSID_MSI)
    }
}

/// A database read back: tables (binary cells left as `Value::Binary` with their stream),
/// other streams, and the summary properties.
#[derive(Debug, Clone)]
pub struct ReadDatabase {
    /// Tables, by name order.
    pub tables: Vec<Table>,
    /// Non-table streams: (decoded name, data).
    pub streams: Vec<(String, Vec<u8>)>,
    /// Summary information properties.
    pub summary: Vec<(u32, Value)>,
}

impl ReadDatabase {
    /// A table by name.
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }
}

/// Reads an installer database.
pub fn read(data: &[u8]) -> Result<ReadDatabase> {
    let root = cfb::read(data)?;
    let mut table_streams = std::collections::HashMap::new();
    let mut streams = Vec::new();
    let mut summary = Vec::new();
    for c in &root.children {
        if c.is_storage {
            continue;
        }
        if c.name.first() == Some(&5) {
            if String::from_utf16_lossy(&c.name[1..]) == "SummaryInformation" {
                summary = Summary::parse(&c.data)?;
            }
            continue;
        }
        let (n, table) = decode_stream_name(&c.name);
        if table {
            table_streams.insert(n, c.data.clone());
        } else {
            streams.push((n, c.data.clone()));
        }
    }
    let pool = table_streams.get("_StringPool").ok_or_else(|| bad("no _StringPool"))?;
    let sdata = table_streams.get("_StringData").ok_or_else(|| bad("no _StringData"))?;
    let strref = if pool.len() >= 4 && pool[3] & 0x80 != 0 { 3 } else { 2 };
    let mut strings = vec![String::new()];
    let mut off = 0;
    let mut i = 4;
    while i + 4 <= pool.len() {
        let mut len = u16::from_le_bytes([pool[i], pool[i + 1]]) as usize;
        let refs = u16::from_le_bytes([pool[i + 2], pool[i + 3]]);
        if len == 0 && refs != 0 && i + 8 <= pool.len() {
            len = u16::from_le_bytes([pool[i + 4], pool[i + 5]]) as usize | (u16::from_le_bytes([pool[i + 6], pool[i + 7]]) as usize) << 16;
            i += 4;
        }
        let b = sdata.get(off..off + len).ok_or_else(|| bad("string data out of range"))?;
        strings.push(from_cp1252(b));
        off += len;
        i += 4;
    }
    let get = |d: &[u8], at: usize, w: usize| -> Result<u32> {
        let b = d.get(at..at + w).ok_or_else(|| bad("table data truncated"))?;
        Ok(b.iter().rev().fold(0u32, |a, &x| (a << 8) | u32::from(x)))
    };
    let s = |id: u32| strings.get(id as usize).cloned().ok_or_else(|| bad(format!("string id {id} out of range")));
    let tdata = table_streams.get("_Tables").cloned().unwrap_or_default();
    let table_names: Vec<String> = (0..tdata.len() / strref).map(|k| get(&tdata, k * strref, strref).and_then(s)).collect::<Result<_>>()?;
    let cdata = table_streams.get("_Columns").cloned().unwrap_or_default();
    let crow = 2 * strref + 4;
    let n = cdata.len() / crow;
    let mut schema: std::collections::BTreeMap<String, Vec<(i32, Column)>> = std::collections::BTreeMap::new();
    for k in 0..n {
        let t = s(get(&cdata, k * strref, strref)?)?;
        let num = (get(&cdata, n * strref + 2 * k, 2)? ^ 0x8000) as i32;
        let name = s(get(&cdata, n * (strref + 2) + strref * k, strref)?)?;
        let ty = (get(&cdata, n * (2 * strref + 2) + 2 * k, 2)? ^ 0x8000) as u16;
        schema.entry(t).or_default().push((num, Column::from_bits(name, ty)));
    }
    let mut tables = Vec::new();
    for name in table_names {
        let mut cols = schema.remove(&name).unwrap_or_default();
        cols.sort_by_key(|c| c.0);
        let columns: Vec<Column> = cols.into_iter().map(|c| c.1).collect();
        let raw = table_streams.get(&name).cloned().unwrap_or_default();
        let row_len: usize = columns.iter().map(|c| c.width(strref)).sum();
        let rows_n = raw.len().checked_div(row_len).unwrap_or(0);
        let mut rows = vec![Vec::with_capacity(columns.len()); rows_n];
        let mut base = 0;
        for c in &columns {
            let w = c.width(strref);
            for (r, row) in rows.iter_mut().enumerate() {
                let v = get(&raw, base + r * w, w)?;
                row.push(match c.kind {
                    _ if v == 0 && c.kind != Kind::Binary => Value::Null,
                    Kind::Str(_) | Kind::LocStr(_) => Value::Str(s(v)?),
                    Kind::Short => Value::Int((v as u16 ^ 0x8000) as i16 as i32),
                    Kind::Long => Value::Int((v ^ 0x8000_0000) as i32),
                    Kind::Binary => Value::Null,
                });
            }
            base += w * rows_n;
        }
        // Attach binary streams.
        for row in rows.iter_mut() {
            let keys: Vec<String> =
                columns.iter().zip(row.iter()).filter(|(c, _)| c.key).map(|(_, v)| v.as_str().map(String::from).or_else(|| v.as_int().map(|i| i.to_string())).unwrap_or_default()).collect();
            let sname = format!("{name}.{}", keys.join("."));
            for (c, v) in columns.iter().zip(row.iter_mut()) {
                if c.kind == Kind::Binary
                    && let Some((_, d)) = streams.iter().find(|(n, _)| *n == sname)
                {
                    *v = Value::Binary(d.clone());
                }
            }
        }
        tables.push(Table { name, columns, rows });
    }
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ReadDatabase { tables, streams, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_names() {
        let e = encode_stream_name("_StringPool", true);
        assert_eq!(e[0], 0x4840);
        assert_eq!(decode_stream_name(&e), ("_StringPool".to_string(), true));
        assert_eq!(decode_stream_name(&encode_stream_name("data.cab", false)), ("data.cab".to_string(), false));
        // Odd lengths end in a single packed character.
        assert_eq!(encode_stream_name("abc", false).len(), 2);
    }

    #[test]
    fn round_trip() {
        let mut prop = Table::new("Property", vec![col("Property", "*s72"), col("Value", "l0")]);
        prop.row(vec!["ProductName".into(), "Café App".into()]).row(vec!["ALLUSERS".into(), "1".into()]);
        let mut file = Table::new("File", vec![col("File", "*s72"), col("FileSize", "i4"), col("Attributes", "i2?"), col("Sequence", "i2")]);
        file.row(vec!["b".into(), 70_000.into(), Value::Null, 2.into()]).row(vec!["a".into(), 5.into(), 512.into(), 1.into()]);
        let mut icon = Table::new("Icon", vec![col("Name", "*s72"), col("Data", "v0")]);
        icon.row(vec!["app.ico".into(), Value::Binary(vec![1, 2, 3])]);
        let db = Database {
            tables: vec![prop, file, icon],
            streams: vec![("data.cab".into(), vec![9; 5000])],
            summary: Summary { subject: "Café App".into(), template: "x64;1033".into(), page_count: 500, word_count: 2, ..Default::default() },
        };
        let bytes = db.write(&[]).unwrap();
        let back = read(&bytes).unwrap();
        let p = back.table("Property").unwrap();
        assert!(p.rows.contains(&vec![Value::Str("ProductName".into()), Value::Str("Café App".into())]));
        let f = back.table("File").unwrap();
        assert_eq!(f.rows[0], vec![Value::Str("b".into()), Value::Int(70_000), Value::Null, Value::Int(2)]);
        assert_eq!(back.table("Icon").unwrap().rows[0][1], Value::Binary(vec![1, 2, 3]));
        assert_eq!(back.streams.iter().find(|s| s.0 == "data.cab").map(|s| s.1.len()), Some(5000));
        assert!(back.summary.contains(&(7, Value::Str("x64;1033".into()))));
        assert!(cp1252("日本").is_err());
    }
}
