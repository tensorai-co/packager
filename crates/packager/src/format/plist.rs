//! Property lists: an ordered value tree, the XML format (read and write), and a reader for
//! the binary format (`bplist00`), since apps and frameworks often ship binary `Info.plist`s.

use crate::format::{base64, xml};
use crate::{Error, Result};

/// A property-list value. Dictionaries keep insertion order.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `<string>`
    String(String),
    /// `<integer>`
    Integer(i64),
    /// `<real>`
    Real(f64),
    /// `<true/>` / `<false/>`
    Bool(bool),
    /// `<date>`, as written (ISO 8601, `2026-01-01T00:00:00Z`).
    Date(String),
    /// `<data>`
    Data(Vec<u8>),
    /// `<array>`
    Array(Vec<Value>),
    /// `<dict>`
    Dict(Dict),
}

/// An ordered dictionary.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dict(pub Vec<(String, Value)>);

impl Dict {
    /// An empty dictionary.
    pub fn new() -> Self {
        Dict(Vec::new())
    }
    /// Sets `key`, replacing an existing value in place.
    pub fn insert(&mut self, key: impl Into<String>, v: impl Into<Value>) -> &mut Self {
        let key = key.into();
        let v = v.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = v;
        } else {
            self.0.push((key, v));
        }
        self
    }
    /// Builder-style [`Dict::insert`].
    pub fn with(mut self, key: impl Into<String>, v: impl Into<Value>) -> Self {
        self.insert(key, v);
        self
    }
    /// The value for `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// The string value for `key`.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::String(s)) => Some(s),
            _ => None,
        }
    }
    /// Removes `key`.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let i = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(i).1)
    }
    /// Sorts keys by their UTF-8 bytes, recursively, as `plutil` and `codesign` write them.
    pub fn sort_recursive(&mut self) {
        self.0.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, v) in &mut self.0 {
            v.sort_recursive();
        }
    }
    /// Iterates entries in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Value {
    fn sort_recursive(&mut self) {
        match self {
            Value::Dict(d) => d.sort_recursive(),
            Value::Array(a) => a.iter_mut().for_each(Value::sort_recursive),
            _ => {}
        }
    }
    /// The dictionary inside, if this is one.
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    /// The string inside, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Serializes as an XML property list, tab-indented like Apple's own writer.
    pub fn to_xml(&self) -> String {
        let mut s = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n",
        );
        write_value(&mut s, self, 0);
        s.push_str("</plist>\n");
        s
    }

    /// Serializes as a binary property list (`bplist00`).
    pub fn to_binary(&self) -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = Vec::new();
        // First pass counts objects to size references.
        fn count(v: &Value) -> usize {
            match v {
                Value::Array(a) => 1 + a.iter().map(count).sum::<usize>(),
                Value::Dict(d) => 1 + d.0.iter().map(|(_, v)| 1 + count(v)).sum::<usize>(),
                _ => 1,
            }
        }
        let n = count(self);
        let ref_size = if n < 256 { 1 } else if n < 65536 { 2 } else { 4 };
        fn put_ref(out: &mut Vec<u8>, r: usize, size: usize) {
            out.extend_from_slice(&(r as u32).to_be_bytes()[4 - size..]);
        }
        fn marker_len(out: &mut Vec<u8>, hi: u8, len: usize) {
            if len < 15 {
                out.push(hi << 4 | len as u8);
            } else {
                out.push(hi << 4 | 0xf);
                int_obj(out, len as i64);
            }
        }
        fn int_obj(out: &mut Vec<u8>, i: i64) {
            if (0..=0xff).contains(&i) {
                out.extend_from_slice(&[0x10, i as u8]);
            } else if (0..=0xffff).contains(&i) {
                out.push(0x11);
                out.extend_from_slice(&(i as u16).to_be_bytes());
            } else if (0..=0xffff_ffff).contains(&i) {
                out.push(0x12);
                out.extend_from_slice(&(i as u32).to_be_bytes());
            } else {
                out.push(0x13);
                out.extend_from_slice(&i.to_be_bytes());
            }
        }
        fn string_obj(s: &str) -> Vec<u8> {
            let mut o = Vec::new();
            if s.is_ascii() {
                marker_len(&mut o, 5, s.len());
                o.extend_from_slice(s.as_bytes());
            } else {
                let u: Vec<u16> = s.encode_utf16().collect();
                marker_len(&mut o, 6, u.len());
                for x in u {
                    o.extend_from_slice(&x.to_be_bytes());
                }
            }
            o
        }
        // Objects are numbered depth first; containers reserve their slot before children.
        fn emit(v: &Value, objects: &mut Vec<Vec<u8>>, rs: usize) -> usize {
            let idx = objects.len();
            objects.push(Vec::new());
            let body = match v {
                Value::Bool(b) => vec![if *b { 0x09 } else { 0x08 }],
                Value::Integer(i) => {
                    let mut o = Vec::new();
                    int_obj(&mut o, *i);
                    o
                }
                Value::Real(r) => {
                    let mut o = vec![0x23];
                    o.extend_from_slice(&r.to_be_bytes());
                    o
                }
                Value::Date(d) => string_obj(d),
                Value::String(s) => string_obj(s),
                Value::Data(d) => {
                    let mut o = Vec::new();
                    marker_len(&mut o, 4, d.len());
                    o.extend_from_slice(d);
                    o
                }
                Value::Array(a) => {
                    let refs: Vec<usize> = a.iter().map(|x| emit(x, objects, rs)).collect();
                    let mut o = Vec::new();
                    marker_len(&mut o, 0xa, refs.len());
                    for r in refs {
                        put_ref(&mut o, r, rs);
                    }
                    o
                }
                Value::Dict(d) => {
                    let mut keys = Vec::new();
                    let mut vals = Vec::new();
                    for (k, x) in &d.0 {
                        keys.push(emit(&Value::String(k.clone()), objects, rs));
                        vals.push(emit(x, objects, rs));
                    }
                    let mut o = Vec::new();
                    marker_len(&mut o, 0xd, keys.len());
                    for r in keys.into_iter().chain(vals) {
                        put_ref(&mut o, r, rs);
                    }
                    o
                }
            };
            objects[idx] = body;
            idx
        }
        emit(self, &mut objects, ref_size);
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::with_capacity(objects.len());
        for o in &objects {
            offsets.push(out.len());
            out.extend_from_slice(o);
        }
        let table = out.len();
        let off_size = if table < 256 { 1 } else if table < 65536 { 2 } else { 4 };
        for o in offsets {
            out.extend_from_slice(&(o as u32).to_be_bytes()[4 - off_size..]);
        }
        out.extend_from_slice(&[0u8; 6]);
        out.push(off_size as u8);
        out.push(ref_size as u8);
        out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&(table as u64).to_be_bytes());
        out
    }

    /// Parses an XML or binary property list.
    pub fn parse(bytes: &[u8]) -> Result<Value> {
        if bytes.starts_with(b"bplist00") {
            return parse_binary(bytes);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::malformed("plist", "not UTF-8"))?;
        let root = xml::parse(text)?;
        if root.name != "plist" {
            return Err(Error::malformed("plist", format!("root element is `{}`", root.name)));
        }
        let v = root.elements().next().ok_or_else(|| Error::malformed("plist", "empty plist"))?;
        from_element(v)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::String(s.clone())
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Integer(i)
    }
}
impl From<Dict> for Value {
    fn from(d: Dict) -> Self {
        Value::Dict(d)
    }
}
impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

fn write_value(s: &mut String, v: &Value, depth: usize) {
    let pad = "\t".repeat(depth);
    match v {
        Value::String(t) => s.push_str(&format!("{pad}<string>{}</string>\n", xml::escape(t))),
        Value::Integer(i) => s.push_str(&format!("{pad}<integer>{i}</integer>\n")),
        Value::Real(r) => s.push_str(&format!("{pad}<real>{r}</real>\n")),
        Value::Bool(true) => s.push_str(&format!("{pad}<true/>\n")),
        Value::Bool(false) => s.push_str(&format!("{pad}<false/>\n")),
        Value::Date(d) => s.push_str(&format!("{pad}<date>{}</date>\n", xml::escape(d))),
        Value::Data(d) => {
            s.push_str(&format!("{pad}<data>\n"));
            let enc = base64::encode(d);
            for line in enc.as_bytes().chunks(68) {
                s.push_str(&pad);
                s.push_str(std::str::from_utf8(line).unwrap_or_default());
                s.push('\n');
            }
            s.push_str(&format!("{pad}</data>\n"));
        }
        Value::Array(a) if a.is_empty() => s.push_str(&format!("{pad}<array/>\n")),
        Value::Array(a) => {
            s.push_str(&format!("{pad}<array>\n"));
            for x in a {
                write_value(s, x, depth + 1);
            }
            s.push_str(&format!("{pad}</array>\n"));
        }
        Value::Dict(d) if d.is_empty() => s.push_str(&format!("{pad}<dict/>\n")),
        Value::Dict(d) => {
            s.push_str(&format!("{pad}<dict>\n"));
            for (k, x) in &d.0 {
                s.push_str(&format!("{pad}\t<key>{}</key>\n", xml::escape(k)));
                write_value(s, x, depth + 1);
            }
            s.push_str(&format!("{pad}</dict>\n"));
        }
    }
}

fn from_element(e: &xml::Element) -> Result<Value> {
    let bad = |m: String| Error::malformed("plist", m);
    Ok(match e.name.as_str() {
        "string" => Value::String(e.text_content()),
        "integer" => {
            let t = e.text_content();
            let t = t.trim();
            let v = if let Some(h) = t.strip_prefix("0x") {
                i64::from_str_radix(h, 16).ok()
            } else {
                t.parse::<i64>().ok().or_else(|| t.parse::<u64>().ok().map(|u| u as i64))
            };
            Value::Integer(v.ok_or_else(|| bad(format!("bad integer `{t}`")))?)
        }
        "real" => Value::Real(e.text_content().trim().parse().map_err(|_| bad("bad real".into()))?),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "date" => Value::Date(e.text_content().trim().to_string()),
        "data" => Value::Data(base64::decode(&e.text_content())?),
        "array" => Value::Array(e.elements().map(from_element).collect::<Result<_>>()?),
        "dict" => {
            let mut d = Dict::new();
            let mut it = e.elements();
            while let Some(k) = it.next() {
                if k.name != "key" {
                    return Err(bad(format!("expected <key>, found <{}>", k.name)));
                }
                let v = it.next().ok_or_else(|| bad("key without value".into()))?;
                d.0.push((k.text_content(), from_element(v)?));
            }
            Value::Dict(d)
        }
        other => return Err(bad(format!("unknown element <{other}>"))),
    })
}

fn parse_binary(b: &[u8]) -> Result<Value> {
    let bad = |m: &str| Error::malformed("binary plist", m);
    if b.len() < 40 {
        return Err(bad("too short"));
    }
    let t = &b[b.len() - 32..];
    let off_size = t[6] as usize;
    let ref_size = t[7] as usize;
    let num = be_uint(&t[8..16]) as usize;
    let top = be_uint(&t[16..24]) as usize;
    let table = be_uint(&t[24..32]) as usize;
    if off_size == 0 || ref_size == 0 || off_size > 8 || ref_size > 8 {
        return Err(bad("bad trailer"));
    }
    let offsets: Vec<usize> = (0..num)
        .map(|i| {
            let p = table + i * off_size;
            b.get(p..p + off_size).map(|s| be_uint(s) as usize).ok_or_else(|| bad("offset table out of range"))
        })
        .collect::<Result<_>>()?;
    fn obj(b: &[u8], offs: &[usize], refsz: usize, idx: usize, depth: usize) -> Result<Value> {
        let bad = |m: &str| Error::malformed("binary plist", m);
        if depth > 64 {
            return Err(bad("nesting too deep"));
        }
        let p = *offs.get(idx).ok_or_else(|| bad("object index out of range"))?;
        let marker = *b.get(p).ok_or_else(|| bad("object out of range"))?;
        let (hi, lo) = (marker >> 4, (marker & 15) as usize);
        let len_at = |p: usize| -> Result<(usize, usize)> {
            if lo != 15 {
                return Ok((lo, p + 1));
            }
            let m = *b.get(p + 1).ok_or_else(|| bad("truncated"))?;
            let n = 1usize << (m & 15);
            let v = b.get(p + 2..p + 2 + n).ok_or_else(|| bad("truncated"))?;
            Ok((be_uint(v) as usize, p + 2 + n))
        };
        let slice = |s: usize, n: usize| b.get(s..s + n).ok_or_else(|| bad("truncated"));
        Ok(match hi {
            0 => match marker {
                8 => Value::Bool(false),
                9 => Value::Bool(true),
                _ => return Err(bad("unsupported singleton")),
            },
            1 => {
                let n = 1 << lo;
                let v = slice(p + 1, n)?;
                Value::Integer(if n == 8 { i64::from_be_bytes(v.try_into().unwrap_or_default()) } else { be_uint(v) as i64 })
            }
            2 => {
                let v = slice(p + 1, 1 << lo)?;
                Value::Real(match v.len() {
                    4 => f32::from_be_bytes(v.try_into().unwrap_or_default()) as f64,
                    8 => f64::from_be_bytes(v.try_into().unwrap_or_default()),
                    _ => return Err(bad("bad real size")),
                })
            }
            3 => {
                let secs = f64::from_be_bytes(slice(p + 1, 8)?.try_into().unwrap_or_default());
                Value::Date(crate::util::iso8601(978_307_200 + secs as i64))
            }
            4 => {
                let (n, s) = len_at(p)?;
                Value::Data(slice(s, n)?.to_vec())
            }
            5 => {
                let (n, s) = len_at(p)?;
                Value::String(String::from_utf8_lossy(slice(s, n)?).into_owned())
            }
            6 => {
                let (n, s) = len_at(p)?;
                let units: Vec<u16> = slice(s, n * 2)?.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Value::String(String::from_utf16_lossy(&units))
            }
            10 => {
                let (n, s) = len_at(p)?;
                let mut a = Vec::with_capacity(n);
                for i in 0..n {
                    let r = be_uint(slice(s + i * refsz, refsz)?) as usize;
                    a.push(obj(b, offs, refsz, r, depth + 1)?);
                }
                Value::Array(a)
            }
            13 => {
                let (n, s) = len_at(p)?;
                let mut d = Dict::new();
                for i in 0..n {
                    let kr = be_uint(slice(s + i * refsz, refsz)?) as usize;
                    let vr = be_uint(slice(s + (n + i) * refsz, refsz)?) as usize;
                    let k = match obj(b, offs, refsz, kr, depth + 1)? {
                        Value::String(k) => k,
                        _ => return Err(bad("non-string key")),
                    };
                    d.0.push((k, obj(b, offs, refsz, vr, depth + 1)?));
                }
                Value::Dict(d)
            }
            _ => return Err(bad("unsupported object type")),
        })
    }
    obj(b, &offsets, ref_size, top, 0)
}

fn be_uint(s: &[u8]) -> u64 {
    s.iter().fold(0u64, |a, &x| a << 8 | x as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_round_trip() {
        let v = Value::Dict(
            Dict::new()
                .with("CFBundleName", "My <App>")
                .with("n", 42i64)
                .with("ok", true)
                .with("blob", Value::Data(vec![1, 2, 3, 255]))
                .with("list", vec![Value::from("a"), Value::Array(vec![])])
                .with("empty", Dict::new()),
        );
        let x = v.to_xml();
        assert_eq!(Value::parse(x.as_bytes()).unwrap(), v);
        assert_eq!(Value::parse(&v.to_binary()).unwrap(), v);
        let big = Value::Array((0..300).map(|i| Value::String(format!("é{i}"))).collect());
        assert_eq!(Value::parse(&big.to_binary()).unwrap(), big);
    }
}
