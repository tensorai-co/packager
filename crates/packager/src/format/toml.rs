//! A TOML reader covering what `packager.toml` and `Cargo.toml` use: tables, arrays of tables,
//! dotted and quoted keys, strings (basic, literal, multi-line), integers, floats, booleans,
//! arrays and inline tables. Dates aren't supported.

use std::collections::BTreeMap;

/// A TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Toml {
    /// A string.
    String(String),
    /// An integer.
    Integer(i64),
    /// A float.
    Float(f64),
    /// A boolean.
    Bool(bool),
    /// An array.
    Array(Vec<Toml>),
    /// A table (also an inline table), keys sorted.
    Table(BTreeMap<String, Toml>),
}

impl Toml {
    /// A table's value for `key`.
    pub fn get(&self, key: &str) -> Option<&Toml> {
        match self {
            Toml::Table(t) => t.get(key),
            _ => None,
        }
    }
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Toml::String(s) => Some(s),
            _ => None,
        }
    }
    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Toml::Integer(i) => Some(*i),
            _ => None,
        }
    }
    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Toml::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&[Toml]> {
        match self {
            Toml::Array(a) => Some(a),
            _ => None,
        }
    }
    /// The table, if this is one.
    pub fn as_table(&self) -> Option<&BTreeMap<String, Toml>> {
        match self {
            Toml::Table(t) => Some(t),
            _ => None,
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    line: usize,
}

type R<T> = Result<T, String>;

impl P<'_> {
    fn err<T>(&self, m: impl Into<String>) -> R<T> {
        Err(format!("line {}: {}", self.line, m.into()))
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn starts(&self, p: &str) -> bool {
        self.s[self.i..].starts_with(p.as_bytes())
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    /// Whitespace, newlines and comments (inside arrays).
    fn ws_nl(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'#') => self.comment(),
                _ => return,
            }
        }
    }
    fn comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == b'\n' {
                break;
            }
            self.i += 1;
        }
    }
    fn end_of_line(&mut self) -> R<()> {
        self.ws();
        if self.peek() == Some(b'#') {
            self.comment();
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.bump();
                Ok(())
            }
            Some(b'\r') if self.s.get(self.i + 1) == Some(&b'\n') => {
                self.bump();
                self.bump();
                Ok(())
            }
            Some(c) => self.err(format!("unexpected `{}` after value", c as char)),
        }
    }
    fn key_part(&mut self) -> R<String> {
        self.ws();
        match self.peek() {
            Some(b'"') => self.basic_string(),
            Some(b'\'') => self.literal_string(),
            _ => {
                let start = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                    self.i += 1;
                }
                if start == self.i {
                    return self.err("expected a key");
                }
                Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
            }
        }
    }
    fn key(&mut self) -> R<Vec<String>> {
        let mut parts = vec![self.key_part()?];
        loop {
            self.ws();
            if self.peek() == Some(b'.') {
                self.i += 1;
                parts.push(self.key_part()?);
            } else {
                return Ok(parts);
            }
        }
    }
    fn basic_string(&mut self) -> R<String> {
        let multi = self.starts("\"\"\"");
        self.i += if multi { 3 } else { 1 };
        if multi && self.peek() == Some(b'\n') {
            self.bump();
        }
        let mut out = String::new();
        loop {
            if multi && self.starts("\"\"\"") {
                self.i += 3;
                return Ok(out);
            }
            let c = match self.bump() {
                Some(c) => c,
                None => return self.err("unterminated string"),
            };
            match c {
                b'"' if !multi => return Ok(out),
                b'\n' if !multi => return self.err("newline in string"),
                b'\\' => {
                    let e = self.bump().unwrap_or(0);
                    match e {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'u' | b'U' => {
                            let n = if e == b'u' { 4 } else { 8 };
                            let hex = String::from_utf8_lossy(self.s.get(self.i..self.i + n).unwrap_or_default()).into_owned();
                            self.i += n;
                            match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                                Some(ch) => out.push(ch),
                                None => return self.err("bad unicode escape"),
                            }
                        }
                        b'\n' if multi => self.ws_nl(),
                        _ => return self.err(format!("bad escape `\\{}`", e as char)),
                    }
                }
                _ => {
                    // Re-decode UTF-8 sequences byte-wise.
                    let start = self.i - 1;
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    self.i = start + len;
                    out.push_str(&String::from_utf8_lossy(self.s.get(start..start + len).unwrap_or_default()));
                }
            }
        }
    }
    fn literal_string(&mut self) -> R<String> {
        let multi = self.starts("'''");
        self.i += if multi { 3 } else { 1 };
        if multi && self.peek() == Some(b'\n') {
            self.bump();
        }
        let start = self.i;
        loop {
            if multi && self.starts("'''") {
                let s = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                self.i += 3;
                return Ok(s);
            }
            match self.bump() {
                Some(b'\'') if !multi => return Ok(String::from_utf8_lossy(&self.s[start..self.i - 1]).into_owned()),
                Some(b'\n') if !multi => return self.err("newline in string"),
                Some(_) => {}
                None => return self.err("unterminated string"),
            }
        }
    }
    fn value(&mut self) -> R<Toml> {
        self.ws();
        match self.peek() {
            Some(b'"') => self.basic_string().map(Toml::String),
            Some(b'\'') => self.literal_string().map(Toml::String),
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws_nl();
                    if self.peek() == Some(b']') {
                        self.i += 1;
                        return Ok(Toml::Array(a));
                    }
                    a.push(self.value()?);
                    self.ws_nl();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {}
                        _ => return self.err("expected `,` or `]` in array"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut t = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Toml::Table(t));
                }
                loop {
                    let k = self.key()?;
                    self.ws();
                    if self.peek() != Some(b'=') {
                        return self.err("expected `=` in inline table");
                    }
                    self.i += 1;
                    let v = self.value()?;
                    insert(&mut t, &k, v).map_err(|e| format!("line {}: {e}", self.line))?;
                    self.ws();
                    match self.bump() {
                        Some(b',') => continue,
                        Some(b'}') => return Ok(Toml::Table(t)),
                        _ => return self.err("expected `,` or `}` in inline table"),
                    }
                }
            }
            Some(b't') if self.starts("true") => {
                self.i += 4;
                Ok(Toml::Bool(true))
            }
            Some(b'f') if self.starts("false") => {
                self.i += 5;
                Ok(Toml::Bool(false))
            }
            Some(_) => {
                let start = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || b"+-._".contains(&c)) {
                    self.i += 1;
                }
                let raw: String = String::from_utf8_lossy(&self.s[start..self.i]).replace('_', "");
                if let Ok(i) = raw.parse::<i64>() {
                    Ok(Toml::Integer(i))
                } else if let Some(h) = raw.strip_prefix("0x") {
                    i64::from_str_radix(h, 16).map(Toml::Integer).or_else(|_| self.err("bad hex integer"))
                } else if let Ok(f) = raw.parse::<f64>() {
                    Ok(Toml::Float(f))
                } else {
                    self.err(format!("unsupported value `{raw}`"))
                }
            }
            None => self.err("expected a value"),
        }
    }
}

fn insert(t: &mut BTreeMap<String, Toml>, key: &[String], v: Toml) -> Result<(), String> {
    let (last, path) = key.split_last().ok_or("empty key")?;
    let mut cur = t;
    for k in path {
        let e = cur.entry(k.clone()).or_insert_with(|| Toml::Table(BTreeMap::new()));
        cur = match e {
            Toml::Table(t) => t,
            _ => return Err(format!("`{k}` isn't a table")),
        };
    }
    if cur.contains_key(last) {
        return Err(format!("`{}` is defined twice", key.join(".")));
    }
    cur.insert(last.clone(), v);
    Ok(())
}

/// Finds (creating) the table at `path`; for arrays of tables, the last element.
fn table_at<'a>(root: &'a mut BTreeMap<String, Toml>, path: &[String]) -> Result<&'a mut BTreeMap<String, Toml>, String> {
    let mut cur = root;
    for k in path {
        let e = cur.entry(k.clone()).or_insert_with(|| Toml::Table(BTreeMap::new()));
        cur = match e {
            Toml::Table(t) => t,
            Toml::Array(a) => match a.last_mut() {
                Some(Toml::Table(t)) => t,
                _ => return Err(format!("`{k}` isn't a table")),
            },
            _ => return Err(format!("`{k}` isn't a table")),
        };
    }
    Ok(cur)
}

/// Parses a document into its root table; errors name the line.
pub fn parse(src: &str) -> Result<Toml, String> {
    let mut p = P { s: src.as_bytes(), i: 0, line: 1 };
    let mut root = BTreeMap::new();
    let mut current: Vec<String> = Vec::new();
    loop {
        p.ws_nl();
        match p.peek() {
            None => break,
            Some(b'[') => {
                let array = p.starts("[[");
                p.i += if array { 2 } else { 1 };
                let path = p.key()?;
                p.ws();
                let close = if array { "]]" } else { "]" };
                if !p.starts(close) {
                    return p.err(format!("expected `{close}`"));
                }
                p.i += close.len();
                p.end_of_line()?;
                if array {
                    let (last, parent) = path.split_last().ok_or("empty table name")?;
                    let t = table_at(&mut root, parent).map_err(|e| format!("line {}: {e}", p.line))?;
                    match t.entry(last.clone()).or_insert_with(|| Toml::Array(Vec::new())) {
                        Toml::Array(a) => a.push(Toml::Table(BTreeMap::new())),
                        _ => return p.err(format!("`{last}` isn't an array of tables")),
                    }
                } else {
                    table_at(&mut root, &path).map_err(|e| format!("line {}: {e}", p.line))?;
                }
                current = path;
            }
            Some(_) => {
                let k = p.key()?;
                p.ws();
                if p.peek() != Some(b'=') {
                    return p.err("expected `=`");
                }
                p.i += 1;
                let v = p.value()?;
                p.end_of_line()?;
                let line = p.line;
                let t = table_at(&mut root, &current).map_err(|e| format!("line {line}: {e}"))?;
                insert(t, &k, v).map_err(|e| format!("line {line}: {e}"))?;
            }
        }
    }
    Ok(Toml::Table(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let t = parse(
            r#"
# comment
[app]
name = "My \"App\""   # trailing
version = '1.4.0'
url_schemes = ["a", "b",]
resources = [{ from = "dist/", to = "web" }]
[app.binaries]
macos-universal = "x"
[package.dmg]
window_size = [540, 380]
ok = true
[[extra]]
n = 1
[[extra]]
n = 2
"#,
        )
        .unwrap();
        let app = t.get("app").unwrap();
        assert_eq!(app.get("name").unwrap().as_str(), Some("My \"App\""));
        assert_eq!(app.get("binaries").unwrap().get("macos-universal").unwrap().as_str(), Some("x"));
        assert_eq!(app.get("url_schemes").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(t.get("package").unwrap().get("dmg").unwrap().get("window_size").unwrap().as_array().unwrap()[1].as_int(), Some(380));
        assert_eq!(t.get("extra").unwrap().as_array().unwrap()[1].get("n").unwrap().as_int(), Some(2));
        assert!(parse("a = 1\na = 2").is_err());
    }
}
