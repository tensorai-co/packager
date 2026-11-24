//! A small XML writer and a non-validating reader into a tree, enough for property lists,
//! XAR tables of contents, `PackageInfo` and `Distribution` files.

use crate::{Error, Result};

/// Escapes text for element content and attribute values.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// An element: name, attributes in document order, children.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    /// Tag name.
    pub name: String,
    /// Attributes, in document order.
    pub attrs: Vec<(String, String)>,
    /// Child nodes.
    pub children: Vec<Node>,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Character data, entities decoded.
    Text(String),
}

impl Element {
    /// A new element with no attributes or children.
    pub fn new(name: impl Into<String>) -> Self {
        Element { name: name.into(), ..Default::default() }
    }
    /// Adds an attribute (builder style).
    pub fn attr(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attrs.push((k.into(), v.into()));
        self
    }
    /// Adds a child element (builder style).
    pub fn child(mut self, e: Element) -> Self {
        self.children.push(Node::Element(e));
        self
    }
    /// Adds text (builder style).
    pub fn text(mut self, t: impl Into<String>) -> Self {
        self.children.push(Node::Text(t.into()));
        self
    }
    /// An attribute's value.
    pub fn get_attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    /// Child elements.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }
    /// The first child element named `name`.
    pub fn find(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name == name)
    }
    /// All text directly inside this element, concatenated.
    pub fn text_content(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s
    }

    /// Serializes with `indent` spaces per level and a trailing newline. Elements holding only
    /// text are written on one line; whitespace-only text between elements is dropped.
    pub fn write(&self, out: &mut String, depth: usize, indent: usize) {
        let pad = " ".repeat(depth * indent);
        out.push_str(&pad);
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape(v));
            out.push('"');
        }
        let elems = self.elements().count();
        if self.children.is_empty() {
            out.push_str("/>\n");
        } else if elems == 0 {
            out.push('>');
            out.push_str(&escape(&self.text_content()));
            out.push_str("</");
            out.push_str(&self.name);
            out.push_str(">\n");
        } else {
            out.push_str(">\n");
            for n in &self.children {
                match n {
                    Node::Element(e) => e.write(out, depth + 1, indent),
                    Node::Text(t) if !t.trim().is_empty() => {
                        out.push_str(&" ".repeat((depth + 1) * indent));
                        out.push_str(&escape(t.trim()));
                        out.push('\n');
                    }
                    Node::Text(_) => {}
                }
            }
            out.push_str(&pad);
            out.push_str("</");
            out.push_str(&self.name);
            out.push_str(">\n");
        }
    }

    /// The whole document with an XML declaration.
    pub fn to_document(&self, indent: usize) -> String {
        let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        self.write(&mut s, 0, indent);
        s
    }
}

/// Parses a document and returns its root element.
pub fn parse(input: &str) -> Result<Element> {
    let mut p = Parser { s: input.as_bytes(), i: 0, src: input };
    p.skip_prolog()?;
    let root = p.element()?;
    Ok(root)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    src: &'a str,
}

fn err(m: impl Into<String>) -> Error {
    Error::malformed("xml", m)
}

impl Parser<'_> {
    fn starts(&self, pat: &str) -> bool {
        self.s[self.i..].starts_with(pat.as_bytes())
    }
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn skip_until(&mut self, pat: &str) -> Result<()> {
        while self.i < self.s.len() {
            if self.starts(pat) {
                self.i += pat.len();
                return Ok(());
            }
            self.i += 1;
        }
        Err(err(format!("unterminated construct, expected `{pat}`")))
    }
    fn skip_prolog(&mut self) -> Result<()> {
        if self.starts("\u{feff}") {
            self.i += 3;
        }
        loop {
            self.skip_ws();
            if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<!--") {
                self.skip_until("-->")?;
            } else if self.starts("<!DOCTYPE") {
                // DOCTYPE may hold an internal subset in brackets.
                let mut depth = 0;
                while self.i < self.s.len() {
                    match self.s[self.i] {
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        b'>' if depth == 0 => {
                            self.i += 1;
                            break;
                        }
                        _ => {}
                    }
                    self.i += 1;
                }
            } else {
                return Ok(());
            }
        }
    }
    fn name(&mut self) -> Result<String> {
        let start = self.i;
        while self.i < self.s.len() {
            let c = self.s[self.i];
            if c.is_ascii_whitespace() || c == b'>' || c == b'/' || c == b'=' {
                break;
            }
            self.i += 1;
        }
        if start == self.i {
            return Err(err(format!("expected a name at byte {start}")));
        }
        Ok(self.src[start..self.i].to_string())
    }
    fn element(&mut self) -> Result<Element> {
        if !self.starts("<") {
            return Err(err(format!("expected `<` at byte {}", self.i)));
        }
        self.i += 1;
        let mut el = Element::new(self.name()?);
        loop {
            self.skip_ws();
            if self.starts("/>") {
                self.i += 2;
                return Ok(el);
            }
            if self.starts(">") {
                self.i += 1;
                break;
            }
            let k = self.name()?;
            self.skip_ws();
            if !self.starts("=") {
                return Err(err(format!("attribute `{k}` has no value")));
            }
            self.i += 1;
            self.skip_ws();
            let q = *self.s.get(self.i).ok_or_else(|| err("unexpected end"))?;
            if q != b'"' && q != b'\'' {
                return Err(err("attribute value must be quoted"));
            }
            self.i += 1;
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i] != q {
                self.i += 1;
            }
            let v = decode_entities(&self.src[start..self.i])?;
            self.i += 1;
            el.attrs.push((k, v));
        }
        loop {
            if self.i >= self.s.len() {
                return Err(err(format!("unclosed element `{}`", el.name)));
            }
            if self.starts("</") {
                self.i += 2;
                let n = self.name()?;
                if n != el.name {
                    return Err(err(format!("`</{n}>` closes `<{}>`", el.name)));
                }
                self.skip_ws();
                self.i += 1;
                return Ok(el);
            } else if self.starts("<!--") {
                self.skip_until("-->")?;
            } else if self.starts("<![CDATA[") {
                self.i += 9;
                let start = self.i;
                self.skip_until("]]>")?;
                push_text(&mut el, &self.src[start..self.i - 3]);
            } else if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<") {
                let child = self.element()?;
                el.children.push(Node::Element(child));
            } else {
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i] != b'<' {
                    self.i += 1;
                }
                push_text(&mut el, &decode_entities(&self.src[start..self.i])?);
            }
        }
    }
}

fn push_text(el: &mut Element, t: &str) {
    if let Some(Node::Text(prev)) = el.children.last_mut() {
        prev.push_str(t);
    } else {
        el.children.push(Node::Text(t.to_string()));
    }
}

fn decode_entities(s: &str) -> Result<String> {
    if !s.contains('&') {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        let end = rest[p..].find(';').ok_or_else(|| err("unterminated entity"))? + p;
        let ent = &rest[p + 1..end];
        let c = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32).ok_or_else(|| err(format!("bad character reference `&{ent};`")))?,
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32).ok_or_else(|| err(format!("bad character reference `&{ent};`")))?,
            _ => return Err(err(format!("unknown entity `&{ent};`"))),
        };
        out.push(c);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let doc = Element::new("a").attr("x", "1 & \"2\"").child(Element::new("b").text("hi <there>")).child(Element::new("c"));
        let s = doc.to_document(2);
        let back = parse(&s).unwrap();
        assert_eq!(back.get_attr("x"), Some("1 & \"2\""));
        assert_eq!(back.find("b").unwrap().text_content(), "hi <there>");
        assert!(back.find("c").unwrap().children.is_empty());
    }

    #[test]
    fn prolog_and_cdata() {
        let s = "<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"x\" \"y\">\n<!-- c --><r><![CDATA[<raw>]]>&#65;&#x42;</r>";
        assert_eq!(parse(s).unwrap().text_content(), "<raw>AB");
    }
}
