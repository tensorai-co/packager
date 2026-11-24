//! Code requirements: the language `codesign -r` and `csreq` accept, compiled to Apple's binary
//! form (and back), plus the designated requirement `codesign` derives from a certificate chain.
//!
//! ```text
//! designated => identifier "com.example.app" and anchor apple generic
//!     and certificate leaf[subject.OU] = ABCDE12345
//! ```

use crate::crypto::der;
use crate::crypto::x509::Certificate;
use crate::util::PutBe;
use crate::{Error, Result};

/// `CSMAGIC_REQUIREMENT`.
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade_0c00;
/// `CSMAGIC_REQUIREMENTS`.
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;

/// Requirement types in a requirement set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequirementType {
    /// `host =>`
    Host = 1,
    /// `guest =>`
    Guest = 2,
    /// `designated =>`
    Designated = 3,
    /// `library =>`
    Library = 4,
    /// `plugin =>`
    Plugin = 5,
}

impl RequirementType {
    fn name(self) -> &'static str {
        match self {
            RequirementType::Host => "host",
            RequirementType::Guest => "guest",
            RequirementType::Designated => "designated",
            RequirementType::Library => "library",
            RequirementType::Plugin => "plugin",
        }
    }
    fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => RequirementType::Host,
            2 => RequirementType::Guest,
            3 => RequirementType::Designated,
            4 => RequirementType::Library,
            5 => RequirementType::Plugin,
            _ => return None,
        })
    }
}

/// Certificate positions: 0 is the leaf, -1 the anchor (root), N counts up from the leaf.
pub const LEAF: i32 = 0;
/// The anchor certificate.
pub const ANCHOR: i32 = -1;

/// How a field is compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// `exists`
    Exists,
    /// `absent`
    Absent,
    /// `= value`
    Equal(Value),
    /// `= "*value*"`
    Contains(Value),
    /// `= "value*"`
    BeginsWith(Value),
    /// `= "*value"`
    EndsWith(Value),
    /// `< value`
    LessThan(Value),
    /// `> value`
    GreaterThan(Value),
    /// `<= value`
    LessEqual(Value),
    /// `>= value`
    GreaterEqual(Value),
}

/// A literal: text or raw bytes (`H"…"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string.
    Text(String),
    /// Bytes.
    Data(Vec<u8>),
}

impl Value {
    fn bytes(&self) -> &[u8] {
        match self {
            Value::Text(s) => s.as_bytes(),
            Value::Data(d) => d,
        }
    }
}

/// A requirement expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// `never`
    False,
    /// `always`
    True,
    /// `identifier "…"`
    Ident(String),
    /// `anchor apple`
    AppleAnchor,
    /// `anchor apple generic`
    AppleGenericAnchor,
    /// `certificate N = H"sha1"`
    AnchorHash(i32, Vec<u8>),
    /// `info [key] = "value"` (legacy form)
    InfoKeyValue(String, String),
    /// `a and b`
    And(Box<Expr>, Box<Expr>),
    /// `a or b`
    Or(Box<Expr>, Box<Expr>),
    /// `cdhash H"…"`
    CdHash(Vec<u8>),
    /// `! a`
    Not(Box<Expr>),
    /// `info [key] match`
    InfoKeyField(String, Match),
    /// `certificate N[subject.CN] match`
    CertField(i32, String, Match),
    /// `certificate N trusted`
    TrustedCert(i32),
    /// `anchor trusted`
    TrustedCerts,
    /// `certificate N[field.OID] match` (OID body)
    CertGeneric(i32, Vec<u8>, Match),
    /// `entitlement [key] match`
    EntitlementField(String, Match),
    /// `certificate N[policy.OID] match`
    CertPolicy(i32, Vec<u8>, Match),
    /// `anchor "name"`
    NamedAnchor(String),
    /// `(name)`
    NamedCode(String),
    /// `platform = N`
    Platform(u32),
    /// `notarized`
    Notarized,
    /// `legacy`
    LegacyDevId,
}

// ---------------------------------------------------------------------------------------------
// Binary form
// ---------------------------------------------------------------------------------------------

fn put_data(out: &mut Vec<u8>, b: &[u8]) {
    out.u32(b.len() as u32);
    out.extend_from_slice(b);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn put_match(out: &mut Vec<u8>, m: &Match) {
    let (op, v) = match m {
        Match::Exists => (0, None),
        Match::Equal(v) => (1, Some(v)),
        Match::Contains(v) => (2, Some(v)),
        Match::BeginsWith(v) => (3, Some(v)),
        Match::EndsWith(v) => (4, Some(v)),
        Match::LessThan(v) => (5, Some(v)),
        Match::GreaterThan(v) => (6, Some(v)),
        Match::LessEqual(v) => (7, Some(v)),
        Match::GreaterEqual(v) => (8, Some(v)),
        Match::Absent => (14, None),
    };
    out.u32(op);
    if let Some(v) = v {
        put_data(out, v.bytes());
    }
}

impl Expr {
    /// Appends the opcode stream.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Expr::False => out.u32(0),
            Expr::True => out.u32(1),
            Expr::Ident(s) => {
                out.u32(2);
                put_data(out, s.as_bytes());
            }
            Expr::AppleAnchor => out.u32(3),
            Expr::AnchorHash(slot, h) => {
                out.u32(4);
                out.u32(*slot as u32);
                put_data(out, h);
            }
            Expr::InfoKeyValue(k, v) => {
                out.u32(5);
                put_data(out, k.as_bytes());
                put_data(out, v.as_bytes());
            }
            Expr::And(a, b) => {
                out.u32(6);
                a.encode(out);
                b.encode(out);
            }
            Expr::Or(a, b) => {
                out.u32(7);
                a.encode(out);
                b.encode(out);
            }
            Expr::CdHash(h) => {
                out.u32(8);
                put_data(out, h);
            }
            Expr::Not(a) => {
                out.u32(9);
                a.encode(out);
            }
            Expr::InfoKeyField(k, m) => {
                out.u32(10);
                put_data(out, k.as_bytes());
                put_match(out, m);
            }
            Expr::CertField(slot, f, m) => {
                out.u32(11);
                out.u32(*slot as u32);
                put_data(out, f.as_bytes());
                put_match(out, m);
            }
            Expr::TrustedCert(slot) => {
                out.u32(12);
                out.u32(*slot as u32);
            }
            Expr::TrustedCerts => out.u32(13),
            Expr::CertGeneric(slot, oid, m) => {
                out.u32(14);
                out.u32(*slot as u32);
                put_data(out, oid);
                put_match(out, m);
            }
            Expr::AppleGenericAnchor => out.u32(15),
            Expr::EntitlementField(k, m) => {
                out.u32(16);
                put_data(out, k.as_bytes());
                put_match(out, m);
            }
            Expr::CertPolicy(slot, oid, m) => {
                out.u32(17);
                out.u32(*slot as u32);
                put_data(out, oid);
                put_match(out, m);
            }
            Expr::NamedAnchor(n) => {
                out.u32(18);
                put_data(out, n.as_bytes());
            }
            Expr::NamedCode(n) => {
                out.u32(19);
                put_data(out, n.as_bytes());
            }
            Expr::Platform(p) => {
                out.u32(20);
                out.u32(*p);
            }
            Expr::Notarized => out.u32(21),
            Expr::LegacyDevId => out.u32(23),
        }
    }

    /// The requirement blob (`0xfade0c00`, expression form).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.u32(1); // kind: expression
        self.encode(&mut body);
        let mut out = Vec::with_capacity(body.len() + 8);
        out.u32(CSMAGIC_REQUIREMENT);
        out.u32(body.len() as u32 + 8);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes a requirement blob.
    pub fn from_blob(b: &[u8]) -> Result<Expr> {
        let bad = |m: &str| Error::malformed("requirement", m);
        if b.len() < 12 || be(b, 0)? != CSMAGIC_REQUIREMENT {
            return Err(bad("not a requirement blob"));
        }
        if be(b, 8)? != 1 {
            return Err(bad("only expression-form requirements are supported"));
        }
        let mut p = 12;
        let e = decode(b, &mut p, 0)?;
        Ok(e)
    }

    /// `a and b`, nesting to the right like Apple's compiler.
    pub fn and(parts: Vec<Expr>) -> Expr {
        let mut it = parts.into_iter().rev();
        let mut acc = it.next().unwrap_or(Expr::True);
        for e in it {
            acc = Expr::And(Box::new(e), Box::new(acc));
        }
        acc
    }
}

fn be(b: &[u8], p: usize) -> Result<u32> {
    b.get(p..p + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| Error::malformed("requirement", "truncated"))
}

fn get_data(b: &[u8], p: &mut usize) -> Result<Vec<u8>> {
    let n = be(b, *p)? as usize;
    let d = b.get(*p + 4..*p + 4 + n).ok_or_else(|| Error::malformed("requirement", "truncated data"))?.to_vec();
    *p += 4 + n.div_ceil(4) * 4;
    Ok(d)
}

fn get_text(b: &[u8], p: &mut usize) -> Result<String> {
    Ok(String::from_utf8_lossy(&get_data(b, p)?).into_owned())
}

fn get_match(b: &[u8], p: &mut usize) -> Result<Match> {
    let op = be(b, *p)?;
    *p += 4;
    let mut val = || -> Result<Value> {
        let d = get_data(b, p)?;
        Ok(match String::from_utf8(d.clone()) {
            Ok(s) if s.chars().all(|c| !c.is_control()) => Value::Text(s),
            _ => Value::Data(d),
        })
    };
    Ok(match op {
        0 => Match::Exists,
        1 => Match::Equal(val()?),
        2 => Match::Contains(val()?),
        3 => Match::BeginsWith(val()?),
        4 => Match::EndsWith(val()?),
        5 => Match::LessThan(val()?),
        6 => Match::GreaterThan(val()?),
        7 => Match::LessEqual(val()?),
        8 => Match::GreaterEqual(val()?),
        14 => Match::Absent,
        o => return Err(Error::malformed("requirement", format!("unsupported match operation {o}"))),
    })
}

fn decode(b: &[u8], p: &mut usize, depth: usize) -> Result<Expr> {
    if depth > 64 {
        return Err(Error::malformed("requirement", "nesting too deep"));
    }
    let op = be(b, *p)? & 0x00ff_ffff;
    *p += 4;
    let slot = |p: &mut usize| -> Result<i32> {
        let v = be(b, *p)? as i32;
        *p += 4;
        Ok(v)
    };
    Ok(match op {
        0 => Expr::False,
        1 => Expr::True,
        2 => Expr::Ident(get_text(b, p)?),
        3 => Expr::AppleAnchor,
        4 => {
            let s = slot(p)?;
            Expr::AnchorHash(s, get_data(b, p)?)
        }
        5 => {
            let k = get_text(b, p)?;
            Expr::InfoKeyValue(k, get_text(b, p)?)
        }
        6 | 7 => {
            let a = decode(b, p, depth + 1)?;
            let c = decode(b, p, depth + 1)?;
            if op == 6 { Expr::And(Box::new(a), Box::new(c)) } else { Expr::Or(Box::new(a), Box::new(c)) }
        }
        8 => Expr::CdHash(get_data(b, p)?),
        9 => Expr::Not(Box::new(decode(b, p, depth + 1)?)),
        10 => {
            let k = get_text(b, p)?;
            Expr::InfoKeyField(k, get_match(b, p)?)
        }
        11 => {
            let s = slot(p)?;
            let f = get_text(b, p)?;
            Expr::CertField(s, f, get_match(b, p)?)
        }
        12 => Expr::TrustedCert(slot(p)?),
        13 => Expr::TrustedCerts,
        14 | 17 => {
            let s = slot(p)?;
            let oid = get_data(b, p)?;
            let m = get_match(b, p)?;
            if op == 14 { Expr::CertGeneric(s, oid, m) } else { Expr::CertPolicy(s, oid, m) }
        }
        15 => Expr::AppleGenericAnchor,
        16 => {
            let k = get_text(b, p)?;
            Expr::EntitlementField(k, get_match(b, p)?)
        }
        18 => Expr::NamedAnchor(get_text(b, p)?),
        19 => Expr::NamedCode(get_text(b, p)?),
        20 => Expr::Platform(be(b, {
            let q = *p;
            *p += 4;
            q
        })?),
        21 => Expr::Notarized,
        23 => Expr::LegacyDevId,
        o => return Err(Error::malformed("requirement", format!("unsupported opcode {o}"))),
    })
}

/// A requirement set blob (`0xfade0c01`) from typed requirements, sorted by type.
pub fn requirement_set(reqs: &[(RequirementType, Expr)]) -> Vec<u8> {
    let mut sorted: Vec<&(RequirementType, Expr)> = reqs.iter().collect();
    sorted.sort_by_key(|(t, _)| *t);
    let blobs: Vec<Vec<u8>> = sorted.iter().map(|(_, e)| e.to_blob()).collect();
    let mut out = Vec::new();
    out.u32(CSMAGIC_REQUIREMENTS);
    out.u32(0);
    out.u32(sorted.len() as u32);
    let mut off = 12 + 8 * sorted.len();
    for ((t, _), b) in sorted.iter().zip(&blobs) {
        out.u32(*t as u32);
        out.u32(off as u32);
        off += b.len();
    }
    for b in &blobs {
        out.extend_from_slice(b);
    }
    let len = out.len() as u32;
    out[4..8].copy_from_slice(&len.to_be_bytes());
    out
}

/// Decodes a requirement set blob.
pub fn parse_requirement_set(b: &[u8]) -> Result<Vec<(RequirementType, Expr)>> {
    if be(b, 0)? != CSMAGIC_REQUIREMENTS {
        return Err(Error::malformed("requirement", "not a requirement set"));
    }
    let mut out = Vec::new();
    for i in 0..be(b, 8)? as usize {
        let t = RequirementType::from_u32(be(b, 12 + 8 * i)?).ok_or_else(|| Error::malformed("requirement", "unknown requirement type"))?;
        let off = be(b, 16 + 8 * i)? as usize;
        let len = be(b, off + 4)? as usize;
        let blob = b.get(off..off + len).ok_or_else(|| Error::malformed("requirement", "requirement out of range"))?;
        out.push((t, Expr::from_blob(blob)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Text form
// ---------------------------------------------------------------------------------------------

fn is_bare(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        && !matches!(
            s,
            "and"
                | "or"
                | "exists"
                | "absent"
                | "always"
                | "never"
                | "true"
                | "false"
                | "anchor"
                | "certificate"
                | "cert"
                | "identifier"
                | "info"
                | "entitlement"
                | "cdhash"
                | "platform"
                | "notarized"
                | "legacy"
                | "leaf"
                | "root"
                | "trusted"
                | "apple"
                | "generic"
        )
}

fn quote(s: &str) -> String {
    if is_bare(s) {
        return s.to_string();
    }
    let mut q = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q
}

fn value_text(v: &Value, wild_pre: bool, wild_post: bool) -> String {
    match v {
        Value::Data(d) => format!("H\"{}\"", crate::crypto::hex(d)),
        Value::Text(s) if !wild_pre && !wild_post => quote(s),
        Value::Text(s) => format!("{}{s}{}", if wild_pre { "*" } else { "" }, if wild_post { "*" } else { "" }),
    }
}

fn match_text(m: &Match) -> String {
    match m {
        Match::Exists => " /* exists */".into(),
        Match::Absent => " absent".into(),
        Match::Equal(v) => format!(" = {}", value_text(v, false, false)),
        Match::Contains(v) => format!(" = {}", value_text(v, true, true)),
        Match::BeginsWith(v) => format!(" = {}", value_text(v, false, true)),
        Match::EndsWith(v) => format!(" = {}", value_text(v, true, false)),
        Match::LessThan(v) => format!(" < {}", value_text(v, false, false)),
        Match::GreaterThan(v) => format!(" > {}", value_text(v, false, false)),
        Match::LessEqual(v) => format!(" <= {}", value_text(v, false, false)),
        Match::GreaterEqual(v) => format!(" >= {}", value_text(v, false, false)),
    }
}

fn slot_text(s: i32) -> String {
    match s {
        LEAF => "leaf".into(),
        ANCHOR => "root".into(),
        n => n.to_string(),
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn prec(e: &Expr) -> u8 {
            match e {
                Expr::Or(..) => 1,
                Expr::And(..) => 2,
                _ => 3,
            }
        }
        fn sub(e: &Expr, min: u8) -> String {
            if prec(e) < min { format!("({e})") } else { e.to_string() }
        }
        match self {
            Expr::False => write!(f, "never"),
            Expr::True => write!(f, "always"),
            Expr::Ident(s) => write!(f, "identifier \"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            Expr::AppleAnchor => write!(f, "anchor apple"),
            Expr::AppleGenericAnchor => write!(f, "anchor apple generic"),
            Expr::AnchorHash(slot, h) => write!(f, "certificate {} = H\"{}\"", slot_text(*slot), crate::crypto::hex(h)),
            Expr::InfoKeyValue(k, v) => write!(f, "info[{k}] = {}", quote(v)),
            Expr::And(a, b) => write!(f, "{} and {}", sub(a, 2), sub(b, 2)),
            Expr::Or(a, b) => write!(f, "{} or {}", sub(a, 1), sub(b, 1)),
            Expr::CdHash(h) => write!(f, "cdhash H\"{}\"", crate::crypto::hex(h)),
            Expr::Not(a) => write!(f, "! {}", sub(a, 3)),
            Expr::InfoKeyField(k, m) => write!(f, "info[{k}]{}", match_text(m)),
            Expr::CertField(s, field, m) => write!(f, "certificate {}[{field}]{}", slot_text(*s), match_text(m)),
            Expr::TrustedCert(s) => write!(f, "certificate {} trusted", slot_text(*s)),
            Expr::TrustedCerts => write!(f, "anchor trusted"),
            Expr::CertGeneric(s, oid, m) => write!(f, "certificate {}[field.{}]{}", slot_text(*s), der::oid_to_string(oid), match_text(m)),
            Expr::CertPolicy(s, oid, m) => write!(f, "certificate {}[policy.{}]{}", slot_text(*s), der::oid_to_string(oid), match_text(m)),
            Expr::EntitlementField(k, m) => write!(f, "entitlement[{}]{}", quote(k), match_text(m)),
            Expr::NamedAnchor(n) => write!(f, "anchor {}", quote(n)),
            Expr::NamedCode(n) => write!(f, "({})", quote(n)),
            Expr::Platform(p) => write!(f, "platform = {p}"),
            Expr::Notarized => write!(f, "notarized"),
            Expr::LegacyDevId => write!(f, "legacy"),
        }
    }
}

/// Renders a requirement set as `codesign -d -r-` prints it.
pub fn requirement_set_text(reqs: &[(RequirementType, Expr)]) -> String {
    reqs.iter().map(|(t, e)| format!("{} => {e}", t.name())).collect::<Vec<_>>().join("\n")
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Hex(Vec<u8>),
    Num(i64),
    Sym(&'static str),
}

fn lex(src: &str) -> Result<Vec<Tok>> {
    let err = |m: String| Error::invalid("requirement", src.to_string(), m);
    let s: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < s.len() {
        let c = s[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && s.get(i + 1) == Some(&'*') {
            let start = i;
            i += 2;
            while i + 1 < s.len() && !(s[i] == '*' && s[i + 1] == '/') {
                i += 1;
            }
            let comment: String = s[start + 2..i.min(s.len())].iter().collect();
            i += 2;
            if comment.trim() == "exists" {
                out.push(Tok::Word("exists".into()));
            }
        } else if c == '#' || (c == '/' && s.get(i + 1) == Some(&'/')) {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            let mut t = String::new();
            while i < s.len() && s[i] != '"' {
                if s[i] == '\\' && i + 1 < s.len() {
                    i += 1;
                }
                t.push(s[i]);
                i += 1;
            }
            if i >= s.len() {
                return Err(err("unterminated string".into()));
            }
            i += 1;
            out.push(Tok::Str(t));
        } else if c == 'H' && s.get(i + 1) == Some(&'"') {
            i += 2;
            let mut h = String::new();
            while i < s.len() && s[i] != '"' {
                h.push(s[i]);
                i += 1;
            }
            i += 1;
            if !h.len().is_multiple_of(2) || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(format!("bad hex literal H\"{h}\"")));
            }
            out.push(Tok::Hex((0..h.len()).step_by(2).map(|k| u8::from_str_radix(&h[k..k + 2], 16).unwrap_or(0)).collect()));
        } else if "()[]!".contains(c) {
            out.push(Tok::Sym(match c {
                '(' => "(",
                ')' => ")",
                '[' => "[",
                ']' => "]",
                _ => "!",
            }));
            i += 1;
        } else if c == '=' && s.get(i + 1) == Some(&'>') {
            out.push(Tok::Sym("=>"));
            i += 2;
        } else if c == '<' || c == '>' {
            if s.get(i + 1) == Some(&'=') {
                out.push(Tok::Sym(if c == '<' { "<=" } else { ">=" }));
                i += 2;
            } else {
                out.push(Tok::Sym(if c == '<' { "<" } else { ">" }));
                i += 1;
            }
        } else if c == '=' || c == '~' {
            out.push(Tok::Sym("="));
            i += 1;
        } else if c == '-' || c.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < s.len() && s[i].is_ascii_digit() {
                i += 1;
            }
            let t: String = s[start..i].iter().collect();
            out.push(Tok::Num(t.parse().map_err(|_| err(format!("bad number `{t}`")))?));
        } else if c.is_alphanumeric() || c == '_' || c == '.' || c == '*' {
            let start = i;
            while i < s.len() && (s[i].is_alphanumeric() || "._-+*".contains(s[i])) {
                i += 1;
            }
            out.push(Tok::Word(s[start..i].iter().collect()));
        } else {
            return Err(err(format!("unexpected `{c}`")));
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
    src: String,
}

impl Parser {
    fn err<T>(&self, m: impl Into<String>) -> Result<T> {
        Err(Error::invalid("requirement", self.src.clone(), m.into()))
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }
    fn word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }
    fn sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if *x == s)
    }
    fn eat_word(&mut self, w: &str) -> bool {
        if self.word(w) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat_sym(&mut self, s: &str) -> bool {
        if self.sym(s) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn expect_sym(&mut self, s: &str) -> Result<()> {
        if self.eat_sym(s) { Ok(()) } else { self.err(format!("expected `{s}`")) }
    }
    fn string(&mut self) -> Result<String> {
        match self.toks.get(self.i).cloned() {
            Some(Tok::Str(s)) | Some(Tok::Word(s)) => {
                self.i += 1;
                Ok(s)
            }
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(n.to_string())
            }
            _ => self.err("expected a string"),
        }
    }

    // `and` binds tighter than `or`; both associate to the left, as `csreq` compiles them.
    fn or_expr(&mut self) -> Result<Expr> {
        let mut a = self.and_expr()?;
        while self.eat_word("or") {
            let b = self.and_expr()?;
            a = Expr::Or(Box::new(a), Box::new(b));
        }
        Ok(a)
    }
    fn and_expr(&mut self) -> Result<Expr> {
        let mut a = self.unary()?;
        while self.eat_word("and") {
            let b = self.unary()?;
            a = Expr::And(Box::new(a), Box::new(b));
        }
        Ok(a)
    }
    fn unary(&mut self) -> Result<Expr> {
        if self.eat_sym("!") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.eat_sym("(") {
            // `(name)` is a named code reference when it holds just a string.
            if let (Some(Tok::Str(s)), Some(Tok::Sym(")"))) = (self.toks.get(self.i).cloned(), self.toks.get(self.i + 1).cloned()) {
                self.i += 2;
                return Ok(Expr::NamedCode(s));
            }
            let e = self.or_expr()?;
            self.expect_sym(")")?;
            return Ok(e);
        }
        self.primary()
    }
    fn slot(&mut self) -> Result<i32> {
        match self.toks.get(self.i).cloned() {
            Some(Tok::Word(w)) if w == "leaf" => {
                self.i += 1;
                Ok(LEAF)
            }
            Some(Tok::Word(w)) if w == "root" || w == "anchor" => {
                self.i += 1;
                Ok(ANCHOR)
            }
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(n as i32)
            }
            _ => self.err("expected a certificate position (leaf, root or a number)"),
        }
    }
    fn value(&mut self) -> Result<Value> {
        match self.toks.get(self.i).cloned() {
            Some(Tok::Hex(h)) => {
                self.i += 1;
                Ok(Value::Data(h))
            }
            _ => Ok(Value::Text(self.string()?)),
        }
    }
    fn matcher(&mut self) -> Result<Match> {
        if self.eat_word("exists") {
            return Ok(Match::Exists);
        }
        if self.eat_word("absent") {
            return Ok(Match::Absent);
        }
        for (s, mk) in [("<=", Match::LessEqual as fn(Value) -> Match), (">=", Match::GreaterEqual), ("<", Match::LessThan), (">", Match::GreaterThan)] {
            if self.eat_sym(s) {
                return Ok(mk(self.value()?));
            }
        }
        if self.eat_sym("=") {
            // Wildcards apply to unquoted values only; a quoted "*x*" is a literal, as in csreq.
            let quoted = matches!(self.peek(), Some(Tok::Str(_)));
            let v = self.value()?;
            if let (Value::Text(t), false) = (&v, quoted) {
                let (pre, post) = (t.starts_with('*'), t.ends_with('*') && t.len() > 1);
                let core = t.trim_start_matches('*').trim_end_matches('*').to_string();
                return Ok(match (pre, post) {
                    (true, true) => Match::Contains(Value::Text(core)),
                    (true, false) => Match::EndsWith(Value::Text(core)),
                    (false, true) => Match::BeginsWith(Value::Text(core)),
                    _ => Match::Equal(v),
                });
            }
            return Ok(Match::Equal(v));
        }
        // A bare field means `exists`.
        Ok(Match::Exists)
    }
    fn bracket_key(&mut self) -> Result<String> {
        self.expect_sym("[")?;
        let mut k = self.string()?;
        // Field names like `subject.CN` lex as one word; anything else joins up to `]`.
        while !self.sym("]") {
            match self.toks.get(self.i).cloned() {
                Some(Tok::Word(w)) | Some(Tok::Str(w)) => k.push_str(&w),
                Some(Tok::Num(n)) => k.push_str(&n.to_string()),
                _ => return self.err("expected `]`"),
            }
            self.i += 1;
        }
        self.expect_sym("]")?;
        Ok(k)
    }
    fn primary(&mut self) -> Result<Expr> {
        let w = match self.toks.get(self.i).cloned() {
            Some(Tok::Word(w)) => w,
            _ => return self.err("expected a requirement"),
        };
        self.i += 1;
        Ok(match w.as_str() {
            "always" | "true" => Expr::True,
            "never" | "false" => Expr::False,
            "notarized" => Expr::Notarized,
            "legacy" => Expr::LegacyDevId,
            "identifier" => {
                self.eat_sym("=");
                Expr::Ident(self.string()?)
            }
            "cdhash" => {
                self.eat_sym("=");
                match self.value()? {
                    Value::Data(d) => Expr::CdHash(d),
                    Value::Text(_) => return self.err("cdhash needs H\"…\""),
                }
            }
            "platform" => {
                self.eat_sym("=");
                match self.toks.get(self.i).cloned() {
                    Some(Tok::Num(n)) => {
                        self.i += 1;
                        Expr::Platform(n as u32)
                    }
                    _ => return self.err("platform needs a number"),
                }
            }
            "anchor" => {
                if self.eat_word("apple") {
                    if self.eat_word("generic") { Expr::AppleGenericAnchor } else { Expr::AppleAnchor }
                } else if self.eat_word("trusted") {
                    Expr::TrustedCerts
                } else if self.eat_sym("=") {
                    match self.value()? {
                        Value::Data(d) => Expr::AnchorHash(ANCHOR, d),
                        Value::Text(_) => return self.err("anchor = needs H\"…\""),
                    }
                } else {
                    Expr::NamedAnchor(self.string()?)
                }
            }
            "info" => {
                let k = self.bracket_key()?;
                Expr::InfoKeyField(k, self.matcher()?)
            }
            "entitlement" => {
                let k = self.bracket_key()?;
                Expr::EntitlementField(k, self.matcher()?)
            }
            "certificate" | "cert" => {
                let slot = self.slot()?;
                if self.eat_word("trusted") {
                    return Ok(Expr::TrustedCert(slot));
                }
                if self.sym("[") {
                    let field = self.bracket_key()?;
                    let m = self.matcher()?;
                    if let Some(oid) = field.strip_prefix("field.") {
                        return Ok(Expr::CertGeneric(slot, der::oid_from_str(oid)?, m));
                    }
                    if let Some(oid) = field.strip_prefix("policy.") {
                        return Ok(Expr::CertPolicy(slot, der::oid_from_str(oid)?, m));
                    }
                    return Ok(Expr::CertField(slot, field, m));
                }
                if self.eat_sym("=") {
                    return match self.value()? {
                        Value::Data(d) => Ok(Expr::AnchorHash(slot, d)),
                        Value::Text(_) => self.err("certificate = needs H\"…\" (file paths aren't supported)"),
                    };
                }
                return self.err("expected `[field]`, `= H\"…\"` or `trusted` after certificate");
            }
            other => return self.err(format!("unknown requirement `{other}`")),
        })
    }
}

/// Compiles one requirement expression.
pub fn compile(src: &str) -> Result<Expr> {
    let mut p = Parser { toks: lex(src)?, i: 0, src: src.to_string() };
    let e = p.or_expr()?;
    if p.i != p.toks.len() {
        return p.err("unexpected text after the requirement");
    }
    Ok(e)
}

/// Compiles a requirement set (`designated => …` lines). A bare expression is the designated
/// requirement.
pub fn compile_set(src: &str) -> Result<Vec<(RequirementType, Expr)>> {
    let toks = lex(src)?;
    if !toks.contains(&Tok::Sym("=>")) {
        return Ok(vec![(RequirementType::Designated, compile(src)?)]);
    }
    let mut p = Parser { toks, i: 0, src: src.to_string() };
    let mut out = Vec::new();
    while p.peek().is_some() {
        let ty = match p.string()?.as_str() {
            "host" => RequirementType::Host,
            "guest" => RequirementType::Guest,
            "designated" => RequirementType::Designated,
            "library" => RequirementType::Library,
            "plugin" => RequirementType::Plugin,
            other => return p.err(format!("unknown requirement type `{other}`")),
        };
        p.expect_sym("=>")?;
        out.push((ty, p.or_expr()?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

/// What a requirement is checked against.
#[derive(Debug, Clone, Default)]
pub struct Context<'a> {
    /// The signing identifier.
    pub identifier: &'a str,
    /// Certificates leaf first, anchor last (empty for ad hoc).
    pub chain: &'a [Certificate],
    /// Full CodeDirectory hashes.
    pub cdhashes: &'a [Vec<u8>],
    /// The bound `Info.plist`, if any.
    pub info: Option<&'a crate::format::plist::Dict>,
    /// The entitlements, if any.
    pub entitlements: Option<&'a crate::format::plist::Dict>,
    /// Certificates the caller trusts as anchors (besides Apple's roots).
    pub trusted_anchors: &'a [Certificate],
}

fn cert_at<'a>(ctx: &'a Context, slot: i32) -> Option<&'a Certificate> {
    if slot < 0 {
        let i = ctx.chain.len() as i32 + slot;
        if i < 0 { None } else { ctx.chain.get(i as usize) }
    } else {
        ctx.chain.get(slot as usize)
    }
}

fn subject_field(c: &Certificate, field: &str) -> Option<String> {
    let (part, attr) = field.split_once('.')?;
    let names = match part {
        "subject" => &c.subject,
        "issuer" => &c.issuer,
        _ => return None,
    };
    let oid = match attr {
        "CN" => der::oids::CN.to_vec(),
        "O" => der::oids::O.to_vec(),
        "OU" => der::oids::OU.to_vec(),
        "C" => der::oids::C.to_vec(),
        "UID" => der::oids::UID.to_vec(),
        "email" | "emailAddress" => der::oids::EMAIL.to_vec(),
        "L" => vec![0x55, 0x04, 0x07],
        "ST" => vec![0x55, 0x04, 0x08],
        "STREET" => vec![0x55, 0x04, 0x09],
        other => der::oid_from_str(other).ok()?,
    };
    names.iter().find(|(o, _)| *o == oid).map(|(_, v)| v.clone())
}

fn matches(m: &Match, value: Option<&str>) -> bool {
    let v = |x: &Value| String::from_utf8_lossy(x.bytes()).into_owned();
    match (m, value) {
        (Match::Exists, got) => got.is_some(),
        (Match::Absent, got) => got.is_none(),
        (_, None) => false,
        (Match::Equal(x), Some(g)) => g == v(x),
        (Match::Contains(x), Some(g)) => g.contains(&v(x)),
        (Match::BeginsWith(x), Some(g)) => g.starts_with(&v(x)),
        (Match::EndsWith(x), Some(g)) => g.ends_with(&v(x)),
        (Match::LessThan(x), Some(g)) => g < v(x).as_str(),
        (Match::GreaterThan(x), Some(g)) => g > v(x).as_str(),
        (Match::LessEqual(x), Some(g)) => g <= v(x).as_str(),
        (Match::GreaterEqual(x), Some(g)) => g >= v(x).as_str(),
    }
}

fn plist_text(d: Option<&crate::format::plist::Dict>, key: &str) -> Option<String> {
    use crate::format::plist::Value as P;
    match d?.get(key)? {
        P::String(s) => Some(s.clone()),
        P::Bool(b) => Some(b.to_string()),
        P::Integer(i) => Some(i.to_string()),
        _ => Some(String::new()),
    }
}

impl Expr {
    /// Evaluates the requirement. Certificate trust is structural: "anchor apple" means the
    /// chain ends at one of Apple's roots, "anchor trusted" at a caller-trusted anchor.
    pub fn evaluate(&self, ctx: &Context) -> bool {
        let apple_anchor = || ctx.chain.last().is_some_and(|a| APPLE_ROOT_SHA1.contains(&crate::crypto::hex(&a.sha1()).as_str()));
        match self {
            Expr::False => false,
            Expr::True => true,
            Expr::Ident(s) => ctx.identifier == s,
            // Only Apple's own (platform) code satisfies plain `anchor apple`; code signed by
            // developer certificates satisfies `anchor apple generic`.
            Expr::AppleAnchor => apple_anchor() && ctx.chain.len() >= 2 && ctx.chain[ctx.chain.len() - 2].common_name().is_some_and(|n| n.starts_with("Apple Code Signing")),
            Expr::AppleGenericAnchor => apple_anchor(),
            Expr::AnchorHash(slot, h) => cert_at(ctx, *slot).is_some_and(|c| c.sha1()[..] == h[..]),
            Expr::InfoKeyValue(k, v) => plist_text(ctx.info, k).as_deref() == Some(v.as_str()),
            Expr::And(a, b) => a.evaluate(ctx) && b.evaluate(ctx),
            Expr::Or(a, b) => a.evaluate(ctx) || b.evaluate(ctx),
            Expr::CdHash(h) => ctx.cdhashes.iter().any(|c| c.starts_with(h) || (c.len() >= 20 && h.len() >= 20 && c[..20] == h[..20])),
            Expr::Not(a) => !a.evaluate(ctx),
            Expr::InfoKeyField(k, m) => matches(m, plist_text(ctx.info, k).as_deref()),
            Expr::CertField(slot, field, m) => cert_at(ctx, *slot).is_some_and(|c| matches(m, subject_field(c, field).as_deref())),
            Expr::TrustedCert(slot) => cert_at(ctx, *slot).is_some_and(|c| ctx.trusted_anchors.iter().any(|t| t.der == c.der)),
            Expr::TrustedCerts => ctx.chain.iter().any(|c| ctx.trusted_anchors.iter().any(|t| t.der == c.der)) || apple_anchor(),
            Expr::CertGeneric(slot, oid, m) => cert_at(ctx, *slot).is_some_and(|c| {
                let present = c.extension(oid).is_some();
                match m {
                    Match::Absent => !present,
                    _ => present,
                }
            }),
            Expr::CertPolicy(..) => false,
            Expr::EntitlementField(k, m) => matches(m, plist_text(ctx.entitlements, k).as_deref()),
            Expr::NamedAnchor(_) | Expr::NamedCode(_) => false,
            Expr::Platform(_) => false,
            // Notarization is checked online against Apple's ticket service, not offline.
            Expr::Notarized => false,
            Expr::LegacyDevId => false,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Designated requirement
// ---------------------------------------------------------------------------------------------

/// Marker OIDs Apple puts in its certificates.
pub mod apple_oids {
    /// Leaf: Developer ID Application.
    pub const DEVELOPER_ID_LEAF: &str = "1.2.840.113635.100.6.1.13";
    /// Leaf: Mac App Store application signing.
    pub const MAC_APP_STORE_LEAF: &str = "1.2.840.113635.100.6.1.9";
    /// Intermediate: Apple Worldwide Developer Relations.
    pub const WWDR_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.1";
    /// Intermediate: Developer ID Certification Authority.
    pub const DEVELOPER_ID_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.6";
}

/// SHA-1 fingerprints of Apple's root CAs.
pub const APPLE_ROOT_SHA1: [&str; 2] = [
    "611e5b662c593a08ff58d14ae22452d198df6c60", // Apple Root CA
    "b52cb02fd567e0359fe8fa4d4c41037970fe01b0", // Apple Root CA - G3
];

/// Whether `chain` is Apple-issued: anchored at an Apple root, or (when the anchor isn't
/// included) issued by an intermediate carrying Apple's developer markers.
pub fn is_apple_issued(chain: &[Certificate]) -> bool {
    if chain.last().is_some_and(|a| APPLE_ROOT_SHA1.contains(&crate::crypto::hex(&a.sha1()).as_str())) {
        return true;
    }
    chain.get(1).is_some_and(|i| has_ext(i, apple_oids::WWDR_INTERMEDIATE) || has_ext(i, apple_oids::DEVELOPER_ID_INTERMEDIATE))
}

/// The team identifier `codesign` writes into the CodeDirectory: the leaf's subject OU, for
/// Apple-issued certificates only (macOS refuses to run code claiming a team no Apple
/// certificate vouches for).
pub fn team_id(chain: &[Certificate]) -> Option<String> {
    if !is_apple_issued(chain) {
        return None;
    }
    chain.first()?.team_id().map(str::to_string)
}

fn has_ext(c: &Certificate, oid: &str) -> bool {
    der::oid_from_str(oid).map(|o| c.extension(&o).is_some()).unwrap_or(false)
}

/// The designated requirement `codesign` derives for `identifier` signed by `chain` (leaf first,
/// ending at the anchor when known).
pub fn designated(identifier: &str, chain: &[Certificate]) -> Result<Expr> {
    let ident = Expr::Ident(identifier.to_string());
    let leaf = chain.first().ok_or_else(|| Error::Other("designated requirement: empty certificate chain".into()))?;
    let anchor = chain.last().unwrap_or(leaf);
    let apple_anchored = APPLE_ROOT_SHA1.contains(&crate::crypto::hex(&anchor.sha1()).as_str()) || is_apple_issued(chain);
    let oid = |s: &str| der::oid_from_str(s).unwrap_or_default();
    if apple_anchored && chain.len() >= 2 {
        let intermediate = &chain[1];
        if has_ext(intermediate, apple_oids::DEVELOPER_ID_INTERMEDIATE) && has_ext(leaf, apple_oids::DEVELOPER_ID_LEAF) {
            let team = leaf.team_id().ok_or_else(|| Error::Other("Developer ID certificate has no team identifier (subject OU)".into()))?;
            return Ok(Expr::and(vec![
                ident,
                Expr::AppleGenericAnchor,
                Expr::CertGeneric(1, oid(apple_oids::DEVELOPER_ID_INTERMEDIATE), Match::Exists),
                Expr::CertGeneric(LEAF, oid(apple_oids::DEVELOPER_ID_LEAF), Match::Exists),
                Expr::CertField(LEAF, "subject.OU".into(), Match::Equal(Value::Text(team.to_string()))),
            ]));
        }
        if has_ext(intermediate, apple_oids::WWDR_INTERMEDIATE) {
            let cn = leaf.common_name().ok_or_else(|| Error::Other("signing certificate has no common name".into()))?;
            return Ok(Expr::and(vec![
                ident,
                Expr::AppleGenericAnchor,
                Expr::CertField(LEAF, "subject.CN".into(), Match::Equal(Value::Text(cn.to_string()))),
                Expr::CertGeneric(1, oid(apple_oids::WWDR_INTERMEDIATE), Match::Exists),
            ]));
        }
        return Ok(Expr::and(vec![ident, Expr::AppleGenericAnchor]));
    }
    // Not Apple-anchored: pin the highest certificate that shares the leaf's organization.
    let org = leaf.subject_attr(der::oids::O);
    let mut slot = 0usize;
    if let Some(org) = org {
        while slot + 1 < chain.len() && chain[slot + 1].subject_attr(der::oids::O) == Some(org) {
            slot += 1;
        }
    }
    let (pos, cert) = if org.is_some() && slot == chain.len() - 1 { (ANCHOR, &chain[slot]) } else { (slot as i32, &chain[slot]) };
    Ok(Expr::and(vec![ident, Expr::AnchorHash(pos, cert.sha1().to_vec())]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_like_apple() {
        // The designated requirement codesign wrote for an Apple Development signature.
        let src = r#"identifier "com.example.real" and anchor apple generic and certificate leaf[subject.CN] = "Apple Development: Someone (ABCDE12345)" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"#;
        // codesign builds its designated requirement right-nested; csreq parses text left-nested.
        let parts = src.split(" and ").map(|p| compile(p).unwrap()).collect();
        let e = Expr::and(parts);
        let blob = e.to_blob();
        let mut want = Vec::new();
        for w in [0xfade0c00u32, 0, 1, 6, 2, 16] {
            want.u32(w);
        }
        want.extend_from_slice(b"com.example.real");
        for w in [6u32, 15, 6, 11, 0, 10] {
            want.u32(w);
        }
        want.extend_from_slice(b"subject.CN\0\0");
        want.u32(1);
        put_data(&mut want, b"Apple Development: Someone (ABCDE12345)");
        for w in [14u32, 1, 10] {
            want.u32(w);
        }
        want.extend_from_slice(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01, 0, 0]);
        want.u32(0);
        let len = want.len() as u32;
        want[4..8].copy_from_slice(&len.to_be_bytes());
        assert_eq!(blob, want);
        assert_eq!(Expr::from_blob(&blob).unwrap(), e);
        assert_eq!(e.to_string(), src);
        assert_eq!(compile(src).unwrap().to_string(), src);
    }

    #[test]
    fn operators_and_sets() {
        let e = compile(r#"anchor apple or (identifier com.a and ! info[CFBundleVersion] < "2") and entitlement["com.apple.security.app-sandbox"] exists"#).unwrap();
        assert_eq!(Expr::from_blob(&e.to_blob()).unwrap(), e);
        let set = compile_set("designated => cdhash H\"0102\" host => anchor apple").unwrap();
        let blob = requirement_set(&set);
        let back = parse_requirement_set(&blob).unwrap();
        assert_eq!(back[0].0, RequirementType::Host);
        assert_eq!(back[1].1, Expr::CdHash(vec![1, 2]));
        assert_eq!(compile(r#"certificate leaf[subject.CN] = *Dev*"#).unwrap(), Expr::CertField(0, "subject.CN".into(), Match::Contains(Value::Text("Dev".into()))));
        assert_eq!(compile(r#"certificate leaf[subject.CN] = "*Dev*""#).unwrap(), Expr::CertField(0, "subject.CN".into(), Match::Equal(Value::Text("*Dev*".into()))));
        assert!(compile("identifier").is_err());
    }
}
