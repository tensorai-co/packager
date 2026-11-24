//! ASN.1: a DER writer and a reader that also accepts BER indefinite lengths (Apple's CMS uses
//! them), plus OID helpers.

use crate::crypto::bigint::BigUint;
use crate::{Error, Result};

/// Universal tags used here.
pub mod tag {
    /// BOOLEAN
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER
    pub const OID: u8 = 0x06;
    /// UTF8String
    pub const UTF8_STRING: u8 = 0x0c;
    /// PrintableString
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// IA5String
    pub const IA5_STRING: u8 = 0x16;
    /// UTCTime
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// BMPString
    pub const BMP_STRING: u8 = 0x1e;
    /// SEQUENCE (constructed)
    pub const SEQUENCE: u8 = 0x30;
    /// SET (constructed)
    pub const SET: u8 = 0x31;
}

// ---------------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------------

/// Appends a DER length.
pub fn put_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// A tag-length-value with an already-encoded tag (one or more bytes).
pub fn tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.extend_from_slice(tag);
    put_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// `SEQUENCE` of already-encoded elements.
pub fn sequence(body: &[u8]) -> Vec<u8> {
    tlv(&[tag::SEQUENCE], body)
}

/// `SEQUENCE` of the concatenation of `parts`.
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    sequence(&parts.concat())
}

/// `SET OF`, with elements sorted by their encodings as DER requires.
pub fn set_of(mut elements: Vec<Vec<u8>>) -> Vec<u8> {
    elements.sort();
    tlv(&[tag::SET], &elements.concat())
}

/// Context-specific tag `[n]`, constructed (explicit or a constructed implicit type).
pub fn context(n: u8, body: &[u8]) -> Vec<u8> {
    tlv(&[0xa0 | n], body)
}

/// Context-specific tag `[n]`, primitive (implicit primitive types).
pub fn context_prim(n: u8, body: &[u8]) -> Vec<u8> {
    tlv(&[0x80 | n], body)
}

/// `UTF8String`.
pub fn utf8(s: &str) -> Vec<u8> {
    tlv(&[tag::UTF8_STRING], s.as_bytes())
}

/// `PrintableString`.
pub fn printable(s: &str) -> Vec<u8> {
    tlv(&[tag::PRINTABLE_STRING], s.as_bytes())
}

/// `BOOLEAN`.
pub fn boolean(b: bool) -> Vec<u8> {
    tlv(&[tag::BOOLEAN], &[if b { 0xff } else { 0 }])
}

/// `NULL`.
pub fn null() -> Vec<u8> {
    vec![tag::NULL, 0]
}

/// `OCTET STRING`.
pub fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(&[tag::OCTET_STRING], b)
}

/// `BIT STRING` with no unused bits.
pub fn bit_string(b: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8];
    body.extend_from_slice(b);
    tlv(&[tag::BIT_STRING], &body)
}

/// `INTEGER`, minimal two's complement.
pub fn integer(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(&[tag::INTEGER], &bytes[start..])
}

/// A non-negative `INTEGER` from a big value.
pub fn integer_big(v: &BigUint) -> Vec<u8> {
    integer_unsigned_bytes(&v.to_be_bytes())
}

/// A non-negative `INTEGER` from big-endian magnitude bytes.
pub fn integer_unsigned_bytes(b: &[u8]) -> Vec<u8> {
    let skip = b.iter().take_while(|&&x| x == 0).count();
    let mut body = Vec::with_capacity(b.len() + 1);
    let b = &b[skip.min(b.len())..];
    if b.is_empty() || b[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(b);
    tlv(&[tag::INTEGER], &body)
}

/// `OBJECT IDENTIFIER` from its encoded body.
pub fn oid(body: &[u8]) -> Vec<u8> {
    tlv(&[tag::OID], body)
}

/// `UTCTime` for Unix seconds (years 1950–2049).
pub fn utc_time(unix: i64) -> Vec<u8> {
    let s = crate::util::iso8601(unix); // YYYY-MM-DDTHH:MM:SSZ
    let t = format!("{}{}{}{}{}{}Z", &s[2..4], &s[5..7], &s[8..10], &s[11..13], &s[14..16], &s[17..19]);
    tlv(&[tag::UTC_TIME], t.as_bytes())
}

/// `GeneralizedTime` for Unix seconds.
pub fn generalized_time(unix: i64) -> Vec<u8> {
    let s = crate::util::iso8601(unix);
    let t = format!("{}{}{}{}{}{}Z", &s[0..4], &s[5..7], &s[8..10], &s[11..13], &s[14..16], &s[17..19]);
    tlv(&[tag::GENERALIZED_TIME], t.as_bytes())
}

/// Encodes a dotted OID (`1.2.840.113549`) as the body of an OBJECT IDENTIFIER.
pub fn oid_from_str(s: &str) -> Result<Vec<u8>> {
    let parts: Vec<u64> = s.split('.').map(|p| p.parse::<u64>()).collect::<std::result::Result<_, _>>().map_err(|_| Error::invalid("oid", s, "must be dotted decimal"))?;
    if parts.len() < 2 || parts[0] > 2 || (parts[0] < 2 && parts[1] >= 40) {
        return Err(Error::invalid("oid", s, "isn't a valid object identifier"));
    }
    let mut out = Vec::new();
    let mut put = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        out.extend_from_slice(&tmp);
    };
    put(parts[0] * 40 + parts[1]);
    for &p in &parts[2..] {
        put(p);
    }
    Ok(out)
}

/// The dotted form of an encoded OID body.
pub fn oid_to_string(body: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut v = 0u64;
    for (i, &b) in body.iter().enumerate() {
        v = v << 7 | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = if v < 80 { v / 40 } else { 2 };
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        }
        let _ = i;
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

// ---------------------------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------------------------

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("asn.1", m)
}

/// One decoded element.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The first identifier byte (class, constructed bit, tag number < 31).
    pub tag: u8,
    /// Contents (for indefinite lengths, without the end-of-contents marker).
    pub value: &'a [u8],
    /// The whole element as encoded.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// A reader over this element's contents.
    pub fn reader(&self) -> Reader<'a> {
        Reader::new(self.value)
    }
    /// Whether this is context tag `[n]` (either form).
    pub fn is_context(&self, n: u8) -> bool {
        self.tag & 0xc0 == 0x80 && self.tag & 0x1f == n
    }
    /// The value as a non-negative INTEGER.
    pub fn as_biguint(&self) -> Result<BigUint> {
        if self.tag != tag::INTEGER {
            return Err(bad(format!("expected INTEGER, found tag {:#04x}", self.tag)));
        }
        if self.value.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(bad("negative INTEGER"));
        }
        Ok(BigUint::from_be_bytes(self.value))
    }
    /// The value as a small INTEGER.
    pub fn as_i64(&self) -> Result<i64> {
        if self.tag != tag::INTEGER || self.value.is_empty() || self.value.len() > 8 {
            return Err(bad("expected a small INTEGER"));
        }
        let mut v: i64 = if self.value[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in self.value {
            v = v << 8 | b as i64;
        }
        Ok(v)
    }
    /// The value of a string type as text.
    pub fn as_string(&self) -> Result<String> {
        match self.tag {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING | 0x14 | 0x1a | tag::UTC_TIME | tag::GENERALIZED_TIME => Ok(String::from_utf8_lossy(self.value).into_owned()),
            tag::BMP_STRING => {
                let u: Vec<u16> = self.value.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Ok(String::from_utf16_lossy(&u))
            }
            t => Err(bad(format!("expected a string, found tag {t:#04x}"))),
        }
    }
    /// The bits of a BIT STRING (requires zero unused bits).
    pub fn as_bit_string(&self) -> Result<&'a [u8]> {
        if self.tag != tag::BIT_STRING || self.value.is_empty() {
            return Err(bad("expected BIT STRING"));
        }
        Ok(&self.value[1..])
    }
}

/// Sequential reader over concatenated elements.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    /// Whether everything has been read.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    /// The next element's tag without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }
    /// Reads the next element.
    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let (t, used) = parse_one(&self.data[self.pos..])?;
        self.pos += used;
        Ok(t)
    }
    /// Reads the next element, requiring tag `t`.
    pub fn expect(&mut self, t: u8) -> Result<Tlv<'a>> {
        let el = self.read()?;
        if el.tag != t {
            return Err(bad(format!("expected tag {t:#04x}, found {:#04x}", el.tag)));
        }
        Ok(el)
    }
    /// Reads the next element if it has tag `t`.
    pub fn optional(&mut self, t: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(t) { self.read().map(Some) } else { Ok(None) }
    }
}

/// Parses one element at the start of `data`; returns it and the bytes used.
fn parse_one(data: &[u8]) -> Result<(Tlv<'_>, usize)> {
    let t = *data.first().ok_or_else(|| bad("unexpected end of data"))?;
    if t & 0x1f == 0x1f {
        return Err(bad("multi-byte tags aren't supported"));
    }
    let l0 = *data.get(1).ok_or_else(|| bad("truncated length"))?;
    if l0 == 0x80 {
        if t & 0x20 == 0 {
            return Err(bad("indefinite length on a primitive element"));
        }
        // Indefinite: children until end-of-contents (00 00).
        let mut p = 2;
        loop {
            if data.get(p..p + 2) == Some(&[0, 0]) {
                let value = &data[2..p];
                return Ok((Tlv { tag: t, value, raw: &data[..p + 2] }, p + 2));
            }
            if p >= data.len() {
                return Err(bad("unterminated indefinite length"));
            }
            let (_, used) = parse_one(&data[p..])?;
            p += used;
        }
    }
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n > 4 {
            return Err(bad("length too large"));
        }
        let b = data.get(2..2 + n).ok_or_else(|| bad("truncated length"))?;
        (b.iter().fold(0usize, |a, &x| a << 8 | x as usize), 2 + n)
    };
    let end = hdr.checked_add(len).ok_or_else(|| bad("length overflow"))?;
    let value = data.get(hdr..end).ok_or_else(|| bad("element runs past the end"))?;
    Ok((Tlv { tag: t, value, raw: &data[..end] }, end))
}

/// Parses a single complete element (no trailing data).
pub fn parse(data: &[u8]) -> Result<Tlv<'_>> {
    let (t, used) = parse_one(data)?;
    if used != data.len() {
        return Err(bad("trailing data after element"));
    }
    Ok(t)
}

/// Well-known OIDs, as encoded bodies.
pub mod oids {
    /// rsaEncryption
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// sha256WithRSAEncryption
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// sha1WithRSAEncryption
    pub const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    /// sha384WithRSAEncryption
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// sha512WithRSAEncryption
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// id-ecPublicKey
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1 / P-256
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1 / P-384
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// ecdsa-with-SHA256
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384
    pub const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// sha1
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    /// sha256
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// sha384
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// sha512
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    /// pkcs7-data
    pub const PKCS7_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
    /// pkcs7-signedData
    pub const PKCS7_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    /// pkcs7-encryptedData
    pub const PKCS7_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
    /// contentType attribute
    pub const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    /// messageDigest attribute
    pub const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    /// signingTime attribute
    pub const SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
    /// id-smime-aa-timeStampToken
    pub const TIMESTAMP_TOKEN: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e];
    /// id-ct-TSTInfo
    pub const TST_INFO: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];
    /// Apple's CodeDirectory hashes plist attribute
    pub const APPLE_CDHASHES_PLIST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01];
    /// Apple's CodeDirectory hashes (algorithm, digest) attribute
    pub const APPLE_CDHASHES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02];
    /// commonName
    pub const CN: &[u8] = &[0x55, 0x04, 0x03];
    /// countryName
    pub const C: &[u8] = &[0x55, 0x04, 0x06];
    /// organizationName
    pub const O: &[u8] = &[0x55, 0x04, 0x0a];
    /// organizationalUnitName
    pub const OU: &[u8] = &[0x55, 0x04, 0x0b];
    /// userId (UID)
    pub const UID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01];
    /// emailAddress
    pub const EMAIL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    /// basicConstraints
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// keyUsage
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// extKeyUsage
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// id-kp-codeSigning
    pub const KP_CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    /// subjectKeyIdentifier
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    /// authorityKeyIdentifier
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_round_trip() {
        for s in ["1.2.840.113549.1.1.11", "2.5.4.3", "1.2.840.113635.100.6.2.6", "2.16.840.1.101.3.4.2.1"] {
            assert_eq!(oid_to_string(&oid_from_str(s).unwrap()), s);
        }
        assert_eq!(oid_from_str("1.2.840.113635.100.9.2").unwrap(), oids::APPLE_CDHASHES);
    }

    #[test]
    fn reads_indefinite_and_definite() {
        // SEQUENCE(indef) { INTEGER 1, SEQUENCE { NULL } } EOC
        let ber = [0x30, 0x80, 0x02, 0x01, 0x01, 0x30, 0x02, 0x05, 0x00, 0x00, 0x00];
        let t = parse(&ber).unwrap();
        let mut r = t.reader();
        assert_eq!(r.expect(tag::INTEGER).unwrap().as_i64().unwrap(), 1);
        assert_eq!(r.expect(tag::SEQUENCE).unwrap().value, &[0x05, 0x00]);
        assert!(r.is_empty());
        assert_eq!(integer_big(&BigUint::from_u64(0x80)), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(utc_time(1_700_000_000), tlv(&[0x17], b"231114221320Z"));
    }
}
