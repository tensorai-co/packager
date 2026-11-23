//! A minimal ASN.1 DER writer: enough for Apple's DER entitlements, with room to grow into
//! X.509 and CMS.

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

/// `SEQUENCE`.
pub fn sequence(body: &[u8]) -> Vec<u8> {
    tlv(&[0x30], body)
}

/// `UTF8String`.
pub fn utf8(s: &str) -> Vec<u8> {
    tlv(&[0x0c], s.as_bytes())
}

/// `BOOLEAN`.
pub fn boolean(b: bool) -> Vec<u8> {
    tlv(&[0x01], &[if b { 0xff } else { 0 }])
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
    tlv(&[0x02], &bytes[start..])
}
