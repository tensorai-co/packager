//! RFC 3161 time-stamping: request a token over a signature value and return the token
//! (a CMS `ContentInfo`) to embed as the `timeStampToken` unsigned attribute.

use crate::crypto::der::{self, oids, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::digest_oid;
use crate::transport::Transport;
use crate::{Error, Result};

/// Apple's time-stamping server, the only one notarization accepts.
pub const APPLE_TSA: &str = "http://timestamp.apple.com/ts01";

/// The DER `TimeStampReq` for `digest` (made with `hash`), asking for the TSA's certificate.
pub fn request(hash: HashAlg, digest: &[u8], nonce: &[u8]) -> Vec<u8> {
    let imprint = der::seq(&[&der::seq(&[&der::oid(digest_oid(hash)), &der::null()]), &der::octet_string(digest)]);
    der::seq(&[&der::integer(1), &imprint, &der::integer_unsigned_bytes(nonce), &der::boolean(true)])
}

/// Gets a token for `data` (the signature value being timestamped) from the server at `url`.
pub fn fetch(transport: &dyn Transport, url: &str, data: &[u8]) -> Result<Vec<u8>> {
    let digest = HashAlg::Sha256.digest(data);
    let mut nonce = crate::crypto::random_bytes(8)?;
    nonce[0] &= 0x7f;
    let req = request(HashAlg::Sha256, &digest, &nonce);
    let resp = transport.post(url, "application/timestamp-query", &req)?;
    let token = parse_response(&resp)?;
    check_token(&token, &digest, &nonce)?;
    Ok(token)
}

/// Extracts the token from a `TimeStampResp`, failing unless the status is granted.
pub fn parse_response(resp: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::malformed("timestamp response", m);
    let t = der::parse(resp)?;
    let mut r = t.reader();
    let status = r.expect(tag::SEQUENCE)?;
    let code = status.reader().expect(tag::INTEGER)?.as_i64()?;
    if code != 0 && code != 1 {
        return Err(Error::Other(format!("timestamp server refused the request (status {code})")));
    }
    let token = r.expect(tag::SEQUENCE).map_err(|_| bad("no token"))?;
    Ok(token.raw.to_vec())
}

/// Checks that a token's TSTInfo covers `digest` and echoes `nonce`. (The TSA's own signature is
/// checked by whoever verifies the code signature against their trust store.)
pub fn check_token(token: &[u8], digest: &[u8], nonce: &[u8]) -> Result<()> {
    let info = tst_info(token)?;
    let mut r = der::Reader::new(&info);
    let tst = r.expect(tag::SEQUENCE)?;
    let mut tr = tst.reader();
    tr.expect(tag::INTEGER)?;
    tr.expect(tag::OID)?;
    let imprint = tr.expect(tag::SEQUENCE)?;
    let mut ir = imprint.reader();
    ir.expect(tag::SEQUENCE)?;
    if ir.expect(tag::OCTET_STRING)?.value != digest {
        return Err(Error::Other("timestamp token covers a different digest".into()));
    }
    tr.expect(tag::INTEGER)?; // serial
    tr.expect(tag::GENERALIZED_TIME)?;
    while !tr.is_empty() {
        let el = tr.read()?;
        if el.tag == tag::INTEGER {
            let got = el.value.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();
            let want = nonce.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();
            if got != want {
                return Err(Error::Other("timestamp nonce mismatch".into()));
            }
        }
    }
    Ok(())
}

/// The DER `TSTInfo` inside a token.
pub fn tst_info(token: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::malformed("timestamp token", m);
    let t = der::parse(token)?;
    let mut r = t.reader();
    if r.expect(tag::OID)?.value != oids::PKCS7_SIGNED_DATA {
        return Err(bad("not SignedData"));
    }
    let sd = der::parse(r.read()?.value)?;
    let mut sr = sd.reader();
    sr.expect(tag::INTEGER)?;
    sr.expect(tag::SET)?;
    let eci = sr.expect(tag::SEQUENCE)?;
    let mut er = eci.reader();
    if er.expect(tag::OID)?.value != oids::TST_INFO {
        return Err(bad("content isn't TSTInfo"));
    }
    let wrapped = er.read()?;
    let octets = der::parse(wrapped.value)?;
    Ok(octets.value.to_vec())
}

/// The time (`YYYYMMDDHHMMSSZ`) a token asserts.
pub fn token_time(token: &[u8]) -> Result<String> {
    let info = tst_info(token)?;
    let t = der::parse(&info)?;
    let mut r = t.reader();
    r.expect(tag::INTEGER)?;
    r.expect(tag::OID)?;
    r.expect(tag::SEQUENCE)?;
    r.expect(tag::INTEGER)?;
    r.expect(tag::GENERALIZED_TIME)?.as_string()
}
