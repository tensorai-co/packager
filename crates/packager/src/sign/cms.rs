//! The CMS `SignedData` in an Apple code signature: detached, over the primary CodeDirectory,
//! with Apple's CodeDirectory-hash attributes and an optional RFC 3161 timestamp. The layout
//! follows what `codesign` writes.

use crate::crypto::der::{self, oids, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::{digest_oid, hash_for_digest_oid, hash_for_signature_oid};
use crate::crypto::x509::Certificate;
use crate::format::plist::{Dict, Value};
use crate::sign::Signer;
use crate::{Error, Result};

/// Fetches a timestamp token for a signature value.
pub type Timestamper<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;

/// One CodeDirectory the signature vouches for: its hash algorithm and full digest.
#[derive(Debug, Clone)]
pub struct CdHash {
    /// The CodeDirectory's hash type.
    pub hash: HashAlg,
    /// Its full digest.
    pub digest: Vec<u8>,
}

fn attribute(oid: &[u8], values: Vec<Vec<u8>>) -> Vec<u8> {
    der::seq(&[&der::oid(oid), &der::set_of(values)])
}

fn algorithm(hash: HashAlg) -> Vec<u8> {
    der::seq(&[&der::oid(digest_oid(hash)), &der::null()])
}

/// The `{cdhashes: [<20-byte hash>…]}` plist Apple carries as a signed attribute.
fn cdhashes_plist(cds: &[CdHash]) -> Vec<u8> {
    let list: Vec<Value> = cds.iter().map(|c| Value::Data(c.digest[..20.min(c.digest.len())].to_vec())).collect();
    Value::Dict(Dict::new().with("cdhashes", list)).to_xml().into_bytes()
}

/// Builds the DER `ContentInfo` signing `primary_cd` (the CodeDirectory blob in slot 0). `cds`
/// lists every CodeDirectory (primary first). `tsa` gets the signature value and returns a
/// timestamp token when timestamping.
pub fn sign(signer: &dyn Signer, primary_cd: &[u8], cds: &[CdHash], signing_time: i64, tsa: Option<Timestamper>) -> Result<Vec<u8>> {
    let apple = vec![
        attribute(oids::APPLE_CDHASHES, cds.iter().map(|c| der::seq(&[&der::oid(digest_oid(c.hash)), &der::octet_string(&c.digest)])).collect()),
        attribute(oids::APPLE_CDHASHES_PLIST, vec![der::octet_string(&cdhashes_plist(cds))]),
    ];
    sign_detached(signer, primary_cd, HashAlg::Sha256, apple, signing_time, tsa)
}

/// A detached `SignedData` over `content`: signed attributes `contentType`, `signingTime`,
/// `messageDigest` plus `extra_attrs`, the signer's whole chain, and an optional RFC 3161
/// timestamp over the signature value.
pub fn sign_detached(signer: &dyn Signer, content: &[u8], digest_alg: HashAlg, extra_attrs: Vec<Vec<u8>>, signing_time: i64, tsa: Option<Timestamper>) -> Result<Vec<u8>> {
    let chain = signer.certificate_chain();
    let leaf = chain.first().ok_or_else(|| Error::Other("signer has no certificate".into()))?;
    let mut attrs = vec![
        attribute(oids::CONTENT_TYPE, vec![der::oid(oids::PKCS7_DATA)]),
        attribute(oids::SIGNING_TIME, vec![der::utc_time(signing_time)]),
        attribute(oids::MESSAGE_DIGEST, vec![der::octet_string(&digest_alg.digest(content))]),
    ];
    attrs.extend(extra_attrs);
    // Signed over the explicit SET OF encoding; stored with the [0] IMPLICIT tag.
    let signed_attrs = der::set_of(attrs);
    let signature = signer.sign_digest(&digest_alg.digest(&signed_attrs), digest_alg)?;
    let mut implicit_attrs = signed_attrs.clone();
    implicit_attrs[0] = 0xa0;

    let sid = der::seq(&[&leaf.issuer_raw, &der::tlv(&[tag::INTEGER], &leaf.serial)]);
    let mut si_parts: Vec<Vec<u8>> = vec![der::integer(1), sid, algorithm(digest_alg), implicit_attrs, signer.signature_algorithm(digest_alg), der::octet_string(&signature)];
    if let Some(tsa) = tsa {
        let token = tsa(&signature)?;
        si_parts.push(der::context(1, &attribute(oids::TIMESTAMP_TOKEN, vec![token])));
    }
    let signer_info = der::sequence(&si_parts.concat());
    let certs: Vec<u8> = chain.iter().flat_map(|c| c.der.clone()).collect();
    let signed_data = der::seq(&[
        &der::integer(1),
        &der::set_of(vec![algorithm(digest_alg)]),
        &der::seq(&[&der::oid(oids::PKCS7_DATA)]),
        &der::context(0, &certs),
        &der::set_of(vec![signer_info]),
    ]);
    Ok(der::seq(&[&der::oid(oids::PKCS7_SIGNED_DATA), &der::context(0, &signed_data)]))
}

/// What a verified CMS signature says.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Certificates in the order embedded (leaf first for Apple's signatures).
    pub certificates: Vec<Certificate>,
    /// The signing certificate.
    pub signer: Certificate,
    /// `signingTime`, as written.
    pub signing_time: Option<String>,
    /// The timestamp token's time, when timestamped.
    pub timestamp: Option<String>,
    /// The CodeDirectory hashes from Apple's plist attribute (20 bytes each).
    pub cdhashes: Vec<Vec<u8>>,
}

/// Checks a detached CMS signature over `content` (the primary CodeDirectory, or a XAR checksum): the message
/// digest, the signer's signature over the signed attributes, and that the issuing chain links up.
/// Trust in the anchor is the caller's decision.
pub fn verify(cms: &[u8], content: &[u8]) -> Result<Verified> {
    let bad = |m: &str| Error::malformed("cms", m);
    let ci = der::parse(cms)?;
    let mut r = ci.reader();
    if r.expect(tag::OID)?.value != oids::PKCS7_SIGNED_DATA {
        return Err(bad("not SignedData"));
    }
    let sd = der::parse(r.read()?.value)?;
    let mut sr = sd.reader();
    sr.expect(tag::INTEGER)?;
    sr.expect(tag::SET)?;
    sr.expect(tag::SEQUENCE)?;
    let mut certificates = Vec::new();
    let mut signer_infos = None;
    while !sr.is_empty() {
        let el = sr.read()?;
        if el.is_context(0) {
            let mut cr = el.reader();
            while !cr.is_empty() {
                certificates.push(Certificate::from_der(cr.read()?.raw)?);
            }
        } else if el.tag == tag::SET {
            signer_infos = Some(el);
        }
    }
    let sis = signer_infos.ok_or_else(|| bad("no signerInfos"))?;
    let si = sis.reader().expect(tag::SEQUENCE)?;
    let mut ir = si.reader();
    ir.expect(tag::INTEGER)?;
    let sid = ir.expect(tag::SEQUENCE)?;
    let mut sidr = sid.reader();
    let issuer = sidr.expect(tag::SEQUENCE)?.raw.to_vec();
    let serial = sidr.expect(tag::INTEGER)?.value.to_vec();
    let digest_alg = ir.expect(tag::SEQUENCE)?;
    let hash = hash_for_digest_oid(digest_alg.reader().expect(tag::OID)?.value).ok_or_else(|| bad("unsupported digest"))?;
    let attrs = ir.read()?;
    if !attrs.is_context(0) {
        return Err(bad("no signed attributes"));
    }
    let sig_alg = ir.expect(tag::SEQUENCE)?.reader().expect(tag::OID)?.value.to_vec();
    let signature = ir.expect(tag::OCTET_STRING)?.value.to_vec();
    let mut timestamp = None;
    if let Ok(unsigned) = ir.read()
        && unsigned.is_context(1)
    {
        let mut ur = unsigned.reader();
        while !ur.is_empty() {
            let a = ur.expect(tag::SEQUENCE)?;
            let mut ar = a.reader();
            if ar.expect(tag::OID)?.value == oids::TIMESTAMP_TOKEN {
                let token = ar.expect(tag::SET)?.reader().read()?;
                timestamp = Some(crate::sign::timestamp::token_time(token.raw)?);
                let info = crate::sign::timestamp::tst_info(token.raw)?;
                let _ = info;
            }
        }
    }
    let signer = certificates.iter().find(|c| c.issuer_raw == issuer && c.serial == serial).cloned().ok_or_else(|| bad("signer certificate isn't embedded"))?;

    // Signed attributes: re-tag as SET for hashing.
    let mut set = attrs.raw.to_vec();
    set[0] = tag::SET;
    let mut message_digest = None;
    let mut signing_time = None;
    let mut cdhashes = Vec::new();
    let mut ar = attrs.reader();
    while !ar.is_empty() {
        let a = ar.expect(tag::SEQUENCE)?;
        let mut xr = a.reader();
        let o = xr.expect(tag::OID)?.value.to_vec();
        let vals = xr.expect(tag::SET)?;
        let first = vals.reader().read()?;
        match o.as_slice() {
            x if x == oids::MESSAGE_DIGEST => message_digest = Some(first.value.to_vec()),
            x if x == oids::SIGNING_TIME => signing_time = Some(first.as_string()?),
            x if x == oids::APPLE_CDHASHES_PLIST => {
                if let Ok(Value::Dict(d)) = Value::parse(first.value)
                    && let Some(Value::Array(list)) = d.get("cdhashes")
                {
                    cdhashes = list.iter().filter_map(|v| if let Value::Data(b) = v { Some(b.clone()) } else { None }).collect();
                }
            }
            _ => {}
        }
    }
    if message_digest.as_deref() != Some(&hash.digest(content)[..]) {
        return Err(Error::Other("CMS message digest doesn't match the signed content".into()));
    }
    let sig_hash = hash_for_signature_oid(&sig_alg).unwrap_or(hash);
    if !signer.public_key.verify(&sig_alg, &sig_hash.digest(&set), &signature) {
        return Err(Error::Other("CMS signature doesn't verify against the signing certificate".into()));
    }
    // Each certificate must be signed by the next one up the chain.
    let mut cur = signer.clone();
    for _ in 0..certificates.len() {
        if cur.is_self_issued() {
            break;
        }
        match certificates.iter().find(|c| c.subject_raw == cur.issuer_raw) {
            Some(issuer) => {
                if !cur.is_signed_by(issuer) {
                    return Err(Error::Other(format!("certificate {:?} isn't signed by its issuer", cur.common_name())));
                }
                cur = issuer.clone();
            }
            None => break,
        }
    }
    Ok(Verified { certificates, signer, signing_time, timestamp, cdhashes })
}
