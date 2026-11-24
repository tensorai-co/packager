//! Authenticode signatures on PE files (what `signtool sign /fd sha256` does): a PKCS#7
//! `SignedData` whose content is an `SpcIndirectDataContent` holding the image hash, stored in
//! the certificate table (`WIN_CERTIFICATE`) at the end of the file, with an optional RFC 3161
//! timestamp as `szOID_RFC3161_counterSign`.
//!
//! The image hash covers the whole file except the checksum field, the certificate-table
//! directory entry and the certificate table itself (the file is first padded to 8 bytes).

use crate::crypto::der::{self, oids, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::{digest_oid, hash_for_digest_oid};
use crate::format::pe::{self, Image};
use crate::sign::{cms, timestamp, Signer};
use crate::transport::{Curl, Transport};
use crate::{Error, Result};

/// Microsoft's Authenticode OIDs.
pub mod ms_oids {
    /// `SPC_INDIRECT_DATA_OBJID` 1.3.6.1.4.1.311.2.1.4.
    pub const SPC_INDIRECT_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
    /// `SPC_PE_IMAGE_DATAOBJ` 1.3.6.1.4.1.311.2.1.15.
    pub const SPC_PE_IMAGE_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f];
    /// `SPC_SP_OPUS_INFO_OBJID` 1.3.6.1.4.1.311.2.1.12.
    pub const SPC_SP_OPUS_INFO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c];
    /// `SPC_STATEMENT_TYPE_OBJID` 1.3.6.1.4.1.311.2.1.11.
    pub const SPC_STATEMENT_TYPE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b];
    /// `SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID` 1.3.6.1.4.1.311.2.1.21.
    pub const SPC_INDIVIDUAL_SP_KEY_PURPOSE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15];
    /// `szOID_RFC3161_counterSign` 1.3.6.1.4.1.311.3.3.1.
    pub const RFC3161_COUNTER_SIGN: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
}

/// Options for an Authenticode signature.
pub struct Options<'a> {
    /// File digest (`/fd`): SHA-256 unless something needs SHA-1.
    pub digest: HashAlg,
    /// RFC 3161 server (`/tr`), if timestamping.
    pub timestamp_url: Option<String>,
    /// Network access for timestamps.
    pub transport: &'a dyn Transport,
    /// Program name shown in the UAC prompt (`/d`).
    pub description: Option<String>,
    /// URL shown with it (`/du`).
    pub url: Option<String>,
}

impl Options<'static> {
    /// SHA-256, no timestamp.
    pub fn sha256() -> Self {
        Options { digest: HashAlg::Sha256, timestamp_url: None, transport: &Curl, description: None, url: None }
    }
}

impl<'a> Options<'a> {
    /// Timestamps with the RFC 3161 server at `url`.
    pub fn timestamp(mut self, url: impl Into<String>) -> Self {
        self.timestamp_url = Some(url.into());
        self
    }
    /// Sets the description shown when Windows asks for elevation.
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
}

/// The Authenticode image hash of `img` with `hash`. The file must already be 8-byte aligned
/// (as it is once signed); unsigned images are hashed as if padded.
pub fn image_hash(img: &Image, hash: HashAlg) -> Vec<u8> {
    let data = img.bytes();
    let ck = img.checksum_offset();
    let cd = img.dir_entry_offset(pe::dir::SECURITY);
    let end = img.certificate_table().map(|(off, _)| off).unwrap_or(data.len());
    let mut buf = Vec::with_capacity(end + 8);
    buf.extend_from_slice(&data[..ck]);
    buf.extend_from_slice(&data[ck + 4..cd]);
    buf.extend_from_slice(&data[cd + 8..end]);
    if img.certificate_table().is_none() {
        buf.resize(buf.len() + (8 - end % 8) % 8, 0);
    }
    hash.digest(&buf)
}

fn attribute(oid: &[u8], values: Vec<Vec<u8>>) -> Vec<u8> {
    der::seq(&[&der::oid(oid), &der::set_of(values)])
}

fn algorithm(hash: HashAlg) -> Vec<u8> {
    der::seq(&[&der::oid(digest_oid(hash)), &der::null()])
}

/// `SpcIndirectDataContent` for a PE image hash.
fn indirect_data(hash: HashAlg, digest: &[u8]) -> Vec<u8> {
    // SpcPeImageData: empty flags, and the legacy file link `<<<Obsolete>>>` as a BMPString.
    let obsolete: Vec<u8> = "<<<Obsolete>>>".encode_utf16().flat_map(u16::to_be_bytes).collect();
    let link = der::context(0, &der::context(2, &der::context_prim(0, &obsolete)));
    let pe_data = der::seq(&[&[0x03, 0x01, 0x00], &link]);
    let attr = der::seq(&[&der::oid(ms_oids::SPC_PE_IMAGE_DATA), &pe_data]);
    let digest_info = der::seq(&[&algorithm(hash), &der::octet_string(digest)]);
    der::seq(&[&attr, &digest_info])
}

/// The value octets of a DER TLV (Authenticode's message digest skips the outer header).
fn value_of(tlv: &[u8]) -> Result<&[u8]> {
    Ok(der::parse(tlv)?.value)
}

fn opus_info(opts: &Options) -> Vec<u8> {
    let mut parts = Vec::new();
    if let Some(d) = &opts.description {
        let bmp: Vec<u8> = d.encode_utf16().flat_map(u16::to_be_bytes).collect();
        parts.push(der::context(0, &der::context_prim(0, &bmp)));
    }
    if let Some(u) = &opts.url {
        parts.push(der::context(1, &der::context_prim(0, u.as_bytes())));
    }
    der::sequence(&parts.concat())
}

/// The PKCS#7 `ContentInfo` signing `content` (an `SpcIndirectDataContent`).
pub fn signed_data(signer: &dyn Signer, content: &[u8], opts: &Options) -> Result<Vec<u8>> {
    let chain = signer.certificate_chain();
    let leaf = chain.first().ok_or_else(|| Error::Other("signer has no certificate".into()))?;
    let h = opts.digest;
    let attrs = vec![
        attribute(oids::CONTENT_TYPE, vec![der::oid(ms_oids::SPC_INDIRECT_DATA)]),
        attribute(ms_oids::SPC_SP_OPUS_INFO, vec![opus_info(opts)]),
        attribute(ms_oids::SPC_STATEMENT_TYPE, vec![der::seq(&[&der::oid(ms_oids::SPC_INDIVIDUAL_SP_KEY_PURPOSE)])]),
        attribute(oids::MESSAGE_DIGEST, vec![der::octet_string(&h.digest(value_of(content)?))]),
    ];
    let signed_attrs = der::set_of(attrs);
    let signature = signer.sign_digest(&h.digest(&signed_attrs), h)?;
    let mut implicit = signed_attrs.clone();
    implicit[0] = 0xa0;
    let sid = der::seq(&[&leaf.issuer_raw, &der::tlv(&[tag::INTEGER], &leaf.serial)]);
    let mut si: Vec<Vec<u8>> = vec![der::integer(1), sid, algorithm(h), implicit, signer.signature_algorithm(h), der::octet_string(&signature)];
    if let Some(url) = &opts.timestamp_url {
        let token = timestamp::fetch(opts.transport, url, &signature)?;
        si.push(der::context(1, &attribute(ms_oids::RFC3161_COUNTER_SIGN, vec![token])));
    }
    let certs: Vec<u8> = chain.iter().flat_map(|c| c.der.clone()).collect();
    let sd = der::seq(&[
        &der::integer(1),
        &der::set_of(vec![algorithm(h)]),
        &der::seq(&[&der::oid(ms_oids::SPC_INDIRECT_DATA), &der::context(0, content)]),
        &der::context(0, &certs),
        &der::set_of(vec![der::sequence(&si.concat())]),
    ]);
    Ok(der::seq(&[&der::oid(oids::PKCS7_SIGNED_DATA), &der::context(0, &sd)]))
}

/// `WIN_CERTIFICATE` holding a PKCS#7 signature, padded to 8 bytes.
fn win_certificate(pkcs7: &[u8]) -> Vec<u8> {
    let len = 8 + pkcs7.len();
    let mut out = Vec::with_capacity(len + 8);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    out.extend_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    out.extend_from_slice(pkcs7);
    out.resize(len.div_ceil(8) * 8, 0);
    out
}

/// Signs (or re-signs) a PE image in place: replaces any existing signature.
pub fn sign_pe(img: &mut Image, signer: &dyn Signer, opts: &Options) -> Result<()> {
    img.strip_certificates()?;
    img.pad_to_8();
    let digest = image_hash(img, opts.digest);
    let content = indirect_data(opts.digest, &digest);
    let p7 = signed_data(signer, &content, opts)?;
    img.set_certificate_table(&win_certificate(&p7))?;
    img.update_checksum();
    Ok(())
}

/// Signs PE file bytes.
pub fn sign_pe_bytes(data: Vec<u8>, signer: &dyn Signer, opts: &Options) -> Result<Vec<u8>> {
    let mut img = Image::parse(data)?;
    sign_pe(&mut img, signer, opts)?;
    Ok(img.into_bytes())
}

/// A verified Authenticode signature.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The file digest algorithm.
    pub digest: HashAlg,
    /// The CMS signer, chain and times (`timestamp` from the RFC 3161 counter-signature).
    pub cms: cms::Verified,
}

/// The PKCS#7 blob and its `SpcIndirectDataContent` from a signed PE.
fn signature_parts(img: &Image) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let bad = |m: &str| Error::malformed("authenticode", m);
    let Some((off, size)) = img.certificate_table() else { return Ok(None) };
    let t = img.bytes().get(off..off + size).ok_or_else(|| bad("certificate table out of range"))?;
    let len = u32::from_le_bytes(t.get(..4).ok_or_else(|| bad("truncated"))?.try_into().unwrap_or_default()) as usize;
    if u16::from_le_bytes([t[6], t[7]]) != 2 || len < 8 || len > t.len() {
        return Err(bad("not a PKCS#7 certificate entry"));
    }
    let p7 = der::Reader::new(&t[8..len]).read()?.raw.to_vec();
    let ci = der::parse(&p7)?;
    let mut r = ci.reader();
    r.expect(tag::OID)?;
    let sd = der::parse(r.read()?.value)?;
    let mut sr = sd.reader();
    sr.expect(tag::INTEGER)?;
    sr.expect(tag::SET)?;
    let eci = sr.expect(tag::SEQUENCE)?;
    let mut er = eci.reader();
    if er.expect(tag::OID)?.value != ms_oids::SPC_INDIRECT_DATA {
        return Err(bad("content isn't SpcIndirectDataContent"));
    }
    let content = der::Reader::new(er.read()?.value).read()?.raw.to_vec();
    Ok(Some((p7, content)))
}

/// Checks a signed PE: the image hash against the signed one, and the CMS signature and chain.
/// `Ok(None)` when unsigned. Trust in the root is the caller's (or Windows') decision.
pub fn verify_pe(img: &Image) -> Result<Option<Verified>> {
    let bad = |m: &str| Error::malformed("authenticode", m);
    let Some((p7, content)) = signature_parts(img)? else { return Ok(None) };
    let ct = der::parse(&content)?;
    let mut cr = ct.reader();
    cr.expect(tag::SEQUENCE)?;
    let di = cr.expect(tag::SEQUENCE)?;
    let mut dr = di.reader();
    let alg = dr.expect(tag::SEQUENCE)?;
    let hash = hash_for_digest_oid(alg.reader().expect(tag::OID)?.value).ok_or_else(|| bad("unsupported digest"))?;
    let signed_digest = dr.expect(tag::OCTET_STRING)?.value.to_vec();
    if image_hash(img, hash) != signed_digest {
        return Err(Error::Other("the file changed after signing (Authenticode hash mismatch)".into()));
    }
    let v = cms::verify_with_counter_sign(&p7, value_of(&content)?, ms_oids::RFC3161_COUNTER_SIGN)?;
    Ok(Some(Verified { digest: hash, cms: v }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::KeySigner;

    #[test]
    fn sign_verify_resign_tamper() {
        let signer = KeySigner::self_signed("Packager Authenticode Test", None).unwrap();
        let exe = crate::format::pe::tests::tiny_exe();
        let signed = sign_pe_bytes(exe.clone(), &signer, &Options::sha256()).unwrap();
        let img = Image::parse(signed.clone()).unwrap();
        let v = verify_pe(&img).unwrap().unwrap();
        assert_eq!(v.cms.signer.common_name(), Some("Packager Authenticode Test"));
        assert_eq!(img.compute_checksum(), u32::from_le_bytes(signed[img.checksum_offset()..img.checksum_offset() + 4].try_into().unwrap()));
        // Re-signing replaces the signature; the hash doesn't change with it.
        let again = sign_pe_bytes(signed.clone(), &signer, &Options::sha256()).unwrap();
        assert_eq!(again.len(), signed.len());
        assert_eq!(image_hash(&Image::parse(again).unwrap(), HashAlg::Sha256), image_hash(&img, HashAlg::Sha256));
        // The unsigned image hashes the same as the signed one (padding included).
        assert_eq!(image_hash(&Image::parse(exe).unwrap(), HashAlg::Sha256), image_hash(&img, HashAlg::Sha256));
        let mut t = signed.clone();
        t[0x200] ^= 1;
        assert!(verify_pe(&Image::parse(t).unwrap()).is_err());
    }
}
