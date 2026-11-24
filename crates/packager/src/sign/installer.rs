//! Installer signatures on flat packages (what `productsign` does): an RSA signature and a CMS
//! signature over the XAR table-of-contents checksum, both stored at the start of the heap and
//! described in the TOC (`<signature style="RSA">`, `<x-signature style="CMS">`), with the
//! signing chain in each `KeyInfo`.
//!
//! The layout matches `productsign`: SHA-1 TOC checksum at heap offset 0, then the RSA
//! signature (PKCS#1 v1.5, a SHA-1 `DigestInfo` holding the checksum), then the CMS signature
//! (detached over the 20 checksum bytes, SHA-1, timestamped) zero-padded into a reserved slot,
//! then the file data, moved up to make room.

use crate::crypto::der::{self, oids};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::PublicKey;
use crate::crypto::sha1;
use crate::crypto::x509::Certificate;
use crate::format::base64;
use crate::format::xar;
use crate::format::xml::{Element, Node};
use crate::sign::{Signer, cms, timestamp};
use crate::transport::{Curl, Transport};
use crate::{Error, Result};

const XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Options for signing a flat package.
pub struct InstallerSignOptions<'a> {
    /// The installer identity (Developer ID Installer, or 3rd Party Mac Developer Installer).
    pub signer: &'a dyn Signer,
    /// RFC 3161 server, if timestamping (Apple's for notarization).
    pub timestamp_url: Option<String>,
    /// Network access for timestamps.
    pub transport: &'a dyn Transport,
    /// `signingTime` (Unix seconds); defaults to now.
    pub signing_time: Option<i64>,
}

impl<'a> InstallerSignOptions<'a> {
    /// Signs with `signer`, timestamped by Apple's server, over `curl`.
    pub fn new(signer: &'a dyn Signer) -> Self {
        InstallerSignOptions { signer, timestamp_url: Some(timestamp::APPLE_TSA.to_string()), transport: &Curl, signing_time: None }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn key_info(chain: &[Certificate]) -> Element {
    let mut data = Element::new("X509Data");
    for c in chain {
        let b64 = base64::encode(&c.der);
        let wrapped: Vec<&str> = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
        data = data.child(Element::new("X509Certificate").text(wrapped.join("\n")));
    }
    Element::new("KeyInfo").attr("xmlns", XMLDSIG).child(data)
}

fn sig_element(name: &str, style: &str, offset: usize, size: usize, chain: &[Certificate]) -> Element {
    Element::new(name).attr("style", style).child(Element::new("offset").text(offset.to_string())).child(Element::new("size").text(size.to_string())).child(key_info(chain))
}

/// Every `<data><offset>` under `el`, for rewriting.
fn data_offsets(el: &mut Element, f: &mut dyn FnMut(usize) -> usize) {
    for n in &mut el.children {
        if let Node::Element(c) = n {
            if c.name == "data" {
                for d in &mut c.children {
                    if let Node::Element(o) = d
                        && o.name == "offset"
                        && let Ok(v) = o.text_content().trim().parse::<usize>()
                    {
                        o.children = vec![Node::Text(f(v).to_string())];
                    }
                }
            }
            data_offsets(c, f);
        }
    }
}

fn min_data_offset(el: &Element) -> Option<usize> {
    let mut min: Option<usize> = None;
    let mut probe = el.clone();
    data_offsets(&mut probe, &mut |v| {
        min = Some(min.map_or(v, |m| m.min(v)));
        v
    });
    min
}

/// Signs (or re-signs) a flat package. A stapled ticket is dropped: it no longer matches.
pub fn sign_pkg(data: &[u8], opts: &InstallerSignOptions) -> Result<Vec<u8>> {
    let signer = opts.signer;
    let chain = signer.certificate_chain();
    let leaf = chain.first().ok_or_else(|| Error::Other("installer signer has no certificate".into()))?;
    let rsa_len = match &leaf.public_key {
        PublicKey::Rsa(k) => k.size(),
        PublicKey::Ec(_) => return Err(Error::invalid("pkg signature", "identity", "installer signatures need an RSA key (Apple's installer certificates are RSA)")),
    };
    let parts = xar::parts(data)?;
    let old_toc = parts.root.find("toc").ok_or_else(|| Error::malformed("xar", "no <toc>"))?;
    let old_start = min_data_offset(old_toc).unwrap_or(parts.heap.len());
    let file_data = parts.heap.get(old_start..).ok_or_else(|| Error::malformed("xar", "data out of range"))?;

    let signing_time = opts.signing_time.unwrap_or_else(now);
    let tsa_fn = opts.timestamp_url.clone().map(|url| move |sig: &[u8]| timestamp::fetch(opts.transport, &url, sig));
    let tsa: Option<cms::Timestamper> = tsa_fn.as_ref().map(|f| f as cms::Timestamper);

    // The CMS slot is sized before the real signature exists: a trial signature without the
    // timestamp, plus room for a token (Apple's are ~4.3 KB), rounded up like productsign.
    let trial = cms::sign_detached(signer, &[0u8; 20], HashAlg::Sha1, Vec::new(), signing_time, None)?.len();
    let mut reserve = (trial + if tsa.is_some() { 6144 } else { 0 } + 512).div_ceil(1024) * 1024;
    loop {
        let new_start = 20 + rsa_len + reserve;
        let mut toc = Element::new("toc");
        let mut placed = false;
        for n in &old_toc.children {
            match n {
                Node::Element(e) if e.name == "signature" || e.name == "x-signature" => {}
                Node::Element(e) if e.name == "checksum" => {
                    toc = toc
                        .child(Element::new("checksum").attr("style", "sha1").child(Element::new("offset").text("0")).child(Element::new("size").text("20")))
                        .child(sig_element("signature", "RSA", 20, rsa_len, chain))
                        .child(sig_element("x-signature", "CMS", 20 + rsa_len, reserve, chain));
                    placed = true;
                }
                other => toc.children.push(other.clone()),
            }
        }
        if !placed {
            return Err(Error::malformed("xar", "TOC has no <checksum>"));
        }
        toc.attrs = old_toc.attrs.clone();
        data_offsets(&mut toc, &mut |v| v - old_start + new_start);
        let mut root = parts.root.clone();
        root.children = vec![Node::Element(toc)];
        let toc_xml = root.to_document(1);
        let toc_z = crate::compress::zlib(toc_xml.as_bytes(), crate::compress::Level::BEST);
        let checksum = sha1(&toc_z);

        let rsa = signer.sign_digest(&checksum, HashAlg::Sha1)?;
        if rsa.len() != rsa_len {
            return Err(Error::Other(format!("installer signer returned a {}-byte RSA signature, expected {rsa_len}", rsa.len())));
        }
        let mut cms_sig = cms::sign_detached(signer, &checksum, HashAlg::Sha1, Vec::new(), signing_time, tsa)?;
        if cms_sig.len() > reserve {
            reserve = (cms_sig.len() + 512).div_ceil(1024) * 1024;
            continue;
        }
        cms_sig.resize(reserve, 0);

        let mut out = Vec::with_capacity(28 + toc_z.len() + new_start + file_data.len());
        out.extend_from_slice(b"xar!");
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(toc_z.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&toc_z);
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&rsa);
        out.extend_from_slice(&cms_sig);
        out.extend_from_slice(file_data);
        return Ok(out);
    }
}

/// A verified installer signature.
#[derive(Debug, Clone)]
pub struct InstallerSignature {
    /// The certificates in the RSA signature's `KeyInfo`, leaf first.
    pub chain: Vec<Certificate>,
    /// The verified CMS signature, when present (signer, chain, signing time, timestamp).
    pub cms: Option<cms::Verified>,
    /// The signed TOC checksum.
    pub checksum: [u8; 20],
}

impl InstallerSignature {
    /// The signing certificate.
    pub fn leaf(&self) -> &Certificate {
        &self.chain[0]
    }
}

/// Checks a flat package's installer signatures. `Ok(None)` when it isn't signed. Trust in the
/// anchor is the caller's decision (see [`crate::sign::assess`]).
pub fn verify_pkg(data: &[u8]) -> Result<Option<InstallerSignature>> {
    let bad = |m: &str| Error::malformed("pkg signature", m);
    let parts = xar::parts(data)?;
    let toc = parts.root.find("toc").ok_or_else(|| bad("no <toc>"))?;
    let Some(rsa_el) = toc.find("signature") else { return Ok(None) };
    let checksum = sha1(parts.toc_compressed);
    let num = |e: &Element, k: &str| e.find(k).and_then(|x| x.text_content().trim().parse::<usize>().ok()).ok_or_else(|| bad("bad signature offset/size"));
    let certs = |e: &Element| -> Result<Vec<Certificate>> {
        let mut out = Vec::new();
        if let Some(d) = e.find("KeyInfo").and_then(|k| k.find("X509Data")) {
            for c in d.elements().filter(|c| c.name == "X509Certificate") {
                out.push(Certificate::from_der(&base64::decode(&c.text_content())?)?);
            }
        }
        Ok(out)
    };
    let chain = certs(rsa_el)?;
    let leaf = chain.first().ok_or_else(|| bad("the RSA signature lists no certificate"))?;
    let (off, size) = (num(rsa_el, "offset")?, num(rsa_el, "size")?);
    let sig = parts.heap.get(off..off + size).ok_or_else(|| bad("RSA signature out of range"))?;
    if !leaf.public_key.verify(oids::SHA1_WITH_RSA, &checksum, sig) {
        return Err(Error::Other("the package's RSA signature doesn't verify (the package changed after signing)".into()));
    }
    let cms = match toc.find("x-signature") {
        Some(x) => {
            let (off, size) = (num(x, "offset")?, num(x, "size")?);
            let slot = parts.heap.get(off..off + size).ok_or_else(|| bad("CMS signature out of range"))?;
            let first = der::Reader::new(slot).read()?;
            Some(cms::verify(first.raw, &checksum)?)
        }
        None => None,
    };
    Ok(Some(InstallerSignature { chain, cms, checksum }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::xar::XarEntry;
    use crate::sign::KeySigner;

    #[test]
    fn sign_then_verify_and_resign() {
        let x = xar::write(&[XarEntry::file("Distribution", b"<d/>".to_vec()), XarEntry::dir("a.pkg", vec![XarEntry::raw("Payload", vec![7; 3000])])], 0).unwrap();
        let signer = KeySigner::self_signed("Packager Installer Test", None).unwrap();
        let mut o = InstallerSignOptions::new(&signer);
        o.timestamp_url = None;
        o.signing_time = Some(1_700_000_000);
        let signed = sign_pkg(&x, &o).unwrap();
        let (_, files) = xar::read(&signed).unwrap();
        assert_eq!(files[1].data, vec![7; 3000]);
        let v = verify_pkg(&signed).unwrap().unwrap();
        assert_eq!(v.leaf().common_name(), Some("Packager Installer Test"));
        assert!(v.cms.is_some());
        // Re-signing replaces the old signatures rather than stacking them.
        let again = sign_pkg(&signed, &o).unwrap();
        assert_eq!(again, signed);
        // A changed RSA signature, or a changed CMS signature, is caught.
        let heap = 28 + u64::from_be_bytes(signed[8..16].try_into().unwrap()) as usize;
        for at in [heap + 20 + 7, heap + 20 + 256 + 40] {
            let mut t = signed.clone();
            t[at] ^= 1;
            assert!(verify_pkg(&t).is_err(), "tampering at heap+{} went unnoticed", at - heap);
        }
        assert!(verify_pkg(&x).unwrap().is_none());
    }
}
