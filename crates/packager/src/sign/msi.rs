//! Authenticode signatures on `.msi` packages (what `signtool sign` does for them): the hash of
//! every stream (in Windows Installer's order: names compared as UTF-16LE bytes, the longer
//! first on a tie), then each storage's CLSID, signed in an `SpcSipInfo` with the MSI SIP's GUID
//! and stored as the root's `\x05DigitalSignature` stream.

use crate::crypto::der::{self, tag};
use crate::crypto::hmac::HashAlg;
use crate::format::cfb::{self, ReadEntry, Stream};
use crate::format::appx::SPC_SIPINFO;
use crate::sign::authenticode::{self, ms_oids, Options};
use crate::sign::{cms, Signer};
use crate::{Error, Result};

/// The MSI SIP's GUID {000C10F1-0000-0000-C000-000000000046}.
pub const MSI_SIP_GUID: [u8; 16] = [0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
const DIGITAL_SIGNATURE: &str = "\u{5}DigitalSignature";
const DIGITAL_SIGNATURE_EX: &str = "\u{5}MsiDigitalSignatureEx";

fn is_signature(e: &ReadEntry) -> bool {
    let n = String::from_utf16_lossy(&e.name);
    n == DIGITAL_SIGNATURE || n == DIGITAL_SIGNATURE_EX
}

fn hash_into(e: &ReadEntry, root: bool, out: &mut Vec<u8>) {
    let mut kids: Vec<&ReadEntry> = e.children.iter().filter(|c| !(root && is_signature(c))).collect();
    kids.sort_by(|a, b| {
        let n = a.raw_name.len().min(b.raw_name.len());
        a.raw_name[..n].cmp(&b.raw_name[..n]).then(b.raw_name.len().cmp(&a.raw_name.len()))
    });
    for k in kids {
        if k.is_storage {
            hash_into(k, false, out);
        } else if !k.data.is_empty() {
            out.extend_from_slice(&k.data);
        }
    }
    out.extend_from_slice(&e.clsid);
}

/// The Authenticode hash of an installer database.
pub fn msi_hash(file: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
    let root = cfb::read(file)?;
    let mut buf = Vec::new();
    hash_into(&root, true, &mut buf);
    Ok(hash.digest(&buf))
}

fn indirect_data(hash: HashAlg, digest: &[u8]) -> Vec<u8> {
    let sip = der::seq(&[&der::integer(1), &der::octet_string(&MSI_SIP_GUID), &der::integer(0), &der::integer(0), &der::integer(0), &der::integer(0), &der::integer(0)]);
    let attr = der::seq(&[&der::oid(SPC_SIPINFO), &sip]);
    let alg = der::seq(&[&der::oid(crate::crypto::keys::digest_oid(hash)), &der::null()]);
    der::seq(&[&attr, &der::seq(&[&alg, &der::octet_string(digest)])])
}

/// Signs (or re-signs) an `.msi`: the database is rewritten with a `\x05DigitalSignature`
/// stream (any old signature streams dropped).
pub fn sign_msi(file: &[u8], signer: &dyn Signer, opts: &Options) -> Result<Vec<u8>> {
    let root = cfb::read(file)?;
    if root.children.iter().any(|c| c.is_storage) {
        return Err(Error::invalid("msi", "storages", "packages with embedded storages (transforms, nested databases) can't be re-signed yet"));
    }
    let digest = msi_hash(file, opts.digest)?;
    let p7 = authenticode::signed_data(signer, &indirect_data(opts.digest, &digest), opts)?;
    let mut streams: Vec<Stream> = root.children.iter().filter(|c| !is_signature(c)).map(|c| Stream { name: c.name.clone(), data: c.data.clone() }).collect();
    streams.push(Stream::new(DIGITAL_SIGNATURE, p7));
    let mut clsid = [0u8; 16];
    clsid.copy_from_slice(&root.clsid);
    cfb::write(&streams, clsid)
}

/// A verified MSI signature.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The digest algorithm.
    pub digest: HashAlg,
    /// Signer, chain and timestamp.
    pub cms: cms::Verified,
}

/// Checks an `.msi`'s signature against its contents. `Ok(None)` when unsigned.
pub fn verify_msi(file: &[u8]) -> Result<Option<Verified>> {
    let bad = |m: &str| Error::malformed("msi signature", m);
    let root = cfb::read(file)?;
    let Some(sig) = root.children.iter().find(|c| String::from_utf16_lossy(&c.name) == DIGITAL_SIGNATURE) else { return Ok(None) };
    let p7 = der::Reader::new(&sig.data).read()?.raw.to_vec();
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
    let content = der::Reader::new(er.read()?.value).read()?;
    let mut cr = content.reader();
    cr.expect(tag::SEQUENCE)?;
    let mut dr = cr.expect(tag::SEQUENCE)?.reader();
    let alg = dr.expect(tag::SEQUENCE)?;
    let hash = crate::crypto::keys::hash_for_digest_oid(alg.reader().expect(tag::OID)?.value).ok_or_else(|| bad("unsupported digest"))?;
    let signed = dr.expect(tag::OCTET_STRING)?.value;
    if root.children.iter().any(|c| String::from_utf16_lossy(&c.name) == DIGITAL_SIGNATURE_EX) {
        return Err(bad("MsiDigitalSignatureEx (metadata pre-hash) isn't supported yet"));
    }
    if msi_hash(file, hash)? != signed {
        return Err(Error::Other("the package changed after signing (MSI hash mismatch)".into()));
    }
    let v = cms::verify_with_counter_sign(&p7, content.value, ms_oids::RFC3161_COUNTER_SIGN)?;
    Ok(Some(Verified { digest: hash, cms: v }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::msi::{col, Database, Table};
    use crate::sign::KeySigner;

    #[test]
    fn sign_verify_tamper() {
        let mut t = Table::new("Property", vec![col("Property", "*s72"), col("Value", "l0")]);
        t.row(vec!["ProductName".into(), "X".into()]);
        let db = Database { tables: vec![t], streams: vec![("data.cab".into(), vec![1; 9000])], ..Default::default() };
        let unsigned = db.write(&[]).unwrap();
        assert!(verify_msi(&unsigned).unwrap().is_none());
        let signer = KeySigner::self_signed("Packager Msi Test", None).unwrap();
        let signed = sign_msi(&unsigned, &signer, &Options::sha256()).unwrap();
        let v = verify_msi(&signed).unwrap().unwrap();
        assert_eq!(v.cms.signer.common_name(), Some("Packager Msi Test"));
        assert_eq!(msi_hash(&signed, HashAlg::Sha256).unwrap(), msi_hash(&unsigned, HashAlg::Sha256).unwrap());
        let resigned = sign_msi(&signed, &signer, &Options::sha256()).unwrap();
        assert!(verify_msi(&resigned).unwrap().is_some());
        // Change the cabinet stream: the hash no longer matches.
        let mut root = cfb::read(&signed).unwrap();
        for c in &mut root.children {
            if c.data.len() == 9000 {
                c.data[5] ^= 1;
            }
        }
        let streams: Vec<Stream> = root.children.iter().map(|c| Stream { name: c.name.clone(), data: c.data.clone() }).collect();
        let tampered = cfb::write(&streams, root.clsid).unwrap();
        assert!(verify_msi(&tampered).is_err());
    }
}
