//! Authenticode signatures on `.msi` packages (what `signtool sign` does for them): the hash of
//! every stream (in Windows Installer's order: names compared as UTF-16LE bytes, the longer
//! first on a tie), then each storage's CLSID, signed in an `SpcSipInfo` with the MSI SIP's GUID
//! and stored as the root's `\x05DigitalSignature` stream.

use crate::crypto::der::{self, tag};
use crate::crypto::hmac::HashAlg;
use crate::format::appx::SPC_SIPINFO;
use crate::format::cfb::{self, ReadEntry, Stream};
use crate::sign::authenticode::{self, Options, ms_oids};
use crate::sign::{Signer, cms};
use crate::{Error, Result};

/// The MSI SIP's GUID {000C10F1-0000-0000-C000-000000000046}.
pub const MSI_SIP_GUID: [u8; 16] = [0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
const DIGITAL_SIGNATURE: &str = "\u{5}DigitalSignature";
const DIGITAL_SIGNATURE_EX: &str = "\u{5}MsiDigitalSignatureEx";

fn name_is(e: &ReadEntry, n: &str) -> bool {
    String::from_utf16_lossy(&e.name) == n
}

/// Children in the order both hashes visit them: names compared as stored bytes, the longer
/// first on a tie.
fn sorted<'a>(e: &'a ReadEntry, skip: &dyn Fn(&ReadEntry) -> bool) -> Vec<&'a ReadEntry> {
    let mut kids: Vec<&ReadEntry> = e.children.iter().filter(|c| !skip(c)).collect();
    kids.sort_by(|a, b| {
        let n = a.raw_name.len().min(b.raw_name.len());
        a.raw_name[..n].cmp(&b.raw_name[..n]).then(b.raw_name.len().cmp(&a.raw_name.len()))
    });
    kids
}

/// The content hash: every stream's bytes (MsiDigitalSignatureEx included), then each
/// storage's CLSID after its children.
fn hash_into(e: &ReadEntry, root: bool, out: &mut Vec<u8>) {
    for k in sorted(e, &|c| root && name_is(c, DIGITAL_SIGNATURE)) {
        if k.is_storage {
            hash_into(k, false, out);
        } else if !k.data.is_empty() {
            out.extend_from_slice(&k.data);
        }
    }
    out.extend_from_slice(&e.clsid);
}

/// The metadata pre-hash input (pre-order): names, CLSIDs or sizes, state bits and times.
fn prehash_into(e: &ReadEntry, root: bool, out: &mut Vec<u8>) {
    let meta = |x: &ReadEntry, is_root: bool, out: &mut Vec<u8>| {
        if !is_root {
            out.extend_from_slice(&x.raw_name[..x.raw_name.len().saturating_sub(2)]);
        }
        if x.is_storage {
            out.extend_from_slice(&x.clsid);
        } else {
            out.extend_from_slice(&x.size_low);
        }
        out.extend_from_slice(&x.state_bits);
        if !is_root {
            out.extend_from_slice(&x.created);
            out.extend_from_slice(&x.modified);
        }
    };
    meta(e, root, out);
    for k in sorted(e, &|c| root && (name_is(c, DIGITAL_SIGNATURE) || name_is(c, DIGITAL_SIGNATURE_EX))) {
        if k.is_storage {
            prehash_into(k, false, out);
        } else {
            meta(k, false, out);
        }
    }
}

/// The Authenticode hash of an installer database.
pub fn msi_hash(file: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
    let root = cfb::read(file)?;
    let mut buf = Vec::new();
    hash_into(&root, true, &mut buf);
    Ok(hash.digest(&buf))
}

/// The `MsiDigitalSignatureEx` value: the hash of the directory metadata.
pub fn metadata_hash(file: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
    let root = cfb::read(file)?;
    let mut buf = Vec::new();
    prehash_into(&root, true, &mut buf);
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
/// Like `signtool`, it also writes `\x05MsiDigitalSignatureEx`, so changes to the directory
/// metadata (names, timestamps) are caught too.
pub fn sign_msi(file: &[u8], signer: &dyn Signer, opts: &Options) -> Result<Vec<u8>> {
    let root = cfb::read(file)?;
    if root.children.iter().any(|c| c.is_storage) {
        return Err(Error::invalid("msi", "storages", "packages with embedded storages (transforms, nested databases) can't be re-signed yet"));
    }
    let mut streams: Vec<Stream> =
        root.children.iter().filter(|c| !name_is(c, DIGITAL_SIGNATURE) && !name_is(c, DIGITAL_SIGNATURE_EX)).map(|c| Stream { name: c.name.clone(), data: c.data.clone() }).collect();
    // The metadata pre-hash covers the database as written without either signature stream.
    let bare = cfb::write(&streams, root.clsid)?;
    streams.push(Stream::new(DIGITAL_SIGNATURE_EX, metadata_hash(&bare, opts.digest)?));
    let with_ex = cfb::write(&streams, root.clsid)?;
    let digest = msi_hash(&with_ex, opts.digest)?;
    let p7 = authenticode::signed_data(signer, &indirect_data(opts.digest, &digest), opts)?;
    streams.push(Stream::new(DIGITAL_SIGNATURE, p7));
    cfb::write(&streams, root.clsid)
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
    if let Some(ex) = root.children.iter().find(|c| name_is(c, DIGITAL_SIGNATURE_EX))
        && metadata_hash(file, hash)? != ex.data
    {
        return Err(Error::Other("the package's metadata changed after signing (MsiDigitalSignatureEx mismatch)".into()));
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
    use crate::format::msi::{Database, Table, col};
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
        // The metadata pre-hash is stored and covers the database as it was before signing.
        let root = cfb::read(&signed).unwrap();
        let ex = root.children.iter().find(|c| name_is(c, DIGITAL_SIGNATURE_EX)).unwrap();
        assert_eq!(ex.data, metadata_hash(&unsigned, HashAlg::Sha256).unwrap());
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
