//! MSIX / APPX packages at the container level (what `makeappx pack` and `signtool sign` do
//! for them): a ZIP of the payload, `AppxManifest.xml`, `AppxBlockMap.xml` (a SHA-256 per
//! 64 KB block of every file), `[Content_Types].xml`, and `AppxSignature.p7x`.
//!
//! The signature is Authenticode's `SignedData` over an `SpcSipInfo` + digest blob: `APPX`, then
//! `AXPC` (the ZIP's local records), `AXCD` (central directory and end record), `AXCT`
//! (`[Content_Types].xml`), `AXBM` (the block map), each a SHA-256 computed as if the signature
//! entry weren't there. The signature entry is the archive's last. Like `makeappx`, the archive
//! always ends with ZIP64 end records, which `AXCD` covers. Payload files are stored
//! uncompressed for now (like `makeappx pack /nc`).

use crate::crypto::der::{self, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::crc::crc32;
use crate::crypto::sha256;
use crate::format::base64;
use crate::format::xml::{escape, Element};
use crate::format::zip::{self, ZipWriter};
use crate::sign::authenticode::{self, ms_oids, Options};
use crate::sign::{cms, Signer};
use crate::{Error, Result};

/// The block size of `AppxBlockMap.xml`.
pub const BLOCK: usize = 64 * 1024;
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// `SPC_SIPINFO_OBJID` 1.3.6.1.4.1.311.2.1.30.
pub const SPC_SIPINFO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1e];
/// The APPX SIP's GUID (packages).
pub const APPX_SIP_GUID: [u8; 16] = [0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1];
/// The APPX bundle SIP's GUID.
pub const APPX_BUNDLE_SIP_GUID: [u8; 16] = [0xb3, 0x58, 0x5f, 0x0f, 0xde, 0xaa, 0x9a, 0x4b, 0xa4, 0x34, 0x95, 0x74, 0x2d, 0x92, 0xec, 0xeb];

const MANIFEST: &str = "AppxManifest.xml";
const BLOCK_MAP: &str = "AppxBlockMap.xml";
const CONTENT_TYPES: &str = "[Content_Types].xml";
const SIGNATURE: &str = "AppxSignature.p7x";

/// The ZIP item name for a part path (`Assets/My Logo.png` → `Assets/My%20Logo.png`).
pub fn part_name(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The part path for a ZIP item name (decodes `%XX`).
pub fn decode_part_name(name: &str) -> String {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = name.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn content_type(ext: &str) -> &'static str {
    match ext {
        "exe" | "dll" => "application/x-msdownload",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/vnd.microsoft.icon",
        "json" => "application/json",
        "js" | "mjs" => "application/javascript",
        "css" => "text/css",
        "html" | "htm" => "text/html",
        "txt" => "text/plain",
        "xml" => "text/xml",
        "wasm" => "application/wasm",
        "pri" => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

/// `[Content_Types].xml` for these part paths.
fn content_types(paths: &[&str], signed: bool) -> String {
    let mut defaults = std::collections::BTreeMap::new();
    let mut overrides = Vec::new();
    for p in paths {
        let file = p.rsplit('/').next().unwrap_or(p);
        match file.rsplit_once('.') {
            Some((_, ext)) if !ext.is_empty() => {
                defaults.entry(ext.to_lowercase()).or_insert_with(|| content_type(&ext.to_lowercase()));
            }
            _ => overrides.push((format!("/{}", part_name(p)), "application/octet-stream")),
        }
    }
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
    for (ext, ct) in &defaults {
        s.push_str(&format!("<Default Extension=\"{}\" ContentType=\"{ct}\"/>", escape(ext)));
    }
    for (p, ct) in &overrides {
        s.push_str(&format!("<Override PartName=\"{}\" ContentType=\"{ct}\"/>", escape(p)));
    }
    s.push_str("<Override PartName=\"/AppxManifest.xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/>");
    s.push_str("<Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/>");
    if signed {
        s.push_str("<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>");
    }
    s.push_str("</Types>");
    s
}

/// One `<File>` of the block map.
fn block_map_file(path: &str, data: &[u8], lfh: usize) -> Element {
    let mut f = Element::new("File").attr("Name", path.replace('/', "\\")).attr("Size", data.len().to_string()).attr("LfhSize", lfh.to_string());
    for block in data.chunks(BLOCK) {
        f = f.child(Element::new("Block").attr("Hash", base64::encode(&sha256(block))));
    }
    f
}

/// The `APPX` digest blob over the parts of an unsigned-view package.
fn digest_blob(pc: &[u8], cd: &[u8], ct: &[u8], bm: &[u8]) -> Vec<u8> {
    let mut b = b"APPX".to_vec();
    for (tag, h) in [(b"AXPC", pc), (b"AXCD", cd), (b"AXCT", ct), (b"AXBM", bm)] {
        b.extend_from_slice(tag);
        b.extend_from_slice(h);
    }
    b
}

/// `SpcIndirectDataContent` for an APPX digest blob.
fn indirect_data(blob: &[u8], guid: &[u8; 16]) -> Vec<u8> {
    let sip = der::seq(&[&der::integer(0x0101_0000), &der::octet_string(guid), &der::integer(0), &der::integer(0), &der::integer(0), &der::integer(0), &der::integer(0)]);
    let attr = der::seq(&[&der::oid(SPC_SIPINFO), &sip]);
    let alg = der::seq(&[&der::oid(crate::crypto::keys::digest_oid(HashAlg::Sha256)), &der::null()]);
    der::seq(&[&attr, &der::seq(&[&alg, &der::octet_string(blob)])])
}

/// Writes an MSIX package from its payload (part path → bytes, `/`-separated) and manifest,
/// signed when `signer` is given (the manifest's `Publisher` must equal the certificate's
/// subject).
pub fn write(payload: &[(String, Vec<u8>)], manifest: &[u8], signer: Option<(&dyn Signer, &Options)>, mtime: i64) -> Result<Vec<u8>> {
    let mut files: Vec<(String, &[u8])> = payload.iter().map(|(p, d)| (p.clone(), d.as_slice())).collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    for (p, _) in &files {
        if [MANIFEST, BLOCK_MAP, CONTENT_TYPES, SIGNATURE].iter().any(|r| p.eq_ignore_ascii_case(r)) || p.starts_with("AppxMetadata/") {
            return Err(Error::invalid("msix", p.clone(), "is a reserved part name"));
        }
    }
    files.push((MANIFEST.into(), manifest));
    let mut z = ZipWriter::new(mtime, false).appx();
    let mut bm = Element::new("BlockMap").attr("xmlns", "http://schemas.microsoft.com/appx/2010/blockmap").attr("HashMethod", SHA256_URI);
    for (p, d) in &files {
        let w = z.add_described(&part_name(p), zip::Method::Stored, d, crc32(d), d.len())?;
        bm = bm.child(block_map_file(p, d, w.header_len));
    }
    let bm_xml = bm.to_document(0).replacen("?>", " standalone=\"no\"?>", 1).into_bytes();
    let bm_z = crate::compress::deflate(&bm_xml, crate::compress::Level::DEFAULT);
    z.add_described(BLOCK_MAP, zip::Method::Deflate, &bm_z, crc32(&bm_xml), bm_xml.len())?;
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let ct = content_types(&paths, signer.is_some()).into_bytes();
    z.add(CONTENT_TYPES, &ct, true, 0o100644)?;
    let Some((signer, opts)) = signer else { return z.finish() };

    // Digests of the package as it is now, without the signature entry.
    let mut cd = z.central_directory().to_vec();
    cd.extend_from_slice(&z.end_record()?);
    let blob = digest_blob(&sha256(z.local_records()), &sha256(&cd), &sha256(&ct), &sha256(&bm_xml));
    let p7 = authenticode::signed_data(signer, &indirect_data(&blob, &APPX_SIP_GUID), opts)?;
    let mut p7x = b"PKCX".to_vec();
    p7x.extend_from_slice(&p7);
    z.add(SIGNATURE, &p7x, true, 0o100644)?;
    z.finish()
}

/// A verified package signature.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The CMS signer, chain and timestamp.
    pub cms: cms::Verified,
}

/// Checks a package: every file against the block map, then (when signed) each digest in the
/// signature and the CMS signature itself. `Ok(None)` when unsigned.
pub fn verify(data: &[u8]) -> Result<Option<Verified>> {
    let bad = |m: String| Error::malformed("msix", m);
    let (entries, cd_off) = zip::read_entries(data)?;
    let find = |n: &str| entries.iter().find(|e| e.name == n);
    let bm_entry = find(BLOCK_MAP).ok_or_else(|| bad("no AppxBlockMap.xml".into()))?;
    let bm_xml = zip::entry_data(data, bm_entry)?;
    let bm = crate::format::xml::parse(&String::from_utf8_lossy(&bm_xml))?;
    for f in bm.elements().filter(|e| e.name == "File") {
        let name = f.get_attr("Name").unwrap_or_default().replace('\\', "/");
        let e = find(&part_name(&name)).ok_or_else(|| bad(format!("{name}: in the block map but not the package")))?;
        let d = zip::entry_data(data, e)?;
        let hashes: Vec<String> = d.chunks(BLOCK).map(|b| base64::encode(&sha256(b))).collect();
        let listed: Vec<&str> = f.elements().filter(|b| b.name == "Block").filter_map(|b| b.get_attr("Hash")).collect();
        if hashes != listed {
            return Err(bad(format!("{name}: contents don't match the block map")));
        }
    }
    let Some(sig) = find(SIGNATURE) else { return Ok(None) };
    let p7x = zip::entry_data(data, sig)?;
    let p7 = p7x.strip_prefix(b"PKCX").ok_or_else(|| bad("AppxSignature.p7x has no PKCX header".into()))?;
    // The signed content: SpcIndirectDataContent with the digest blob.
    let ci = der::parse(p7)?;
    let mut r = ci.reader();
    r.expect(tag::OID)?;
    let sd = der::parse(r.read()?.value)?;
    let mut sr = sd.reader();
    sr.expect(tag::INTEGER)?;
    sr.expect(tag::SET)?;
    let eci = sr.expect(tag::SEQUENCE)?;
    let mut er = eci.reader();
    if er.expect(tag::OID)?.value != ms_oids::SPC_INDIRECT_DATA {
        return Err(bad("signature content isn't SpcIndirectDataContent".into()));
    }
    let content = der::Reader::new(er.read()?.value).read()?;
    let mut cr = content.reader();
    cr.expect(tag::SEQUENCE)?;
    let mut dr = cr.expect(tag::SEQUENCE)?.reader();
    dr.expect(tag::SEQUENCE)?;
    let blob = dr.expect(tag::OCTET_STRING)?.value;
    // Recompute the digests over the package without the signature entry.
    // Everything before the signature entry's local header (data descriptors included).
    let unsigned_end = sig.offset;
    if entries.iter().any(|e| e.name != SIGNATURE && e.offset >= sig.offset) {
        return Err(bad("AppxSignature.p7x isn't the last entry".into()));
    }
    let mut cd = Vec::new();
    for e in entries.iter().filter(|e| e.name != SIGNATURE) {
        cd.extend_from_slice(&data[e.central_offset..e.central_offset + e.central_len]);
    }
    // The end records as if the signature weren't there (Windows always hashes ZIP64 ones).
    let zip64 = data.windows(4).rev().take(64 * 1024).any(|w| w == [0x50, 0x4b, 0x06, 0x07]);
    let end = zip::end_records(entries.len() - 1, cd.len(), unsigned_end, zip64)?;
    cd.extend_from_slice(&end);
    let ct = zip::entry_data(data, find(CONTENT_TYPES).ok_or_else(|| bad("no [Content_Types].xml".into()))?)?;
    let _ = cd_off;
    let want = digest_blob(&sha256(&data[..unsigned_end]), &sha256(&cd), &sha256(&ct), &sha256(&bm_xml));
    if blob.get(..want.len()) != Some(&want[..]) {
        let names = ["AXPC (file records)", "AXCD (central directory)", "AXCT (content types)", "AXBM (block map)"];
        let which = (0..4).find(|&k| blob.get(8 + 36 * k..8 + 36 * k + 32) != want.get(8 + 36 * k..8 + 36 * k + 32)).map(|k| names[k]).unwrap_or("header");
        return Err(Error::Other(format!("the package changed after signing ({which} digest mismatch)")));
    }
    let v = cms::verify_with_counter_sign(p7, content.value, ms_oids::RFC3161_COUNTER_SIGN)?;
    Ok(Some(Verified { cms: v }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::KeySigner;

    #[test]
    fn write_sign_verify() {
        let payload = vec![("My App.exe".to_string(), vec![0x4d; 200_000]), ("Assets/Logo.png".to_string(), vec![1; 10])];
        let unsigned = write(&payload, b"<Package/>", None, 0).unwrap();
        assert!(verify(&unsigned).unwrap().is_none());
        let signer = KeySigner::self_signed("Packager Msix Test", None).unwrap();
        let signed = write(&payload, b"<Package/>", Some((&signer, &Options::sha256())), 0).unwrap();
        let v = verify(&signed).unwrap().unwrap();
        assert_eq!(v.cms.signer.common_name(), Some("Packager Msix Test"));
        let (entries, _) = zip::read_entries(&signed).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Assets/Logo.png", "My%20App.exe", "AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml", "AppxSignature.p7x"]);
        // A changed payload byte is caught by the block map.
        let mut t = signed.clone();
        let e = &entries[1];
        t[e.offset + e.header_len + 5] ^= 1;
        assert!(verify(&t).is_err());
        assert_eq!(decode_part_name("My%20App.exe"), "My App.exe");
    }
}
