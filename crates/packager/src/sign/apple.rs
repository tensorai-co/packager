//! Apple code signing for Mach-O: the embedded signature (`LC_CODE_SIGNATURE`) holding a
//! SuperBlob of CodeDirectory, requirements, entitlements (XML and DER) and the CMS wrapper.
//!
//! The layout follows what `codesign` writes, so `codesign --verify --strict` accepts it.

use crate::crypto::{sha256, Sha256};
use crate::format::macho::{self, Image, MH_EXECUTE};
use crate::format::plist::Value;
use crate::sign::{der, AppleIdentity};
use crate::util::PutBe;
use crate::{Error, Result};

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;

const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_INFOSLOT: usize = 1;
const CSSLOT_REQUIREMENTS: usize = 2;
const CSSLOT_RESOURCEDIR: usize = 3;
const CSSLOT_ENTITLEMENTS: usize = 5;
const CSSLOT_DER_ENTITLEMENTS: usize = 7;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// `CS_ADHOC`.
pub const CS_ADHOC: u32 = 0x2;
/// `CS_RUNTIME` (hardened runtime).
pub const CS_RUNTIME: u32 = 0x10000;
const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
const CS_HASHTYPE_SHA256: u8 = 2;

/// What goes into one code signature.
#[derive(Debug, Clone)]
pub struct CodeSignOptions {
    /// The signing identifier (the bundle identifier for a bundle's main executable).
    pub identifier: String,
    /// Ad hoc or certificate-backed.
    pub identity: AppleIdentity,
    /// Opt into the hardened runtime.
    pub hardened_runtime: bool,
    /// Entitlements plist (XML).
    pub entitlements: Option<Vec<u8>>,
    /// The bundle's `Info.plist` bytes, bound into special slot 1.
    pub info_plist: Option<Vec<u8>>,
    /// The bundle's `_CodeSignature/CodeResources` bytes, bound into special slot 3.
    pub code_resources: Option<Vec<u8>>,
}

impl CodeSignOptions {
    /// Ad-hoc options with just an identifier.
    pub fn ad_hoc(identifier: impl Into<String>) -> Self {
        CodeSignOptions {
            identifier: identifier.into(),
            identity: AppleIdentity::AdHoc,
            hardened_runtime: false,
            entitlements: None,
            info_plist: None,
            code_resources: None,
        }
    }
}

/// The result of signing a (possibly universal) Mach-O file.
#[derive(Debug, Clone)]
pub struct Signed {
    /// The signed file.
    pub data: Vec<u8>,
    /// One CodeDirectory hash (full SHA-256) per architecture, in file order.
    pub cdhashes: Vec<[u8; 32]>,
}

impl Signed {
    /// The designated requirement an ad-hoc signature implies, as `codesign` records it for
    /// nested code: `cdhash H"…"` per architecture, joined with `or`.
    pub fn cdhash_requirement(&self) -> String {
        self.cdhashes.iter().map(|h| format!("cdhash H\"{}\"", crate::crypto::hex(&h[..20]))).collect::<Vec<_>>().join(" or ")
    }
}

/// Signs every architecture of a Mach-O file. Any existing signature is replaced.
pub fn sign_macho(input: &[u8], opts: &CodeSignOptions) -> Result<Signed> {
    if let AppleIdentity::Signer(_) = opts.identity {
        return Err(Error::Other(
            "certificate-backed Apple signatures (CMS) aren't implemented yet; sign ad hoc for now".into(),
        ));
    }
    let mut slices = macho::slices(input)?;
    let mut cdhashes = Vec::with_capacity(slices.len());
    for s in &mut slices {
        let (data, cdhash) = sign_slice(std::mem::take(&mut s.data), opts)?;
        s.data = data;
        cdhashes.push(cdhash);
    }
    let fat = slices.len() > 1;
    let data = if fat { macho::join_in_order(slices)? } else { slices.remove(0).data };
    Ok(Signed { data, cdhashes })
}

fn blob(magic: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(body.len() + 8);
    b.u32(magic);
    b.u32(body.len() as u32 + 8);
    b.extend_from_slice(body);
    b
}

/// The empty requirement set ad-hoc signatures carry.
fn empty_requirements() -> Vec<u8> {
    blob(CSMAGIC_REQUIREMENTS, &0u32.to_be_bytes())
}

/// Encodes an entitlements plist as Apple's DER entitlements.
pub fn der_entitlements(xml: &[u8]) -> Result<Vec<u8>> {
    let v = Value::parse(xml)?;
    let dict = match &v {
        Value::Dict(_) => der_value(&v)?,
        _ => return Err(Error::invalid("entitlements", "root", "must be a dictionary")),
    };
    let mut body = der::integer(1);
    body.extend_from_slice(&dict);
    Ok(der::tlv(&[0x70], &body))
}

fn der_value(v: &Value) -> Result<Vec<u8>> {
    Ok(match v {
        Value::Bool(b) => der::boolean(*b),
        Value::Integer(i) => der::integer(*i),
        Value::String(s) => der::utf8(s),
        Value::Data(d) => der::tlv(&[0x04], d),
        Value::Array(a) => {
            let mut body = Vec::new();
            for x in a {
                body.extend(der_value(x)?);
            }
            der::sequence(&body)
        }
        Value::Dict(d) => {
            let mut entries: Vec<(&str, &Value)> = d.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut body = Vec::new();
            for (k, x) in entries {
                let mut kv = der::utf8(k);
                kv.extend(der_value(x)?);
                body.extend(der::sequence(&kv));
            }
            der::tlv(&[0xb0], &body)
        }
        Value::Real(_) | Value::Date(_) => {
            return Err(Error::invalid("entitlements", "value", "reals and dates can't be encoded as DER entitlements"));
        }
    })
}

fn sign_slice(mut data: Vec<u8>, opts: &CodeSignOptions) -> Result<(Vec<u8>, [u8; 32])> {
    let img = Image::parse(&data)?;
    let page_shift: u8 = if img.cputype == macho::CPU_TYPE_ARM64 { 14 } else { 12 };
    let page = 1usize << page_shift;

    let requirements = empty_requirements();
    let ent = opts.entitlements.as_ref().map(|x| blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, x));
    let der_ent = match &opts.entitlements {
        Some(x) => Some(blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, &der_entitlements(x)?)),
        None => None,
    };
    let cms = blob(CSMAGIC_BLOBWRAPPER, &[]);

    let mut special: Vec<Option<[u8; 32]>> = vec![None; 8];
    if let Some(p) = &opts.info_plist {
        special[CSSLOT_INFOSLOT] = Some(sha256(p));
    }
    special[CSSLOT_REQUIREMENTS] = Some(sha256(&requirements));
    if let Some(r) = &opts.code_resources {
        special[CSSLOT_RESOURCEDIR] = Some(sha256(r));
    }
    if let Some(e) = &ent {
        special[CSSLOT_ENTITLEMENTS] = Some(sha256(e));
    }
    if let Some(e) = &der_ent {
        special[CSSLOT_DER_ENTITLEMENTS] = Some(sha256(e));
    }
    let n_special = special.iter().rposition(|s| s.is_some()).unwrap_or(0);

    // Where the signature goes decides how many pages are hashed; find it first.
    let code_limit = macho::reserve_signature(&mut data, 0)? as usize;
    let n_code = code_limit.div_ceil(page);

    let version: u32 = if opts.hardened_runtime { 0x20500 } else { 0x20400 };
    let header_len = if version >= 0x20500 { 96 } else { 88 };
    let ident_len = opts.identifier.len() + 1;
    let cd_len = header_len + ident_len + 32 * (n_special + n_code);

    let mut blobs: Vec<(u32, usize)> = vec![(CSSLOT_CODEDIRECTORY, cd_len), (CSSLOT_REQUIREMENTS as u32, requirements.len())];
    if let Some(e) = &ent {
        blobs.push((CSSLOT_ENTITLEMENTS as u32, e.len()));
    }
    if let Some(e) = &der_ent {
        blobs.push((CSSLOT_DER_ENTITLEMENTS as u32, e.len()));
    }
    blobs.push((CSSLOT_SIGNATURESLOT, cms.len()));
    let sb_len = 12 + 8 * blobs.len() + blobs.iter().map(|b| b.1).sum::<usize>();
    let reserved = sb_len.div_ceil(16) * 16;
    let code_limit2 = macho::reserve_signature(&mut data, reserved as u32)? as usize;
    debug_assert_eq!(code_limit, code_limit2);
    let img = Image::parse(&data)?;
    let text = img.segment("__TEXT");

    let mut flags = match opts.identity {
        AppleIdentity::AdHoc => CS_ADHOC,
        AppleIdentity::Signer(_) => 0,
    };
    if opts.hardened_runtime {
        flags |= CS_RUNTIME;
    }

    let mut cd = Vec::with_capacity(cd_len);
    cd.u32(CSMAGIC_CODEDIRECTORY);
    cd.u32(cd_len as u32);
    cd.u32(version);
    cd.u32(flags);
    cd.u32((header_len + ident_len + 32 * n_special) as u32); // hashOffset
    cd.u32(header_len as u32); // identOffset
    cd.u32(n_special as u32);
    cd.u32(n_code as u32);
    cd.u32(code_limit as u32);
    cd.u8(32);
    cd.u8(CS_HASHTYPE_SHA256);
    cd.u8(0); // platform
    cd.u8(page_shift);
    cd.u32(0); // spare2
    cd.u32(0); // scatterOffset
    cd.u32(0); // teamOffset
    cd.u32(0); // spare3
    cd.u64(0); // codeLimit64
    cd.u64(text.map(|t| t.fileoff).unwrap_or(0));
    cd.u64(text.map(|t| t.filesize).unwrap_or(0));
    cd.u64(if img.filetype == MH_EXECUTE { CS_EXECSEG_MAIN_BINARY } else { 0 });
    if version >= 0x20500 {
        cd.u32(img.sdk_version.unwrap_or(0)); // runtime
        cd.u32(0); // preEncryptOffset
    }
    cd.extend_from_slice(opts.identifier.as_bytes());
    cd.u8(0);
    for slot in (1..=n_special).rev() {
        cd.extend_from_slice(&special[slot].unwrap_or([0; 32]));
    }
    for chunk in data[..code_limit].chunks(page) {
        let mut h = Sha256::new();
        h.update(chunk);
        cd.extend_from_slice(&h.finish());
    }
    debug_assert_eq!(cd.len(), cd_len);
    let cdhash = sha256(&cd);

    let mut sb = Vec::with_capacity(reserved);
    sb.u32(CSMAGIC_EMBEDDED_SIGNATURE);
    sb.u32(sb_len as u32);
    sb.u32(blobs.len() as u32);
    let mut off = 12 + 8 * blobs.len();
    for (slot, len) in &blobs {
        sb.u32(*slot);
        sb.u32(off as u32);
        off += len;
    }
    sb.extend_from_slice(&cd);
    sb.extend_from_slice(&requirements);
    if let Some(e) = &ent {
        sb.extend_from_slice(e);
    }
    if let Some(e) = &der_ent {
        sb.extend_from_slice(e);
    }
    sb.extend_from_slice(&cms);
    sb.resize(reserved, 0);
    data.truncate(code_limit);
    data.extend_from_slice(&sb);
    Ok((data, cdhash))
}

/// What an embedded signature says about one architecture slice.
#[derive(Debug, Clone)]
pub struct SliceSignature {
    /// `arm64`, `x86_64`…
    pub arch: &'static str,
    /// The signing identifier.
    pub identifier: String,
    /// CodeDirectory flags (`CS_ADHOC`, `CS_RUNTIME`…).
    pub flags: u32,
    /// CodeDirectory version.
    pub version: u32,
    /// Full SHA-256 CodeDirectory hash.
    pub cdhash: [u8; 32],
    /// Special-slot hashes by slot number (1 = Info.plist, 3 = CodeResources…).
    pub special: Vec<(usize, [u8; 32])>,
    /// Whether a CMS signature (certificate-backed) is present.
    pub has_cms: bool,
    /// Embedded XML entitlements.
    pub entitlements: Option<Vec<u8>>,
}

/// Reads and checks the signature of every slice: page hashes against the code, and the
/// requirement and entitlement blobs against their special slots. Errors on any mismatch.
pub fn verify_macho(data: &[u8]) -> Result<Vec<SliceSignature>> {
    let bad = |m: String| Error::malformed("code signature", m);
    let mut out = Vec::new();
    for s in macho::slices(data)? {
        let img = Image::parse(&s.data)?;
        let arch = img.arch_name();
        let (_, off, size) = img.code_signature.ok_or_else(|| bad(format!("{arch}: not signed")))?;
        let sb = s.data.get(off as usize..(off + size) as usize).ok_or_else(|| bad(format!("{arch}: signature out of range")))?;
        let be = |b: &[u8], p: usize| -> Result<u32> {
            b.get(p..p + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| bad(format!("{arch}: truncated blob")))
        };
        if be(sb, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
            return Err(bad(format!("{arch}: not an embedded signature")));
        }
        let mut blobs = std::collections::BTreeMap::new();
        for i in 0..be(sb, 8)? as usize {
            let (slot, boff) = (be(sb, 12 + 8 * i)?, be(sb, 16 + 8 * i)? as usize);
            let len = be(sb, boff + 4)? as usize;
            let b = sb.get(boff..boff + len).ok_or_else(|| bad(format!("{arch}: blob out of range")))?;
            blobs.insert(slot, b);
        }
        let cd = *blobs.get(&CSSLOT_CODEDIRECTORY).ok_or_else(|| bad(format!("{arch}: no CodeDirectory")))?;
        if be(cd, 0)? != CSMAGIC_CODEDIRECTORY {
            return Err(bad(format!("{arch}: bad CodeDirectory magic")));
        }
        let version = be(cd, 8)?;
        let flags = be(cd, 12)?;
        let hash_off = be(cd, 16)? as usize;
        let ident_off = be(cd, 20)? as usize;
        let n_special = be(cd, 24)? as usize;
        let n_code = be(cd, 28)? as usize;
        let code_limit = be(cd, 32)? as usize;
        let (hash_size, hash_type, page_shift) = (cd[36] as usize, cd[37], cd[39]);
        if hash_type != CS_HASHTYPE_SHA256 || hash_size != 32 {
            return Err(bad(format!("{arch}: only SHA-256 CodeDirectories are checked")));
        }
        let page = 1usize << page_shift;
        let code = s.data.get(..code_limit).ok_or_else(|| bad(format!("{arch}: code limit past end")))?;
        if code.len().div_ceil(page) != n_code {
            return Err(bad(format!("{arch}: page count mismatch")));
        }
        for (k, chunk) in code.chunks(page).enumerate() {
            let want = cd.get(hash_off + 32 * k..hash_off + 32 * (k + 1)).ok_or_else(|| bad(format!("{arch}: truncated hashes")))?;
            if sha256(chunk) != want {
                return Err(bad(format!("{arch}: page {k} hash mismatch (the file changed after signing)")));
            }
        }
        let mut special = Vec::new();
        for slot in 1..=n_special {
            let p = hash_off - 32 * slot;
            let h: [u8; 32] = cd.get(p..p + 32).and_then(|x| x.try_into().ok()).ok_or_else(|| bad(format!("{arch}: truncated special slots")))?;
            if h != [0; 32] {
                special.push((slot, h));
            }
        }
        for (slot, blob_slot) in [(CSSLOT_REQUIREMENTS, 2u32), (CSSLOT_ENTITLEMENTS, 5), (CSSLOT_DER_ENTITLEMENTS, 7)] {
            if let Some(b) = blobs.get(&blob_slot) {
                match special.iter().find(|(s, _)| *s == slot) {
                    Some((_, h)) if *h == sha256(b) => {}
                    _ => return Err(bad(format!("{arch}: special slot {slot} doesn't match its blob"))),
                }
            }
        }
        let ident_end = cd[ident_off..].iter().position(|&b| b == 0).map(|p| ident_off + p).unwrap_or(cd.len());
        let has_cms = blobs.get(&CSSLOT_SIGNATURESLOT).is_some_and(|b| b.len() > 8);
        out.push(SliceSignature {
            arch,
            identifier: String::from_utf8_lossy(&cd[ident_off..ident_end]).into_owned(),
            flags,
            version,
            cdhash: sha256(cd),
            special,
            has_cms,
            entitlements: blobs.get(&5).map(|b| b[8..].to_vec()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_entitlements_match_codesign() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
<key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>"#;
        let d = der_entitlements(xml).unwrap();
        // Prefix as written by `codesign` for the same two keys.
        assert_eq!(&d[..9], &[0x70, 0x53, 0x02, 0x01, 0x01, 0xb0, 0x4e, 0x30, 0x24]);
        assert_eq!(d.len(), 0x55);
    }
}
