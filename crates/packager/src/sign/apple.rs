//! Apple code signing for Mach-O: the embedded signature (`LC_CODE_SIGNATURE`) holding a
//! SuperBlob of CodeDirectory, requirements, entitlements (XML and DER) and the CMS wrapper.
//!
//! The layout follows what `codesign` writes, so `codesign --verify --strict` accepts it.

use std::sync::Arc;

use crate::crypto::der;
use crate::crypto::hmac::HashAlg;
use crate::crypto::sha256;
use crate::format::macho::{self, Image, MH_EXECUTE};
use crate::format::plist::Value;
use crate::sign::requirement::{self, RequirementType};
use crate::sign::{cms, timestamp, AppleIdentity, Signer};
use crate::transport::{Curl, Transport};
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
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// `CS_ADHOC`.
pub const CS_ADHOC: u32 = 0x2;
/// `CS_RUNTIME` (hardened runtime).
pub const CS_RUNTIME: u32 = 0x10000;
const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
const CS_HASHTYPE_SHA1: u8 = 1;
const CS_HASHTYPE_SHA256: u8 = 2;

/// What goes into one code signature.
#[derive(Clone)]
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
    /// Explicit requirements in the requirement language (`codesign -r`). Without them, ad-hoc
    /// signatures carry an empty set and certificate signatures the designated requirement
    /// `codesign` would derive.
    pub requirements: Option<String>,
    /// RFC 3161 server for certificate signatures; `None` skips timestamping.
    pub timestamp_url: Option<String>,
    /// Network access for timestamps.
    pub transport: Arc<dyn Transport>,
}

impl std::fmt::Debug for CodeSignOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeSignOptions")
            .field("identifier", &self.identifier)
            .field("identity", &self.identity)
            .field("hardened_runtime", &self.hardened_runtime)
            .field("timestamp_url", &self.timestamp_url)
            .finish_non_exhaustive()
    }
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
            requirements: None,
            timestamp_url: None,
            transport: Arc::new(Curl),
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
    /// The embedded designated requirement's text, for certificate signatures.
    pub designated: Option<String>,
}

impl Signed {
    /// The designated requirement an ad-hoc signature implies, as `codesign` records it for
    /// nested code: `cdhash H"…"` per architecture, joined with `or`.
    pub fn cdhash_requirement(&self) -> String {
        self.cdhashes.iter().map(|h| format!("cdhash H\"{}\"", crate::crypto::hex(&h[..20]))).collect::<Vec<_>>().join(" or ")
    }
    /// The requirement `CodeResources` records for this code when nested: the embedded
    /// designated requirement, or the cdhashes for ad-hoc code.
    pub fn nested_requirement(&self) -> String {
        self.designated.clone().unwrap_or_else(|| self.cdhash_requirement())
    }
}

/// Signs every architecture of a Mach-O file. Any existing signature is replaced.
pub fn sign_macho(input: &[u8], opts: &CodeSignOptions) -> Result<Signed> {
    let requirements = requirements_for(opts)?;
    let designated = match &opts.identity {
        AppleIdentity::AdHoc => None,
        AppleIdentity::Signer(_) => requirement::parse_requirement_set(&requirements)?
            .into_iter()
            .find(|(t, _)| *t == RequirementType::Designated)
            .map(|(_, e)| e.to_string()),
    };
    let mut slices = macho::slices(input)?;
    let mut cdhashes = Vec::with_capacity(slices.len());
    for s in &mut slices {
        let (data, cdhash) = sign_slice(std::mem::take(&mut s.data), opts, &requirements)?;
        s.data = data;
        cdhashes.push(cdhash);
    }
    let fat = slices.len() > 1;
    let data = if fat { macho::join_in_order(slices)? } else { slices.remove(0).data };
    Ok(Signed { data, cdhashes, designated })
}

/// The requirement set to embed: explicit, empty (ad hoc), or the derived designated requirement.
fn requirements_for(opts: &CodeSignOptions) -> Result<Vec<u8>> {
    if let Some(text) = &opts.requirements {
        return Ok(requirement::requirement_set(&requirement::compile_set(text)?));
    }
    match &opts.identity {
        AppleIdentity::AdHoc => Ok(empty_requirements()),
        AppleIdentity::Signer(s) => {
            let dr = requirement::designated(&opts.identifier, s.certificate_chain())?;
            Ok(requirement::requirement_set(&[(RequirementType::Designated, dr)]))
        }
    }
}

/// Bytes to reserve for the CMS blob: certificates, signature, attributes, and a timestamp token.
fn cms_reserve(signer: &dyn Signer, timestamped: bool) -> usize {
    let certs: usize = signer.certificate_chain().iter().map(|c| c.der.len()).sum();
    certs + signer.max_signature_len() + 1600 + if timestamped { 6144 } else { 0 }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
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

fn sign_slice(mut data: Vec<u8>, opts: &CodeSignOptions, requirements: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let img = Image::parse(&data)?;
    let page_shift: u8 = if img.cputype == macho::CPU_TYPE_ARM64 { 14 } else { 12 };
    let page = 1usize << page_shift;
    let signer: Option<&dyn Signer> = match &opts.identity {
        AppleIdentity::AdHoc => None,
        AppleIdentity::Signer(s) => Some(s.as_ref()),
    };
    let team_id = signer.and_then(|s| requirement::team_id(s.certificate_chain()));

    let ent = opts.entitlements.as_ref().map(|x| blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, x));
    let der_ent = match &opts.entitlements {
        Some(x) => Some(blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, &der_entitlements(x)?)),
        None => None,
    };

    // What each special slot binds; hashed per CodeDirectory, in its own algorithm.
    let mut special: Vec<Option<&[u8]>> = vec![None; 8];
    special[CSSLOT_INFOSLOT] = opts.info_plist.as_deref();
    special[CSSLOT_REQUIREMENTS] = Some(requirements);
    special[CSSLOT_RESOURCEDIR] = opts.code_resources.as_deref();
    special[CSSLOT_ENTITLEMENTS] = ent.as_deref();
    special[CSSLOT_DER_ENTITLEMENTS] = der_ent.as_deref();
    let n_special = special.iter().rposition(|s| s.is_some()).unwrap_or(0);
    // Like codesign: SHA-1 primary plus SHA-256 alternate for macOS deployment targets before
    // 10.11.4, which can't check SHA-256 CodeDirectories; SHA-256 only otherwise.
    let legacy = matches!(img.min_os, Some((1, v)) if v < 0x000a_0b04);
    let algs: &[HashAlg] = if legacy { &[HashAlg::Sha1, HashAlg::Sha256] } else { &[HashAlg::Sha256] };

    // Where the signature goes decides how many pages are hashed; find it first.
    let code_limit = macho::reserve_signature(&mut data, 0)? as usize;
    let n_code = code_limit.div_ceil(page);

    let version: u32 = if opts.hardened_runtime { 0x20500 } else { 0x20400 };
    let header_len = if version >= 0x20500 { 96 } else { 88 };
    let ident_len = opts.identifier.len() + 1;
    let team_len = team_id.as_ref().map_or(0, |t| t.len() + 1);
    let hash_offset = |alg: HashAlg| header_len + ident_len + team_len + alg.len() * n_special;
    let cd_len = |alg: HashAlg| hash_offset(alg) + alg.len() * n_code;

    let mut flags = if signer.is_none() { CS_ADHOC } else { 0 };
    if opts.hardened_runtime {
        flags |= CS_RUNTIME;
    }
    // The CMS blob's size isn't known until it's signed (and timestamped), but the header that
    // holds the signature size is hashed. Reserve generously, and redo if it doesn't fit.
    let mut cms_room = match signer {
        Some(s) => cms_reserve(s, opts.timestamp_url.is_some()),
        None => 8,
    };
    loop {
        let mut fixed: Vec<usize> = algs.iter().map(|&a| cd_len(a)).collect();
        fixed.push(requirements.len());
        fixed.extend(ent.as_ref().map(|e| e.len()));
        fixed.extend(der_ent.as_ref().map(|e| e.len()));
        let n_blobs = fixed.len() + 1;
        let reserved = (12 + 8 * n_blobs + fixed.iter().sum::<usize>() + cms_room).div_ceil(16) * 16;
        let code_limit2 = macho::reserve_signature(&mut data, reserved as u32)? as usize;
        debug_assert_eq!(code_limit, code_limit2);
        let img = Image::parse(&data)?;
        let text = img.segment("__TEXT");

        let build_cd = |alg: HashAlg| -> Vec<u8> {
            let mut cd = Vec::with_capacity(cd_len(alg));
            cd.u32(CSMAGIC_CODEDIRECTORY);
            cd.u32(cd_len(alg) as u32);
            cd.u32(version);
            cd.u32(flags);
            cd.u32(hash_offset(alg) as u32);
            cd.u32(header_len as u32); // identOffset
            cd.u32(n_special as u32);
            cd.u32(n_code as u32);
            cd.u32(code_limit as u32);
            cd.u8(alg.len() as u8);
            cd.u8(if alg == HashAlg::Sha1 { CS_HASHTYPE_SHA1 } else { CS_HASHTYPE_SHA256 });
            cd.u8(0); // platform
            cd.u8(page_shift);
            cd.u32(0); // spare2
            cd.u32(0); // scatterOffset
            cd.u32(if team_id.is_some() { (header_len + ident_len) as u32 } else { 0 }); // teamOffset
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
            if let Some(t) = &team_id {
                cd.extend_from_slice(t.as_bytes());
                cd.u8(0);
            }
            for slot in (1..=n_special).rev() {
                match special[slot] {
                    Some(b) => cd.extend_from_slice(&alg.digest(b)),
                    None => cd.extend(std::iter::repeat_n(0u8, alg.len())),
                }
            }
            for chunk in data[..code_limit].chunks(page) {
                cd.extend_from_slice(&alg.digest(chunk));
            }
            debug_assert_eq!(cd.len(), cd_len(alg));
            cd
        };
        let cds: Vec<(HashAlg, Vec<u8>)> = algs.iter().map(|&a| (a, build_cd(a))).collect();
        let cd = &cds[0].1;
        // The cdhash that identifies this code: the SHA-256 CodeDirectory's.
        let cdhash = sha256(&cds.last().map(|c| c.1.clone()).unwrap_or_default());

        let cms_blob = match signer {
            None => blob(CSMAGIC_BLOBWRAPPER, &[]),
            Some(s) => {
                let cd_hashes: Vec<cms::CdHash> = cds.iter().map(|(a, c)| cms::CdHash { hash: *a, digest: a.digest(c) }).collect();
                let transport = opts.transport.clone();
                let tsa = opts.timestamp_url.clone().map(|url| move |sig: &[u8]| timestamp::fetch(transport.as_ref(), &url, sig));
                let tsa_ref: Option<cms::Timestamper> = tsa.as_ref().map(|f| f as cms::Timestamper);
                blob(CSMAGIC_BLOBWRAPPER, &cms::sign(s, cd, &cd_hashes, now(), tsa_ref)?)
            }
        };
        if cms_blob.len() > cms_room {
            cms_room = cms_blob.len() + 1024;
            continue;
        }

        let mut blobs: Vec<(u32, &[u8])> = vec![(CSSLOT_CODEDIRECTORY, cd), (CSSLOT_REQUIREMENTS as u32, requirements)];
        if let Some(e) = &ent {
            blobs.push((CSSLOT_ENTITLEMENTS as u32, e));
        }
        if let Some(e) = &der_ent {
            blobs.push((CSSLOT_DER_ENTITLEMENTS as u32, e));
        }
        for (i, (_, c)) in cds.iter().enumerate().skip(1) {
            blobs.push((CSSLOT_ALTERNATE_CODEDIRECTORIES + i as u32 - 1, c));
        }
        blobs.push((CSSLOT_SIGNATURESLOT, &cms_blob));
        let sb_len = 12 + 8 * blobs.len() + blobs.iter().map(|b| b.1.len()).sum::<usize>();
        let mut sb = Vec::with_capacity(reserved);
        sb.u32(CSMAGIC_EMBEDDED_SIGNATURE);
        sb.u32(sb_len as u32);
        sb.u32(blobs.len() as u32);
        let mut off = 12 + 8 * blobs.len();
        for (slot, b) in &blobs {
            sb.u32(*slot);
            sb.u32(off as u32);
            off += b.len();
        }
        for (_, b) in &blobs {
            sb.extend_from_slice(b);
        }
        sb.resize(reserved, 0);
        data.truncate(code_limit);
        data.extend_from_slice(&sb);
        return Ok((data, cdhash));
    }
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
    /// The verified CMS signature (signer, chain, times), when certificate-backed.
    pub cms: Option<cms::Verified>,
    /// The team identifier in the CodeDirectory.
    pub team_id: Option<String>,
    /// The embedded requirement set.
    pub requirements: Vec<(RequirementType, requirement::Expr)>,
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
        let ident_off = be(cd, 20)? as usize;
        // Check every CodeDirectory (the primary and any alternates), each in its own hash.
        let mut all_cds: Vec<&[u8]> = vec![cd];
        all_cds.extend(blobs.range(CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_CODEDIRECTORIES + 5).map(|(_, b)| *b));
        let mut special = Vec::new();
        let mut cdhash = sha256(cd);
        for c in &all_cds {
            if be(c, 0)? != CSMAGIC_CODEDIRECTORY {
                return Err(bad(format!("{arch}: bad CodeDirectory magic")));
            }
            let hash_off = be(c, 16)? as usize;
            let n_special = be(c, 24)? as usize;
            let n_code = be(c, 28)? as usize;
            let code_limit = be(c, 32)? as usize;
            let (hash_size, hash_type, page_shift) = (c[36] as usize, c[37], c[39]);
            let alg = match (hash_type, hash_size) {
                (CS_HASHTYPE_SHA1, 20) => HashAlg::Sha1,
                (CS_HASHTYPE_SHA256, 32) => HashAlg::Sha256,
                _ => return Err(bad(format!("{arch}: unsupported CodeDirectory hash type {hash_type}"))),
            };
            let page = if page_shift == 0 { usize::MAX } else { 1usize << page_shift };
            let code = s.data.get(..code_limit).ok_or_else(|| bad(format!("{arch}: code limit past end")))?;
            if code.len().div_ceil(page.min(code.len().max(1))) != n_code && !(page == usize::MAX && n_code == 1) {
                return Err(bad(format!("{arch}: page count mismatch")));
            }
            for (k, chunk) in code.chunks(page.min(code.len().max(1))).enumerate() {
                let want = c.get(hash_off + hash_size * k..hash_off + hash_size * (k + 1)).ok_or_else(|| bad(format!("{arch}: truncated hashes")))?;
                if alg.digest(chunk) != want {
                    return Err(bad(format!("{arch}: page {k} hash mismatch (the file changed after signing)")));
                }
            }
            let slot_hash = |slot: usize| c.get(hash_off - hash_size * slot..hash_off - hash_size * (slot - 1));
            for (slot, blob_slot) in [(CSSLOT_REQUIREMENTS, 2u32), (CSSLOT_ENTITLEMENTS, 5), (CSSLOT_DER_ENTITLEMENTS, 7)] {
                if let Some(b) = blobs.get(&blob_slot)
                    && (slot > n_special || slot_hash(slot) != Some(&alg.digest(b)[..]))
                {
                    return Err(bad(format!("{arch}: special slot {slot} doesn't match its blob")));
                }
            }
            if alg == HashAlg::Sha256 {
                cdhash = sha256(c);
                special.clear();
                for slot in 1..=n_special {
                    let h: [u8; 32] = slot_hash(slot).and_then(|x| x.try_into().ok()).ok_or_else(|| bad(format!("{arch}: truncated special slots")))?;
                    if h != [0; 32] {
                        special.push((slot, h));
                    }
                }
            }
        }
        let ident_end = cd[ident_off..].iter().position(|&b| b == 0).map(|p| ident_off + p).unwrap_or(cd.len());
        let has_cms = blobs.get(&CSSLOT_SIGNATURESLOT).is_some_and(|b| b.len() > 8);
        let cms = match blobs.get(&CSSLOT_SIGNATURESLOT) {
            Some(b) if b.len() > 8 => Some(cms::verify(&b[8..], cd).map_err(|e| bad(format!("{arch}: {e}")))?),
            _ => None,
        };
        let team_off = if version >= 0x20200 { be(cd, 48)? as usize } else { 0 };
        let team_id = (team_off != 0 && team_off < cd.len()).then(|| {
            let end = cd[team_off..].iter().position(|&b| b == 0).map(|p| team_off + p).unwrap_or(cd.len());
            String::from_utf8_lossy(&cd[team_off..end]).into_owned()
        });
        let requirements = match blobs.get(&(CSSLOT_REQUIREMENTS as u32)) {
            Some(b) => requirement::parse_requirement_set(b)?,
            None => Vec::new(),
        };
        out.push(SliceSignature {
            arch,
            identifier: String::from_utf8_lossy(&cd[ident_off..ident_end]).into_owned(),
            flags,
            version,
            cdhash,
            special,
            has_cms,
            cms,
            team_id,
            requirements,
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
