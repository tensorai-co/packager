//! Code signatures on UDIF disk images (`codesign -s ID My.dmg`): a SuperBlob appended after the
//! image data, located by two `koly` trailer fields. The CodeDirectory has a single "page" (the
//! whole image before the signature) and binds the trailer through the rep-specific slot.

use crate::crypto::hmac::HashAlg;
use crate::crypto::sha256;
use crate::sign::apple::{CS_ADHOC, SliceSignature};
use crate::sign::requirement::{self, RequirementType};
use crate::sign::{AppleIdentity, cms, timestamp};
use crate::transport::{Curl, Transport};
use crate::util::PutBe;
use crate::{Error, Result};

const KOLY_LEN: usize = 512;
const SIG_OFFSET_FIELD: usize = 296;
const SIG_LENGTH_FIELD: usize = 304;
const CSSLOT_REQUIREMENTS: usize = 2;
const CSSLOT_REP_SPECIFIC: usize = 6;

/// Options for signing a disk image.
pub struct DiskImageSignOptions<'a> {
    /// Signing identifier (`codesign` uses the file name without extension).
    pub identifier: String,
    /// Ad hoc or certificate-backed.
    pub identity: AppleIdentity,
    /// Explicit requirements text; otherwise the derived designated requirement.
    pub requirements: Option<String>,
    /// RFC 3161 server, if timestamping.
    pub timestamp_url: Option<String>,
    /// Network access for timestamps.
    pub transport: &'a dyn Transport,
}

impl DiskImageSignOptions<'static> {
    /// Defaults for `identifier` and `identity`.
    pub fn new(identifier: impl Into<String>, identity: AppleIdentity) -> Self {
        DiskImageSignOptions { identifier: identifier.into(), identity, requirements: None, timestamp_url: None, transport: &Curl }
    }
}

fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

/// Splits an image into (data before any signature, trailer).
fn split(image: &[u8]) -> Result<(&[u8], [u8; KOLY_LEN])> {
    if image.len() < KOLY_LEN || &image[image.len() - KOLY_LEN..image.len() - KOLY_LEN + 4] != b"koly" {
        return Err(Error::malformed("udif", "missing koly trailer"));
    }
    let mut koly = [0u8; KOLY_LEN];
    koly.copy_from_slice(&image[image.len() - KOLY_LEN..]);
    let sig_off = be64(&koly, SIG_OFFSET_FIELD) as usize;
    let end = if sig_off > 0 && sig_off < image.len() - KOLY_LEN { sig_off } else { image.len() - KOLY_LEN };
    Ok((&image[..end], koly))
}

/// Signs (or re-signs) a UDIF image.
pub fn sign_disk_image(image: &[u8], opts: &DiskImageSignOptions) -> Result<Vec<u8>> {
    let (data, mut koly) = split(image)?;
    let sig_off = data.len();
    if sig_off > u32::MAX as usize {
        return Err(Error::Other("disk images over 4 GB can't be signed yet".into()));
    }
    koly[SIG_OFFSET_FIELD..SIG_OFFSET_FIELD + 8].copy_from_slice(&(sig_off as u64).to_be_bytes());
    koly[SIG_LENGTH_FIELD..SIG_LENGTH_FIELD + 8].fill(0);

    let signer = match &opts.identity {
        AppleIdentity::AdHoc => None,
        AppleIdentity::Signer(s) => Some(s.as_ref()),
    };
    let requirements = match (&opts.requirements, signer) {
        (Some(t), _) => requirement::requirement_set(&requirement::compile_set(t)?),
        (None, Some(s)) => requirement::requirement_set(&[(RequirementType::Designated, requirement::designated(&opts.identifier, s.certificate_chain())?)]),
        (None, None) => {
            let mut b = Vec::new();
            b.u32(requirement::CSMAGIC_REQUIREMENTS);
            b.u32(12);
            b.u32(0);
            b
        }
    };
    let team = signer.and_then(|s| requirement::team_id(s.certificate_chain()));

    let header_len = 52; // through teamOffset (version 0x20200)
    let ident_len = opts.identifier.len() + 1;
    let team_len = team.as_ref().map_or(0, |t| t.len() + 1);
    let n_special = CSSLOT_REP_SPECIFIC;
    let hash_offset = header_len + ident_len + team_len + 32 * n_special;
    let cd_len = hash_offset + 32;
    let mut cd = Vec::with_capacity(cd_len);
    cd.u32(0xfade_0c02);
    cd.u32(cd_len as u32);
    cd.u32(0x20200);
    cd.u32(if signer.is_none() { CS_ADHOC } else { 0 });
    cd.u32(hash_offset as u32);
    cd.u32(header_len as u32);
    cd.u32(n_special as u32);
    cd.u32(1);
    cd.u32(sig_off as u32);
    cd.u8(32);
    cd.u8(2); // SHA-256
    cd.u8(0);
    cd.u8(0); // page size 0: one page covering everything
    cd.u32(0);
    cd.u32(0); // scatter
    cd.u32(if team.is_some() { (header_len + ident_len) as u32 } else { 0 });
    cd.extend_from_slice(opts.identifier.as_bytes());
    cd.u8(0);
    if let Some(t) = &team {
        cd.extend_from_slice(t.as_bytes());
        cd.u8(0);
    }
    for slot in (1..=n_special).rev() {
        let h = match slot {
            CSSLOT_REP_SPECIFIC => sha256(&koly),
            CSSLOT_REQUIREMENTS => sha256(&requirements),
            _ => [0; 32],
        };
        cd.extend_from_slice(&h);
    }
    cd.extend_from_slice(&sha256(data));
    debug_assert_eq!(cd.len(), cd_len);

    let cms_body = match signer {
        None => Vec::new(),
        Some(s) => {
            let cds = [cms::CdHash { hash: HashAlg::Sha256, digest: sha256(&cd).to_vec() }];
            let tsa = opts.timestamp_url.clone().map(|url| move |sig: &[u8]| timestamp::fetch(opts.transport, &url, sig));
            let tsa_ref: Option<cms::Timestamper> = tsa.as_ref().map(|f| f as cms::Timestamper);
            cms::sign(s, &cd, &cds, now(), tsa_ref)?
        }
    };
    let mut cms_blob = Vec::new();
    cms_blob.u32(0xfade_0b01);
    cms_blob.u32(cms_body.len() as u32 + 8);
    cms_blob.extend_from_slice(&cms_body);

    let blobs: [(u32, &[u8]); 3] = [(0, &cd), (CSSLOT_REQUIREMENTS as u32, &requirements), (0x10000, &cms_blob)];
    let sb_len = 12 + 8 * blobs.len() + blobs.iter().map(|b| b.1.len()).sum::<usize>();
    let mut sb = Vec::with_capacity(sb_len);
    sb.u32(0xfade_0cc0);
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
    koly[SIG_LENGTH_FIELD..SIG_LENGTH_FIELD + 8].copy_from_slice(&(sb.len() as u64).to_be_bytes());
    let mut out = Vec::with_capacity(sig_off + sb.len() + KOLY_LEN);
    out.extend_from_slice(data);
    out.extend_from_slice(&sb);
    out.extend_from_slice(&koly);
    Ok(out)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Checks a signed disk image: the data hash, the trailer binding, requirements and CMS.
pub fn verify_disk_image(image: &[u8]) -> Result<SliceSignature> {
    let bad = |m: &str| Error::malformed("disk image signature", m);
    let (data, koly) = split(image)?;
    let sig_off = be64(&koly, SIG_OFFSET_FIELD) as usize;
    let sig_len = be64(&koly, SIG_LENGTH_FIELD) as usize;
    if sig_off == 0 || sig_len == 0 {
        return Err(bad("not signed"));
    }
    let sb = image.get(sig_off..sig_off + sig_len).ok_or_else(|| bad("signature out of range"))?;
    let be = |b: &[u8], p: usize| -> Result<u32> { b.get(p..p + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| bad("truncated")) };
    if be(sb, 0)? != 0xfade_0cc0 {
        return Err(bad("not a SuperBlob"));
    }
    let mut blobs = std::collections::BTreeMap::new();
    for i in 0..be(sb, 8)? as usize {
        let (slot, o) = (be(sb, 12 + 8 * i)?, be(sb, 16 + 8 * i)? as usize);
        let l = be(sb, o + 4)? as usize;
        blobs.insert(slot, sb.get(o..o + l).ok_or_else(|| bad("blob out of range"))?);
    }
    let cd = *blobs.get(&0).ok_or_else(|| bad("no CodeDirectory"))?;
    let hash_offset = be(cd, 16)? as usize;
    let n_special = be(cd, 24)? as usize;
    if cd.get(hash_offset..hash_offset + 32) != Some(&sha256(data)[..]) {
        return Err(bad("the image data changed after signing"));
    }
    let mut zeroed = koly;
    zeroed[SIG_LENGTH_FIELD..SIG_LENGTH_FIELD + 8].fill(0);
    let slot_hash = |n: usize| cd.get(hash_offset - 32 * n..hash_offset - 32 * n + 32);
    if n_special >= CSSLOT_REP_SPECIFIC && slot_hash(CSSLOT_REP_SPECIFIC) != Some(&sha256(&zeroed)[..]) {
        return Err(bad("the image trailer changed after signing"));
    }
    let requirements = match blobs.get(&2) {
        Some(r) => {
            if slot_hash(CSSLOT_REQUIREMENTS) != Some(&sha256(r)[..]) {
                return Err(bad("requirements don't match their slot"));
            }
            requirement::parse_requirement_set(r)?
        }
        None => Vec::new(),
    };
    let cms = match blobs.get(&0x10000) {
        Some(b) if b.len() > 8 => Some(cms::verify(&b[8..], cd)?),
        _ => None,
    };
    let ident_off = be(cd, 20)? as usize;
    let ident = cd[ident_off..].split(|&b| b == 0).next().unwrap_or_default();
    let team_off = be(cd, 48)? as usize;
    let team_id = (team_off != 0).then(|| String::from_utf8_lossy(cd[team_off..].split(|&b| b == 0).next().unwrap_or_default()).into_owned());
    Ok(SliceSignature {
        arch: "disk image",
        identifier: String::from_utf8_lossy(ident).into_owned(),
        flags: be(cd, 12)?,
        version: be(cd, 8)?,
        cdhash: sha256(cd),
        special: (1..=n_special).filter_map(|n| slot_hash(n).and_then(|h| <[u8; 32]>::try_from(h).ok()).filter(|h| *h != [0; 32]).map(|h| (n, h))).collect(),
        has_cms: cms.is_some(),
        cms,
        team_id,
        requirements,
        entitlements: None,
    })
}

/// The blobs of a signed image's SuperBlob, as (slot, whole blob), in slot order.
fn superblob(image: &[u8]) -> Result<Vec<(u32, Vec<u8>)>> {
    let bad = |m: &str| Error::malformed("disk image signature", m);
    let (_, koly) = split(image)?;
    let (off, len) = (be64(&koly, SIG_OFFSET_FIELD) as usize, be64(&koly, SIG_LENGTH_FIELD) as usize);
    if off == 0 || len == 0 {
        return Err(bad("not signed"));
    }
    let sb = image.get(off..off + len).ok_or_else(|| bad("signature out of range"))?;
    let be = |p: usize| -> Result<u32> { sb.get(p..p + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| bad("truncated")) };
    if be(0)? != 0xfade_0cc0 {
        return Err(bad("not a SuperBlob"));
    }
    let mut blobs = Vec::new();
    for i in 0..be(8)? as usize {
        let (slot, o) = (be(12 + 8 * i)?, be(16 + 8 * i)? as usize);
        let l = be(o + 4)? as usize;
        blobs.push((slot, sb.get(o..o + l).ok_or_else(|| bad("blob out of range"))?.to_vec()));
    }
    blobs.sort_by_key(|b| b.0);
    Ok(blobs)
}

/// The payload of a wrapper blob (`0xfade0b01`) in `slot` of a signed image, such as the
/// stapled notarization ticket in slot `0x10002`.
pub fn blob(image: &[u8], slot: u32) -> Result<Option<Vec<u8>>> {
    Ok(superblob(image)?.into_iter().find(|b| b.0 == slot).map(|(_, b)| if b.starts_with(&[0xfa, 0xde, 0x0b, 0x01]) { b[8..].to_vec() } else { b }))
}

/// Puts `payload` (wrapped in a `0xfade0b01` blob) into `slot` of a signed image's SuperBlob,
/// or removes the slot when `None`, and updates the trailer. The CodeDirectory doesn't cover
/// these slots or the signature length, so the signature stays valid.
pub fn replace_blob(image: &[u8], slot: u32, payload: Option<&[u8]>) -> Result<Vec<u8>> {
    if slot == 0 || slot == CSSLOT_REQUIREMENTS as u32 || slot == 0x10000 {
        return Err(Error::invalid("disk image signature", format!("slot {slot:#x}"), "signed slots can't be replaced"));
    }
    let mut blobs = superblob(image)?;
    blobs.retain(|b| b.0 != slot);
    if let Some(p) = payload {
        let mut b = Vec::with_capacity(p.len() + 8);
        b.u32(0xfade_0b01);
        b.u32(p.len() as u32 + 8);
        b.extend_from_slice(p);
        blobs.push((slot, b));
        blobs.sort_by_key(|b| b.0);
    }
    let (data, mut koly) = split(image)?;
    let sb_len = 12 + 8 * blobs.len() + blobs.iter().map(|b| b.1.len()).sum::<usize>();
    let mut sb = Vec::with_capacity(sb_len);
    sb.u32(0xfade_0cc0);
    sb.u32(sb_len as u32);
    sb.u32(blobs.len() as u32);
    let mut off = 12 + 8 * blobs.len();
    for (s, b) in &blobs {
        sb.u32(*s);
        sb.u32(off as u32);
        off += b.len();
    }
    for (_, b) in &blobs {
        sb.extend_from_slice(b);
    }
    koly[SIG_LENGTH_FIELD..SIG_LENGTH_FIELD + 8].copy_from_slice(&(sb.len() as u64).to_be_bytes());
    let mut out = Vec::with_capacity(data.len() + sb.len() + KOLY_LEN);
    out.extend_from_slice(data);
    out.extend_from_slice(&sb);
    out.extend_from_slice(&koly);
    Ok(out)
}

/// The hash type (1 = SHA-1, 2 = SHA-256) and digest of a signed image's CodeDirectory: what
/// its notarization ticket is filed under.
pub fn code_directory_hash(image: &[u8]) -> Result<(u8, Vec<u8>)> {
    let cd = superblob(image)?.into_iter().find(|b| b.0 == 0).map(|b| b.1).ok_or_else(|| Error::malformed("disk image signature", "no CodeDirectory"))?;
    let ty = *cd.get(37).ok_or_else(|| Error::malformed("disk image signature", "truncated CodeDirectory"))?;
    let digest = match ty {
        1 => crate::crypto::sha1(&cd).to_vec(),
        _ => sha256(&cd).to_vec(),
    };
    Ok((ty, digest))
}
