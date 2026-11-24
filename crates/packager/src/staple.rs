//! Stapling (what `xcrun stapler` does): fetch the notarization ticket Apple issued for a
//! piece of code from Apple's ticket service, and attach it so Gatekeeper can check
//! notarization offline.
//!
//! Tickets are filed under `2/<hash type>/<first 20 bytes of the hash, hex>`, hash type 1 being
//! SHA-1 and 2 SHA-256:
//! - App bundles: the main executable's primary CodeDirectory hash. The ticket is written to
//!   `Contents/CodeResources`.
//! - Disk images: the image's CodeDirectory hash. The ticket goes into the image's code
//!   signature SuperBlob, slot `0x10002`, as a wrapper blob.
//! - Flat packages: the XAR TOC checksum (SHA-1). The ticket is appended after the archive
//!   between two `t8lr` records.

use std::path::Path;

use crate::crypto::hex;
use crate::error::IoContext;
use crate::format::base64;
use crate::format::json::Json;
use crate::format::{macho, xar};
use crate::transport::Transport;
use crate::{Error, Result};

/// Apple's ticket-delivery endpoint (CloudKit public database).
pub const TICKET_LOOKUP_URL: &str = "https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup";

/// Tickets start with this magic.
pub const TICKET_MAGIC: &[u8; 4] = b"s8ch";

/// The code-signature slot a disk image's ticket is stapled in.
pub const CSSLOT_TICKET: u32 = 0x10002;

/// A ticket record name: `2/<hash type>/<first 20 bytes of digest, lowercase hex>`.
pub fn record_name(hash_type: u8, digest: &[u8]) -> String {
    format!("2/{hash_type}/{}", hex(&digest[..20.min(digest.len())]))
}

/// What a ticket lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The ticket.
    Ticket(Vec<u8>),
    /// No ticket: Apple's error code and reason (`NOT_FOUND` when not notarized, or not yet).
    Missing(String),
}

/// Fetches the ticket filed under `record`.
pub fn lookup(transport: &dyn Transport, record: &str) -> Result<Lookup> {
    let body = Json::object(vec![("records", Json::Array(vec![Json::object(vec![("recordName", Json::str(record))])]))]);
    let resp = transport.post(TICKET_LOOKUP_URL, "application/json", body.to_string_compact().as_bytes())?;
    let j = Json::parse(&String::from_utf8_lossy(&resp))?;
    let rec = j
        .get("records")
        .and_then(Json::as_array)
        .and_then(|r| r.iter().find(|x| x.get("recordName").and_then(Json::as_str) == Some(record)).or(r.first()))
        .ok_or_else(|| Error::Other("ticket lookup: no records in response".into()))?;
    if let Some(code) = rec.get("serverErrorCode").and_then(Json::as_str) {
        let reason = rec.get("reason").and_then(Json::as_str).unwrap_or("");
        return Ok(Lookup::Missing(if reason.is_empty() { code.to_string() } else { format!("{code}: {reason}") }));
    }
    let field = rec.path(&["fields", "signedTicket"]).ok_or_else(|| Error::Other("ticket lookup: no signedTicket in record".into()))?;
    if let Some(t) = field.get("type").and_then(Json::as_str)
        && t != "BYTES"
    {
        return Err(Error::Other(format!("ticket lookup: signedTicket has type {t}, expected BYTES")));
    }
    let value = field.get("value").and_then(Json::as_str).ok_or_else(|| Error::Other("ticket lookup: signedTicket has no value".into()))?;
    let ticket = base64::decode(value)?;
    if !ticket.starts_with(TICKET_MAGIC) {
        return Err(Error::Other("ticket lookup: response isn't a notarization ticket".into()));
    }
    Ok(Lookup::Ticket(ticket))
}

/// Whether `ticket` is a notarization ticket that names `digest` (its first 20 bytes). Tickets
/// list the hashes of every piece of code they cover.
pub fn ticket_covers(ticket: &[u8], digest: &[u8]) -> bool {
    let id = &digest[..20.min(digest.len())];
    ticket.starts_with(TICKET_MAGIC) && ticket.windows(id.len()).any(|w| w == id)
}

/// The kind of thing being stapled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An `.app` (or other bundle) directory.
    Bundle,
    /// A UDIF disk image.
    DiskImage,
    /// A flat package (XAR).
    FlatPackage,
}

fn is_disk_image(data: &[u8]) -> bool {
    data.len() >= 512 && &data[data.len() - 512..data.len() - 508] == b"koly"
}

/// The hash type and primary CodeDirectory hash of a Mach-O file's first slice.
pub fn macho_code_directory_hash(data: &[u8]) -> Result<(u8, Vec<u8>)> {
    let bad = |m: &str| Error::malformed("code signature", m);
    let slice = macho::slices(data)?.into_iter().next().ok_or_else(|| bad("no slices"))?;
    let img = macho::Image::parse(&slice.data)?;
    let (_, off, size) = img.code_signature.ok_or_else(|| bad("not signed"))?;
    let sb = slice.data.get(off as usize..(off + size) as usize).ok_or_else(|| bad("signature out of range"))?;
    let be = |p: usize| -> Result<u32> { sb.get(p..p + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]])).ok_or_else(|| bad("truncated")) };
    for i in 0..be(8)? as usize {
        if be(12 + 8 * i)? == 0 {
            let o = be(16 + 8 * i)? as usize;
            let cd = sb.get(o..o + be(o + 4)? as usize).ok_or_else(|| bad("CodeDirectory out of range"))?;
            let ty = *cd.get(37).ok_or_else(|| bad("truncated CodeDirectory"))?;
            let digest = if ty == 1 { crate::crypto::sha1(cd).to_vec() } else { crate::crypto::sha256(cd).to_vec() };
            return Ok((ty, digest));
        }
    }
    Err(bad("no CodeDirectory"))
}

/// A bundle's main executable.
fn bundle_executable(bundle: &Path) -> Result<std::path::PathBuf> {
    let info_path = bundle.join("Contents/Info.plist");
    let info = crate::format::plist::Value::parse(&std::fs::read(&info_path).at(&info_path)?)?;
    // Without CFBundleExecutable, CoreFoundation uses the bundle's own name.
    let exe = match info.as_dict().and_then(|d| d.get_str("CFBundleExecutable")) {
        Some(e) => e.to_string(),
        None => bundle.file_stem().map(|n| n.to_string_lossy().into_owned()).ok_or_else(|| Error::invalid("staple", "CFBundleExecutable", "missing from Info.plist"))?,
    };
    Ok(bundle.join("Contents/MacOS").join(exe))
}

/// What a path is, and the record name its ticket is filed under.
pub fn ticket_record(path: impl AsRef<Path>) -> Result<(Kind, String)> {
    let p = path.as_ref();
    if p.is_dir() {
        let exe = bundle_executable(p)?;
        let (ty, d) = macho_code_directory_hash(&std::fs::read(&exe).at(&exe)?)?;
        return Ok((Kind::Bundle, record_name(ty, &d)));
    }
    let data = std::fs::read(p).at(p)?;
    if is_disk_image(&data) {
        let (ty, d) = crate::sign::disk_image::code_directory_hash(&data).map_err(|_| Error::invalid("staple", p.display().to_string(), "the disk image isn't signed; sign it before notarizing"))?;
        return Ok((Kind::DiskImage, record_name(ty, &d)));
    }
    if data.starts_with(b"xar!") {
        return Ok((Kind::FlatPackage, record_name(1, &xar::toc_checksum(&data)?)));
    }
    if macho::is_macho(&data) {
        return Err(Error::invalid("staple", p.display().to_string(), "Mach-O files can't be stapled (put them in a .dmg or .pkg, or rely on the online check)"));
    }
    Err(Error::invalid("staple", p.display().to_string(), "isn't an app bundle, disk image or flat package"))
}

/// Attaches `ticket` to an `.app`, `.dmg` or `.pkg` in memory or on disk.
pub fn attach(path: impl AsRef<Path>, ticket: &[u8]) -> Result<()> {
    let p = path.as_ref();
    if !ticket.starts_with(TICKET_MAGIC) {
        return Err(Error::Other("not a notarization ticket".into()));
    }
    if p.is_dir() {
        let dest = p.join("Contents/CodeResources");
        return std::fs::write(&dest, ticket).at(&dest);
    }
    let data = std::fs::read(p).at(p)?;
    let out = if is_disk_image(&data) {
        staple_disk_image(&data, ticket)?
    } else if data.starts_with(b"xar!") {
        staple_flat_package(&data, ticket)
    } else {
        return Err(Error::invalid("staple", p.display().to_string(), "isn't an app bundle, disk image or flat package"));
    };
    std::fs::write(p, out).at(p)
}

/// Fetches and staples the ticket for an `.app`, `.dmg` or `.pkg`. `Ok(Lookup::Missing)` when
/// Apple has no ticket (yet); the file is left alone.
pub fn staple(transport: &dyn Transport, path: impl AsRef<Path>) -> Result<Lookup> {
    let p = path.as_ref();
    let (_, record) = ticket_record(p)?;
    let found = lookup(transport, &record)?;
    if let Lookup::Ticket(t) = &found {
        attach(p, t)?;
    }
    Ok(found)
}

/// Adds (or replaces) the ticket in a signed disk image's SuperBlob and updates the trailer.
pub fn staple_disk_image(image: &[u8], ticket: &[u8]) -> Result<Vec<u8>> {
    crate::sign::disk_image::replace_blob(image, CSSLOT_TICKET, Some(ticket))
}

/// Appends the ticket to a flat package (replacing a previous one): a terminator record, the
/// ticket, then a ticket record.
pub fn staple_flat_package(data: &[u8], ticket: &[u8]) -> Vec<u8> {
    let base = xar::without_ticket(data);
    let mut out = Vec::with_capacity(base.len() + ticket.len() + 32);
    out.extend_from_slice(base);
    out.extend_from_slice(&xar::ticket_record(1, 0));
    out.extend_from_slice(ticket);
    out.extend_from_slice(&xar::ticket_record(2, ticket.len() as u32));
    out
}

/// The stapled ticket of an `.app`, `.dmg` or `.pkg`, if any.
pub fn stapled_ticket(path: impl AsRef<Path>) -> Result<Option<Vec<u8>>> {
    let p = path.as_ref();
    if p.is_dir() {
        let t = p.join("Contents/CodeResources");
        return Ok(if t.is_file() { Some(std::fs::read(&t).at(&t)?) } else { None });
    }
    let data = std::fs::read(p).at(p)?;
    if is_disk_image(&data) {
        return match crate::sign::disk_image::blob(&data, CSSLOT_TICKET) {
            Ok(t) => Ok(t),
            Err(_) => Ok(None), // unsigned images can't carry a ticket
        };
    }
    if data.starts_with(b"xar!") {
        return Ok(xar::ticket_span(&data).map(|(_, r)| data[r].to_vec()));
    }
    Ok(None)
}

/// Checks offline that a ticket is stapled and names this code (what `stapler validate`
/// checks, minus Apple's signature over the ticket itself).
pub fn validate(path: impl AsRef<Path>) -> Result<()> {
    let p = path.as_ref();
    let ticket = stapled_ticket(p)?.ok_or_else(|| Error::Other(format!("{}: no ticket stapled", p.display())))?;
    let (_, record) = ticket_record(p)?;
    let digest = crate::crypto::unhex(record.rsplit('/').next().unwrap_or_default())?;
    if ticket_covers(&ticket, &digest) {
        Ok(())
    } else {
        Err(Error::Other(format!("{}: the stapled ticket is for different code", p.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::xar::XarEntry;

    fn fake_ticket(digest: &[u8]) -> Vec<u8> {
        let mut t = TICKET_MAGIC.to_vec();
        t.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(&digest[..20]);
        t.extend_from_slice(&[0xee; 40]);
        t
    }

    #[test]
    fn flat_package_round_trip() {
        let dir = std::env::temp_dir().join(format!("packager-staple-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.pkg");
        let x = xar::write(&[XarEntry::file("Distribution", b"<d/>".to_vec())], 0).unwrap();
        std::fs::write(&p, &x).unwrap();
        let (kind, record) = ticket_record(&p).unwrap();
        assert_eq!(kind, Kind::FlatPackage);
        assert_eq!(record, format!("2/1/{}", hex(&xar::toc_checksum(&x).unwrap())));
        assert!(validate(&p).is_err());
        let t = fake_ticket(&xar::toc_checksum(&x).unwrap());
        attach(&p, &t).unwrap();
        attach(&p, &t).unwrap(); // re-stapling replaces, not appends
        let stapled = std::fs::read(&p).unwrap();
        assert_eq!(stapled.len(), x.len() + t.len() + 32);
        assert_eq!(&stapled[stapled.len() - 16..stapled.len() - 12], b"t8lr");
        assert_eq!(stapled_ticket(&p).unwrap(), Some(t));
        validate(&p).unwrap();
        xar::read(&stapled).unwrap();
        // A ticket for other code is rejected.
        attach(&p, &fake_ticket(&[9; 20])).unwrap();
        assert!(validate(&p).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_names() {
        assert_eq!(record_name(2, &[0xab; 32]), format!("2/2/{}", "ab".repeat(20)));
    }
}
