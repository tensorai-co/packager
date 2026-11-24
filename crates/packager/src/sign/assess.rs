//! A Gatekeeper-style assessment (what `spctl -a` decides for downloaded software): is this
//! `.app`, `.dmg` or `.pkg` signed with a Developer ID chained to Apple's root, securely
//! timestamped, hardened (for code) and notarized? Run it before shipping so a build fails
//! instead of a user's first launch.
//!
//! Each rule is reported separately. The notarization ticket is checked against the code
//! offline (stapled) or, when a transport is given, online; Apple's signature over the ticket
//! itself is not checked.

use std::path::Path;

use crate::Result;
use crate::crypto::der;
use crate::crypto::x509::Certificate;
use crate::error::IoContext;
use crate::format::plist::Value;
use crate::sign::apple::{CS_ADHOC, CS_RUNTIME, verify_macho};
use crate::sign::requirement::{APPLE_ROOT_SHA1, apple_oids};
use crate::staple::{self, Kind, Lookup};
use crate::transport::Transport;

/// Leaf: Developer ID Installer.
pub const DEVELOPER_ID_INSTALLER_LEAF: &str = "1.2.840.113635.100.6.1.14";

/// One rule's outcome.
#[derive(Debug, Clone)]
pub struct Check {
    /// What was checked.
    pub name: &'static str,
    /// Whether it passed.
    pub ok: bool,
    /// What was found.
    pub detail: String,
}

/// The outcome of [`assess`].
#[derive(Debug, Clone)]
pub struct Assessment {
    /// What was assessed.
    pub kind: Kind,
    /// Every rule, in order.
    pub checks: Vec<Check>,
}

impl Assessment {
    /// Whether Gatekeeper would accept it: every rule passed.
    pub fn accepted(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
    /// The rules that failed.
    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| !c.ok)
    }
}

fn has_ext(c: &Certificate, oid: &str) -> bool {
    der::oid_from_str(oid).map(|o| c.extension(&o).is_some()).unwrap_or(false)
}

/// Whether `chain` (leaf first) links up, each certificate signed by the next, to one of
/// Apple's root CAs.
pub fn chains_to_apple_root(chain: &[Certificate]) -> bool {
    let Some(anchor) = chain.last() else { return false };
    if !APPLE_ROOT_SHA1.contains(&crate::crypto::hex(&anchor.sha1()).as_str()) || !anchor.is_signed_by(anchor) {
        return false;
    }
    chain.windows(2).all(|w| w[0].is_signed_by(&w[1]))
}

/// `leaf`, then its issuer, and so on, from `pool` (CMS sets aren't ordered).
fn ordered_chain(leaf: &Certificate, pool: &[Certificate]) -> Vec<Certificate> {
    let mut chain = vec![leaf.clone()];
    while chain.len() <= pool.len() {
        let cur = chain.last().unwrap_or(leaf);
        if cur.is_self_issued() {
            break;
        }
        match pool.iter().find(|c| c.subject_raw == cur.issuer_raw) {
            Some(i) => chain.push(i.clone()),
            None => break,
        }
    }
    chain
}

fn cms_chain(cms: &crate::sign::cms::Verified) -> Vec<Certificate> {
    ordered_chain(&cms.signer, &cms.certificates)
}

struct Checks(Vec<Check>);

impl Checks {
    fn add(&mut self, name: &'static str, ok: bool, detail: impl Into<String>) {
        self.0.push(Check { name, ok, detail: detail.into() });
    }
    fn certificate(&mut self, chain: &[Certificate], leaf_oid: &str, what: &str) {
        let leaf = chain.first();
        let cn = leaf.and_then(|c| c.common_name()).unwrap_or("?").to_string();
        let is_devid = leaf.is_some_and(|c| has_ext(c, leaf_oid));
        self.add("developer id", is_devid, if is_devid { cn.clone() } else { format!("{cn} isn't a {what} certificate") });
        let anchored = chains_to_apple_root(chain);
        self.add("apple anchor", anchored, if anchored { "chain verifies to Apple Root CA".to_string() } else { "the chain doesn't verify to an Apple root CA".to_string() });
    }
    fn timestamp(&mut self, ts: Option<&str>) {
        self.add("secure timestamp", ts.is_some(), ts.map(|t| format!("timestamped {t}")).unwrap_or_else(|| "no secure timestamp (sign with --timestamp)".into()));
    }
}

/// Assesses an `.app`, `.dmg` or `.pkg`. With `online`, a missing staple falls back to looking
/// the ticket up at Apple, as Gatekeeper does when the Mac is online.
pub fn assess(path: impl AsRef<Path>, online: Option<&dyn Transport>) -> Result<Assessment> {
    let p = path.as_ref();
    let (kind, record) = staple::ticket_record(p)?;
    let mut c = Checks(Vec::new());
    match kind {
        Kind::Bundle => {
            match crate::sign::bundle::verify_bundle(p) {
                Ok(n) => c.add("signature", true, format!("valid, {n} sealed entries match")),
                Err(e) => c.add("signature", false, e.to_string()),
            }
            let info_path = p.join("Contents/Info.plist");
            let info = Value::parse(&std::fs::read(&info_path).at(&info_path)?)?;
            let exe_name = info.as_dict().and_then(|d| d.get_str("CFBundleExecutable")).map(String::from).or_else(|| p.file_stem().map(|n| n.to_string_lossy().into_owned())).unwrap_or_default();
            let exe = p.join("Contents/MacOS").join(&exe_name);
            let sigs = verify_macho(&std::fs::read(&exe).at(&exe)?)?;
            let s = &sigs[0];
            match &s.cms {
                Some(cms) if s.flags & CS_ADHOC == 0 => {
                    c.certificate(&cms_chain(cms), apple_oids::DEVELOPER_ID_LEAF, "Developer ID Application");
                    c.timestamp(cms.timestamp.as_deref());
                }
                _ => c.add("developer id", false, "ad hoc signature (no certificate)"),
            }
            let runtime = sigs.iter().all(|s| s.flags & CS_RUNTIME != 0);
            c.add("hardened runtime", runtime, if runtime { "enabled on the main executable" } else { "the main executable doesn't opt into the hardened runtime (-o runtime)" });
            let debuggable = sigs.iter().any(|s| {
                s.entitlements.as_ref().and_then(|e| Value::parse(e).ok()).and_then(|v| v.as_dict().and_then(|d| d.get("com.apple.security.get-task-allow")).cloned()) == Some(Value::Bool(true))
            });
            c.add("no get-task-allow", !debuggable, if debuggable { "com.apple.security.get-task-allow is set: notarization rejects debuggable code" } else { "not debuggable" });
        }
        Kind::DiskImage => {
            let data = std::fs::read(p).at(p)?;
            match crate::sign::disk_image::verify_disk_image(&data) {
                Ok(sig) => {
                    c.add("signature", true, "valid image signature");
                    match &sig.cms {
                        Some(cms) => {
                            c.certificate(&cms_chain(cms), apple_oids::DEVELOPER_ID_LEAF, "Developer ID Application");
                            c.timestamp(cms.timestamp.as_deref());
                        }
                        None => c.add("developer id", false, "ad hoc signature (no certificate)"),
                    }
                }
                Err(e) => c.add("signature", false, e.to_string()),
            }
        }
        Kind::FlatPackage => {
            let data = std::fs::read(p).at(p)?;
            match crate::sign::installer::verify_pkg(&data) {
                Ok(Some(sig)) => {
                    c.add("signature", true, "valid installer signature");
                    let chain = sig.cms.as_ref().map(cms_chain).unwrap_or_else(|| ordered_chain(sig.leaf(), &sig.chain));
                    c.certificate(&chain, DEVELOPER_ID_INSTALLER_LEAF, "Developer ID Installer");
                    c.timestamp(sig.cms.as_ref().and_then(|m| m.timestamp.as_deref()));
                }
                Ok(None) => c.add("signature", false, "no installer signature (sign with a Developer ID Installer identity)"),
                Err(e) => c.add("signature", false, e.to_string()),
            }
        }
    }
    match staple::validate(p) {
        Ok(()) => c.add("notarized", true, "ticket stapled"),
        Err(stapled_err) => match online {
            Some(t) => match staple::lookup(t, &record) {
                Ok(Lookup::Ticket(_)) => c.add("notarized", true, "ticket found online (not stapled: offline Macs will warn)"),
                Ok(Lookup::Missing(why)) => c.add("notarized", false, format!("no ticket stapled or at Apple ({why})")),
                Err(e) => c.add("notarized", false, format!("no ticket stapled; online check failed: {e}")),
            },
            None => c.add("notarized", false, stapled_err.to_string()),
        },
    }
    Ok(Assessment { kind, checks: c.0 })
}
