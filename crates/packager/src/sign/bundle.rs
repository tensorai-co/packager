//! Signing bundles (`.app`, `.framework`, `.appex`, `.xpc`…) inside out: nested bundles and
//! binaries first, then `_CodeSignature/CodeResources` sealing every resource, then the main
//! executable, whose signature binds `Info.plist` and `CodeResources`.

use std::path::{Path, PathBuf};

use crate::crypto::{sha1, sha256};
use crate::error::IoContext;
use crate::format::macho::{self, CPU_TYPE_ARM64};
use crate::format::plist::{Dict, Value};
use crate::sign::apple::{sign_macho, CodeSignOptions, Signed};
use crate::sign::AppleIdentity;
use crate::util::{slash_path, walk, EntryKind};
use crate::{Error, Result};

/// Directories whose contents are nested code rather than resources (codesign's `rules2`).
const NESTED_DIRS: [&str; 7] = ["Frameworks", "SharedFrameworks", "PlugIns", "Plug-ins", "XPCServices", "Helpers", "MacOS"];
const NESTED_LIBRARY_DIRS: [&str; 3] = ["Library/Automator", "Library/Spotlight", "Library/LoginItems"];
const BUNDLE_EXTENSIONS: [&str; 8] = ["app", "framework", "appex", "xpc", "bundle", "plugin", "systemextension", "qlgenerator"];

/// Options for signing a bundle.
#[derive(Debug, Clone)]
pub struct BundleSignOptions {
    /// Ad hoc or certificate-backed.
    pub identity: AppleIdentity,
    /// Hardened runtime on executables (frameworks and dylibs don't opt in).
    pub hardened_runtime: bool,
    /// Entitlements for the outermost bundle's main executable only.
    pub entitlements: Option<Vec<u8>>,
    /// Explicit requirements for the outermost bundle (`codesign -r`).
    pub requirements: Option<String>,
    /// RFC 3161 server for certificate signatures; `None` skips timestamping.
    pub timestamp_url: Option<String>,
}

impl BundleSignOptions {
    /// Ad-hoc signing with no runtime options.
    pub fn ad_hoc() -> Self {
        BundleSignOptions { identity: AppleIdentity::AdHoc, hardened_runtime: false, entitlements: None, requirements: None, timestamp_url: None }
    }

    /// Options for one Mach-O file inside the bundle.
    fn code(&self, identifier: impl Into<String>) -> CodeSignOptions {
        let mut o = CodeSignOptions::ad_hoc(identifier);
        o.identity = self.identity.clone();
        o.timestamp_url = self.timestamp_url.clone();
        o
    }
}

/// Where a bundle keeps its parts.
struct Layout {
    /// The directory `CodeResources` paths are relative to (`Contents`, or `Versions/A`).
    content: PathBuf,
    info_plist: PathBuf,
    executable: Option<PathBuf>,
    identifier: String,
}

fn layout(bundle: &Path) -> Result<Layout> {
    let (content, info_plist, exe_dir) = if bundle.join("Contents").is_dir() {
        let c = bundle.join("Contents");
        (c.clone(), c.join("Info.plist"), c.join("MacOS"))
    } else if bundle.join("Versions").is_dir() {
        let current = bundle.join("Versions/Current");
        let target = std::fs::read_link(&current).at(&current)?;
        let c = bundle.join("Versions").join(target);
        (c.clone(), c.join("Resources/Info.plist"), c.clone())
    } else {
        (bundle.to_path_buf(), bundle.join("Info.plist"), bundle.to_path_buf())
    };
    let bytes = std::fs::read(&info_plist).at(&info_plist)?;
    let info = Value::parse(&bytes)?;
    let info = info.as_dict().ok_or_else(|| Error::malformed("plist", "Info.plist root isn't a dictionary"))?;
    let identifier = info
        .get_str("CFBundleIdentifier")
        .ok_or_else(|| Error::invalid("app", "CFBundleIdentifier", format!("is missing from {}", info_plist.display())))?
        .to_string();
    let executable = info.get_str("CFBundleExecutable").map(|e| exe_dir.join(e));
    Ok(Layout { content, info_plist, executable, identifier })
}

/// Whether `rel` (relative to the content directory) is in a nested-code location.
fn is_nested_location(rel: &str) -> bool {
    !rel.contains('/')
        || NESTED_DIRS.iter().any(|d| rel.starts_with(d) && rel.as_bytes().get(d.len()) == Some(&b'/'))
        || NESTED_LIBRARY_DIRS.iter().any(|d| rel.starts_with(d) && rel.as_bytes().get(d.len()) == Some(&b'/'))
}

fn is_bundle_dir(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| BUNDLE_EXTENSIONS.contains(&e))
        && (path.join("Contents/Info.plist").is_file() || path.join("Versions/Current").exists() || path.join("Info.plist").is_file())
}

/// Picks the cdhash `codesign` records for nested code: the arm64 slice if there is one.
fn nested_record(signed: &Signed, cputypes: &[u32]) -> Dict {
    let mut order: Vec<usize> = (0..signed.cdhashes.len()).collect();
    order.sort_by_key(|&i| cputypes.get(i) != Some(&CPU_TYPE_ARM64));
    // Certificate-signed nested code is recorded by its designated requirement, ad-hoc code by
    // its cdhashes.
    let req = match &signed.designated {
        Some(dr) => dr.clone(),
        None => order.iter().map(|&i| format!("cdhash H\"{}\"", crate::crypto::hex(&signed.cdhashes[i][..20]))).collect::<Vec<_>>().join(" or "),
    };
    Dict::new().with("cdhash", Value::Data(signed.cdhashes[order[0]][..20].to_vec())).with("requirement", req)
}

fn cputypes(data: &[u8]) -> Vec<u32> {
    macho::slices(data).map(|s| s.iter().map(|x| x.cputype).collect()).unwrap_or_default()
}

/// Signs a Mach-O file in place.
fn sign_file(path: &Path, opts: &CodeSignOptions) -> Result<(Signed, Vec<u32>)> {
    let data = std::fs::read(path).at(path)?;
    let types = cputypes(&data);
    let signed = sign_macho(&data, opts)?;
    std::fs::write(path, &signed.data).at(path)?;
    Ok((signed, types))
}

/// Signs `bundle` and everything nested in it. Returns the main executable's signature.
pub fn sign_bundle(bundle: &Path, opts: &BundleSignOptions) -> Result<Signed> {
    sign_bundle_inner(bundle, opts, true).map(|(s, _)| s)
}

fn sign_bundle_inner(bundle: &Path, opts: &BundleSignOptions, outermost: bool) -> Result<(Signed, Vec<u32>)> {
    let lay = layout(bundle)?;
    let exe = lay.executable.clone().ok_or_else(|| {
        Error::invalid("app", "CFBundleExecutable", format!("is missing from {}", lay.info_plist.display()))
    })?;
    let entries = walk(&lay.content)?;
    let sig_dir = lay.content.join("_CodeSignature");

    // 1. Nested bundles, outermost-first discovery, signed recursively (so inside out).
    let mut nested_bundles: Vec<PathBuf> = Vec::new();
    for e in &entries {
        if e.kind != EntryKind::Dir || !is_bundle_dir(&e.path) {
            continue;
        }
        let rel = slash_path(&e.rel);
        if !is_nested_location(&rel) || nested_bundles.iter().any(|b| e.path.starts_with(b)) {
            continue;
        }
        nested_bundles.push(e.path.clone());
    }
    let mut records: Vec<(String, Value)> = Vec::new();
    for b in &nested_bundles {
        let (signed, types) = sign_bundle_inner(b, opts, false)?;
        let rel = slash_path(b.strip_prefix(&lay.content).unwrap_or(b));
        records.push((rel, Value::Dict(nested_record(&signed, &types))));
    }

    // 2. Loose Mach-O files in nested locations, then 3. resources.
    let mut files = Dict::new();
    let mut files2 = Dict::new();
    for e in &entries {
        if e.path.starts_with(&sig_dir) || e.path == exe || e.path == lay.info_plist {
            continue;
        }
        if nested_bundles.iter().any(|b| e.path.starts_with(b)) {
            continue;
        }
        let rel = slash_path(&e.rel);
        let name = e.rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match &e.kind {
            EntryKind::Dir => {}
            EntryKind::Symlink(target) => {
                if name != ".DS_Store" {
                    files2.insert(rel, Dict::new().with("symlink", target.to_string_lossy().into_owned()));
                }
            }
            EntryKind::File { .. } => {
                let data = std::fs::read(&e.path).at(&e.path)?;
                if is_nested_location(&rel) && macho::is_macho(&data) {
                    let stem = e.rel.file_stem().and_then(|s| s.to_str()).unwrap_or("code").to_string();
                    let mut o = opts.code(stem);
                    let is_exe = macho::Image::parse(macho::slices(&data)?[0].data.as_slice()).map(|i| i.filetype == macho::MH_EXECUTE).unwrap_or(false);
                    o.hardened_runtime = opts.hardened_runtime && is_exe;
                    let (signed, types) = sign_file(&e.path, &o)?;
                    records.push((rel, Value::Dict(nested_record(&signed, &types))));
                    continue;
                }
                let top_omit = rel == "Info.plist" || rel == "PkgInfo";
                let lproj = rel.starts_with("Resources/") && rel.contains(".lproj/");
                let base_lproj = rel.starts_with("Resources/Base.lproj/");
                let locversion = lproj && rel.ends_with(".lproj/locversion.plist");
                let optional = lproj && !base_lproj;
                // v1 rules: only Resources/ and version.plist.
                if (rel.starts_with("Resources/") || rel == "version.plist") && !locversion {
                    let h = Value::Data(sha1(&data).to_vec());
                    files.insert(rel.clone(), if optional { Value::Dict(Dict::new().with("hash", h).with("optional", true)) } else { h });
                }
                if top_omit || name == ".DS_Store" || locversion {
                    continue;
                }
                let mut d = Dict::new().with("hash2", Value::Data(sha256(&data).to_vec()));
                if optional {
                    d.insert("optional", true);
                }
                files2.insert(rel, d);
            }
        }
    }
    for (rel, rec) in records {
        files2.insert(rel, rec);
    }
    files.sort_recursive();
    files2.sort_recursive();
    let mut root = Dict::new().with("files", files).with("files2", files2).with("rules", rules()).with("rules2", rules2());
    root.sort_recursive();
    let code_resources = Value::Dict(root).to_xml().into_bytes();
    std::fs::create_dir_all(&sig_dir).at(&sig_dir)?;
    let cr_path = sig_dir.join("CodeResources");
    std::fs::write(&cr_path, &code_resources).at(&cr_path)?;

    // 4. The main executable, binding Info.plist and CodeResources.
    let info = std::fs::read(&lay.info_plist).at(&lay.info_plist)?;
    let exe_data = std::fs::read(&exe).at(&exe)?;
    let is_exe = macho::slices(&exe_data)
        .ok()
        .and_then(|s| macho::Image::parse(&s[0].data).ok())
        .is_some_and(|i| i.filetype == macho::MH_EXECUTE);
    let mut o = opts.code(lay.identifier.clone());
    o.hardened_runtime = opts.hardened_runtime && is_exe;
    o.entitlements = if outermost { opts.entitlements.clone() } else { None };
    o.requirements = if outermost { opts.requirements.clone() } else { None };
    o.info_plist = Some(info);
    o.code_resources = Some(code_resources);
    sign_file(&exe, &o)
}

/// Checks a signed bundle without native tools: the main executable's signature, its binding of
/// `Info.plist` and `CodeResources`, every sealed resource hash, and nested code recursively.
/// Returns the number of sealed entries checked.
pub fn verify_bundle(bundle: &Path) -> Result<usize> {
    let bad = |m: String| Error::malformed("bundle signature", m);
    let lay = layout(bundle)?;
    let exe = lay.executable.clone().ok_or_else(|| bad("no CFBundleExecutable".into()))?;
    let sigs = crate::sign::apple::verify_macho(&std::fs::read(&exe).at(&exe)?)?;
    let cr_path = lay.content.join("_CodeSignature/CodeResources");
    let cr = std::fs::read(&cr_path).at(&cr_path)?;
    let info = std::fs::read(&lay.info_plist).at(&lay.info_plist)?;
    for s in &sigs {
        let slot = |n: usize| s.special.iter().find(|(k, _)| *k == n).map(|(_, h)| *h);
        if slot(1) != Some(sha256(&info)) {
            return Err(bad(format!("{}: Info.plist changed after signing", s.arch)));
        }
        if slot(3) != Some(sha256(&cr)) {
            return Err(bad(format!("{}: CodeResources changed after signing", s.arch)));
        }
    }
    let v = Value::parse(&cr)?;
    let files2 = v.as_dict().and_then(|d| d.get("files2")).and_then(|f| f.as_dict()).ok_or_else(|| bad("no files2".into()))?;
    let mut checked = 0;
    for (rel, rec) in files2.iter() {
        let path = lay.content.join(rel);
        let rec = rec.as_dict().ok_or_else(|| bad(format!("{rel}: bad record")))?;
        if let Some(Value::Data(want)) = rec.get("hash2") {
            let data = std::fs::read(&path).map_err(|e| bad(format!("{rel}: {e}")))?;
            if sha256(&data)[..] != want[..] {
                return Err(bad(format!("{rel}: modified after signing")));
            }
        } else if let Some(target) = rec.get_str("symlink") {
            let t = std::fs::read_link(&path).map_err(|e| bad(format!("{rel}: {e}")))?;
            if t.to_string_lossy() != target {
                return Err(bad(format!("{rel}: symlink target changed")));
            }
        } else if let Some(Value::Data(want)) = rec.get("cdhash") {
            let hashes: Vec<[u8; 32]> = if path.is_dir() {
                verify_bundle(&path)?;
                let l = layout(&path)?;
                let e = l.executable.ok_or_else(|| bad(format!("{rel}: nested bundle has no executable")))?;
                crate::sign::apple::verify_macho(&std::fs::read(&e).at(&e)?)?.iter().map(|s| s.cdhash).collect()
            } else {
                crate::sign::apple::verify_macho(&std::fs::read(&path).at(&path)?)?.iter().map(|s| s.cdhash).collect()
            };
            if !hashes.iter().any(|h| h[..20] == want[..]) {
                return Err(bad(format!("{rel}: nested code changed after sealing")));
            }
        }
        checked += 1;
    }
    Ok(checked)
}

fn weighted(weight: i64, extra: &[(&str, bool)]) -> Value {
    let mut d = Dict::new();
    for (k, v) in extra {
        d.insert(*k, *v);
    }
    d.insert("weight", Value::Real(weight as f64));
    Value::Dict(d)
}

fn rules() -> Dict {
    Dict::new()
        .with("^Resources/", true)
        .with("^Resources/.*\\.lproj/", weighted(1000, &[("optional", true)]))
        .with("^Resources/.*\\.lproj/locversion.plist$", weighted(1100, &[("omit", true)]))
        .with("^Resources/Base\\.lproj/", weighted(1010, &[]))
        .with("^version.plist$", true)
}

fn rules2() -> Dict {
    Dict::new()
        .with(".*\\.dSYM($|/)", weighted(11, &[]))
        .with("^(.*/)?\\.DS_Store$", weighted(2000, &[("omit", true)]))
        .with(
            "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/",
            weighted(10, &[("nested", true)]),
        )
        .with("^.*", true)
        .with("^Info\\.plist$", weighted(20, &[("omit", true)]))
        .with("^PkgInfo$", weighted(20, &[("omit", true)]))
        .with("^Resources/", weighted(20, &[]))
        .with("^Resources/.*\\.lproj/", weighted(1000, &[("optional", true)]))
        .with("^Resources/.*\\.lproj/locversion.plist$", weighted(1100, &[("omit", true)]))
        .with("^Resources/Base\\.lproj/", weighted(1010, &[]))
        .with("^[^/]+$", weighted(10, &[("nested", true)]))
        .with("^embedded\\.provisionprofile$", weighted(20, &[]))
        .with("^version\\.plist$", weighted(20, &[]))
}
