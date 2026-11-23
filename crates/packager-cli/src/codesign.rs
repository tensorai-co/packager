//! `packager codesign …`: Apple's `codesign` command line on top of the library — sign (`-s`),
//! verify (`-v`, `-R`) and display (`-d`, `-r-`, `--entitlements -`) — so build scripts can
//! switch over without changing their arguments. `packager sign` is the same signer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use packager::crypto::x509::Certificate;
use packager::format::macho;
use packager::format::plist::{Dict, Value};
use packager::sign::apple::{sign_macho, verify_macho, CodeSignOptions, SliceSignature, CS_ADHOC, CS_RUNTIME};
use packager::sign::bundle::{sign_bundle, verify_bundle, BundleSignOptions};
use packager::sign::disk_image::{sign_disk_image, verify_disk_image, DiskImageSignOptions};
use packager::sign::requirement::{self, RequirementType};
use packager::sign::{timestamp, AppleIdentity, KeySigner, Signer};

pub const CODESIGN_USAGE: &str = "\
packager codesign — the codesign command line, implemented by packager

    packager codesign -s IDENTITY [-f] [-i ID] [-o runtime] [--entitlements FILE]
                      [-r REQS] [--timestamp[=URL|none]] [--deep] PATH...
    packager codesign -v [-v…] [--strict] [-R REQUIREMENT] PATH...
    packager codesign -d [-v…] [-r-] [--entitlements -] PATH...

IDENTITY is `-` (ad hoc), a keychain identity (common name, unique part of it, or SHA-1),
`p12:FILE` (password from PACKAGER_P12_PASSWORD or --password), or `pem:CERT,KEY`.
REQS is a file path, or `=TEXT` for inline requirement text.";

#[derive(Default)]
struct Opts {
    sign: Option<String>,
    verify: u32,
    display: bool,
    identifier: Option<String>,
    runtime: bool,
    entitlements: Option<String>,
    requirements: Option<String>,
    test_requirement: Option<String>,
    timestamp: Option<Option<String>>,
    password: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    paths: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    let take = |i: &mut usize, rest: &str, name: &str| -> Result<String, String> {
        if !rest.is_empty() {
            return Ok(rest.trim_start_matches('=').to_string());
        }
        *i += 1;
        args.get(*i).cloned().ok_or_else(|| format!("{name} needs a value"))
    };
    while i < args.len() {
        let a = &args[i];
        if let Some(long) = a.strip_prefix("--") {
            let (k, v) = match long.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (long, None),
            };
            let mut val = |name: &str| -> Result<String, String> {
                if let Some(v) = &v {
                    return Ok(v.clone());
                }
                i += 1;
                args.get(i).cloned().ok_or_else(|| format!("--{name} needs a value"))
            };
            match k {
                "sign" => o.sign = Some(val("sign")?),
                "verify" => o.verify += 1,
                "display" => o.display = true,
                "identifier" => o.identifier = Some(val("identifier")?),
                "options" => {
                    for f in val("options")?.split(',') {
                        match f.trim() {
                            "runtime" => o.runtime = true,
                            "" => {}
                            other => return Err(format!("--options {other}: only `runtime` is supported")),
                        }
                    }
                }
                "entitlements" => o.entitlements = Some(val("entitlements")?),
                "requirements" => o.requirements = Some(val("requirements")?),
                "test-requirement" => o.test_requirement = Some(val("test-requirement")?),
                "timestamp" => o.timestamp = Some(v),
                "password" => o.password = Some(val("password")?),
                "hardened-runtime" => o.runtime = true,
                "p12" => o.sign = Some(format!("p12:{}", val("p12")?)),
                "cert" => o.cert = Some(val("cert")?),
                "key" => o.key = Some(val("key")?),
                "force" | "deep" | "strict" | "preserve-metadata" | "generate-entitlement-der" => {}
                other => return Err(format!("unknown option --{other}\n\n{CODESIGN_USAGE}")),
            }
        } else if a.len() > 1 && a.starts_with('-') {
            let cluster: Vec<char> = a[1..].chars().collect();
            let mut j = 0;
            while j < cluster.len() {
                let c = cluster[j];
                let rest: String = cluster[j + 1..].iter().collect();
                match c {
                    'f' => {}
                    'v' => o.verify += 1,
                    'd' => o.display = true,
                    's' => {
                        o.sign = Some(take(&mut i, &rest, "-s")?);
                        break;
                    }
                    'i' => {
                        o.identifier = Some(take(&mut i, &rest, "-i")?);
                        break;
                    }
                    'o' => {
                        let v = take(&mut i, &rest, "-o")?;
                        o.runtime |= v.split(',').any(|x| x == "runtime" || x == "0x10000");
                        break;
                    }
                    'r' => {
                        o.requirements = Some(take(&mut i, &rest, "-r")?);
                        break;
                    }
                    'R' => {
                        o.test_requirement = Some(take(&mut i, &rest, "-R")?);
                        break;
                    }
                    _ => return Err(format!("unknown option -{c}\n\n{CODESIGN_USAGE}")),
                }
                j += 1;
            }
        } else {
            o.paths.push(a.clone());
        }
        i += 1;
    }
    Ok(o)
}

/// Resolves an identity argument to a signer (`-` is ad hoc).
pub fn identity(spec: &str, password: Option<&str>) -> Result<AppleIdentity, String> {
    if spec == "-" || spec == "adhoc" {
        return Ok(AppleIdentity::AdHoc);
    }
    let pw = password.map(String::from).or_else(|| std::env::var("PACKAGER_P12_PASSWORD").ok());
    let signer: Arc<dyn Signer> = if let Some(p12) = spec.strip_prefix("p12:") {
        KeySigner::pkcs12(p12, pw.as_deref().unwrap_or("")).map_err(|e| e.to_string())?.complete_chain(&packager::transport::Curl).map_err(|e| e.to_string())?.into_arc()
    } else if let Some(pem) = spec.strip_prefix("pem:") {
        let (cert, key) = pem.split_once(',').ok_or("pem:CERT,KEY needs both files")?;
        KeySigner::pem(cert, key, pw.as_deref()).map_err(|e| e.to_string())?.complete_chain(&packager::transport::Curl).map_err(|e| e.to_string())?.into_arc()
    } else {
        keychain(spec)?
    };
    Ok(AppleIdentity::Signer(signer))
}

#[cfg(target_os = "macos")]
fn keychain(spec: &str) -> Result<Arc<dyn Signer>, String> {
    Ok(Arc::new(packager::sign::keychain::KeychainSigner::find(spec).map_err(|e| e.to_string())?))
}

#[cfg(not(target_os = "macos"))]
fn keychain(spec: &str) -> Result<Arc<dyn Signer>, String> {
    Err(format!("{spec}: keychain identities need macOS; use p12:FILE or pem:CERT,KEY"))
}

fn requirement_text(r: &str) -> Result<String, String> {
    match r.strip_prefix('=') {
        Some(text) => Ok(text.to_string()),
        None => std::fs::read_to_string(r).map_err(|e| format!("{r}: {e}")),
    }
}

fn entitlements_xml(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(Value::parse(&bytes).map_err(|e| e.to_string())?.to_xml().into_bytes())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut o = parse(args)?;
    match (&o.cert, &o.key) {
        (Some(c), Some(k)) => o.sign = Some(format!("pem:{c},{k}")),
        (None, None) => {}
        _ => return Err("--cert and --key go together".into()),
    }
    if o.paths.is_empty() {
        return Err(CODESIGN_USAGE.to_string());
    }
    if let Some(spec) = &o.sign {
        return sign(&o, spec);
    }
    if o.display {
        for p in &o.paths {
            display(Path::new(p), &o)?;
        }
        return Ok(());
    }
    if o.verify > 0 {
        let mut failed = false;
        for p in &o.paths {
            if let Err(e) = verify(Path::new(p), &o) {
                eprintln!("{p}: {e}");
                failed = true;
            }
        }
        return if failed { Err("verification failed".into()) } else { Ok(()) };
    }
    Err(format!("say what to do: -s (sign), -v (verify) or -d (display)\n\n{CODESIGN_USAGE}"))
}

fn sign(o: &Opts, spec: &str) -> Result<(), String> {
    let id = identity(spec, o.password.as_deref())?;
    let entitlements = o.entitlements.as_deref().map(entitlements_xml).transpose()?;
    let requirements = o.requirements.as_deref().map(requirement_text).transpose()?;
    let timestamp_url = match (&id, &o.timestamp) {
        (AppleIdentity::AdHoc, _) => None,
        (_, Some(Some(v))) if v == "none" => None,
        (_, Some(Some(url))) => Some(url.clone()),
        (_, Some(None)) => Some(timestamp::APPLE_TSA.to_string()),
        (AppleIdentity::Signer(_), None) => packager::sign::Apple { application: id.clone(), ..packager::sign::Apple::ad_hoc() }.timestamp_url(&id),
    };
    for p in &o.paths {
        let path = Path::new(p);
        let signed = if path.is_dir() {
            let opts = BundleSignOptions {
                identity: id.clone(),
                hardened_runtime: o.runtime,
                entitlements: entitlements.clone(),
                requirements: requirements.clone(),
                timestamp_url: timestamp_url.clone(),
            };
            sign_bundle(path, &opts).map_err(|e| format!("{p}: {e}"))?
        } else if is_disk_image(path) {
            let data = std::fs::read(path).map_err(|e| format!("{p}: {e}"))?;
            let ident = o.identifier.clone().unwrap_or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
            let mut dopts = DiskImageSignOptions::new(ident, id.clone());
            dopts.requirements = requirements.clone();
            dopts.timestamp_url = timestamp_url.clone();
            let out = sign_disk_image(&data, &dopts).map_err(|e| format!("{p}: {e}"))?;
            std::fs::write(path, &out).map_err(|e| format!("{p}: {e}"))?;
            let sig = verify_disk_image(&out).map_err(|e| format!("{p}: {e}"))?;
            eprintln!("{p}: signed disk image cdhash {}", packager::crypto::hex(&sig.cdhash[..20]));
            continue;
        } else {
            let data = std::fs::read(path).map_err(|e| format!("{p}: {e}"))?;
            if !macho::is_macho(&data) {
                return Err(format!("{p}: not a Mach-O file, bundle or disk image"));
            }
            let ident = o.identifier.clone().unwrap_or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
            let mut co = CodeSignOptions::ad_hoc(ident);
            co.identity = id.clone();
            co.hardened_runtime = o.runtime;
            co.entitlements = entitlements.clone();
            co.requirements = requirements.clone();
            co.timestamp_url = timestamp_url.clone();
            let signed = sign_macho(&data, &co).map_err(|e| format!("{p}: {e}"))?;
            // Write a new file and rename it over the old one: Apple silicon caches code
            // signatures per vnode, and rewriting in place can leave a stale one.
            let tmp = path.with_extension("packager-signing");
            std::fs::write(&tmp, &signed.data).map_err(|e| format!("{p}: {e}"))?;
            let mode = std::fs::metadata(path).map(|m| permissions(&m)).unwrap_or(0o755);
            packager::util::set_mode(&tmp, mode).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, path).map_err(|e| format!("{p}: {e}"))?;
            signed
        };
        let how = match &id {
            AppleIdentity::AdHoc => "ad hoc".to_string(),
            AppleIdentity::Signer(s) => format!("{}{}", s.leaf().and_then(|c| c.common_name()).unwrap_or("certificate"), if timestamp_url.is_some() { ", timestamped" } else { "" }),
        };
        eprintln!("{p}: signed ({how}) cdhash {}", packager::crypto::hex(&signed.cdhashes[0][..20]));
    }
    Ok(())
}

#[cfg(unix)]
fn permissions(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn permissions(_m: &std::fs::Metadata) -> u32 {
    0o755
}

/// Whether `path` is a UDIF disk image (by its `koly` trailer).
fn is_disk_image(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::End(-512)).is_ok() && f.read_exact(&mut magic).is_ok() && &magic == b"koly"
}

/// The signature of whatever `path` is: a disk image, or a bundle's main executable / a Mach-O.
fn signatures(path: &Path) -> Result<(Vec<SliceSignature>, Option<Dict>, String), String> {
    if is_disk_image(path) {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        return Ok((vec![verify_disk_image(&data).map_err(|e| e.to_string())?], None, "disk image".into()));
    }
    let (exe, info) = target(path)?;
    let data = std::fs::read(&exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let sigs = verify_macho(&data).map_err(|e| e.to_string())?;
    let slices = macho::slices(&data).map_err(|e| e.to_string())?;
    let archs: Vec<&str> = slices.iter().filter_map(|x| macho::Image::parse(&x.data).ok()).map(|i| i.arch_name()).collect();
    let format = if archs.len() > 1 { format!("Mach-O universal ({})", archs.join(" ")) } else { format!("Mach-O thin ({})", archs.first().unwrap_or(&"?")) };
    let format = if path.is_dir() { format!("app bundle with {format}") } else { format };
    Ok((sigs, info, format))
}

/// The main executable and Info.plist for a bundle, or the file itself.
fn target(path: &Path) -> Result<(PathBuf, Option<Dict>), String> {
    if !path.is_dir() {
        return Ok((path.to_path_buf(), None));
    }
    let info_path = path.join("Contents/Info.plist");
    let info = Value::parse(&std::fs::read(&info_path).map_err(|e| format!("{}: {e}", info_path.display()))?).map_err(|e| e.to_string())?;
    let d = info.as_dict().cloned().ok_or("Info.plist isn't a dictionary")?;
    let exe = d.get_str("CFBundleExecutable").ok_or("Info.plist has no CFBundleExecutable")?;
    Ok((path.join("Contents/MacOS").join(exe), Some(d)))
}

fn context_check(path: &Path, sigs: &[SliceSignature], info: Option<&Dict>, req: &requirement::Expr) -> bool {
    let _ = path;
    sigs.iter().all(|s| {
        let chain: Vec<Certificate> = s.cms.as_ref().map(|c| packager::sign::signer::order_chain(std::iter::once(c.signer.clone()).chain(c.certificates.iter().filter(|x| x.der != c.signer.der).cloned()).collect())).unwrap_or_default();
        let ents = s.entitlements.as_ref().and_then(|e| Value::parse(e).ok()).and_then(|v| v.as_dict().cloned());
        let cdhashes = vec![s.cdhash.to_vec()];
        let ctx = requirement::Context { identifier: &s.identifier, chain: &chain, cdhashes: &cdhashes, info, entitlements: ents.as_ref(), trusted_anchors: &[] };
        req.evaluate(&ctx)
    })
}

fn verify(path: &Path, o: &Opts) -> Result<(), String> {
    if path.is_dir() {
        verify_bundle(path).map_err(|e| e.to_string())?;
    }
    let (sigs, info, _) = signatures(path)?;
    println!("{}: valid on disk", path.display());
    // The designated requirement: embedded, or the implicit cdhash requirement for ad-hoc code.
    let dr = sigs[0].requirements.iter().find(|(t, _)| *t == RequirementType::Designated).map(|(_, e)| e.clone());
    let dr_ok = match &dr {
        Some(e) => context_check(path, &sigs, info.as_ref(), e),
        None => true,
    };
    if !dr_ok {
        return Err("does not satisfy its designated Requirement".into());
    }
    println!("{}: satisfies its Designated Requirement", path.display());
    if let Some(r) = &o.test_requirement {
        let text = requirement_text(r).or_else(|_| Ok::<_, String>(r.clone()))?;
        let e = requirement::compile(&text).map_err(|e| e.to_string())?;
        if !context_check(path, &sigs, info.as_ref(), &e) {
            return Err("test-requirement: code failed to satisfy specified code requirement(s)".into());
        }
        println!("{}: explicit requirement satisfied", path.display());
    }
    Ok(())
}

fn display(path: &Path, o: &Opts) -> Result<(), String> {
    let (sigs, info, format) = signatures(path)?;
    let s = &sigs[0];
    let mut flags = Vec::new();
    if s.flags & CS_ADHOC != 0 {
        flags.push("adhoc");
    }
    if s.flags & CS_RUNTIME != 0 {
        flags.push("runtime");
    }
    eprintln!("Executable={}", std::fs::canonicalize(path).unwrap_or(path.to_path_buf()).display());
    eprintln!("Identifier={}", s.identifier);
    eprintln!("Format={format}");
    eprintln!("CodeDirectory v={:x} flags={:#x}({}) location=embedded", s.version, s.flags, flags.join(","));
    if o.verify > 0 {
        eprintln!("Hash type=sha256 size=32");
        eprintln!("CDHash={}", packager::crypto::hex(&s.cdhash[..20]));
    }
    match &s.cms {
        None => eprintln!("Signature=adhoc"),
        Some(cms) => {
            let chain = packager::sign::signer::order_chain(std::iter::once(cms.signer.clone()).chain(cms.certificates.iter().filter(|x| x.der != cms.signer.der).cloned()).collect());
            for c in &chain {
                eprintln!("Authority={}", c.common_name().unwrap_or("?"));
            }
            match (&cms.timestamp, &cms.signing_time) {
                (Some(t), _) => eprintln!("Timestamp={t}"),
                (None, Some(t)) => eprintln!("Signed Time={t}"),
                _ => {}
            }
        }
    }
    match &info {
        Some(d) => eprintln!("Info.plist entries={}", d.0.len()),
        None => eprintln!("Info.plist=not bound"),
    }
    eprintln!("TeamIdentifier={}", s.team_id.as_deref().unwrap_or("not set"));
    if path.is_dir() {
        eprintln!("Sealed Resources version=2");
    } else {
        eprintln!("Sealed Resources=none");
    }
    if o.requirements.as_deref() == Some("-") {
        let text = requirement::requirement_set_text(&s.requirements);
        if text.is_empty() {
            println!("# designated => {}", sigs.iter().map(|x| format!("cdhash H\"{}\"", packager::crypto::hex(&x.cdhash[..20]))).collect::<Vec<_>>().join(" or "));
        } else {
            println!("{text}");
        }
    }
    if matches!(o.entitlements.as_deref(), Some("-") | Some(":-")) {
        if let Some(e) = &s.entitlements {
            print!("{}", String::from_utf8_lossy(e));
        }
    }
    Ok(())
}
