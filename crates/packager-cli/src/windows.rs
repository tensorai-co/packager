//! Windows executables: Authenticode signing (`signtool sign`), verification, and resource
//! editing (`rcedit`), on top of the library.

use std::path::Path;

use packager::crypto::hmac::HashAlg;
use packager::format::pe::{Image, VersionInfo};
use packager::sign::authenticode::{self, Options};
use packager::sign::AppleIdentity;

use crate::Args;

pub const USAGE: &str = "    packager sign <file.exe|.dll> -s IDENTITY [--timestamp URL] [--digest sha256|sha1] [--description TEXT]
    packager rcedit <file.exe> [--icon icon.png|.ico] [--version 1.4.0] [--set KEY=VALUE]... [--manifest FILE]";

/// Whether `path` is a PE file (by its `MZ` header).
pub fn is_pe(path: &Path) -> bool {
    use std::io::Read;
    let mut m = [0u8; 2];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut m)).is_ok() && &m == b"MZ"
}

/// `packager sign file.exe -s ID …`: an Authenticode signature, in place.
pub fn sign(args: &[String]) -> Result<(), String> {
    let mut spec = None;
    let mut ts = None;
    let mut digest = HashAlg::Sha256;
    let mut desc = None;
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let val = |it: &mut std::slice::Iter<String>, name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "-s" | "--sign" => spec = Some(val(&mut it, a)?),
            "--timestamp" | "-tr" | "--tr" => ts = Some(val(&mut it, a)?),
            "--digest" | "-fd" | "--fd" => {
                digest = match val(&mut it, a)?.to_lowercase().as_str() {
                    "sha256" => HashAlg::Sha256,
                    "sha1" => HashAlg::Sha1,
                    "sha384" => HashAlg::Sha384,
                    "sha512" => HashAlg::Sha512,
                    o => return Err(format!("unknown digest `{o}`")),
                }
            }
            "--description" | "-d" => desc = Some(val(&mut it, a)?),
            x if x.starts_with("--timestamp=") => ts = Some(x["--timestamp=".len()..].to_string()),
            x if x.starts_with("--sign=") => spec = Some(x["--sign=".len()..].to_string()),
            x if x.starts_with('-') => return Err(format!("unknown option {x} for signing a PE file\n\n{USAGE}")),
            x => files.push(x.to_string()),
        }
    }
    let spec = spec.ok_or("signing a .exe/.dll needs a code-signing identity: -s IDENTITY")?;
    let id = crate::codesign::identity(&spec, std::env::var("PACKAGER_P12_PASSWORD").ok().as_deref())?;
    let AppleIdentity::Signer(signer) = id else { return Err("Authenticode has no ad-hoc signatures: give a certificate identity".into()) };
    for f in &files {
        let mut o = Options::sha256();
        o.digest = digest;
        o.timestamp_url = ts.clone();
        o.description = desc.clone();
        let mut img = Image::read(f).map_err(|e| format!("{f}: {e}"))?;
        authenticode::sign_pe(&mut img, signer.as_ref(), &o).map_err(|e| format!("{f}: {e}"))?;
        img.write(f).map_err(|e| format!("{f}: {e}"))?;
        eprintln!("{f}: signed ({}{})", signer.leaf().and_then(|c| c.common_name()).unwrap_or("certificate"), if ts.is_some() { ", timestamped" } else { "" });
    }
    Ok(())
}

/// `packager verify file.exe`.
pub fn verify(path: &Path) -> Result<(), String> {
    let img = Image::read(path).map_err(|e| e.to_string())?;
    match authenticode::verify_pe(&img).map_err(|e| e.to_string())? {
        None => println!("{}: valid PE, not signed", path.display()),
        Some(v) => {
            let cn = v.cms.signer.common_name().unwrap_or("?").to_string();
            let ts = v.cms.timestamp.map(|t| format!(", timestamped {t}")).unwrap_or_default();
            println!("{}: Authenticode signature valid ({cn}, {:?}{ts})", path.display(), v.digest);
        }
    }
    Ok(())
}

/// `packager rcedit file.exe …`.
pub fn rcedit(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["icon", "version", "set", "manifest"])?;
    a.check(&["icon", "version", "set", "manifest"])?;
    let [target] = a.positional[..] else { return Err(format!("rcedit takes one .exe\n\n{USAGE}")) };
    let mut img = Image::read(target).map_err(|e| format!("{target}: {e}"))?;
    let e = |x: packager::Error| format!("{target}: {x}");
    if let Some(icon) = a.value("icon") {
        let ico = if icon.to_lowercase().ends_with(".png") { packager::image::ico_from_png(icon).map_err(e)? } else { std::fs::read(icon).map_err(|x| format!("{icon}: {x}"))? };
        img.set_icon(&ico).map_err(e)?;
    }
    let sets: Vec<(String, String)> = a.flags.iter().filter(|(k, _)| *k == "set").filter_map(|(_, v)| v.and_then(|v| v.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string()))).collect();
    if a.value("version").is_some() || !sets.is_empty() {
        let mut v = VersionInfo::new(a.value("version").unwrap_or("0.0.0")).map_err(e)?;
        for (k, val) in sets {
            v = v.string(&k, val);
        }
        img.set_version_info(&v).map_err(e)?;
    }
    if let Some(m) = a.value("manifest") {
        img.set_manifest(&std::fs::read(m).map_err(|x| format!("{m}: {x}"))?).map_err(e)?;
    }
    img.write(target).map_err(e)?;
    eprintln!("{target}: resources updated (sign it again afterwards)");
    Ok(())
}
