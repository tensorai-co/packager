//! `packager`: parses arguments and `packager.toml`, then calls the library's public API.

mod codesign;
mod config;
mod toml;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use packager::format::{bom, cpio, macho, udif, xar};
use packager::sign::apple::{verify_macho, CS_ADHOC, CS_RUNTIME};
use packager::sign::bundle::verify_bundle;

const USAGE: &str = "\
packager — native macOS packages from scratch, no platform tools needed

USAGE:
    packager build [--config packager.toml] [--only app,dmg,pkg] [--out DIR]
    packager sign <file|bundle>... [-s IDENTITY | --p12 FILE | --cert FILE --key FILE]
                  [-i ID] [--hardened-runtime] [--entitlements FILE] [-r REQS] [--timestamp[=URL|none]]
    packager codesign …                codesign's own command line (sign, -v verify, -d display)
    packager identities                code-signing identities in the keychain
    packager verify <file|bundle>      signatures and structure, without native tools
    packager inspect <file|bundle>     what's inside a .dmg, .pkg, .app or Mach-O file
    packager icns <icon.png> <out.icns>
    packager --version

IDENTITY: `-` (ad hoc, the default), a keychain identity name/SHA-1, `p12:FILE`, `pem:CERT,KEY`.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Args<'a> {
    positional: Vec<&'a str>,
    flags: Vec<(&'a str, Option<&'a str>)>,
}

impl<'a> Args<'a> {
    fn parse(args: &'a [String], with_value: &[&str]) -> Result<Self, String> {
        let mut out = Args { positional: Vec::new(), flags: Vec::new() };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if let Some(flag) = a.strip_prefix("--") {
                if let Some((k, v)) = flag.split_once('=') {
                    out.flags.push((k, Some(v)));
                } else if with_value.contains(&flag) {
                    let v = it.next().ok_or_else(|| format!("--{flag} needs a value"))?;
                    out.flags.push((flag, Some(v.as_str())));
                } else {
                    out.flags.push((flag, None));
                }
            } else {
                out.positional.push(a);
            }
        }
        Ok(out)
    }
    fn value(&self, k: &str) -> Option<&'a str> {
        self.flags.iter().rev().find(|(f, _)| *f == k).and_then(|(_, v)| *v)
    }
    fn check(&self, allowed: &[&str]) -> Result<(), String> {
        for (f, _) in &self.flags {
            if !allowed.contains(f) {
                return Err(format!("unknown option --{f}\n\n{USAGE}"));
            }
        }
        Ok(())
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        println!("{USAGE}");
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "build" => build(rest),
        "sign" => sign(rest),
        "codesign" => codesign::run(rest),
        "identities" => identities(),
        "verify" => verify(rest),
        "inspect" => inspect(rest),
        "icns" => icns(rest),
        "--version" | "-V" | "version" => {
            println!("packager {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn build(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["config", "only", "out"])?;
    a.check(&["config", "only", "out"])?;
    let cfg_path = PathBuf::from(a.value("config").unwrap_or("packager.toml"));
    let cfg = config::load(&cfg_path)?;
    let only: Option<Vec<&str>> = a.value("only").map(|o| o.split(',').map(str::trim).collect());
    if let Some(o) = &only {
        for k in o {
            if !["app", "dmg", "pkg"].contains(k) {
                return Err(format!("--only: unknown package kind `{k}` (macOS kinds: app, dmg, pkg)"));
            }
        }
    }
    let want = |k: &str, configured: bool| match &only {
        Some(o) => o.contains(&k),
        None => configured,
    };
    let mut b = packager::build(&cfg.app).app_bundle(cfg.app_bundle.clone()).out_dir(a.value("out").map(PathBuf::from).unwrap_or(cfg.out_dir));
    let mut any = false;
    if want("app", cfg.app_package) {
        b = b.package(cfg.app_bundle.clone());
        any = true;
    }
    if want("dmg", cfg.dmg.is_some()) {
        b = b.package(cfg.dmg.clone().unwrap_or_default());
        any = true;
    }
    if want("pkg", cfg.pkg.is_some()) {
        b = b.package(cfg.pkg.clone().unwrap_or_default());
        any = true;
    }
    if !any {
        return Err("nothing to build: add [package.dmg] / [package.pkg] / [package.app], or pass --only".into());
    }
    if let Some(apple) = cfg.apple {
        b = b.sign(apple);
    }
    let out = b.run().map_err(|e| e.to_string())?;
    for p in out.packages() {
        println!("{:<4} {:<16} {:>10}  {}  {}", p.kind(), p.arch(), p.size(), p.sha256_hex(), p.path().display());
    }
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    let has_identity = args.iter().any(|a| a == "-s" || a.starts_with("--sign") || a.starts_with("--p12") || a.starts_with("--cert") || (a.starts_with("-s") && !a.starts_with("--")));
    let mut a = args.to_vec();
    if !has_identity {
        a.splice(0..0, ["-s".to_string(), "-".to_string()]);
    }
    codesign::run(&a)
}

#[cfg(target_os = "macos")]
fn identities() -> Result<(), String> {
    let list = packager::sign::keychain::list_identities().map_err(|e| e.to_string())?;
    for (i, (sha1, name)) in list.iter().enumerate() {
        println!("  {}) {sha1} \"{name}\"", i + 1);
    }
    println!("     {} identities found", list.len());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn identities() -> Result<(), String> {
    Err("keychain identities need macOS".into())
}

fn ext(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default()
}

fn verify(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &[])?;
    a.check(&[])?;
    let [target] = a.positional[..] else { return Err(format!("verify takes one path\n\n{USAGE}")) };
    let path = Path::new(target);
    let e = |x: packager::Error| x.to_string();
    if path.is_dir() {
        let n = verify_bundle(path).map_err(e)?;
        println!("{}: valid signature, {n} sealed entries match", path.display());
        return Ok(());
    }
    let data = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    match ext(path).as_str() {
        "dmg" => {
            let vol = udif::read(&data).map_err(e)?;
            let sig = vol.get(1024..1026).unwrap_or_default();
            if sig != b"HX" && sig != b"H+" {
                return Err("the image doesn't hold an HFS+ volume".into());
            }
            println!("{}: valid UDIF image, CRC32 checksums match, {} KB HFS+ volume", path.display(), vol.len() / 1024);
        }
        "pkg" => {
            let (_, files) = xar::read(&data).map_err(e)?;
            let mut paths = 0;
            for f in &files {
                if f.path.ends_with("/Bom") || f.path == "Bom" {
                    paths += bom::read(&f.data).map_err(e)?.len();
                }
                if f.path.ends_with("/Payload") || f.path == "Payload" {
                    let raw = packager::compress::gunzip(&f.data).map_err(e)?;
                    cpio::read_odc(&raw).map_err(e)?;
                }
            }
            println!("{}: valid XAR archive ({} files, checksums match), Bom lists {paths} paths, payload readable; no installer signature", path.display(), files.len());
        }
        _ if macho::is_macho(&data) => {
            for s in verify_macho(&data).map_err(e)? {
                println!("{}: {} valid ({}), identifier {}", path.display(), s.arch, if s.has_cms { "certificate" } else { "ad hoc" }, s.identifier);
            }
        }
        _ => return Err(format!("{}: not a .dmg, .pkg, bundle or Mach-O file", path.display())),
    }
    Ok(())
}

fn inspect(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &[])?;
    a.check(&[])?;
    let [target] = a.positional[..] else { return Err(format!("inspect takes one path\n\n{USAGE}")) };
    let path = Path::new(target);
    let e = |x: packager::Error| x.to_string();
    let print_sig = |label: &str, data: &[u8]| -> Result<(), String> {
        for s in verify_macho(data).map_err(e)? {
            let mut flags = Vec::new();
            if s.flags & CS_ADHOC != 0 {
                flags.push("adhoc");
            }
            if s.flags & CS_RUNTIME != 0 {
                flags.push("runtime");
            }
            println!("{label} [{}] identifier={} cd=v{:x} flags={:#x}({}) cdhash={}", s.arch, s.identifier, s.version, s.flags, flags.join(","), packager::crypto::hex(&s.cdhash[..20]));
            if let Some(ent) = &s.entitlements {
                println!("  entitlements: {} bytes", ent.len());
            }
        }
        Ok(())
    };
    if path.is_dir() {
        let info = std::fs::read(path.join("Contents/Info.plist")).map_err(|err| format!("Info.plist: {err}"))?;
        let v = packager::format::plist::Value::parse(&info).map_err(e)?;
        let d = v.as_dict().ok_or("Info.plist isn't a dictionary")?;
        for k in ["CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion", "CFBundleExecutable", "LSMinimumSystemVersion"] {
            println!("{k}: {}", d.get_str(k).unwrap_or("-"));
        }
        if let Some(exe) = d.get_str("CFBundleExecutable") {
            let data = std::fs::read(path.join("Contents/MacOS").join(exe)).map_err(|err| err.to_string())?;
            print_sig("executable", &data)?;
        }
        return Ok(());
    }
    let data = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    match ext(path).as_str() {
        "pkg" => {
            let (_, files) = xar::read(&data).map_err(e)?;
            for f in &files {
                println!("{:>10}  {}", f.data.len(), f.path);
                if f.path.ends_with("Bom") {
                    for p in bom::read(&f.data).map_err(e)?.iter().take(40) {
                        println!("            {:o} {:>9} {}", p.mode, p.size, p.path);
                    }
                }
            }
        }
        "dmg" => {
            let vol = udif::read(&data).map_err(e)?;
            println!("UDIF image: {} bytes compressed, {} bytes volume ({})", data.len(), vol.len(), String::from_utf8_lossy(&vol[1024..1026]));
        }
        "icns" => {
            for ent in packager::format::icns::read(&data).map_err(e)? {
                let size = ent.image.as_ref().map(|i| format!("{}x{}", i.width, i.height)).unwrap_or_else(|| "?".into());
                println!("{} {:>8} bytes {}", String::from_utf8_lossy(&ent.kind), ent.data.len(), size);
            }
        }
        _ if macho::is_macho(&data) => {
            for s in macho::slices(&data).map_err(e)? {
                let img = macho::Image::parse(&s.data).map_err(e)?;
                println!("slice {} ({} bytes, filetype {})", img.arch_name(), s.data.len(), img.filetype);
            }
            print_sig("signature", &data)?;
        }
        _ => return Err(format!("{}: don't know how to inspect this", path.display())),
    }
    Ok(())
}

fn icns(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &[])?;
    a.check(&[])?;
    let [src, dst] = a.positional[..] else { return Err(format!("icns takes <icon.png> <out.icns>\n\n{USAGE}")) };
    let data = packager::image::icns_from_png(src).map_err(|e| e.to_string())?;
    std::fs::write(dst, data).map_err(|e| format!("{dst}: {e}"))?;
    println!("wrote {dst}");
    Ok(())
}
