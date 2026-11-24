//! Shipping outside the App Store: `notarize` (notarytool), `staple` (stapler), `productsign`
//! and `assess` (spctl), on top of the library.

use std::path::Path;
use std::time::Duration;

use packager::notary::{log_issues, ApiKey, Notarize, Notary};
use packager::sign::assess::assess;
use packager::sign::installer::{sign_pkg, verify_pkg, InstallerSignOptions};
use packager::sign::{timestamp, AppleIdentity};
use packager::staple::{self, Lookup};
use packager::transport::Curl;

use crate::Args;

pub const USAGE: &str = "    packager notarize <file|bundle> [--key AuthKey_ID.p8] [--key-id ID] [--issuer UUID]
                      [--no-wait] [--timeout MINUTES] [--no-staple]
    packager notarize --status ID | --log ID [--key …]
    packager staple <file|bundle>...            fetch and attach the ticket (stapler staple)
    packager staple --validate <file|bundle>... check the stapled ticket (stapler validate)
    packager productsign --sign IDENTITY [--timestamp[=URL|none]] <in.pkg> <out.pkg>
    packager assess <file|bundle> [--offline]   would Gatekeeper accept it? (spctl -a)

The API key also comes from PACKAGER_NOTARY_KEY, PACKAGER_NOTARY_KEY_ID and
PACKAGER_NOTARY_ISSUER (omit the issuer for individual keys).";

fn api_key(a: &Args) -> Result<ApiKey, String> {
    let path = a.value("key").map(String::from).or_else(|| std::env::var("PACKAGER_NOTARY_KEY").ok()).ok_or("give the App Store Connect API key with --key AuthKey_<ID>.p8 (or PACKAGER_NOTARY_KEY)")?;
    let id = a.value("key-id").map(String::from).or_else(|| std::env::var("PACKAGER_NOTARY_KEY_ID").ok());
    let issuer = a.value("issuer").map(String::from).or_else(|| std::env::var("PACKAGER_NOTARY_ISSUER").ok());
    ApiKey::from_file(&path, id.as_deref(), issuer.as_deref()).map_err(|e| e.to_string())
}

pub fn notarize(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["key", "key-id", "issuer", "timeout", "status", "log"])?;
    a.check(&["key", "key-id", "issuer", "timeout", "status", "log", "no-wait", "no-staple"])?;
    let key = api_key(&a)?;
    let curl = Curl;
    if let Some(id) = a.value("status") {
        let s = Notary::new(key, &curl).status(id).map_err(|e| e.to_string())?;
        println!("{id}: {s:?}");
        return Ok(());
    }
    if let Some(id) = a.value("log") {
        let log = Notary::new(key, &curl).log(id).map_err(|e| e.to_string())?;
        println!("{}", log.to_string_compact());
        return Ok(());
    }
    let [target] = a.positional[..] else { return Err(format!("notarize takes one path\n\n{USAGE}")) };
    let path = Path::new(target);
    Notarize::preflight(path).map_err(|e| e.to_string())?;
    if a.flags.iter().any(|(f, _)| *f == "no-wait") {
        let data = if path.is_dir() {
            packager::format::zip::from_dir(path, packager::util::source_date_epoch()).map_err(|e| e.to_string())?
        } else {
            std::fs::read(path).map_err(|e| format!("{target}: {e}"))?
        };
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default() + if path.is_dir() { ".zip" } else { "" };
        let notary = Notary::new(key, &curl);
        let sha = packager::crypto::sha256(&data);
        let (id, creds, bucket, object) = notary.create_submission(&name, &sha).map_err(|e| e.to_string())?;
        notary.upload(&data, &creds, &bucket, &object).map_err(|e| e.to_string())?;
        println!("submitted {target}: id {id}\ncheck with: packager notarize --status {id}");
        return Ok(());
    }
    let mut n = Notarize::new(key);
    n.staple = !a.flags.iter().any(|(f, _)| *f == "no-staple");
    if let Some(m) = a.value("timeout") {
        n.timeout = Duration::from_secs(m.parse::<u64>().map_err(|_| "--timeout is in minutes")? * 60);
    }
    eprintln!("{target}: submitting to Apple's notary service (this usually takes a few minutes)…");
    let out = n.run(path).map_err(|e| e.to_string())?;
    match &out.submission {
        Some(s) => {
            println!("{target}: {:?} (submission {})", s.status, s.id);
            if let Some(log) = &s.log {
                for i in log_issues(log) {
                    println!("  warning: {i}");
                }
            }
        }
        None => println!("{target}: already notarized"),
    }
    if out.stapled {
        println!("{target}: ticket stapled");
    }
    Ok(())
}

pub fn staple(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &[])?;
    a.check(&["validate"])?;
    if a.positional.is_empty() {
        return Err(format!("staple takes one or more paths\n\n{USAGE}"));
    }
    let validate = a.flags.iter().any(|(f, _)| *f == "validate");
    let mut failed = false;
    for p in &a.positional {
        let r = if validate {
            staple::validate(p).map(|()| "the validate action worked".to_string()).map_err(|e| e.to_string())
        } else {
            match staple::staple(&Curl, p) {
                Ok(Lookup::Ticket(_)) => Ok("the staple and validate action worked".to_string()),
                Ok(Lookup::Missing(why)) => Err(format!("no ticket at Apple for this code ({why}); notarize it first")),
                Err(e) => Err(e.to_string()),
            }
        };
        match r {
            Ok(m) => println!("{p}: {m}"),
            Err(e) => {
                eprintln!("{p}: {e}");
                failed = true;
            }
        }
    }
    if failed { Err(if validate { "validation failed".into() } else { "stapling failed".into() }) } else { Ok(()) }
}

pub fn productsign(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["sign", "password"])?;
    a.check(&["sign", "password", "timestamp"])?;
    let spec = a.value("sign").ok_or("productsign needs --sign IDENTITY")?;
    let [input, output] = a.positional[..] else { return Err(format!("productsign takes <in.pkg> <out.pkg>\n\n{USAGE}")) };
    sign_installer(spec, a.value("password"), a.flags.iter().find(|(f, _)| *f == "timestamp").map(|(_, v)| *v), Path::new(input), Path::new(output))
}

/// Signs `input` into `output` with an installer identity. `timestamp`: `None` = automatic
/// (Apple's server for Developer ID), `Some(None)` = Apple's, `Some(Some("none"|URL))`.
pub fn sign_installer(spec: &str, password: Option<&str>, timestamp: Option<Option<&str>>, input: &Path, output: &Path) -> Result<(), String> {
    let id = crate::codesign::identity(spec, password)?;
    let AppleIdentity::Signer(signer) = &id else { return Err("installer packages can't be signed ad hoc: give an installer identity".into()) };
    let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let mut o = InstallerSignOptions::new(signer.as_ref());
    o.timestamp_url = match timestamp {
        Some(Some("none")) => None,
        Some(Some(url)) => Some(url.to_string()),
        Some(None) => Some(timestamp::APPLE_TSA.to_string()),
        None => packager::sign::Apple { installer: Some(id.clone()), ..packager::sign::Apple::ad_hoc() }.timestamp_url(&id),
    };
    let signed = sign_pkg(&data, &o).map_err(|e| format!("{}: {e}", input.display()))?;
    std::fs::write(output, &signed).map_err(|e| format!("{}: {e}", output.display()))?;
    let cn = signer.leaf().and_then(|c| c.common_name()).unwrap_or("certificate").to_string();
    eprintln!("{}: signed with {cn}{}", output.display(), if o.timestamp_url.is_some() { ", timestamped" } else { "" });
    Ok(())
}

/// The installer signature summary `packager verify` prints for a `.pkg`.
pub fn describe_pkg_signature(data: &[u8]) -> Result<String, String> {
    Ok(match verify_pkg(data).map_err(|e| e.to_string())? {
        None => "no installer signature".into(),
        Some(s) => {
            let cn = s.leaf().common_name().unwrap_or("?").to_string();
            let ts = s.cms.as_ref().and_then(|c| c.timestamp.clone()).map(|t| format!(", timestamped {t}")).unwrap_or_default();
            format!("installer signature valid ({cn}{ts})")
        }
    })
}

pub fn run_assess(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &[])?;
    a.check(&["offline"])?;
    let [target] = a.positional[..] else { return Err(format!("assess takes one path\n\n{USAGE}")) };
    let offline = a.flags.iter().any(|(f, _)| *f == "offline");
    let curl = Curl;
    let r = assess(target, if offline { None } else { Some(&curl) }).map_err(|e| e.to_string())?;
    for c in &r.checks {
        println!("{} {:<18} {}", if c.ok { "ok  " } else { "FAIL" }, c.name, c.detail);
    }
    if r.accepted() {
        println!("{target}: accepted (Notarized Developer ID)");
        Ok(())
    } else {
        Err(format!("{target}: rejected"))
    }
}
