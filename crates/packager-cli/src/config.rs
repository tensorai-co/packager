//! `packager.toml` → [`App`] and package builders. The file mirrors the library one-to-one:
//! `[app]` is `App`, `[package.<kind>]` is each builder, `[sign.apple]` is the Apple signing config.

use std::path::{Path, PathBuf};

use packager::package::{AppBundle, Dmg, Msi, Msix, MsixBundle, Pkg};
use packager::{App, Arch};

use crate::toml::{self, Toml};

pub struct Config {
    pub app: App,
    pub app_bundle: AppBundle,
    pub dmg: Option<Dmg>,
    pub pkg: Option<Pkg>,
    pub msix: Option<Msix>,
    pub msi: Option<Msi>,
    pub msixbundle: Option<MsixBundle>,
    pub app_package: bool,
    pub apple: Option<packager::sign::Apple>,
    pub authenticode: Option<packager::sign::Authenticode>,
    pub notarize: Option<packager::notary::Notarize>,
    pub out_dir: PathBuf,
}

fn s<'a>(t: &'a Toml, key: &str, ctx: &str) -> Result<Option<&'a str>, String> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => v.as_str().map(Some).ok_or_else(|| format!("`{ctx}.{key}` must be a string")),
    }
}

fn req<'a>(t: &'a Toml, key: &str, ctx: &str) -> Result<&'a str, String> {
    s(t, key, ctx)?.ok_or_else(|| format!("`{ctx}.{key}` is required"))
}

fn pair(t: &Toml, key: &str, ctx: &str) -> Result<Option<(u32, u32)>, String> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => {
            let a = v.as_array().filter(|a| a.len() == 2).ok_or_else(|| format!("`{ctx}.{key}` must be [x, y]"))?;
            let n = |x: &Toml| x.as_int().filter(|i| (0..=100_000).contains(i)).map(|i| i as u32).ok_or_else(|| format!("`{ctx}.{key}` must hold integers"));
            Ok(Some((n(&a[0])?, n(&a[1])?)))
        }
    }
}

fn strings(t: &Toml, key: &str, ctx: &str) -> Result<Vec<String>, String> {
    match t.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("`{ctx}.{key}` must be an array"))?
            .iter()
            .map(|x| x.as_str().map(String::from).ok_or_else(|| format!("`{ctx}.{key}` must hold strings")))
            .collect(),
    }
}

fn check_keys(t: &Toml, allowed: &[&str], ctx: &str) -> Result<(), String> {
    if let Some(map) = t.as_table() {
        for k in map.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(format!("unknown key `{ctx}.{k}` (expected one of: {})", allowed.join(", ")));
            }
        }
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<Config, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let root = toml::parse(&src).map_err(|e| format!("{}: {e}", path.display()))?;
    let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let rel = |p: &str| -> PathBuf { if Path::new(p).is_absolute() { PathBuf::from(p) } else { base.join(p) } };
    check_keys(&root, &["app", "package", "sign", "notarize", "build"], "")?;

    let a = root.get("app").ok_or("missing [app] table")?;
    check_keys(a, &["name", "identifier", "version", "build_number", "publisher", "description", "copyright", "executable", "icon", "binaries", "resources", "url_schemes", "file_types"], "app")?;
    let mut app = App::new(req(a, "name", "app")?, req(a, "identifier", "app")?, req(a, "version", "app")?);
    if let Some(v) = s(a, "build_number", "app")? {
        app = app.build_number(v);
    }
    if let Some(v) = s(a, "publisher", "app")? {
        app = app.publisher(v);
    }
    if let Some(v) = s(a, "description", "app")? {
        app = app.description(v);
    }
    if let Some(v) = s(a, "copyright", "app")? {
        app = app.copyright(v);
    }
    if let Some(v) = s(a, "executable", "app")? {
        app = app.executable(v);
    }
    if let Some(v) = s(a, "icon", "app")? {
        app = app.icon(rel(v));
    }
    if let Some(b) = a.get("binaries") {
        let t = b.as_table().ok_or("`app.binaries` must be a table of arch = path")?;
        for (arch, p) in t {
            let arch_v = Arch::parse(arch).ok_or_else(|| format!("unknown architecture `{arch}` in app.binaries"))?;
            let p = p.as_str().ok_or_else(|| format!("`app.binaries.{arch}` must be a path"))?;
            app = app.binary(arch_v, rel(p));
        }
    }
    if let Some(r) = a.get("resources") {
        for item in r.as_array().ok_or("`app.resources` must be an array of { from, to }")? {
            app = app.resources(rel(req(item, "from", "app.resources")?), req(item, "to", "app.resources")?);
        }
    }
    for scheme in strings(a, "url_schemes", "app")? {
        app = app.url_scheme(scheme);
    }
    if let Some(r) = a.get("file_types") {
        for item in r.as_array().ok_or("`app.file_types` must be an array of { extension, name }")? {
            app = app.file_type(req(item, "extension", "app.file_types")?, req(item, "name", "app.file_types")?);
        }
    }

    let pkgs = root.get("package");
    let empty = Toml::Table(Default::default());
    let section = |k: &str| pkgs.and_then(|p| p.get(k));
    let mut app_bundle = AppBundle::new();
    let ab = section("app").unwrap_or(&empty);
    check_keys(ab, &["min_macos", "category", "frameworks", "info_plist"], "package.app")?;
    if let Some(v) = s(ab, "min_macos", "package.app")? {
        app_bundle = app_bundle.min_macos(v);
    }
    if let Some(v) = s(ab, "category", "package.app")? {
        app_bundle = app_bundle.category(v);
    }
    for f in strings(ab, "frameworks", "package.app")? {
        app_bundle = app_bundle.framework(rel(&f));
    }
    if let Some(extra) = ab.get("info_plist").and_then(|t| t.as_table()) {
        for (k, v) in extra {
            let pv = toml_to_plist(v).ok_or_else(|| format!("`package.app.info_plist.{k}` has an unsupported value"))?;
            app_bundle = app_bundle.info_plist(k, pv);
        }
    }

    let dmg = match section("dmg") {
        None => None,
        Some(d) => {
            check_keys(d, &["volume_name", "background", "icon_size", "window_size", "app_position", "applications_position", "volume_icon", "layout"], "package.dmg")?;
            let mut x = Dmg::new();
            if let Some(v) = s(d, "volume_name", "package.dmg")? {
                x = x.volume_name(v);
            }
            if let Some(v) = s(d, "background", "package.dmg")? {
                x = x.window_background(rel(v));
            }
            if let Some(v) = d.get("icon_size") {
                x = x.icon_size(v.as_int().ok_or("`package.dmg.icon_size` must be an integer")? as u32);
            }
            if let Some((w, h)) = pair(d, "window_size", "package.dmg")? {
                x = x.window_size(w, h);
            }
            if let Some((px, py)) = pair(d, "app_position", "package.dmg")? {
                x = x.app_position(px, py);
            }
            if let Some((px, py)) = pair(d, "applications_position", "package.dmg")? {
                x = x.applications_position(px, py);
            }
            if d.get("volume_icon").and_then(Toml::as_bool) == Some(false) {
                x = x.no_volume_icon();
            }
            if d.get("layout").and_then(Toml::as_bool) == Some(false) {
                x = x.no_layout();
            }
            Some(x)
        }
    };
    let pkg = match section("pkg") {
        None => None,
        Some(p) => {
            check_keys(p, &["install_location", "preinstall", "postinstall", "min_macos", "title"], "package.pkg")?;
            let mut x = Pkg::new();
            if let Some(v) = s(p, "install_location", "package.pkg")? {
                x = x.install_location(v);
            }
            if let Some(v) = s(p, "preinstall", "package.pkg")? {
                x = x.preinstall(rel(v));
            }
            if let Some(v) = s(p, "postinstall", "package.pkg")? {
                x = x.postinstall(rel(v));
            }
            if let Some(v) = s(p, "min_macos", "package.pkg")? {
                x = x.min_macos(v);
            }
            if let Some(v) = s(p, "title", "package.pkg")? {
                x = x.title(v);
            }
            Some(x)
        }
    };
    let msix = match section("msix") {
        None => None,
        Some(m) => {
            check_keys(m, &["min_version", "background", "publisher", "archs", "execution_alias"], "package.msix")?;
            let mut x = Msix::new();
            if let Some(v) = s(m, "min_version", "package.msix")? {
                x = x.min_version(v);
            }
            if let Some(v) = s(m, "background", "package.msix")? {
                x = x.background(v);
            }
            if let Some(v) = s(m, "publisher", "package.msix")? {
                x = x.publisher(v);
            }
            if let Some(v) = s(m, "execution_alias", "package.msix")? {
                x = x.execution_alias(v);
            }
            let archs = strings(m, "archs", "package.msix")?;
            if !archs.is_empty() {
                let parsed: Result<Vec<Arch>, String> = archs.iter().map(|a| Arch::parse(a).ok_or_else(|| format!("unknown architecture `{a}` in package.msix.archs"))).collect();
                x = x.archs(parsed?);
            }
            Some(x)
        }
    };
    let msi = match section("msi") {
        None => None,
        Some(m) => {
            check_keys(m, &["scope", "upgrade_code", "shortcut", "archs", "ui"], "package.msi")?;
            let mut x = Msi::new();
            match s(m, "scope", "package.msi")? {
                None | Some("per-machine") => {}
                Some("per-user") => x = x.per_user(),
                Some(o) => return Err(format!("package.msi.scope: `{o}` must be `per-machine` or `per-user`")),
            }
            if let Some(v) = s(m, "upgrade_code", "package.msi")? {
                x = x.upgrade_code(v);
            }
            if m.get("shortcut").and_then(Toml::as_bool) == Some(false) {
                x = x.no_shortcut();
            }
            match s(m, "ui", "package.msi")? {
                None | Some("basic") => {}
                Some("wizard") => x = x.wizard(),
                Some(o) => return Err(format!("package.msi.ui: `{o}` must be `basic` or `wizard`")),
            }
            let archs = strings(m, "archs", "package.msi")?;
            if !archs.is_empty() {
                let parsed: Result<Vec<Arch>, String> = archs.iter().map(|a| Arch::parse(a).ok_or_else(|| format!("unknown architecture `{a}` in package.msi.archs"))).collect();
                x = x.archs(parsed?);
            }
            Some(x)
        }
    };
    let msixbundle = match section("msixbundle") {
        None => None,
        Some(b) => {
            check_keys(b, &["archs"], "package.msixbundle")?;
            let archs = strings(b, "archs", "package.msixbundle")?;
            let parsed: Result<Vec<Arch>, String> = archs.iter().map(|a| Arch::parse(a).ok_or_else(|| format!("unknown architecture `{a}` in package.msixbundle.archs"))).collect();
            let parsed = parsed?;
            let mut x = if parsed.is_empty() { MsixBundle::all() } else { MsixBundle::new(parsed) };
            // The packages inside take [package.msix]'s settings.
            if let Some(m) = &msix {
                x = x.packages(m.clone());
            }
            Some(x)
        }
    };
    let app_package = section("app").is_some() || (dmg.is_none() && pkg.is_none() && msix.is_none() && msi.is_none() && msixbundle.is_none());

    let apple = match root.get("sign").and_then(|s| s.get("apple")) {
        None => None,
        Some(sa) => {
            check_keys(sa, &["identity", "installer_identity", "hardened_runtime", "entitlements", "timestamp", "requirements"], "sign.apple")?;
            // Paths in identity specs are relative to packager.toml too.
            let spec = |identity: &str| match identity.strip_prefix("p12:") {
                Some(p) => format!("p12:{}", rel(p).display()),
                None => match identity.strip_prefix("pem:").and_then(|p| p.split_once(',')) {
                    Some((c, k)) => format!("pem:{},{}", rel(c).display(), rel(k).display()),
                    None => identity.to_string(),
                },
            };
            let identity = spec(s(sa, "identity", "sign.apple")?.unwrap_or("-"));
            let mut ap = packager::sign::Apple::ad_hoc();
            ap.application = crate::codesign::identity(&identity, None)?;
            if let Some(i) = s(sa, "installer_identity", "sign.apple")? {
                ap.installer = Some(crate::codesign::identity(&spec(i), None)?);
            }
            if sa.get("hardened_runtime").and_then(Toml::as_bool) == Some(true) {
                ap = ap.hardened_runtime();
            }
            if let Some(e) = s(sa, "entitlements", "sign.apple")? {
                ap = ap.entitlements(rel(e)).map_err(|e| e.to_string())?;
            }
            if let Some(t) = s(sa, "timestamp", "sign.apple")? {
                ap = ap.timestamp(match t {
                    "auto" => packager::sign::Timestamp::Auto,
                    "none" => packager::sign::Timestamp::None,
                    "apple" => packager::sign::Timestamp::Apple,
                    url => packager::sign::Timestamp::Url(url.to_string()),
                });
            }
            if let Some(r) = s(sa, "requirements", "sign.apple")? {
                ap = ap.requirements(r);
            }
            Some(ap)
        }
    };
    let authenticode = match root.get("sign").and_then(|s| s.get("windows")) {
        None => None,
        Some(sw) => {
            check_keys(sw, &["identity", "timestamp", "digest"], "sign.windows")?;
            let identity = s(sw, "identity", "sign.windows")?.ok_or("[sign.windows] needs `identity`")?;
            let identity = match identity.strip_prefix("p12:") {
                Some(p) => format!("p12:{}", rel(p).display()),
                None => match identity.strip_prefix("pem:").and_then(|p| p.split_once(',')) {
                    Some((c, k)) => format!("pem:{},{}", rel(c).display(), rel(k).display()),
                    None => identity.to_string(),
                },
            };
            let packager::sign::AppleIdentity::Signer(signer) = crate::codesign::identity(&identity, None)? else {
                return Err("[sign.windows] identity can't be `-`: Authenticode needs a certificate".into());
            };
            let mut a = packager::sign::Authenticode::new(signer);
            if let Some(t) = s(sw, "timestamp", "sign.windows")? {
                if t != "none" {
                    a = a.timestamp(t);
                }
            }
            if let Some(d) = s(sw, "digest", "sign.windows")? {
                a.digest = match d {
                    "sha256" => packager::crypto::hmac::HashAlg::Sha256,
                    "sha384" => packager::crypto::hmac::HashAlg::Sha384,
                    "sha512" => packager::crypto::hmac::HashAlg::Sha512,
                    o => return Err(format!("sign.windows.digest: unknown `{o}`")),
                };
            }
            Some(a)
        }
    };
    let notarize = match root.get("notarize") {
        None => None,
        Some(n) => {
            check_keys(n, &["key", "key_id", "issuer", "timeout_minutes", "staple"], "notarize")?;
            let key = std::env::var("PACKAGER_NOTARY_KEY").ok().map(PathBuf::from).or(s(n, "key", "notarize")?.map(rel));
            let key_id = std::env::var("PACKAGER_NOTARY_KEY_ID").ok().or(s(n, "key_id", "notarize")?.map(String::from));
            let issuer = std::env::var("PACKAGER_NOTARY_ISSUER").ok().or(s(n, "issuer", "notarize")?.map(String::from));
            let key = key.ok_or("[notarize] needs `key` (an AuthKey_<ID>.p8 file) or PACKAGER_NOTARY_KEY")?;
            let api = packager::notary::ApiKey::from_file(&key, key_id.as_deref(), issuer.as_deref()).map_err(|e| e.to_string())?;
            let mut nz = packager::notary::Notarize::new(api);
            if let Some(m) = n.get("timeout_minutes").and_then(Toml::as_int) {
                nz.timeout = std::time::Duration::from_secs(m.max(1) as u64 * 60);
            }
            if let Some(b) = n.get("staple").and_then(Toml::as_bool) {
                nz.staple = b;
            }
            Some(nz)
        }
    };
    let out_dir = root
        .get("build")
        .map(|b| -> Result<Option<PathBuf>, String> {
            check_keys(b, &["out_dir"], "build")?;
            Ok(s(b, "out_dir", "build")?.map(rel))
        })
        .transpose()?
        .flatten()
        .unwrap_or_else(|| base.join("target/dist"));
    Ok(Config { app, app_bundle, dmg, pkg, msix, msi, msixbundle, app_package, apple, authenticode, notarize, out_dir })
}

fn toml_to_plist(v: &Toml) -> Option<packager::format::plist::Value> {
    use packager::format::plist::{Dict, Value};
    Some(match v {
        Toml::String(s) => Value::String(s.clone()),
        Toml::Integer(i) => Value::Integer(*i),
        Toml::Float(f) => Value::Real(*f),
        Toml::Bool(b) => Value::Bool(*b),
        Toml::Array(a) => Value::Array(a.iter().map(toml_to_plist).collect::<Option<_>>()?),
        Toml::Table(t) => {
            let mut d = Dict::new();
            for (k, x) in t {
                d.insert(k.clone(), toml_to_plist(x)?);
            }
            Value::Dict(d)
        }
    })
}
