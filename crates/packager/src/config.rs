//! Configuration files → [`App`], package builders and signing. `packager.toml` mirrors the
//! library one-to-one: `[app]` is `App`, `[package.<kind>]` is each builder, `[sign.apple]` and
//! `[sign.windows]` the signing configs, `[notarize]` notarization. The same tables can live in
//! `Cargo.toml` under `[package.metadata.packager]`, where the app's name, version, description
//! and publisher default to the crate's and the binary to its release build.
//!
//! ```no_run
//! let cfg = packager::config::load(std::path::Path::new("packager.toml"))?;
//! for p in cfg.run(None, None, true)?.packages() {
//!     println!("{} {}", p.kind(), p.path().display());
//! }
//! # Ok::<(), packager::Error>(())
//! ```

use std::path::{Path, PathBuf};

use crate::build::Output;
use crate::format::toml::{self, Toml};
use crate::package::{AppBundle, Confinement, Deb, DebCompression, Dmg, Msi, Msix, MsixBundle, Pkg, Snap};
use crate::{App, Arch, Error, Result};

/// Package kinds as configuration files and [`Config::run`] name them.
pub const KINDS: [&str; 8] = ["app", "dmg", "pkg", "msi", "msix", "msixbundle", "deb", "snap"];

/// A loaded configuration: the app, every configured builder and the signing settings. Fields
/// are public so tools can adjust them (add a framework, swap a signer) before [`Config::run`].
pub struct Config {
    /// The app.
    pub app: App,
    /// `.app` settings, shared by the `.dmg` and `.pkg`.
    pub app_bundle: AppBundle,
    /// `[package.dmg]`, when present.
    pub dmg: Option<Dmg>,
    /// `[package.pkg]`, when present.
    pub pkg: Option<Pkg>,
    /// `[package.msix]`, when present.
    pub msix: Option<Msix>,
    /// `[package.msi]`, when present.
    pub msi: Option<Msi>,
    /// `[package.msixbundle]`, when present.
    pub msixbundle: Option<MsixBundle>,
    /// `[package.deb]`, when present.
    pub deb: Option<Deb>,
    /// `[package.snap]`, when present.
    pub snap: Option<Snap>,
    /// Whether the `.app` itself is a requested output (`[package.app]`, or nothing else configured).
    pub app_package: bool,
    /// `[sign.apple]`.
    pub apple: Option<crate::sign::Apple>,
    /// `[sign.windows]`.
    pub authenticode: Option<crate::sign::Authenticode>,
    /// `[notarize]`.
    pub notarize: Option<crate::notary::Notarize>,
    /// `[build] out_dir` (default `target/dist`).
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
        Some(v) => {
            v.as_array().ok_or_else(|| format!("`{ctx}.{key}` must be an array"))?.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("`{ctx}.{key}` must hold strings"))).collect()
        }
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

/// What a `Cargo.toml` supplies when `[package.metadata.packager]` leaves it out.
#[derive(Debug, Clone, Default)]
struct Defaults {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    publisher: Option<String>,
    maintainer: Option<String>,
    binary: Option<PathBuf>,
    out_dir: Option<PathBuf>,
}

fn config_error(path: &Path, e: String) -> Error {
    Error::Other(format!("{}: {e}", path.display()))
}

/// Loads a `packager.toml`. Relative paths in it resolve against its directory.
pub fn load(path: &Path) -> Result<Config> {
    let src = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let root = toml::parse(&src).map_err(|e| config_error(path, e))?;
    let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
    from_table(&root, &base, &Defaults::default()).map_err(|e| config_error(path, e))
}

/// Loads `[package.metadata.packager]` from a `Cargo.toml`. The app's name, version and
/// description default to `[package]`'s (`version.workspace = true` is followed to the
/// workspace), the publisher and `.deb` maintainer to the first of `authors`, the binary to the
/// release build (`<target>/release/<name>`, architecture read from the file) and the output to
/// `<target>/dist`. `identifier` has to be given.
pub fn from_cargo_manifest(path: &Path) -> Result<Config> {
    let src = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let root = toml::parse(&src).map_err(|e| config_error(path, e))?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let package = root.get("package").ok_or_else(|| config_error(path, "no [package] table".into()))?;
    let name = package.get("name").and_then(Toml::as_str).map(String::from);
    let version = match package.get("version") {
        Some(Toml::String(v)) => Some(v.clone()),
        Some(t) if t.get("workspace").and_then(Toml::as_bool) == Some(true) => workspace_root(&dir).and_then(|(_, ws)| ws.get("workspace")?.get("package")?.get("version")?.as_str().map(String::from)),
        _ => None,
    };
    let author = package.get("authors").and_then(Toml::as_array).and_then(|a| a.first()).and_then(Toml::as_str).map(String::from);
    let target = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root(&dir).map_or_else(|| dir.clone(), |(d, _)| d).join("target"));
    let binary = name.as_ref().map(|n| {
        let b = target.join("release").join(n);
        if b.exists() || !b.with_extension("exe").exists() { b } else { b.with_extension("exe") }
    });
    let defaults = Defaults {
        version,
        description: package.get("description").and_then(Toml::as_str).map(String::from),
        publisher: author.as_deref().map(|a| a.split('<').next().unwrap_or(a).trim().to_string()).filter(|a| !a.is_empty()),
        maintainer: author.filter(|a| a.contains('<')),
        binary,
        out_dir: Some(target.join("dist")),
        name,
    };
    let empty = Toml::Table(Default::default());
    let table = root.get("package").and_then(|p| p.get("metadata")).and_then(|m| m.get("packager")).unwrap_or(&empty);
    from_table(table, &dir, &defaults).map_err(|e| config_error(path, format!("[package.metadata.packager]: {e}")))
}

/// The nearest directory at or above `dir` whose `Cargo.toml` has a `[workspace]`, and that file.
fn workspace_root(dir: &Path) -> Option<(PathBuf, Toml)> {
    let start = std::fs::canonicalize(dir).ok()?;
    for d in start.ancestors() {
        let f = d.join("Cargo.toml");
        if let Ok(src) = std::fs::read_to_string(&f)
            && let Ok(t) = toml::parse(&src)
            && t.get("workspace").is_some()
        {
            return Some((d.to_path_buf(), t));
        }
    }
    None
}

fn from_table(root: &Toml, base: &Path, defaults: &Defaults) -> Result<Config, String> {
    let base = base.to_path_buf();
    let rel = |p: &str| -> PathBuf { if Path::new(p).is_absolute() { PathBuf::from(p) } else { base.join(p) } };
    check_keys(root, &["app", "package", "sign", "notarize", "build"], "")?;

    let no_app = Toml::Table(Default::default());
    let a = match root.get("app") {
        Some(a) => a,
        None if defaults.name.is_some() => &no_app,
        None => return Err("missing [app] table".into()),
    };
    check_keys(a, &["name", "identifier", "version", "build_number", "publisher", "description", "copyright", "executable", "icon", "binaries", "resources", "url_schemes", "file_types"], "app")?;
    let name = s(a, "name", "app")?.map(String::from).or_else(|| defaults.name.clone()).ok_or("`app.name` is required")?;
    let version = s(a, "version", "app")?.map(String::from).or_else(|| defaults.version.clone()).ok_or("`app.version` is required")?;
    let mut app = App::new(name, req(a, "identifier", "app")?, version);
    if let Some(d) = &defaults.description {
        app = app.description(d.clone());
    }
    if let Some(p) = &defaults.publisher {
        app = app.publisher(p.clone());
    }
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
    match a.get("binaries") {
        Some(Toml::Table(t)) => {
            for (arch, p) in t {
                let arch_v = Arch::parse(arch).ok_or_else(|| format!("unknown architecture `{arch}` in app.binaries"))?;
                let p = p.as_str().ok_or_else(|| format!("`app.binaries.{arch}` must be a path"))?;
                app = app.binary(arch_v, rel(p));
            }
        }
        // A list of paths: each file's architecture is read from it.
        Some(Toml::Array(list)) => {
            for p in list {
                let p = p.as_str().ok_or("`app.binaries` must hold paths")?;
                app = app.binary_file(rel(p)).map_err(|e| e.to_string())?;
            }
        }
        Some(_) => return Err("`app.binaries` must be a table of arch = path, or a list of paths".into()),
        None => {
            if let Some(b) = defaults.binary.as_ref().filter(|b| b.exists()) {
                app = app.binary_file(b).map_err(|e| e.to_string())?;
            }
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
            check_keys(item, &["extension", "name", "mime_type"], "app.file_types")?;
            let (ext, name) = (req(item, "extension", "app.file_types")?, req(item, "name", "app.file_types")?);
            app = match s(item, "mime_type", "app.file_types")? {
                Some(m) => app.file_type_mime(ext, name, m),
                None => app.file_type(ext, name),
            };
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
    let linux_archs =
        |t: &Toml, ctx: &str| -> Result<Vec<Arch>, String> { strings(t, "archs", ctx)?.iter().map(|a| Arch::parse(a).ok_or_else(|| format!("unknown architecture `{a}` in {ctx}.archs"))).collect() };
    let deb = match section("deb") {
        None => None,
        Some(d) => {
            let ctx = "package.deb";
            check_keys(
                d,
                &[
                    "name",
                    "revision",
                    "maintainer",
                    "depends",
                    "recommends",
                    "auto_depends",
                    "section",
                    "priority",
                    "homepage",
                    "license",
                    "copyright_file",
                    "install_dir",
                    "bin_link",
                    "desktop_entry",
                    "categories",
                    "keywords",
                    "terminal",
                    "compression",
                    "archs",
                    "preinst",
                    "postinst",
                    "prerm",
                    "postrm",
                    "man_page",
                ],
                ctx,
            )?;
            let mut x = Deb::new();
            if let Some(v) = s(d, "name", ctx)? {
                x = x.name(v);
            }
            if let Some(v) = s(d, "revision", ctx)? {
                x = x.revision(v);
            }
            if let Some(v) = s(d, "maintainer", ctx)?.map(String::from).or_else(|| defaults.maintainer.clone()) {
                x = x.maintainer(v);
            }
            x = x.depends(strings(d, "depends", ctx)?).recommends(strings(d, "recommends", ctx)?);
            if d.get("auto_depends").and_then(Toml::as_bool) == Some(false) {
                x = x.no_auto_depends();
            }
            if let Some(v) = s(d, "section", ctx)? {
                x = x.section(v);
            }
            if let Some(v) = s(d, "priority", ctx)? {
                x = x.priority(v);
            }
            if let Some(v) = s(d, "homepage", ctx)? {
                x = x.homepage(v);
            }
            if let Some(v) = s(d, "license", ctx)? {
                x = x.license(v);
            }
            if let Some(v) = s(d, "copyright_file", ctx)? {
                x = x.copyright_file(rel(v));
            }
            if let Some(v) = s(d, "install_dir", ctx)? {
                x = x.install_dir(v);
            }
            if d.get("bin_link").and_then(Toml::as_bool) == Some(false) {
                x = x.no_bin_link();
            }
            if d.get("desktop_entry").and_then(Toml::as_bool) == Some(false) {
                x = x.no_desktop_entry();
            }
            if d.get("categories").is_some() {
                x = x.categories(strings(d, "categories", ctx)?);
            }
            x = x.keywords(strings(d, "keywords", ctx)?);
            if d.get("terminal").and_then(Toml::as_bool) == Some(true) {
                x = x.terminal();
            }
            match s(d, "compression", ctx)? {
                None | Some("gzip") => {}
                Some("xz") => x = x.compression(DebCompression::Xz),
                Some(o) => return Err(format!("package.deb.compression: `{o}` must be `gzip` or `xz`")),
            }
            if let Some(v) = s(d, "man_page", ctx)? {
                x = x.man_page(rel(v));
            }
            for kind in ["preinst", "postinst", "prerm", "postrm"] {
                if let Some(v) = s(d, kind, ctx)? {
                    x = x.script(kind, rel(v));
                }
            }
            let archs = linux_archs(d, ctx)?;
            if !archs.is_empty() {
                x = x.archs(archs);
            }
            Some(x)
        }
    };
    let snap = match section("snap") {
        None => None,
        Some(d) => {
            let ctx = "package.snap";
            check_keys(d, &["name", "summary", "title", "base", "grade", "confinement", "plugs", "extra_plugs", "license", "cli", "categories", "keywords", "environment", "archs"], ctx)?;
            let mut x = Snap::new();
            if d.get("cli").and_then(Toml::as_bool) == Some(true) {
                x = x.cli();
            }
            if let Some(v) = s(d, "name", ctx)? {
                x = x.name(v);
            }
            if let Some(v) = s(d, "summary", ctx)? {
                x = x.summary(v);
            }
            if let Some(v) = s(d, "title", ctx)? {
                x = x.title(v);
            }
            if let Some(v) = s(d, "base", ctx)? {
                x = x.base(v);
            }
            if let Some(v) = s(d, "grade", ctx)? {
                x = x.grade(v);
            }
            match s(d, "confinement", ctx)? {
                None | Some("strict") => {}
                Some("classic") => x = x.confinement(Confinement::Classic),
                Some("devmode") => x = x.confinement(Confinement::Devmode),
                Some(o) => return Err(format!("package.snap.confinement: `{o}` must be `strict`, `classic` or `devmode`")),
            }
            if d.get("plugs").is_some() {
                x = x.plugs(strings(d, "plugs", ctx)?);
            }
            for p in strings(d, "extra_plugs", ctx)? {
                x = x.plug(p);
            }
            if let Some(v) = s(d, "license", ctx)? {
                x = x.license(v);
            }
            if d.get("categories").is_some() {
                x = x.categories(strings(d, "categories", ctx)?);
            }
            x = x.keywords(strings(d, "keywords", ctx)?);
            if let Some(env) = d.get("environment") {
                for (k, v) in env.as_table().ok_or("`package.snap.environment` must be a table of NAME = \"value\"")? {
                    x = x.env(k.clone(), v.as_str().ok_or_else(|| format!("`package.snap.environment.{k}` must be a string"))?);
                }
            }
            let archs = linux_archs(d, ctx)?;
            if !archs.is_empty() {
                x = x.archs(archs);
            }
            Some(x)
        }
    };
    let app_package = section("app").is_some() || (dmg.is_none() && pkg.is_none() && msix.is_none() && msi.is_none() && msixbundle.is_none() && deb.is_none() && snap.is_none());

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
            let mut ap = crate::sign::Apple::ad_hoc();
            ap.application = crate::sign::identity(&identity, None).map_err(|e| e.to_string())?;
            if let Some(i) = s(sa, "installer_identity", "sign.apple")? {
                ap.installer = Some(crate::sign::identity(&spec(i), None).map_err(|e| e.to_string())?);
            }
            if sa.get("hardened_runtime").and_then(Toml::as_bool) == Some(true) {
                ap = ap.hardened_runtime();
            }
            // A plist file, or the entitlements inline: `entitlements = { "com.apple.security.cs.allow-jit" = true }`.
            match sa.get("entitlements") {
                None => {}
                Some(Toml::String(e)) => ap = ap.entitlements(rel(e)).map_err(|e| e.to_string())?,
                Some(t @ Toml::Table(_)) => ap = ap.entitlements_xml(toml_to_plist(t).ok_or("`sign.apple.entitlements` has an unsupported value")?.to_xml()),
                Some(_) => return Err("`sign.apple.entitlements` must be a plist path or a table".into()),
            }
            if let Some(t) = s(sa, "timestamp", "sign.apple")? {
                ap = ap.timestamp(match t {
                    "auto" => crate::sign::Timestamp::Auto,
                    "none" => crate::sign::Timestamp::None,
                    "apple" => crate::sign::Timestamp::Apple,
                    url => crate::sign::Timestamp::Url(url.to_string()),
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
            let crate::sign::AppleIdentity::Signer(signer) = crate::sign::identity(&identity, None).map_err(|e| e.to_string())? else {
                return Err("[sign.windows] identity can't be `-`: Authenticode needs a certificate".into());
            };
            let mut a = crate::sign::Authenticode::new(signer);
            if let Some(t) = s(sw, "timestamp", "sign.windows")?
                && t != "none"
            {
                a = a.timestamp(t);
            }
            if let Some(d) = s(sw, "digest", "sign.windows")? {
                a.digest = match d {
                    "sha256" => crate::crypto::hmac::HashAlg::Sha256,
                    "sha384" => crate::crypto::hmac::HashAlg::Sha384,
                    "sha512" => crate::crypto::hmac::HashAlg::Sha512,
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
            let api = crate::notary::ApiKey::from_file(&key, key_id.as_deref(), issuer.as_deref()).map_err(|e| e.to_string())?;
            let mut nz = crate::notary::Notarize::new(api);
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
        .or_else(|| defaults.out_dir.clone())
        .unwrap_or_else(|| base.join("target/dist"));
    Ok(Config { app, app_bundle, dmg, pkg, msix, msi, msixbundle, deb, snap, app_package, apple, authenticode, notarize, out_dir })
}

impl Config {
    /// Builds the configured packages, or only the kinds in `only` (see [`KINDS`]), into
    /// `out_dir` (default: the configured one). Notarizes when `[notarize]` is set and `notarize`
    /// is true.
    pub fn run(self, only: Option<&[&str]>, out_dir: Option<&Path>, notarize: bool) -> Result<Output> {
        if let Some(o) = only {
            for k in o {
                if !KINDS.contains(k) {
                    return Err(Error::invalid("config", "only", format!("unknown package kind `{k}` ({})", KINDS.join(", "))));
                }
            }
        }
        let want = |k: &str, configured: bool| only.map_or(configured, |o| o.contains(&k));
        let Config { app, app_bundle, dmg, pkg, msix, msi, msixbundle, deb, snap, app_package, apple, authenticode, notarize: nz, out_dir: configured_out } = self;
        let mut b = crate::build(&app).app_bundle(app_bundle.clone()).out_dir(out_dir.map(Path::to_path_buf).unwrap_or(configured_out));
        let mut any = false;
        if want("app", app_package) {
            b = b.package(app_bundle);
            any = true;
        }
        if want("dmg", dmg.is_some()) {
            b = b.package(dmg.unwrap_or_default());
            any = true;
        }
        if want("pkg", pkg.is_some()) {
            b = b.package(pkg.unwrap_or_default());
            any = true;
        }
        if want("msix", msix.is_some()) {
            b = b.package(msix.clone().unwrap_or_default());
            any = true;
        }
        if want("msixbundle", msixbundle.is_some()) {
            b = b.package(msixbundle.unwrap_or_else(MsixBundle::all));
            any = true;
        }
        if want("msi", msi.is_some()) {
            b = b.package(msi.unwrap_or_default());
            any = true;
        }
        if want("deb", deb.is_some()) {
            b = b.package(deb.unwrap_or_default());
            any = true;
        }
        if want("snap", snap.is_some()) {
            b = b.package(snap.unwrap_or_default());
            any = true;
        }
        if !any {
            return Err(Error::Other("nothing to build: add a [package.<kind>] table (app, dmg, pkg, msi, msix, msixbundle, deb, snap), or name the kinds".into()));
        }
        if let Some(a) = apple {
            b = b.sign(a);
        }
        if let Some(a) = authenticode {
            b = b.sign(a);
        }
        if let Some(n) = nz
            && notarize
        {
            b = b.notarize(n);
        }
        b.run()
    }
}

fn toml_to_plist(v: &Toml) -> Option<crate::format::plist::Value> {
    use crate::format::plist::{Dict, Value};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_loads() {
        let cfg = load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packager.example.toml")).unwrap();
        assert_eq!(cfg.app.identifier, "com.example.myapp");
        assert!(cfg.dmg.is_some() && cfg.msi.is_some() && cfg.deb.is_some() && cfg.snap.is_some());
        assert!(cfg.app.binaries.iter().any(|(a, _)| *a == Arch::LinuxX64));
    }

    #[test]
    fn inline_entitlements() {
        let root = toml::parse("[app]\nname = \"A\"\nidentifier = \"com.example.a\"\nversion = \"1.0.0\"\n[sign.apple.entitlements]\n\"com.apple.security.cs.allow-jit\" = true\n").unwrap();
        let cfg = from_table(&root, Path::new("."), &Defaults::default()).unwrap();
        let xml = String::from_utf8(cfg.apple.unwrap().entitlements.unwrap()).unwrap();
        assert!(xml.contains("<key>com.apple.security.cs.allow-jit</key>") && xml.contains("<true/>"), "{xml}");
    }

    #[test]
    fn cargo_manifest_defaults() {
        let root = std::env::temp_dir().join(format!("packager-cargo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let member = root.join("apps/notes");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::create_dir_all(root.join("target/release")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"apps/notes\"]\n[workspace.package]\nversion = \"2.3.4\"\n").unwrap();
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"notes\"\nversion.workspace = true\ndescription = \"Takes notes.\"\nauthors = [\"Example Ltd <dev@example.com>\"]\n\n\
             [package.metadata.packager.app]\nidentifier = \"com.example.notes\"\nurl_schemes = [\"notes\"]\n\n[package.metadata.packager.package.deb]\n",
        )
        .unwrap();
        std::fs::write(root.join("target/release/notes"), crate::format::elf::tests::stub(crate::format::elf::machine::X86_64)).unwrap();
        let cfg = from_cargo_manifest(&member.join("Cargo.toml")).unwrap();
        assert_eq!((cfg.app.name.as_str(), cfg.app.version.as_str()), ("notes", "2.3.4"));
        assert_eq!(cfg.app.description.as_deref(), Some("Takes notes."));
        assert_eq!(cfg.app.publisher.as_deref(), Some("Example Ltd"));
        assert_eq!(cfg.app.binaries, [(Arch::LinuxX64, std::fs::canonicalize(&root).unwrap().join("target/release/notes"))]);
        assert_eq!(cfg.app.url_schemes, ["notes"]);
        assert!(cfg.deb.is_some() && cfg.out_dir.ends_with("target/dist"));
        // `identifier` is required.
        std::fs::write(member.join("Cargo.toml"), "[package]\nname = \"notes\"\nversion = \"1.0.0\"\n").unwrap();
        assert!(from_cargo_manifest(&member.join("Cargo.toml")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
