//! `.app`: the macOS app bundle — `Info.plist`, the (universal) executable, icon, resources and
//! nested frameworks — signed inside out.

use std::path::{Path, PathBuf};

use crate::app::{App, Arch};
use crate::error::IoContext;
use crate::format::macho;
use crate::format::plist::{Dict, Value};
use crate::identity::macos_versions;
use crate::package::{file_name, Context, Package, PackageBuilder, PackageKind};
use crate::sign::bundle::{sign_bundle, BundleSignOptions};
use crate::sign::{Apple, AppleIdentity};
use crate::util::{copy_file, copy_tree};
use crate::{Error, Result};

/// The `.app` builder.
#[derive(Debug, Clone)]
pub struct AppBundle {
    min_macos: String,
    category: Option<String>,
    frameworks: Vec<PathBuf>,
    extra: Dict,
}

impl Default for AppBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl AppBundle {
    /// Defaults: macOS 11 minimum, no category, no frameworks.
    pub fn new() -> Self {
        AppBundle { min_macos: "11.0".into(), category: None, frameworks: Vec::new(), extra: Dict::new() }
    }
    /// `LSMinimumSystemVersion`.
    pub fn min_macos(mut self, v: impl Into<String>) -> Self {
        self.min_macos = v.into();
        self
    }
    /// `LSApplicationCategoryType` (`public.app-category.productivity`…).
    pub fn category(mut self, c: impl Into<String>) -> Self {
        self.category = Some(c.into());
        self
    }
    /// A framework (or dylib) copied into `Contents/Frameworks`, symlinks preserved.
    pub fn framework(mut self, path: impl Into<PathBuf>) -> Self {
        self.frameworks.push(path.into());
        self
    }
    /// An extra `Info.plist` key, overriding the generated one.
    pub fn info_plist(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key, value);
        self
    }

    /// The minimum macOS version.
    pub fn min_macos_value(&self) -> &str {
        &self.min_macos
    }

    /// Checks the app against bundle rules.
    pub fn check(&self, app: &App) -> Result<()> {
        app.validate()?;
        macos_versions(app)?;
        let bins = app.macos_binaries();
        if bins.is_empty() {
            return Err(Error::invalid("app", "binary", "no macOS binary (macos-arm64, macos-x64 or macos-universal)"));
        }
        if bins.iter().any(|(a, _)| *a == Arch::MacosUniversal) && bins.len() > 1 {
            return Err(Error::invalid("app", "binary", "give either a macos-universal binary or per-architecture ones, not both"));
        }
        let mut seen = Vec::new();
        for (a, _) in &bins {
            if seen.contains(a) {
                return Err(Error::invalid("app", "binary", format!("two binaries for {a}")));
            }
            seen.push(*a);
        }
        let ok = self.min_macos.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            return Err(Error::invalid("app", "min_macos", format!("`{}` must look like `11.0`", self.min_macos)));
        }
        Ok(())
    }

    /// The generated `Info.plist`.
    pub fn info_plist_dict(&self, app: &App, icon_file: Option<&str>) -> Result<Dict> {
        let (short, build) = macos_versions(app)?;
        let mut d = Dict::new();
        d.insert("CFBundleDevelopmentRegion", "en");
        d.insert("CFBundleDisplayName", &app.name);
        d.insert("CFBundleExecutable", app.executable_name());
        if let Some(i) = icon_file {
            d.insert("CFBundleIconFile", i);
        }
        d.insert("CFBundleIdentifier", &app.identifier);
        d.insert("CFBundleInfoDictionaryVersion", "6.0");
        d.insert("CFBundleName", &app.name);
        d.insert("CFBundlePackageType", "APPL");
        d.insert("CFBundleShortVersionString", short);
        d.insert("CFBundleVersion", build);
        if !app.url_schemes.is_empty() {
            let schemes: Vec<Value> = app.url_schemes.iter().map(Value::from).collect();
            d.insert(
                "CFBundleURLTypes",
                vec![Value::Dict(Dict::new().with("CFBundleURLName", &app.identifier).with("CFBundleURLSchemes", schemes))],
            );
        }
        if !app.file_types.is_empty() {
            let types: Vec<Value> = app
                .file_types
                .iter()
                .map(|t| {
                    Value::Dict(
                        Dict::new()
                            .with("CFBundleTypeExtensions", vec![Value::from(&t.extension)])
                            .with("CFBundleTypeName", &t.name)
                            .with("CFBundleTypeRole", &t.role)
                            .with("LSHandlerRank", "Alternate"),
                    )
                })
                .collect();
            d.insert("CFBundleDocumentTypes", types);
        }
        if let Some(c) = &self.category {
            d.insert("LSApplicationCategoryType", c);
        }
        d.insert("LSMinimumSystemVersion", &self.min_macos);
        d.insert("NSHighResolutionCapable", true);
        if let Some(c) = &app.copyright {
            d.insert("NSHumanReadableCopyright", c);
        }
        for (k, v) in self.extra.iter() {
            d.insert(k, v.clone());
        }
        Ok(d)
    }

    /// The executable: the universal binary as given, or the per-architecture ones merged.
    fn executable_bytes(&self, app: &App) -> Result<(Vec<u8>, &'static str)> {
        let bins = app.macos_binaries();
        let mut inputs = Vec::new();
        for (_, p) in &bins {
            let data = std::fs::read(p).at(p)?;
            if !macho::is_macho(&data) {
                return Err(Error::invalid("app", "binary", format!("{} isn't a Mach-O executable", p.display())));
            }
            inputs.push(data);
        }
        let merged = if inputs.len() == 1 { inputs.remove(0) } else { macho::merge_universal(&inputs)? };
        let slices = macho::slices(&merged)?;
        for s in &slices {
            if macho::Image::parse(&s.data)?.filetype != macho::MH_EXECUTE {
                return Err(Error::invalid("app", "binary", "the main binary must be an executable (MH_EXECUTE)"));
            }
        }
        let arch = match slices.len() {
            1 if slices[0].cputype == macho::CPU_TYPE_ARM64 => "macos-arm64",
            1 => "macos-x64",
            _ => "macos-universal",
        };
        Ok((merged, arch))
    }

    /// Assembles and signs `<dir>/<name>.app`. Without an Apple config it signs ad hoc.
    pub fn write(&self, app: &App, dir: &Path, apple: Option<&Apple>) -> Result<PathBuf> {
        self.check(app)?;
        let bundle = dir.join(format!("{}.app", file_name(&app.name)));
        if bundle.exists() {
            std::fs::remove_dir_all(&bundle).at(&bundle)?;
        }
        let contents = bundle.join("Contents");
        let macos = contents.join("MacOS");
        let res = contents.join("Resources");
        std::fs::create_dir_all(&macos).at(&macos)?;
        std::fs::create_dir_all(&res).at(&res)?;

        let (exe, _) = self.executable_bytes(app)?;
        let exe_path = macos.join(app.executable_name());
        std::fs::write(&exe_path, exe).at(&exe_path)?;
        crate::util::set_mode(&exe_path, 0o755)?;

        let icon_file = match &app.icon {
            Some(src) => {
                let icns = if src.extension().is_some_and(|e| e.eq_ignore_ascii_case("icns")) {
                    std::fs::read(src).at(src)?
                } else {
                    crate::image::icns_from_png(src)?
                };
                let p = res.join("AppIcon.icns");
                std::fs::write(&p, icns).at(&p)?;
                Some("AppIcon")
            }
            None => None,
        };

        for r in &app.resources {
            let dest = res.join(&r.dest);
            if !dest.starts_with(&res) || r.dest.split('/').any(|c| c == "..") {
                return Err(Error::invalid("app", "resources", format!("destination `{}` leaves the bundle", r.dest)));
            }
            let meta = std::fs::metadata(&r.source).at(&r.source)?;
            if meta.is_dir() {
                copy_tree(&r.source, &dest)?;
            } else {
                copy_file(&r.source, &dest, false)?;
            }
        }
        if !self.frameworks.is_empty() {
            let fw = contents.join("Frameworks");
            for f in &self.frameworks {
                let name = f.file_name().ok_or_else(|| Error::invalid("app", "framework", "path has no file name"))?;
                copy_tree(f, &fw.join(name))?;
            }
        }

        let info = Value::Dict(self.info_plist_dict(app, icon_file)?).to_xml();
        let info_path = contents.join("Info.plist");
        std::fs::write(&info_path, info).at(&info_path)?;
        let pkginfo = contents.join("PkgInfo");
        std::fs::write(&pkginfo, b"APPL????").at(&pkginfo)?;

        let opts = match apple {
            Some(a) => BundleSignOptions { identity: a.application.clone(), hardened_runtime: a.hardened_runtime, entitlements: a.entitlements.clone() },
            None => BundleSignOptions { identity: AppleIdentity::AdHoc, hardened_runtime: false, entitlements: None },
        };
        sign_bundle(&bundle, &opts)?;
        Ok(bundle)
    }
}

impl PackageBuilder for AppBundle {
    fn kind(&self) -> PackageKind {
        PackageKind::App
    }
    fn validate(&self, app: &App) -> Result<()> {
        self.check(app)
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let path = self.write(ctx.app, &ctx.out_dir, ctx.apple)?;
        ctx.set_signed_app(path.clone());
        let (_, arch) = self.executable_bytes(ctx.app)?;
        Ok(vec![Package::dir(PackageKind::App, arch, path, true)?])
    }
}

/// The architecture label for the app's macOS binaries.
pub(crate) fn macos_arch_label(app: &App) -> &'static str {
    let bins = app.macos_binaries();
    match bins.as_slice() {
        [(Arch::MacosArm64, _)] => "macos-arm64",
        [(Arch::MacosX64, _)] => "macos-x64",
        _ => "macos-universal",
    }
}
