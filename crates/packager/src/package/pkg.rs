//! `.pkg`: a flat product archive (what `productbuild` writes) — a XAR holding `Distribution` and
//! one component package (`PackageInfo`, `Bom`, gzip'd cpio `Payload`, optional `Scripts`).

use std::path::PathBuf;

use crate::app::App;
use crate::compress::{gzip, Level};
use crate::error::IoContext;
use crate::format::cpio::{self, Node, NodeKind};
use crate::format::xar::{self, XarEntry};
use crate::format::xml::Element;
use crate::format::{bom, plist};
use crate::identity::macos_versions;
use crate::package::app_bundle::macos_arch_label;
use crate::package::{file_name, Context, Package, PackageBuilder, PackageKind};
use crate::util::source_date_epoch;
use crate::{Error, Result};

/// The `.pkg` builder.
#[derive(Debug, Clone)]
pub struct Pkg {
    install_location: String,
    preinstall: Option<PathBuf>,
    postinstall: Option<PathBuf>,
    min_macos: Option<String>,
    title: Option<String>,
}

impl Default for Pkg {
    fn default() -> Self {
        Self::new()
    }
}

impl Pkg {
    /// Installs the app into `/Applications`, not relocatable, no scripts.
    pub fn new() -> Self {
        Pkg { install_location: "/Applications".into(), preinstall: None, postinstall: None, min_macos: None, title: None }
    }
    /// Where the `.app` is installed (default `/Applications`).
    pub fn install_location(mut self, path: impl Into<String>) -> Self {
        self.install_location = path.into();
        self
    }
    /// A `preinstall` script.
    pub fn preinstall(mut self, script: impl Into<PathBuf>) -> Self {
        self.preinstall = Some(script.into());
        self
    }
    /// A `postinstall` script.
    pub fn postinstall(mut self, script: impl Into<PathBuf>) -> Self {
        self.postinstall = Some(script.into());
        self
    }
    /// Minimum macOS the installer allows (defaults to the `.app`'s `LSMinimumSystemVersion`).
    pub fn min_macos(mut self, v: impl Into<String>) -> Self {
        self.min_macos = Some(v.into());
        self
    }
    /// The installer window title (defaults to the app name).
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.title = Some(t.into());
        self
    }

    /// Writes `<out>/<Name>-<version>.pkg` from an already signed `.app`.
    pub fn write_from_app(&self, app: &App, app_path: &std::path::Path, out: &std::path::Path, min_macos: &str) -> Result<PathBuf> {
        let mtime = source_date_epoch();
        let (short, build) = macos_versions(app)?;
        let bundle_name = app_path.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::invalid("pkg", "app", "bundle path has no name"))?.to_string();

        let nodes = cpio::tree_from_dir(app_path, &bundle_name, mtime)?;
        let nested = nested_bundles(&nodes);
        let payload = gzip(&cpio::write_odc(&nodes)?, Level::DEFAULT);
        let bom = bom::write(&nodes)?;
        let install_bytes: u64 = nodes.iter().map(|n| n.size() as u64).sum();
        let install_kb = install_bytes.div_ceil(1024);
        let files = nodes.len();

        let id = &app.identifier;
        let main_bundle = |e: &str| Element::new(e).child(Element::new("bundle").attr("id", id.as_str()));
        let mut info = Element::new("pkg-info")
            .attr("overwrite-permissions", "true")
            .attr("relocatable", "false")
            .attr("identifier", id.as_str())
            .attr("postinstall-action", "none")
            .attr("version", short.as_str())
            .attr("format-version", "2")
            .attr("generator-version", concat!("packager-", env!("CARGO_PKG_VERSION")))
            .attr("install-location", self.install_location.as_str())
            .attr("auth", "root")
            .child(Element::new("payload").attr("numberOfFiles", files.to_string()).attr("installKBytes", install_kb.to_string()));
        if self.preinstall.is_some() || self.postinstall.is_some() {
            let mut s = Element::new("scripts");
            if self.preinstall.is_some() {
                s = s.child(Element::new("preinstall").attr("file", "./preinstall"));
            }
            if self.postinstall.is_some() {
                s = s.child(Element::new("postinstall").attr("file", "./postinstall"));
            }
            info = info.child(s);
        }
        for (bid, path) in &nested {
            info = info.child(Element::new("bundle").attr("id", bid.as_str()).attr("path", path.as_str()));
        }
        let mut strict = Element::new("strict-identifier");
        for (bid, _) in &nested {
            strict = strict.child(Element::new("bundle").attr("id", bid.as_str()));
        }
        // An empty <relocate/> keeps BundleIsRelocatable off, so the installer never "upgrades" a
        // stray copy of the app somewhere else on disk.
        let info = info
            .child(main_bundle("bundle-version"))
            .child(main_bundle("upgrade-bundle"))
            .child(Element::new("update-bundle"))
            .child(Element::new("atomic-update-bundle"))
            .child(strict)
            .child(Element::new("relocate"));
        let package_info = info.to_document(4).replacen("encoding=\"UTF-8\"", "encoding=\"utf-8\"", 1);

        let component = format!("{}.pkg", file_name(&app.executable_name()).replace(' ', "-"));
        let mut component_files = vec![XarEntry::file("Bom", bom), XarEntry::raw("Payload", payload), XarEntry::file("PackageInfo", package_info.into_bytes())];
        if let Some(scripts) = self.scripts_archive(mtime)? {
            component_files.push(XarEntry::raw("Scripts", scripts));
        }

        let host_archs = match macos_arch_label(app) {
            "macos-arm64" => "arm64",
            "macos-x64" => "x86_64",
            _ => "arm64,x86_64",
        };
        let title = self.title.clone().unwrap_or_else(|| app.name.clone());
        let pkg_ref = || Element::new("pkg-ref").attr("id", id.as_str());
        let dist = Element::new("installer-gui-script")
            .attr("minSpecVersion", "2")
            .child(Element::new("title").text(title))
            .child(pkg_ref().child(Element::new("bundle-version").child(
                Element::new("bundle").attr("CFBundleShortVersionString", short.as_str()).attr("CFBundleVersion", build.as_str()).attr("id", id.as_str()).attr("path", bundle_name.as_str()),
            )))
            .child(Element::new("options").attr("customize", "never").attr("require-scripts", "false").attr("hostArchitectures", host_archs))
            .child(Element::new("domains").attr("enable_anywhere", "false").attr("enable_currentUserHome", "false").attr("enable_localSystem", "true"))
            .child(Element::new("volume-check").child(Element::new("allowed-os-versions").child(Element::new("os-version").attr("min", min_macos))))
            .child(Element::new("choices-outline").child(Element::new("line").attr("choice", "default").child(Element::new("line").attr("choice", id.as_str()))))
            .child(Element::new("choice").attr("id", "default"))
            .child(Element::new("choice").attr("id", id.as_str()).attr("visible", "false").child(pkg_ref()))
            .child(pkg_ref().attr("version", short.as_str()).attr("onConclusion", "none").attr("installKBytes", install_kb.to_string()).text(format!("#{component}")));
        let distribution = dist.to_document(4).replacen("encoding=\"UTF-8\"", "encoding=\"utf-8\"", 1);

        let archive = xar::write(&[XarEntry::file("Distribution", distribution.into_bytes()), XarEntry::dir(component, component_files)], mtime)?;
        let path = out.join(format!("{}-{}.pkg", file_name(&app.name), app.version));
        std::fs::create_dir_all(out).at(out)?;
        std::fs::write(&path, archive).at(&path)?;
        Ok(path)
    }

    fn scripts_archive(&self, mtime: i64) -> Result<Option<Vec<u8>>> {
        if self.preinstall.is_none() && self.postinstall.is_none() {
            return Ok(None);
        }
        let mut nodes = vec![Node { path: ".".into(), kind: NodeKind::Dir, perm: 0o755, uid: 0, gid: 0, mtime }];
        for (name, src) in [("preinstall", &self.preinstall), ("postinstall", &self.postinstall)] {
            if let Some(src) = src {
                let data = std::fs::read(src).at(src)?;
                if !data.starts_with(b"#!") {
                    return Err(Error::invalid("pkg", name, format!("{} must start with a `#!` line", src.display())));
                }
                nodes.push(Node { path: format!("./{name}"), kind: NodeKind::File(data), perm: 0o755, uid: 0, gid: 0, mtime });
            }
        }
        Ok(Some(gzip(&cpio::write_odc(&nodes)?, Level::DEFAULT)))
    }
}

/// Every bundle in the payload with an `Info.plist` identifier: (id, `./path`), deepest first,
/// as `pkgbuild` lists them.
fn nested_bundles(nodes: &[Node]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for n in nodes {
        if let NodeKind::File(data) = &n.kind
            && let Some(bundle) = n.path.strip_suffix("/Contents/Info.plist")
            && let Ok(v) = plist::Value::parse(data)
            && let Some(id) = v.as_dict().and_then(|d| d.get_str("CFBundleIdentifier"))
        {
            out.push((id.to_string(), bundle.to_string()));
        }
    }
    out.sort_by(|a, b| b.1.matches('/').count().cmp(&a.1.matches('/').count()).then(a.1.cmp(&b.1)));
    out
}

impl PackageBuilder for Pkg {
    fn kind(&self) -> PackageKind {
        PackageKind::Pkg
    }
    fn validate(&self, app: &App) -> Result<()> {
        if !self.install_location.starts_with('/') {
            return Err(Error::invalid("pkg", "install_location", "must be an absolute path"));
        }
        macos_versions(app)?;
        Ok(())
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app_path = ctx.signed_app()?;
        let min = self.min_macos.clone().unwrap_or_else(|| ctx.app_bundle.min_macos_value().to_string());
        let path = self.write_from_app(ctx.app, &app_path, &ctx.out_dir, &min)?;
        // Installer signatures need a Developer ID Installer identity (CMS); not yet available.
        Ok(vec![Package::file(PackageKind::Pkg, macos_arch_label(ctx.app), path, false)?])
    }
}
