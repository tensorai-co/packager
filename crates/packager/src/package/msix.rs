//! `.msix`: the modern Windows package. One per architecture, holding the signed executable,
//! the app's files, logos generated from the icon, and an `AppxManifest.xml` for a full-trust
//! desktop app (`Windows.FullTrustApplication` + `runFullTrust`).
//!
//! Signed with the Authenticode identity; the manifest's `Publisher` is taken from that
//! certificate's subject, since Windows refuses a package where they differ.

use crate::app::{App, Arch};
use crate::error::IoContext;
use crate::format::appx;
use crate::format::xml::Element;
use crate::identity::msix_version;
use crate::package::windows::{arch_label, exe_name, prepare_exe, resource_files, windows_archs};
use crate::package::{Context, Package, PackageBuilder, PackageKind, file_name};
use crate::util::source_date_epoch;
use crate::{Error, Result};

/// The `.msix` builder.
#[derive(Debug, Clone)]
pub struct Msix {
    archs: Option<Vec<Arch>>,
    min_version: String,
    max_version_tested: String,
    background: String,
    publisher: Option<String>,
    alias: Option<String>,
}

impl Default for Msix {
    fn default() -> Self {
        Self::new()
    }
}

/// (asset file, size) of the logos written into every package.
const LOGOS: [(&str, u32, u32); 4] = [("StoreLogo.png", 50, 50), ("Square44x44Logo.png", 44, 44), ("Square150x150Logo.png", 150, 150), ("Wide310x150Logo.png", 310, 150)];

impl Msix {
    /// One package per Windows binary, for Windows 10 1809 and later.
    pub fn new() -> Self {
        Msix { archs: None, min_version: "10.0.17763.0".into(), max_version_tested: "10.0.26100.0".into(), background: "transparent".into(), publisher: None, alias: None }
    }
    /// Only these architectures.
    pub fn archs(mut self, archs: impl IntoIterator<Item = Arch>) -> Self {
        self.archs = Some(archs.into_iter().collect());
        self
    }
    /// The oldest Windows version allowed (`TargetDeviceFamily MinVersion`).
    pub fn min_version(mut self, v: impl Into<String>) -> Self {
        self.min_version = v.into();
        self
    }
    /// The tile background color (`#RRGGBB` or `transparent`).
    pub fn background(mut self, c: impl Into<String>) -> Self {
        self.background = c.into();
        self
    }
    /// The `Publisher` for unsigned packages (signed ones use the certificate's subject).
    pub fn publisher(mut self, dn: impl Into<String>) -> Self {
        self.publisher = Some(dn.into());
        self
    }

    /// A command-line name for the app (`my-app` → `my-app.exe` on the `PATH`), through an app
    /// execution alias: how command-line tools in MSIX packages are run.
    pub fn execution_alias(mut self, name: impl Into<String>) -> Self {
        let n = name.into();
        self.alias = Some(if n.to_lowercase().ends_with(".exe") { n } else { format!("{n}.exe") });
        self
    }

    fn archs_for(&self, app: &App) -> Vec<Arch> {
        let have = windows_archs(app);
        match &self.archs {
            Some(want) => have.into_iter().filter(|a| want.contains(a)).collect(),
            None => have,
        }
    }

    /// The `AppxManifest.xml`.
    pub fn manifest(&self, app: &App, arch: Arch, publisher: &str) -> Result<String> {
        let version = msix_version(app)?;
        let display = app.name.clone();
        let publisher_display = app.publisher.clone().unwrap_or_else(|| app.name.clone());
        let description = app.description.clone().unwrap_or_else(|| app.name.clone());
        let mut ext = Element::new("Extensions");
        let mut any_ext = false;
        for s in &app.url_schemes {
            ext = ext.child(Element::new("uap:Extension").attr("Category", "windows.protocol").child(Element::new("uap:Protocol").attr("Name", s.to_lowercase())));
            any_ext = true;
        }
        for ft in &app.file_types {
            let name = ft.extension.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' }).collect::<String>();
            let assoc = Element::new("uap:FileTypeAssociation")
                .attr("Name", name)
                .child(Element::new("uap:DisplayName").text(ft.name.clone()))
                .child(Element::new("uap:SupportedFileTypes").child(Element::new("uap:FileType").text(format!(".{}", ft.extension.to_lowercase()))));
            ext = ext.child(Element::new("uap:Extension").attr("Category", "windows.fileTypeAssociation").child(assoc));
            any_ext = true;
        }
        if let Some(alias) = &self.alias {
            let a = Element::new("uap3:Extension")
                .attr("Category", "windows.appExecutionAlias")
                .attr("Executable", exe_name(app))
                .attr("EntryPoint", "Windows.FullTrustApplication")
                .child(Element::new("uap3:AppExecutionAlias").child(Element::new("desktop:ExecutionAlias").attr("Alias", alias.clone())));
            ext = ext.child(a);
            any_ext = true;
        }
        let visual = Element::new("uap:VisualElements")
            .attr("DisplayName", display.clone())
            .attr("Description", description)
            .attr("BackgroundColor", self.background.clone())
            .attr("Square150x150Logo", "Assets\\Square150x150Logo.png")
            .attr("Square44x44Logo", "Assets\\Square44x44Logo.png")
            .child(Element::new("uap:DefaultTile").attr("Wide310x150Logo", "Assets\\Wide310x150Logo.png"));
        let mut application = Element::new("Application").attr("Id", "App").attr("Executable", exe_name(app)).attr("EntryPoint", "Windows.FullTrustApplication").child(visual);
        if any_ext {
            application = application.child(ext);
        }
        let pkg = Element::new("Package")
            .attr("xmlns", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
            .attr("xmlns:uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
            .attr("xmlns:uap3", "http://schemas.microsoft.com/appx/manifest/uap/windows10/3")
            .attr("xmlns:desktop", "http://schemas.microsoft.com/appx/manifest/desktop/windows10")
            .attr("xmlns:rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
            .attr("IgnorableNamespaces", "uap uap3 desktop rescap")
            .child(Element::new("Identity").attr("Name", app.identifier.clone()).attr("Publisher", publisher).attr("Version", version).attr("ProcessorArchitecture", arch_label(arch)))
            .child(
                Element::new("Properties")
                    .child(Element::new("DisplayName").text(display))
                    .child(Element::new("PublisherDisplayName").text(publisher_display))
                    .child(Element::new("Logo").text("Assets\\StoreLogo.png")),
            )
            .child(
                Element::new("Dependencies")
                    .child(Element::new("TargetDeviceFamily").attr("Name", "Windows.Desktop").attr("MinVersion", self.min_version.clone()).attr("MaxVersionTested", self.max_version_tested.clone())),
            )
            .child(Element::new("Resources").child(Element::new("Resource").attr("Language", "en-us")))
            .child(Element::new("Applications").child(application))
            .child(Element::new("Capabilities").child(Element::new("rescap:Capability").attr("Name", "runFullTrust")));
        Ok(pkg.to_document(2))
    }

    fn logos(app: &App) -> Result<Vec<(String, Vec<u8>)>> {
        let src = match &app.icon {
            Some(p) if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("png")) => crate::image::Image::open_png(p)?,
            _ => {
                // No icon: a plain tile, so the package still installs.
                let mut i = crate::image::Image::new(256, 256);
                for px in i.rgba.chunks_mut(4) {
                    px.copy_from_slice(&[0x40, 0x60, 0x80, 0xff]);
                }
                i
            }
        };
        Ok(LOGOS
            .iter()
            .map(|(name, w, h)| {
                // Square art centered on wide tiles.
                let side = (*w).min(*h);
                let art = src.resize(side, side);
                let mut tile = crate::image::Image::new(*w, *h);
                let x0 = (w - side) / 2;
                for y in 0..side as usize {
                    let row = &art.rgba[y * side as usize * 4..(y + 1) * side as usize * 4];
                    let at = (y * *w as usize + x0 as usize) * 4;
                    tile.rgba[at..at + row.len()].copy_from_slice(row);
                }
                (format!("Assets/{name}"), tile.to_png())
            })
            .collect())
    }
}

impl PackageBuilder for Msix {
    fn kind(&self) -> PackageKind {
        PackageKind::Msix
    }
    fn validate(&self, app: &App) -> Result<()> {
        let id = &app.identifier;
        if id.len() < 3 || id.len() > 50 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err(Error::invalid("msix", "identifier", format!("`{id}` must be 3–50 letters, digits, `.` and `-` (MSIX Identity Name)")));
        }
        msix_version(app)?;
        if let Some(a) = &self.alias
            && (a.len() < 5 || a.contains(['/', '\\', ' ', ':']))
        {
            return Err(Error::invalid("msix", "execution_alias", format!("`{a}` must be a plain file name like `my-app.exe`")));
        }
        if self.archs_for(app).is_empty() {
            return Err(Error::invalid("msix", "binaries", "needs a windows-x64 or windows-arm64 binary"));
        }
        Ok(())
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app = ctx.app;
        let publisher = self.publisher_for(ctx)?;
        let mut out = Vec::new();
        for arch in self.archs_for(app) {
            let pkg = self.package_bytes(ctx, arch, &publisher)?;
            std::fs::create_dir_all(&ctx.out_dir).at(&ctx.out_dir)?;
            let path = ctx.out_dir.join(Self::file_name_for(app, arch));
            std::fs::write(&path, pkg).at(&path)?;
            out.push(Package::file(PackageKind::Msix, arch.name(), path, ctx.authenticode.is_some())?);
        }
        Ok(out)
    }
}

impl Msix {
    fn publisher_for(&self, ctx: &Context) -> Result<String> {
        let app = ctx.app;
        Ok(match (ctx.authenticode, &self.publisher) {
            (Some(a), _) => a.signer.leaf().map(|c| c.windows_subject()).ok_or_else(|| Error::Other("Authenticode signer has no certificate".into()))?,
            (None, Some(p)) => p.clone(),
            (None, None) => format!("CN={}", crate::crypto::x509::windows_dn_value(app.publisher.as_deref().unwrap_or(&app.name))),
        })
    }

    fn file_name_for(app: &App, arch: Arch) -> String {
        format!("{}-{}-{}.msix", file_name(&app.name), app.version, arch_label(arch))
    }

    /// One signed package for `arch`.
    fn package_bytes(&self, ctx: &Context, arch: Arch, publisher: &str) -> Result<Vec<u8>> {
        let app = ctx.app;
        let mut payload = vec![(exe_name(app), prepare_exe(app, arch, ctx.authenticode)?)];
        payload.extend(resource_files(app)?);
        payload.extend(Self::logos(app)?);
        let manifest = self.manifest(app, arch, publisher)?;
        let opts = ctx.authenticode.map(|a| a.options());
        let signer = ctx.authenticode.zip(opts.as_ref()).map(|(a, o)| (a.signer.as_ref(), o));
        appx::write(&payload, manifest.as_bytes(), signer, source_date_epoch())
    }
}

/// `.msixbundle`: one download with a package per architecture; Windows installs the one that
/// matches. Each inner package and the bundle are signed with the same identity.
#[derive(Debug, Clone)]
pub struct MsixBundle {
    msix: Msix,
}

impl MsixBundle {
    /// A bundle of these architectures' packages (those the app has binaries for).
    pub fn new(archs: impl IntoIterator<Item = Arch>) -> Self {
        MsixBundle { msix: Msix::new().archs(archs) }
    }
    /// A bundle of every Windows architecture the app has.
    pub fn all() -> Self {
        MsixBundle { msix: Msix::new() }
    }
    /// The settings for the packages inside (logos, alias, minimum version…).
    pub fn packages(mut self, msix: Msix) -> Self {
        let archs = self.msix.archs.take();
        self.msix = msix;
        if self.msix.archs.is_none() {
            self.msix.archs = archs;
        }
        self
    }
}

impl PackageBuilder for MsixBundle {
    fn kind(&self) -> PackageKind {
        PackageKind::MsixBundle
    }
    fn validate(&self, app: &App) -> Result<()> {
        self.msix.validate(app)
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app = ctx.app;
        let publisher = self.msix.publisher_for(ctx)?;
        let version = msix_version(app)?;
        let mut packages = Vec::new();
        for arch in self.msix.archs_for(app) {
            packages.push(appx::BundlePackage {
                file_name: Msix::file_name_for(app, arch),
                data: self.msix.package_bytes(ctx, arch, &publisher)?,
                version: version.clone(),
                architecture: arch_label(arch).into(),
                device_family: ("Windows.Desktop".into(), self.msix.min_version.clone(), self.msix.max_version_tested.clone()),
            });
        }
        let opts = ctx.authenticode.map(|a| a.options());
        let signer = ctx.authenticode.zip(opts.as_ref()).map(|(a, o)| (a.signer.as_ref(), o));
        let bundle = appx::write_bundle(&app.identifier, &publisher, &version, &packages, signer, source_date_epoch())?;
        std::fs::create_dir_all(&ctx.out_dir).at(&ctx.out_dir)?;
        let path = ctx.out_dir.join(format!("{}-{}.msixbundle", file_name(&app.name), app.version));
        std::fs::write(&path, bundle).at(&path)?;
        let label = packages.iter().map(|p| p.architecture.as_str()).collect::<Vec<_>>().join("+");
        Ok(vec![Package::file(PackageKind::MsixBundle, format!("windows-{label}"), path, ctx.authenticode.is_some())?])
    }
}
