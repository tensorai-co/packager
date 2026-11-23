//! `.dmg`: the drag-to-Applications disk image. An HFSX volume holding the signed `.app`, an
//! `Applications` symlink, the volume icon, and optionally a background and Finder layout
//! (`.DS_Store`), wrapped as a zlib-compressed UDIF image.

use std::path::{Path, PathBuf};

use crate::app::App;
use crate::compress::Level;
use crate::error::IoContext;
use crate::format::cpio::{self, Node, NodeKind};
use crate::format::ds_store::{self, Background, Layout};
use crate::format::hfsplus::{self, VolumeOptions};
use crate::format::udif::{self, PartitionType};
use crate::package::app_bundle::macos_arch_label;
use crate::package::{file_name, Context, Package, PackageBuilder, PackageKind};
use crate::util::source_date_epoch;
use crate::{Error, Result};

/// The `.dmg` builder. `Dmg::new()` alone gives a valid image: the app, an `Applications`
/// link and the app's icon as the volume icon, laid out side by side.
#[derive(Debug, Clone)]
pub struct Dmg {
    volume_name: Option<String>,
    background: Option<PathBuf>,
    window_size: (u32, u32),
    icon_size: u32,
    app_position: (u32, u32),
    applications_position: (u32, u32),
    volume_icon: bool,
    layout: bool,
}

impl Default for Dmg {
    fn default() -> Self {
        Self::new()
    }
}

impl Dmg {
    /// A 540×380 window with 128 px icons: the app on the left, Applications on the right.
    pub fn new() -> Self {
        Dmg {
            volume_name: None,
            background: None,
            window_size: (540, 380),
            icon_size: 128,
            app_position: (140, 180),
            applications_position: (400, 180),
            volume_icon: true,
            layout: true,
        }
    }
    /// The volume name (defaults to the app name).
    pub fn volume_name(mut self, n: impl Into<String>) -> Self {
        self.volume_name = Some(n.into());
        self
    }
    /// A PNG shown behind the icons; the window takes its size in points, following the image's
    /// DPI as Finder does (a 144-DPI image of 1080×760 pixels gives a 540×380 window). A file
    /// named `…@2x.png` is treated as 144 DPI.
    pub fn window_background(mut self, png: impl Into<PathBuf>) -> Self {
        self.background = Some(png.into());
        self
    }
    /// Window content size in points.
    pub fn window_size(mut self, w: u32, h: u32) -> Self {
        self.window_size = (w, h);
        self
    }
    /// Icon size in points (16–512).
    pub fn icon_size(mut self, s: u32) -> Self {
        self.icon_size = s;
        self
    }
    /// Where the app icon's center sits in the window.
    pub fn app_position(mut self, x: u32, y: u32) -> Self {
        self.app_position = (x, y);
        self
    }
    /// Where the Applications link's center sits.
    pub fn applications_position(mut self, x: u32, y: u32) -> Self {
        self.applications_position = (x, y);
        self
    }
    /// Skips the custom volume icon.
    pub fn no_volume_icon(mut self) -> Self {
        self.volume_icon = false;
        self
    }
    /// Skips the Finder layout (`.DS_Store`): Finder then uses its defaults.
    pub fn no_layout(mut self) -> Self {
        self.layout = false;
        self
    }

    fn volume_name_for(&self, app: &App) -> String {
        self.volume_name.clone().unwrap_or_else(|| app.name.clone())
    }

    /// Writes `<out>/<Name>-<version>.dmg` from an already signed `.app`.
    pub fn write_from_app(&self, app: &App, app_path: &Path, out: &Path) -> Result<PathBuf> {
        let mtime = source_date_epoch();
        let vol = self.volume_name_for(app);
        let bundle = app_path.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::invalid("dmg", "app", "bundle path has no name"))?.to_string();
        let mut nodes = cpio::tree_from_dir(app_path, &bundle, mtime)?;
        let node = |path: &str, kind: NodeKind, perm: u32| Node { path: path.into(), kind, perm, uid: 0, gid: 0, mtime };
        nodes.push(node("./Applications", NodeKind::Symlink("/Applications".into()), 0o755));
        let mut opts = VolumeOptions::new(&vol);
        opts.time = mtime;

        let icns = app_path.join("Contents/Resources/AppIcon.icns");
        if self.volume_icon && icns.is_file() {
            nodes.push(node("./.VolumeIcon.icns", NodeKind::File(std::fs::read(&icns).at(&icns)?), 0o644));
            opts.custom_icon = true;
            opts.invisible.push("./.VolumeIcon.icns".into());
        }
        let mut window = self.window_size;
        let mut background_name = None;
        if let Some(bg) = &self.background {
            let mut png = std::fs::read(bg).at(bg)?;
            let img = crate::format::png::decode(&png)?;
            // Finder draws the picture at its DPI (144 DPI = 2 pixels per point), so the window is
            // sized the same way. A `…@2x.png` without a Retina density tag gets one.
            if bg.to_string_lossy().ends_with("@2x.png") && crate::format::png::backing_scale(&png) == 1 {
                png = crate::format::png::with_dpi(&png, 144.0)?;
            }
            let scale = crate::format::png::backing_scale(&png);
            window = (img.width / scale, img.height / scale);
            nodes.push(node("./.background", NodeKind::Dir, 0o755));
            nodes.push(node("./.background/background.png", NodeKind::File(png), 0o644));
            opts.invisible.push("./.background".into());
            background_name = Some("background.png".to_string());
        }
        if self.layout {
            // The alias to the background needs the catalog IDs the volume will assign, which
            // depend only on paths: add the .DS_Store entry first, then fill it in.
            nodes.push(node("./.DS_Store", NodeKind::File(Vec::new()), 0o644));
            opts.invisible.push("./.DS_Store".into());
            let background = background_name.map(|file| Background {
                    volume_name: vol.clone(),
                    volume_created: hfsplus::hfs_time(mtime),
                    folder: (".background".into(), hfsplus::catalog_id(&nodes, "./.background").unwrap_or(0)),
                    file: (file.clone(), hfsplus::catalog_id(&nodes, &format!("./.background/{file}")).unwrap_or(0)),
                });
            let layout = Layout {
                window,
                icon_size: self.icon_size,
                positions: vec![(bundle.clone(), self.app_position), ("Applications".into(), self.applications_position)],
                background,
            };
            let store = ds_store::write(&layout)?;
            if let Some(n) = nodes.iter_mut().find(|n| n.path == "./.DS_Store") {
                n.kind = NodeKind::File(store);
            }
        }
        let volume = hfsplus::build(&nodes, &opts)?;
        let image = udif::write_udzo(&volume, PartitionType::Hfsx, Level::DEFAULT)?;
        std::fs::create_dir_all(out).at(out)?;
        let path = out.join(format!("{}-{}.dmg", file_name(&app.name), app.version));
        std::fs::write(&path, image).at(&path)?;
        Ok(path)
    }
}

impl PackageBuilder for Dmg {
    fn kind(&self) -> PackageKind {
        PackageKind::Dmg
    }
    fn validate(&self, app: &App) -> Result<()> {
        let vol = self.volume_name_for(app);
        if vol.is_empty() || vol.chars().count() > 27 || vol.contains(':') {
            return Err(Error::invalid("dmg", "volume_name", format!("`{vol}` must be 1 to 27 characters without `:` (Finder aliases store it as a Str27)")));
        }
        if !(16..=512).contains(&self.icon_size) {
            return Err(Error::invalid("dmg", "icon_size", "must be between 16 and 512"));
        }
        if let Some(bg) = &self.background
            && !bg.extension().is_some_and(|e| e.eq_ignore_ascii_case("png"))
        {
            return Err(Error::invalid("dmg", "window_background", "must be a PNG"));
        }
        Ok(())
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app_path = ctx.signed_app()?;
        let path = self.write_from_app(ctx.app, &app_path, &ctx.out_dir)?;
        // Order: the app inside was signed first; now the image itself, with the same identity
        // (ad-hoc builds leave the image unsigned, as codesign users do).
        let mut signed = false;
        if let Some(apple) = ctx.apple
            && let crate::sign::AppleIdentity::Signer(_) = &apple.application
        {
            let mut o = crate::sign::disk_image::DiskImageSignOptions::new(ctx.app.identifier.clone(), apple.application.clone());
            o.timestamp_url = apple.timestamp_url(&apple.application);
            let image = std::fs::read(&path).at(&path)?;
            std::fs::write(&path, crate::sign::disk_image::sign_disk_image(&image, &o)?).at(&path)?;
            signed = true;
        }
        Ok(vec![Package::file(PackageKind::Dmg, macos_arch_label(ctx.app), path, signed)?])
    }
}
