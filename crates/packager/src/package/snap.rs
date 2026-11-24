//! `.snap`: Ubuntu's snap package (what `snap pack` writes). A SquashFS image, xz-compressed and
//! owned by root, holding the app and `meta/snap.yaml`, plus `meta/gui/<app>.desktop` and
//! `meta/gui/icon.png` for the menu entry; one snap per Linux architecture.
//!
//! The app's executable and resources sit at the root of the snap (`$SNAP`), the way they sit
//! together in `/opt/<name>` in a `.deb`. Snaps aren't signed as files: the Snap Store signs
//! what's uploaded, and a local file installs with `snap install --dangerous`.

use crate::app::{App, Arch};
use crate::error::IoContext;
use crate::format::cpio::{Node, NodeKind};
use crate::format::squashfs::{self, Compression};
use crate::identity::{snap_name, snap_version};
use crate::package::linux::{self, complete_tree, DesktopEntry};
use crate::package::{Context, Package, PackageBuilder, PackageKind};
use crate::util::source_date_epoch;
use crate::{Error, Result};

/// How a snap is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confinement {
    /// Sandboxed, with access through the declared plugs (the default, and what the Snap Store
    /// accepts without review).
    Strict,
    /// Runs like a normally installed app with the host's libraries (needs Snap Store approval).
    Classic,
    /// Sandbox violations are only logged (for development; can't be released to stable).
    Devmode,
}

impl Confinement {
    fn name(self) -> &'static str {
        match self {
            Confinement::Strict => "strict",
            Confinement::Classic => "classic",
            Confinement::Devmode => "devmode",
        }
    }
}

/// The plugs a desktop app gets by default: its windows, GPU, sound, the network and the
/// user's home directory.
pub const DESKTOP_PLUGS: &[&str] = &["desktop", "desktop-legacy", "wayland", "x11", "opengl", "audio-playback", "network", "home"];

/// The `.snap` builder.
#[derive(Debug, Clone)]
pub struct Snap {
    name: Option<String>,
    summary: Option<String>,
    title: Option<String>,
    base: String,
    grade: Option<String>,
    confinement: Confinement,
    plugs: Vec<String>,
    license: Option<String>,
    desktop: bool,
    categories: Vec<String>,
    keywords: Vec<String>,
    environment: Vec<(String, String)>,
    archs: Option<Vec<Arch>>,
}

impl Default for Snap {
    fn default() -> Self {
        Self::new()
    }
}

impl Snap {
    /// A strictly confined desktop app on `core24`, named after the identifier, with
    /// [`DESKTOP_PLUGS`]. The grade is `stable`, or `devel` for pre-release versions.
    pub fn new() -> Self {
        Snap {
            name: None,
            summary: None,
            title: None,
            base: "core24".into(),
            grade: None,
            confinement: Confinement::Strict,
            plugs: DESKTOP_PLUGS.iter().map(|s| s.to_string()).collect(),
            license: None,
            desktop: true,
            categories: vec!["Utility".into()],
            keywords: Vec::new(),
            environment: Vec::new(),
            archs: None,
        }
    }
    /// The snap name (default: the identifier's last part, lowercased).
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }
    /// One-line summary, at most 78 characters (default: the description's first line).
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = Some(s.into());
        self
    }
    /// Display title (default: the app name).
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.title = Some(t.into());
        self
    }
    /// The base snap providing the runtime (default `core24`, Ubuntu 24.04's libraries).
    pub fn base(mut self, b: impl Into<String>) -> Self {
        self.base = b.into();
        self
    }
    /// `stable` or `devel`.
    pub fn grade(mut self, g: impl Into<String>) -> Self {
        self.grade = Some(g.into());
        self
    }
    /// Confinement (default strict).
    pub fn confinement(mut self, c: Confinement) -> Self {
        self.confinement = c;
        self
    }
    /// Replaces the plugs (interfaces the app connects to).
    pub fn plugs<S: Into<String>>(mut self, p: impl IntoIterator<Item = S>) -> Self {
        self.plugs = p.into_iter().map(Into::into).collect();
        self
    }
    /// Adds a plug (`camera`, `removable-media`…).
    pub fn plug(mut self, p: impl Into<String>) -> Self {
        let p = p.into();
        if !self.plugs.contains(&p) {
            self.plugs.push(p);
        }
        self
    }
    /// The license as an SPDX expression (`MIT`, `Apache-2.0`).
    pub fn license(mut self, l: impl Into<String>) -> Self {
        self.license = Some(l.into());
        self
    }
    /// No menu entry or icon (command-line tools); also drops the desktop plugs.
    pub fn cli(mut self) -> Self {
        self.desktop = false;
        self.plugs = vec!["home".into(), "network".into()];
        self
    }
    /// Menu categories (default `Utility`).
    pub fn categories<S: Into<String>>(mut self, c: impl IntoIterator<Item = S>) -> Self {
        self.categories = c.into_iter().map(Into::into).collect();
        self
    }
    /// Search keywords for the menu entry.
    pub fn keywords<S: Into<String>>(mut self, k: impl IntoIterator<Item = S>) -> Self {
        self.keywords = k.into_iter().map(Into::into).collect();
        self
    }
    /// An environment variable for the app (`$SNAP` expands to the snap's directory).
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.environment.push((k.into(), v.into()));
        self
    }
    /// Only these architectures (default: every Linux binary).
    pub fn archs(mut self, a: impl IntoIterator<Item = Arch>) -> Self {
        self.archs = Some(a.into_iter().collect());
        self
    }

    fn grade_for(&self, app: &App) -> Result<String> {
        Ok(match &self.grade {
            Some(g) => g.clone(),
            None if app.parsed_version()?.pre.is_some() => "devel".into(),
            None => "stable".into(),
        })
    }

    fn summary_for(&self, app: &App) -> String {
        self.summary.clone().unwrap_or_else(|| app.description.as_deref().and_then(|d| d.lines().next()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| app.name.clone()))
    }

    /// `meta/snap.yaml`.
    pub fn snap_yaml(&self, app: &App, arch: Arch) -> Result<String> {
        let name = snap_name(app, self.name.as_deref())?;
        let mut y = String::new();
        y.push_str(&format!("name: {name}\n"));
        y.push_str(&format!("version: {}\n", quote(&snap_version(app)?)));
        y.push_str(&format!("summary: {}\n", quote(&self.summary_for(app))));
        let description = app.description.clone().unwrap_or_else(|| self.summary_for(app));
        y.push_str("description: |\n");
        for line in description.lines() {
            if line.trim().is_empty() {
                y.push('\n');
            } else {
                y.push_str(&format!("  {}\n", line.trim_end()));
            }
        }
        y.push_str(&format!("title: {}\n", quote(self.title.as_deref().unwrap_or(&app.name))));
        if let Some(l) = &self.license {
            y.push_str(&format!("license: {}\n", quote(l)));
        }
        y.push_str(&format!("base: {}\n", self.base));
        y.push_str(&format!("grade: {}\n", self.grade_for(app)?));
        y.push_str(&format!("confinement: {}\n", self.confinement.name()));
        y.push_str(&format!("architectures:\n- {}\n", linux::arch_label(arch)));
        y.push_str("apps:\n");
        y.push_str(&format!("  {name}:\n"));
        y.push_str(&format!("    command: {}\n", linux::exe_name(app)));
        y.push_str(&format!("    common-id: {}\n", app.identifier));
        if self.confinement != Confinement::Classic && !self.plugs.is_empty() {
            y.push_str("    plugs:\n");
            for p in &self.plugs {
                y.push_str(&format!("    - {p}\n"));
            }
        }
        if !self.environment.is_empty() {
            y.push_str("    environment:\n");
            for (k, v) in &self.environment {
                y.push_str(&format!("      {k}: {}\n", quote(v)));
            }
        }
        Ok(y)
    }

    /// The image's file tree for `arch`.
    pub fn nodes(&self, app: &App, arch: Arch) -> Result<Vec<Node>> {
        let mtime = source_date_epoch();
        let name = snap_name(app, self.name.as_deref())?;
        let exe = linux::exe_name(app);
        let (binary, _) = linux::read_binary(app, arch)?;
        let node = |path: String, kind: NodeKind, perm: u32| Node { path, kind, perm, uid: 0, gid: 0, mtime };
        let mut nodes = vec![node(".".into(), NodeKind::Dir, 0o755), node(format!("./{exe}"), NodeKind::File(binary), 0o755)];
        nodes.extend(linux::resource_nodes(app, ".", mtime, &["meta", "snap", exe.as_str()])?);
        nodes.push(node("./meta/snap.yaml".into(), NodeKind::File(self.snap_yaml(app, arch)?.into_bytes()), 0o644));
        if self.desktop {
            let icons = linux::icon_set(app)?;
            if let Some((_, png)) = icons.iter().rev().find(|(s, _)| *s <= 512).or(icons.last()) {
                nodes.push(node("./meta/gui/icon.png".into(), NodeKind::File(png.clone()), 0o644));
            }
            let types = linux::mime_types(app, &name);
            let entry = DesktopEntry {
                // snapd rewrites `Exec` to run the app through /snap/bin; it must name the app.
                exec: name.clone(),
                icon: if icons.is_empty() { None } else { Some("${SNAP}/meta/gui/icon.png".into()) },
                categories: &self.categories,
                terminal: false,
                wm_class: None,
                mime_types: linux::handled_mime_types(app, &types),
                keywords: &self.keywords,
            };
            nodes.push(node(format!("./meta/gui/{name}.desktop"), NodeKind::File(linux::desktop_entry(app, &entry).into_bytes()), 0o644));
        }
        complete_tree(nodes, mtime)
    }

    /// Builds the snap's bytes for `arch`.
    pub fn package_bytes(&self, app: &App, arch: Arch) -> Result<Vec<u8>> {
        let nodes = self.nodes(app, arch)?;
        squashfs::write(&nodes, &squashfs::Options { compression: Compression::Xz, block_size: 1 << 17, mkfs_time: source_date_epoch() })
    }

    fn file_name(&self, app: &App, arch: Arch) -> Result<String> {
        Ok(format!("{}_{}_{}.snap", snap_name(app, self.name.as_deref())?, snap_version(app)?, linux::arch_label(arch)))
    }
}

/// A single-quoted YAML scalar.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''").replace('\n', " "))
}

impl PackageBuilder for Snap {
    fn kind(&self) -> PackageKind {
        PackageKind::Snap
    }
    fn validate(&self, app: &App) -> Result<()> {
        snap_name(app, self.name.as_deref())?;
        snap_version(app)?;
        linux::check_exe_name("snap", app)?;
        if linux::linux_archs(app, self.archs.as_deref()).is_empty() {
            return Err(Error::invalid("snap", "binaries", "needs a linux-x64 or linux-arm64 binary"));
        }
        let summary = self.summary_for(app);
        if summary.chars().count() > 78 {
            return Err(Error::invalid("snap", "summary", format!("must be at most 78 characters (is {}); set a shorter `summary`", summary.chars().count())));
        }
        let title = self.title.as_deref().unwrap_or(&app.name);
        if title.chars().count() > 40 {
            return Err(Error::invalid("snap", "title", "must be at most 40 characters"));
        }
        let grade = self.grade_for(app)?;
        if grade != "stable" && grade != "devel" {
            return Err(Error::invalid("snap", "grade", format!("`{grade}` must be `stable` or `devel`")));
        }
        let word = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !word(&self.base) {
            return Err(Error::invalid("snap", "base", format!("`{}` isn't a base snap name", self.base)));
        }
        for p in &self.plugs {
            if !word(p) {
                return Err(Error::invalid("snap", "plugs", format!("`{p}` isn't an interface name")));
            }
        }
        for (k, _) in &self.environment {
            if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') || k.as_bytes()[0].is_ascii_digit() {
                return Err(Error::invalid("snap", "environment", format!("`{k}` isn't a variable name")));
            }
        }
        for c in &self.categories {
            if c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(Error::invalid("snap", "categories", format!("`{c}` isn't a desktop menu category")));
            }
        }
        Ok(())
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app = ctx.app;
        std::fs::create_dir_all(&ctx.out_dir).at(&ctx.out_dir)?;
        let mut out = Vec::new();
        for arch in linux::linux_archs(app, self.archs.as_deref()) {
            let bytes = self.package_bytes(app, arch)?;
            let path = ctx.out_dir.join(self.file_name(app, arch)?);
            std::fs::write(&path, bytes).at(&path)?;
            out.push(Package::file(PackageKind::Snap, arch.name(), path, false)?);
        }
        Ok(out)
    }
}

/// Reads `meta/snap.yaml` out of a snap, after checking the image.
pub fn read_snap_yaml(data: &[u8]) -> Result<String> {
    let nodes = squashfs::read(data)?;
    let yaml = nodes.iter().find(|n| n.path == "./meta/snap.yaml").ok_or_else(|| Error::malformed("snap", "no meta/snap.yaml"))?;
    String::from_utf8(yaml.data().to_vec()).map_err(|_| Error::malformed("snap", "meta/snap.yaml isn't UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("packager-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("my-app");
        std::fs::write(&bin, crate::format::elf::tests::stub(crate::format::elf::machine::X86_64)).unwrap();
        let app = App::new("My App", "com.example.myapp", "1.4.0").description("Writes notes.\n\nIn detail.").binary(Arch::LinuxX64, &bin).url_scheme("myapp");
        let snap = Snap::new().license("MIT").env("FOO", "$SNAP/x");
        snap.validate(&app).unwrap();
        let bytes = snap.package_bytes(&app, Arch::LinuxX64).unwrap();
        let yaml = read_snap_yaml(&bytes).unwrap();
        for want in ["name: myapp\n", "version: '1.4.0'\n", "summary: 'Writes notes.'\n", "base: core24\n", "grade: stable\n", "confinement: strict\n", "- amd64\n", "  myapp:\n    command: my-app\n", "    - wayland\n", "      FOO: '$SNAP/x'\n", "description: |\n  Writes notes.\n\n  In detail.\n"] {
            assert!(yaml.contains(want), "missing {want:?} in\n{yaml}");
        }
        let nodes = squashfs::read(&bytes).unwrap();
        let desktop = nodes.iter().find(|n| n.path == "./meta/gui/myapp.desktop").unwrap();
        assert!(String::from_utf8_lossy(desktop.data()).contains("Exec=myapp %U\n"));
        assert!(nodes.iter().any(|n| n.path == "./my-app" && n.perm == 0o755));
        assert!(Snap::new().summary("x".repeat(79)).validate(&app).is_err());
        assert!(Snap::new().plug("Bad Plug").validate(&app).is_err());
        assert_eq!(Snap::new().grade_for(&App::new("A", "com.a.b", "1.0.0-beta.1")).unwrap(), "devel");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
