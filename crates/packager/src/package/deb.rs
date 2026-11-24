//! `.deb`: the Debian/Ubuntu package (what `dpkg-deb --build` writes). An `ar` archive of
//! `debian-binary`, `control.tar.*` (`control`, `md5sums`, optional maintainer scripts) and
//! `data.tar.*` (the files), one package per Linux architecture.
//!
//! Layout: the app in `/opt/<name>` (configurable), a `/usr/bin/<executable>` link, a
//! `.desktop` entry named after the identifier (what Wayland matches windows by), hicolor icons,
//! a shared-mime-info file for custom document types, and `/usr/share/doc/<name>/copyright` and
//! `changelog`. `dpkg` triggers refresh the menu, icon and MIME caches, so no maintainer
//! scripts are needed.

use std::path::PathBuf;

use crate::app::{App, Arch};
use crate::compress::lzma::Options as LzmaOptions;
use crate::compress::{Level, gzip, xz};
use crate::crypto::{hex, md5};
use crate::error::IoContext;
use crate::format::cpio::{Node, NodeKind};
use crate::format::{ar, tar};
use crate::identity::{deb_name, deb_version};
use crate::package::linux::{self, DesktopEntry, complete_tree};
use crate::package::{Context, Package, PackageBuilder, PackageKind};
use crate::util::{rfc2822, source_date_epoch};
use crate::{Error, Result};

/// How the `control.tar` and `data.tar` members are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebCompression {
    /// gzip: every `dpkg` reads it (the default).
    Gzip,
    /// xz: smaller; `dpkg` has read it since Debian 6 and Ubuntu 10.04.
    Xz,
}

/// The `.deb` builder.
#[derive(Debug, Clone)]
pub struct Deb {
    name: Option<String>,
    revision: Option<String>,
    maintainer: Option<String>,
    depends: Vec<String>,
    recommends: Vec<String>,
    auto_depends: bool,
    section: String,
    priority: String,
    homepage: Option<String>,
    license: Option<String>,
    copyright_file: Option<PathBuf>,
    install_dir: Option<String>,
    bin_link: bool,
    desktop: bool,
    categories: Vec<String>,
    keywords: Vec<String>,
    terminal: bool,
    compression: DebCompression,
    archs: Option<Vec<Arch>>,
    scripts: Vec<(&'static str, PathBuf)>,
    man_page: Option<PathBuf>,
}

impl Default for Deb {
    fn default() -> Self {
        Self::new()
    }
}

impl Deb {
    /// A package named after the identifier, installed to `/opt/<name>`, with a menu entry,
    /// `Depends` on the glibc the binary needs, gzip-compressed.
    pub fn new() -> Self {
        Deb {
            name: None,
            revision: None,
            maintainer: None,
            depends: Vec::new(),
            recommends: Vec::new(),
            auto_depends: true,
            section: "utils".into(),
            priority: "optional".into(),
            homepage: None,
            license: None,
            copyright_file: None,
            install_dir: None,
            bin_link: true,
            desktop: true,
            categories: vec!["Utility".into()],
            keywords: Vec::new(),
            terminal: false,
            compression: DebCompression::Gzip,
            archs: None,
            scripts: Vec::new(),
            man_page: None,
        }
    }
    /// The package name (default: the identifier's last part, lowercased).
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }
    /// A Debian revision (`1` → `1.4.0-1`). Without one the version is the app's alone.
    pub fn revision(mut self, r: impl Into<String>) -> Self {
        self.revision = Some(r.into());
        self
    }
    /// `Maintainer`: `Name <email>` (default: the publisher, which needs an email for lintian).
    pub fn maintainer(mut self, m: impl Into<String>) -> Self {
        self.maintainer = Some(m.into());
        self
    }
    /// Packages this one needs (`libwebkit2gtk-4.1-0`, `libgtk-3-0 (>= 3.24)`).
    pub fn depends<S: Into<String>>(mut self, deps: impl IntoIterator<Item = S>) -> Self {
        self.depends.extend(deps.into_iter().map(Into::into));
        self
    }
    /// Packages that should normally be installed too.
    pub fn recommends<S: Into<String>>(mut self, deps: impl IntoIterator<Item = S>) -> Self {
        self.recommends.extend(deps.into_iter().map(Into::into));
        self
    }
    /// Don't add `libc6 (>= …)` from the binary's symbol versions.
    pub fn no_auto_depends(mut self) -> Self {
        self.auto_depends = false;
        self
    }
    /// `Section` (default `utils`).
    pub fn section(mut self, s: impl Into<String>) -> Self {
        self.section = s.into();
        self
    }
    /// `Priority` (default `optional`).
    pub fn priority(mut self, p: impl Into<String>) -> Self {
        self.priority = p.into();
        self
    }
    /// `Homepage`.
    pub fn homepage(mut self, url: impl Into<String>) -> Self {
        self.homepage = Some(url.into());
        self
    }
    /// The license in the copyright file (an SPDX name such as `MIT`; default `proprietary`).
    pub fn license(mut self, l: impl Into<String>) -> Self {
        self.license = Some(l.into());
        self
    }
    /// A ready `copyright` file, used instead of the generated one.
    pub fn copyright_file(mut self, p: impl Into<PathBuf>) -> Self {
        self.copyright_file = Some(p.into());
        self
    }
    /// Where the app goes (default `/opt/<name>`; `/usr/lib/<name>` is the distro-style choice).
    pub fn install_dir(mut self, dir: impl Into<String>) -> Self {
        self.install_dir = Some(dir.into());
        self
    }
    /// No `/usr/bin/<executable>` link.
    pub fn no_bin_link(mut self) -> Self {
        self.bin_link = false;
        self
    }
    /// No `.desktop` entry (command-line tools).
    pub fn no_desktop_entry(mut self) -> Self {
        self.desktop = false;
        self
    }
    /// Menu categories (default `Utility`), from the freedesktop registry.
    pub fn categories<S: Into<String>>(mut self, c: impl IntoIterator<Item = S>) -> Self {
        self.categories = c.into_iter().map(Into::into).collect();
        self
    }
    /// Search keywords for the menu entry.
    pub fn keywords<S: Into<String>>(mut self, k: impl IntoIterator<Item = S>) -> Self {
        self.keywords = k.into_iter().map(Into::into).collect();
        self
    }
    /// Marks the menu entry as a terminal app.
    pub fn terminal(mut self) -> Self {
        self.terminal = true;
        self
    }
    /// Member compression (default gzip).
    pub fn compression(mut self, c: DebCompression) -> Self {
        self.compression = c;
        self
    }
    /// Only these architectures (default: every Linux binary).
    pub fn archs(mut self, a: impl IntoIterator<Item = Arch>) -> Self {
        self.archs = Some(a.into_iter().collect());
        self
    }
    /// A maintainer script: `preinst`, `postinst`, `prerm` or `postrm`.
    pub fn script(mut self, kind: &'static str, path: impl Into<PathBuf>) -> Self {
        self.scripts.retain(|(k, _)| *k != kind);
        self.scripts.push((kind, path.into()));
        self
    }

    /// A manual page for the command (roff source, or already `.gz`), installed as
    /// `/usr/share/man/man1/<executable>.1.gz`. Debian expects one for every command in `/usr/bin`.
    pub fn man_page(mut self, p: impl Into<PathBuf>) -> Self {
        self.man_page = Some(p.into());
        self
    }

    fn pkg_name(&self, app: &App) -> Result<String> {
        deb_name(app, self.name.as_deref())
    }

    fn dir(&self, name: &str) -> String {
        self.install_dir.clone().unwrap_or_else(|| format!("/opt/{name}")).trim_end_matches('/').to_string()
    }

    fn maintainer_for(&self, app: &App) -> String {
        self.maintainer.clone().or_else(|| app.publisher.clone()).unwrap_or_else(|| app.name.clone())
    }

    /// Builds one package's bytes for `arch`.
    pub fn package_bytes(&self, app: &App, arch: Arch) -> Result<Vec<u8>> {
        let mtime = source_date_epoch();
        let name = self.pkg_name(app)?;
        let version = deb_version(app, self.revision.as_deref())?;
        let dir = self.dir(&name);
        let exe = linux::exe_name(app);
        let (binary, elf) = linux::read_binary(app, arch)?;
        let node = |path: String, kind: NodeKind, perm: u32| Node { path, kind, perm, uid: 0, gid: 0, mtime };
        let rel_dir = format!(".{dir}");

        let mut nodes = vec![node(format!("{rel_dir}/{exe}"), NodeKind::File(binary), 0o755)];
        nodes.extend(linux::resource_nodes(app, &rel_dir, mtime, &[exe.as_str()])?);
        if self.bin_link {
            let target = if let Some(rest) = dir.strip_prefix("/usr/") { format!("../{rest}/{exe}") } else { format!("{dir}/{exe}") };
            nodes.push(node(format!("./usr/bin/{exe}"), NodeKind::Symlink(target), 0o777));
        }
        if let Some(p) = &self.man_page {
            let raw = std::fs::read(p).at(p)?;
            let gz = if raw.starts_with(&[0x1f, 0x8b]) { raw } else { gzip(&raw, Level::BEST) };
            nodes.push(node(format!("./usr/share/man/man1/{exe}.1.gz"), NodeKind::File(gz), 0o644));
        }
        let types = linux::mime_types(app, &name);
        let icons = linux::icon_set(app)?;
        if self.desktop {
            let exec = if self.bin_link { exe.clone() } else { format!("{dir}/{exe}") };
            let entry = DesktopEntry {
                exec,
                icon: if icons.is_empty() { None } else { Some(name.clone()) },
                categories: &self.categories,
                terminal: self.terminal,
                wm_class: None,
                mime_types: linux::handled_mime_types(app, &types),
                keywords: &self.keywords,
            };
            nodes.push(node(format!("./usr/share/applications/{}.desktop", app.identifier), NodeKind::File(linux::desktop_entry(app, &entry).into_bytes()), 0o644));
            for (size, png) in &icons {
                nodes.push(node(format!("./usr/share/icons/hicolor/{size}x{size}/apps/{name}.png"), NodeKind::File(png.clone()), 0o644));
            }
        }
        if let Some(xml) = linux::mime_package_xml(&types) {
            nodes.push(node(format!("./usr/share/mime/packages/{name}.xml"), NodeKind::File(xml.into_bytes()), 0o644));
        }
        let doc = format!("./usr/share/doc/{name}");
        let copyright = match &self.copyright_file {
            Some(p) => std::fs::read(p).at(p)?,
            None => self.copyright(app).into_bytes(),
        };
        nodes.push(node(format!("{doc}/copyright"), NodeKind::File(copyright), 0o644));
        // Native-style versions (no revision) carry `changelog.gz`, others `changelog.Debian.gz`.
        let changelog_name = if self.revision.is_some() { "changelog.Debian.gz" } else { "changelog.gz" };
        let changelog = format!("{name} ({version}) stable; urgency=medium\n\n  * Release {version}.\n\n -- {}  {}\n", self.maintainer_for(app), rfc2822(mtime));
        nodes.push(node(format!("{doc}/{changelog_name}"), NodeKind::File(gzip(changelog.as_bytes(), Level::BEST)), 0o644));

        let nodes = complete_tree(nodes, mtime)?;
        let installed_kb: u64 = nodes.iter().map(|n| (n.size() as u64).div_ceil(1024).max(1)).sum();
        let mut md5sums = String::new();
        for n in &nodes {
            if let NodeKind::File(d) = &n.kind {
                md5sums.push_str(&format!("{}  {}\n", hex(&md5::md5(d)), n.path.trim_start_matches("./")));
            }
        }

        let mut depends = Vec::new();
        if self.auto_depends && elf.links_glibc() {
            match elf.min_glibc() {
                Some((a, b, 0)) => depends.push(format!("libc6 (>= {a}.{b})")),
                Some((a, b, c)) => depends.push(format!("libc6 (>= {a}.{b}.{c})")),
                None => depends.push("libc6".into()),
            }
        }
        for d in &self.depends {
            let pkg = d.split([' ', '(']).next().unwrap_or_default();
            depends.retain(|x: &String| !(pkg == "libc6" && x.starts_with("libc6")));
            depends.push(d.clone());
        }
        let control = self.control(app, &name, &version, linux::arch_label(arch), installed_kb, &depends);

        let mut control_nodes =
            vec![node(".".into(), NodeKind::Dir, 0o755), node("./control".into(), NodeKind::File(control.into_bytes()), 0o644), node("./md5sums".into(), NodeKind::File(md5sums.into_bytes()), 0o644)];
        for kind in ["preinst", "postinst", "prerm", "postrm"] {
            if let Some((_, p)) = self.scripts.iter().find(|(k, _)| *k == kind) {
                let data = std::fs::read(p).at(p)?;
                if !data.starts_with(b"#!") {
                    return Err(Error::invalid("deb", kind, format!("{} must start with a `#!` line", p.display())));
                }
                control_nodes.push(node(format!("./{kind}"), NodeKind::File(data), 0o755));
            }
        }
        let control_tar = tar::write(&control_nodes)?;
        let data_tar = tar::write(&nodes)?;
        let (ext, control_c, data_c) = match self.compression {
            DebCompression::Gzip => ("gz", gzip(&control_tar, Level::BEST), gzip(&data_tar, Level::BEST)),
            DebCompression::Xz => ("xz", xz::xz(&control_tar, &LzmaOptions::DEFAULT), xz::xz(&data_tar, &LzmaOptions::DEFAULT)),
        };
        ar::write(&[
            ar::Member::new("debian-binary", mtime, b"2.0\n".to_vec()),
            ar::Member::new(format!("control.tar.{ext}"), mtime, control_c),
            ar::Member::new(format!("data.tar.{ext}"), mtime, data_c),
        ])
    }

    fn control(&self, app: &App, name: &str, version: &str, arch: &str, installed_kb: u64, depends: &[String]) -> String {
        let mut c = format!("Package: {name}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: {}\nInstalled-Size: {installed_kb}\n", self.maintainer_for(app));
        if !depends.is_empty() {
            c.push_str(&format!("Depends: {}\n", depends.join(", ")));
        }
        if !self.recommends.is_empty() {
            c.push_str(&format!("Recommends: {}\n", self.recommends.join(", ")));
        }
        c.push_str(&format!("Section: {}\nPriority: {}\n", self.section, self.priority));
        if let Some(h) = &self.homepage {
            c.push_str(&format!("Homepage: {h}\n"));
        }
        // Synopsis: the description's first line; the extended description says what it is.
        let synopsis = app.description.as_deref().and_then(|d| d.lines().next()).map(|s| s.trim().trim_end_matches('.').to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| app.name.clone());
        c.push_str(&format!("Description: {synopsis}\n"));
        let mut long: Vec<String> = app.description.as_deref().map(|d| d.lines().skip(1).map(String::from).collect()).unwrap_or_default();
        while long.first().is_some_and(|l| l.trim().is_empty()) {
            long.remove(0);
        }
        if long.is_empty() {
            long.push(match &app.publisher {
                Some(p) => format!("{} ({}) from {p}.", app.name, app.identifier),
                None => format!("{} ({}).", app.name, app.identifier),
            });
        }
        for l in long {
            if l.trim().is_empty() {
                c.push_str(" .\n");
            } else {
                c.push_str(&format!(" {}\n", l.trim_end()));
            }
        }
        c
    }

    fn copyright(&self, app: &App) -> String {
        let holder = app.copyright.clone().or_else(|| app.publisher.clone()).unwrap_or_else(|| app.name.clone());
        let holder = holder.trim_start_matches("Copyright").trim_start_matches(['©', ' ']).trim_start_matches("(c)").trim().to_string();
        let license = self.license.clone().unwrap_or_else(|| "proprietary".into());
        let mut s = format!("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: {}\n", app.name);
        if let Some(h) = &self.homepage {
            s.push_str(&format!("Source: {h}\n"));
        }
        s.push_str(&format!("\nFiles: *\nCopyright: {holder}\nLicense: {license}\n"));
        if license == "proprietary" {
            s.push_str(" All rights reserved.\n");
        }
        s
    }

    fn file_name(&self, app: &App, arch: Arch) -> Result<String> {
        // `name_version_arch.deb`, without an epoch (`:` isn't welcome in file names).
        let v = deb_version(app, self.revision.as_deref())?;
        Ok(format!("{}_{}_{}.deb", self.pkg_name(app)?, v.rsplit(':').next().unwrap_or(&v), linux::arch_label(arch)))
    }
}

impl PackageBuilder for Deb {
    fn kind(&self) -> PackageKind {
        PackageKind::Deb
    }
    fn validate(&self, app: &App) -> Result<()> {
        self.pkg_name(app)?;
        deb_version(app, self.revision.as_deref())?;
        linux::check_exe_name("deb", app)?;
        if linux::linux_archs(app, self.archs.as_deref()).is_empty() {
            return Err(Error::invalid("deb", "binaries", "needs a linux-x64 or linux-arm64 binary"));
        }
        let dir = self.dir(&self.pkg_name(app)?);
        if !dir.starts_with('/') || dir.split('/').any(|c| c == "..") || dir == "/" || dir.contains([' ', '\n']) {
            return Err(Error::invalid("deb", "install_dir", format!("`{dir}` must be an absolute path without spaces")));
        }
        let m = self.maintainer_for(app);
        if m.contains('\n') || m.contains(',') {
            return Err(Error::invalid("deb", "maintainer", format!("`{m}` must be `Name <email>` on one line, without commas")));
        }
        for c in &self.categories {
            if c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(Error::invalid("deb", "categories", format!("`{c}` isn't a desktop menu category")));
            }
        }
        for d in self.depends.iter().chain(&self.recommends) {
            if d.trim().is_empty() || d.contains('\n') {
                return Err(Error::invalid("deb", "depends", format!("`{d}` isn't a dependency")));
            }
        }
        if let Some(h) = &self.homepage
            && !(h.starts_with("https://") || h.starts_with("http://"))
        {
            return Err(Error::invalid("deb", "homepage", format!("`{h}` must be an http(s) URL")));
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
            out.push(Package::file(PackageKind::Deb, arch.name(), path, false)?);
        }
        Ok(out)
    }
}

/// What a `.deb` holds, read back: control fields and the data files.
#[derive(Debug, Clone)]
pub struct DebInfo {
    /// `control` fields in order.
    pub control: Vec<(String, String)>,
    /// The `data.tar` entries.
    pub files: Vec<Node>,
    /// The `control.tar` entries.
    pub control_files: Vec<Node>,
}

impl DebInfo {
    /// A control field's value.
    pub fn field(&self, k: &str) -> Option<&str> {
        self.control.iter().find(|(x, _)| x.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

fn decompress_member(name: &str, data: &[u8]) -> Result<Vec<u8>> {
    if name.ends_with(".gz") {
        crate::compress::gunzip(data)
    } else if name.ends_with(".xz") {
        xz::unxz(data, 1 << 34)
    } else if name.ends_with(".tar") {
        Ok(data.to_vec())
    } else {
        Err(Error::malformed("deb", format!("unsupported member compression: {name}")))
    }
}

/// Reads a `.deb`: checks the member order, decompresses both tarballs, parses `control` and
/// checks every file against `md5sums`.
pub fn read(data: &[u8]) -> Result<DebInfo> {
    let members = ar::read(data)?;
    let [bin, control, payload] = &members[..] else {
        return Err(Error::malformed("deb", format!("expected 3 members, found {}", members.len())));
    };
    if bin.name != "debian-binary" || !bin.data.starts_with(b"2.") {
        return Err(Error::malformed("deb", "first member must be debian-binary 2.x"));
    }
    if !control.name.starts_with("control.tar") || !payload.name.starts_with("data.tar") {
        return Err(Error::malformed("deb", "members must be control.tar.* then data.tar.*"));
    }
    let control_files = tar::read(&decompress_member(&control.name, &control.data)?)?;
    let files = tar::read(&decompress_member(&payload.name, &payload.data)?)?;
    let get = |n: &str| control_files.iter().find(|f| f.path == format!("./{n}") || f.path == n).map(|f| f.data().to_vec());
    let text = String::from_utf8(get("control").ok_or_else(|| Error::malformed("deb", "no control file"))?).map_err(|_| Error::malformed("deb", "control isn't UTF-8"))?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            let last = fields.last_mut().ok_or_else(|| Error::malformed("deb", "continuation line first"))?;
            last.1.push('\n');
            last.1.push_str(line);
        } else if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_string(), v.trim().to_string()));
        } else if !line.trim().is_empty() {
            return Err(Error::malformed("deb", format!("bad control line `{line}`")));
        }
    }
    for k in ["Package", "Version", "Architecture", "Maintainer", "Description"] {
        if !fields.iter().any(|(x, _)| x == k) {
            return Err(Error::malformed("deb", format!("control has no {k}")));
        }
    }
    if let Some(sums) = get("md5sums") {
        for line in String::from_utf8_lossy(&sums).lines() {
            let (sum, path) = line.split_once("  ").ok_or_else(|| Error::malformed("deb", format!("bad md5sums line `{line}`")))?;
            let f = files.iter().find(|f| f.path.trim_start_matches("./") == path).ok_or_else(|| Error::malformed("deb", format!("md5sums lists missing {path}")))?;
            if hex(&md5::md5(f.data())) != sum {
                return Err(Error::malformed("deb", format!("{path}: MD5 doesn't match md5sums")));
            }
        }
    }
    Ok(DebInfo { control: fields, files, control_files })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with_binary(dir: &std::path::Path) -> App {
        let bin = dir.join("my-app");
        std::fs::write(&bin, crate::format::elf::tests::stub(crate::format::elf::machine::X86_64)).unwrap();
        let res = dir.join("web");
        std::fs::create_dir_all(res.join("assets")).unwrap();
        std::fs::write(res.join("index.html"), "<p>hi</p>").unwrap();
        std::fs::write(res.join("assets/app.js"), "1").unwrap();
        App::new("My App", "com.example.myapp", "1.4.0-rc.1")
            .publisher("Example Ltd <dev@example.com>")
            .description("Writes notes.\n\nA longer explanation\nover two lines.")
            .binary(Arch::LinuxX64, &bin)
            .resources(&res, "web")
            .url_scheme("myapp")
            .file_type("md", "Markdown document")
    }

    #[test]
    fn builds_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("packager-deb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let app = app_with_binary(&dir);
        for c in [DebCompression::Gzip, DebCompression::Xz] {
            let deb = Deb::new().revision("1").homepage("https://example.com").depends(["libgtk-3-0"]).compression(c);
            deb.validate(&app).unwrap();
            let bytes = deb.package_bytes(&app, Arch::LinuxX64).unwrap();
            assert_eq!(bytes, deb.package_bytes(&app, Arch::LinuxX64).unwrap(), "deterministic");
            let info = read(&bytes).unwrap();
            assert_eq!(info.field("Package"), Some("myapp"));
            assert_eq!(info.field("Version"), Some("1.4.0~rc.1-1"));
            assert_eq!(info.field("Architecture"), Some("amd64"));
            assert_eq!(info.field("Depends"), Some("libgtk-3-0"), "a static stub binary needs no libc");
            assert!(info.field("Description").unwrap().starts_with("Writes notes\n A longer explanation\n over two lines."), "{:?}", info.field("Description"));
            let paths: Vec<&str> = info.files.iter().map(|f| f.path.as_str()).collect();
            for want in [
                ".",
                "./opt/myapp/my-app",
                "./opt/myapp/web/index.html",
                "./opt/myapp/web/assets/app.js",
                "./usr/bin/my-app",
                "./usr/share/applications/com.example.myapp.desktop",
                "./usr/share/doc/myapp/copyright",
                "./usr/share/doc/myapp/changelog.Debian.gz",
            ] {
                assert!(paths.contains(&want), "missing {want} in {paths:?}");
            }
            let link = info.files.iter().find(|f| f.path == "./usr/bin/my-app").unwrap();
            assert_eq!(link.kind, NodeKind::Symlink("/opt/myapp/my-app".into()));
            let exe = info.files.iter().find(|f| f.path == "./opt/myapp/my-app").unwrap();
            assert_eq!(exe.perm, 0o755);
            assert!(info.files.iter().all(|f| f.uid == 0 && f.gid == 0));
            let desktop = info.files.iter().find(|f| f.path.ends_with(".desktop")).unwrap();
            let d = String::from_utf8_lossy(desktop.data());
            assert!(d.contains("Exec=my-app %U\n") && d.contains("MimeType=text/markdown;x-scheme-handler/myapp;\n"), "{d}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validation() {
        let dir = std::env::temp_dir().join(format!("packager-deb-v-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = app_with_binary(&dir);
        assert!(Deb::new().install_dir("relative/dir").validate(&app).is_err());
        assert!(Deb::new().name("X").validate(&app).is_err());
        assert!(Deb::new().homepage("example.com").validate(&app).is_err());
        assert!(Deb::new().validate(&App::new("A", "com.example.a", "1.0.0")).is_err(), "no Linux binary");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
