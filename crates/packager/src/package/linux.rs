//! What the Linux packages share: checked ELF binaries, the freedesktop `.desktop` entry,
//! hicolor icons from one PNG, MIME types for file associations, and the app's files.

use crate::app::{App, Arch};
use crate::error::IoContext;
use crate::format::cpio::{Node, NodeKind};
use crate::format::elf::{self, Elf};
use crate::format::xml::Element;
use crate::util::{EntryKind, slash_path, walk};
use crate::{Error, Result};

/// The Linux architectures `app` has binaries for (optionally narrowed to `only`), in a stable
/// order.
pub fn linux_archs(app: &App, only: Option<&[Arch]>) -> Vec<Arch> {
    let mut v: Vec<Arch> = app.binaries.iter().map(|(a, _)| *a).filter(|a| a.is_linux() && only.is_none_or(|o| o.contains(a))).collect();
    v.sort_by_key(|a| a.name());
    v.dedup();
    v
}

/// The Debian / snap architecture name (`amd64`, `arm64`).
pub fn arch_label(a: Arch) -> &'static str {
    match a {
        Arch::LinuxArm64 => "arm64",
        _ => "amd64",
    }
}

/// The executable's name inside Linux packages (no `.exe`).
pub fn exe_name(app: &App) -> String {
    let n = app.executable_name();
    n.strip_suffix(".exe").map(String::from).unwrap_or(n)
}

/// Checks the executable name is usable as a file name and a command.
pub fn check_exe_name(format: &'static str, app: &App) -> Result<()> {
    let n = exe_name(app);
    if n.is_empty() || n.contains(['/', ' ', '\t', '\n', '"', '\'', '\\', '$', '`', '%']) || n.starts_with('.') || n.starts_with('-') {
        return Err(Error::invalid(format, "executable", format!("`{n}` must be a plain file name without spaces, quotes or `/`")));
    }
    Ok(())
}

/// The binary for `arch`, read and checked to be an ELF file for that architecture.
pub fn read_binary(app: &App, arch: Arch) -> Result<(Vec<u8>, Elf)> {
    let path = app.binaries.iter().find(|(a, _)| *a == arch).map(|(_, p)| p).ok_or_else(|| Error::invalid("app", "binaries", format!("no {arch} binary")))?;
    let data = std::fs::read(path).at(path)?;
    let parsed = Elf::parse(&data).map_err(|_| Error::invalid("app", "binaries", format!("{} isn't an ELF executable (built for Linux?)", path.display())))?;
    let want = match arch {
        Arch::LinuxArm64 => elf::machine::AARCH64,
        _ => elf::machine::X86_64,
    };
    if parsed.machine != want || !parsed.is_64 {
        return Err(Error::invalid("app", "binaries", format!("{} isn't a {arch} executable (e_machine {})", path.display(), parsed.machine)));
    }
    Ok((data, parsed))
}

/// hicolor PNGs from the app's icon: (size, PNG), for the standard sizes up to the source's.
pub fn icon_set(app: &App) -> Result<Vec<(u32, Vec<u8>)>> {
    let Some(icon) = &app.icon else { return Ok(Vec::new()) };
    if !icon.extension().is_some_and(|e| e.eq_ignore_ascii_case("png")) {
        return Ok(Vec::new());
    }
    let img = crate::image::Image::open_png(icon)?;
    if img.width != img.height {
        return Err(Error::invalid("app", "icon", format!("{} must be square for Linux icons ({}×{})", icon.display(), img.width, img.height)));
    }
    let mut out = Vec::new();
    for size in [16u32, 24, 32, 48, 64, 128, 256, 512] {
        if size <= img.width {
            out.push((size, img.resize(size, size).to_png()));
        }
    }
    if out.is_empty() {
        out.push((img.width, img.to_png()));
    }
    Ok(out)
}

/// Standard MIME types for common extensions, so associations join the existing type instead
/// of defining a competing one.
fn known_mime(ext: &str) -> Option<&'static str> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "md" | "markdown" => "text/markdown",
        "txt" | "text" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "epub" => "application/epub+zip",
        "rtf" => "application/rtf",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/vnd.microsoft.icon",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/x-wav",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        _ => return None,
    })
}

/// One file association on Linux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeType {
    /// The MIME type.
    pub mime: String,
    /// The extension it's matched by.
    pub extension: String,
    /// Display name.
    pub name: String,
    /// Whether the package defines it (not a type the system already knows).
    pub custom: bool,
}

/// The MIME types for `app.file_types`; `package` names the custom ones.
pub fn mime_types(app: &App, package: &str) -> Vec<MimeType> {
    app.file_types
        .iter()
        .map(|f| match (&f.mime_type, known_mime(&f.extension)) {
            (Some(m), known) => MimeType { mime: m.clone(), extension: f.extension.clone(), name: f.name.clone(), custom: known != Some(m.as_str()) },
            (None, Some(k)) => MimeType { mime: k.into(), extension: f.extension.clone(), name: f.name.clone(), custom: false },
            (None, None) => {
                let ext: String = f.extension.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
                MimeType { mime: format!("application/x-{package}-{ext}"), extension: f.extension.clone(), name: f.name.clone(), custom: true }
            }
        })
        .collect()
}

/// A shared-mime-info package file (`/usr/share/mime/packages/<package>.xml`) defining the
/// custom types, or `None` when every type is already known.
pub fn mime_package_xml(types: &[MimeType]) -> Option<String> {
    let custom: Vec<&MimeType> = types.iter().filter(|t| t.custom).collect();
    if custom.is_empty() {
        return None;
    }
    let mut root = Element::new("mime-info").attr("xmlns", "http://www.freedesktop.org/standards/shared-mime-info");
    for t in custom {
        root = root.child(
            Element::new("mime-type").attr("type", t.mime.as_str()).child(Element::new("comment").text(t.name.as_str())).child(Element::new("glob").attr("pattern", format!("*.{}", t.extension))),
        );
    }
    Some(root.to_document(2))
}

/// Escapes a `.desktop` string value.
pub fn desktop_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

/// What goes into the `.desktop` entry.
#[derive(Debug, Clone)]
pub struct DesktopEntry<'a> {
    /// `Exec` command (without field codes).
    pub exec: String,
    /// `Icon`: a theme name or an absolute path.
    pub icon: Option<String>,
    /// Main and additional categories (`Utility`, `Development`…).
    pub categories: &'a [String],
    /// Whether it's a terminal app.
    pub terminal: bool,
    /// `StartupWMClass`, matching the window to the entry.
    pub wm_class: Option<String>,
    /// MIME types handled (file types and `x-scheme-handler/…`).
    pub mime_types: Vec<String>,
    /// `Keywords`.
    pub keywords: &'a [String],
}

/// Renders the `.desktop` entry (Desktop Entry Specification 1.5).
pub fn desktop_entry(app: &App, e: &DesktopEntry) -> String {
    let mut s = String::from("[Desktop Entry]\nType=Application\nVersion=1.5\n");
    s.push_str(&format!("Name={}\n", desktop_escape(&app.name)));
    if let Some(d) = &app.description {
        s.push_str(&format!("Comment={}\n", desktop_escape(d.lines().next().unwrap_or(d))));
    }
    // %U for URL handlers, %F for documents, nothing otherwise.
    let has_urls = e.mime_types.iter().any(|m| m.starts_with("x-scheme-handler/"));
    let code = if has_urls {
        " %U"
    } else if !e.mime_types.is_empty() {
        " %F"
    } else {
        ""
    };
    s.push_str(&format!("Exec={}{code}\n", e.exec));
    if let Some(i) = &e.icon {
        s.push_str(&format!("Icon={}\n", desktop_escape(i)));
    }
    s.push_str(&format!("Terminal={}\n", e.terminal));
    if !e.categories.is_empty() {
        s.push_str(&format!("Categories={};\n", e.categories.join(";")));
    }
    if !e.keywords.is_empty() {
        s.push_str(&format!("Keywords={};\n", e.keywords.iter().map(|k| desktop_escape(k)).collect::<Vec<_>>().join(";")));
    }
    if !e.mime_types.is_empty() {
        s.push_str(&format!("MimeType={};\n", e.mime_types.join(";")));
    }
    if let Some(w) = &e.wm_class {
        s.push_str(&format!("StartupWMClass={}\n", desktop_escape(w)));
    }
    s
}

/// The `MimeType` list for an app: its file types, then `x-scheme-handler/<scheme>` per URL
/// scheme.
pub fn handled_mime_types(app: &App, types: &[MimeType]) -> Vec<String> {
    let mut v: Vec<String> = types.iter().map(|t| t.mime.clone()).collect();
    v.extend(app.url_schemes.iter().map(|s| format!("x-scheme-handler/{}", s.to_ascii_lowercase())));
    v.dedup();
    v
}

/// The app's resources as nodes under `prefix` (`./opt/myapp`), keeping symlinks and the
/// executable bit; directories included. `reserved` names may not be used at the top level.
pub fn resource_nodes(app: &App, prefix: &str, mtime: i64, reserved: &[&str]) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    let node = |path: String, kind: NodeKind, perm: u32| Node { path, kind, perm, uid: 0, gid: 0, mtime };
    for r in &app.resources {
        let dest = r.dest.trim_matches('/');
        if r.dest.split('/').any(|c| c == ".." || c == ".") || r.dest.starts_with('/') {
            return Err(Error::invalid("app", "resources", format!("destination `{}` leaves the install directory", r.dest)));
        }
        let top = dest.split('/').next().unwrap_or_default();
        let join = |rel: &str| {
            if dest.is_empty() {
                rel.to_string()
            } else if rel.is_empty() {
                dest.to_string()
            } else {
                format!("{dest}/{rel}")
            }
        };
        if std::fs::metadata(&r.source).at(&r.source)?.is_dir() {
            if !dest.is_empty() {
                out.push(node(format!("{prefix}/{dest}"), NodeKind::Dir, 0o755));
            }
            for e in walk(&r.source)? {
                let rel = join(&slash_path(&e.rel));
                let first = rel.split('/').next().unwrap_or_default();
                if reserved.contains(&first) {
                    return Err(Error::invalid("app", "resources", format!("`{rel}` would replace the package's own `{first}`")));
                }
                let path = format!("{prefix}/{rel}");
                match e.kind {
                    EntryKind::Dir => out.push(node(path, NodeKind::Dir, 0o755)),
                    EntryKind::File { executable } => out.push(node(path, NodeKind::File(std::fs::read(&e.path).at(&e.path)?), if executable { 0o755 } else { 0o644 })),
                    EntryKind::Symlink(t) => out.push(node(path, NodeKind::Symlink(slash_path(&t)), 0o777)),
                }
            }
        } else {
            let name = r.source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let rel = if dest.is_empty() { name } else { dest.to_string() };
            if reserved.contains(&rel.split('/').next().unwrap_or_default()) || reserved.contains(&top) {
                return Err(Error::invalid("app", "resources", format!("`{rel}` would replace one of the package's own files")));
            }
            let meta = std::fs::metadata(&r.source).at(&r.source)?;
            let exec = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    let _ = &meta;
                    false
                }
            };
            out.push(node(format!("{prefix}/{rel}"), NodeKind::File(std::fs::read(&r.source).at(&r.source)?), if exec { 0o755 } else { 0o644 }));
        }
    }
    Ok(out)
}

/// Adds every missing parent directory (`0755`) and sorts the nodes the way `tar` and
/// SquashFS writers list them: depth first, components in byte order, `.` first.
pub fn complete_tree(mut nodes: Vec<Node>, mtime: i64) -> Result<Vec<Node>> {
    let mut have: std::collections::BTreeSet<String> = nodes.iter().map(|n| n.path.clone()).collect();
    let mut extra = Vec::new();
    for n in &nodes {
        let mut p = n.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            if have.insert(parent.to_string()) {
                extra.push(Node { path: parent.to_string(), kind: NodeKind::Dir, perm: 0o755, uid: 0, gid: 0, mtime });
            }
            p = parent;
        }
    }
    nodes.extend(extra);
    let key = |n: &Node| -> Vec<Vec<u8>> { n.path.split('/').map(|c| c.as_bytes().to_vec()).collect() };
    nodes.sort_by_key(key);
    for w in nodes.windows(2) {
        if w[0].path == w[1].path {
            return Err(Error::invalid("app", "resources", format!("`{}` appears twice in the package", w[0].path.trim_start_matches("./"))));
        }
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_and_mime() {
        let app = App::new("My App", "com.example.myapp", "1.0.0").description("Writes notes.").url_scheme("MyApp").file_type("md", "Markdown document").file_type("mynote", "My note");
        let types = mime_types(&app, "myapp");
        assert_eq!(types[0].mime, "text/markdown");
        assert!(!types[0].custom);
        assert_eq!(types[1].mime, "application/x-myapp-mynote");
        let xml = mime_package_xml(&types).unwrap();
        assert!(xml.contains("<glob pattern=\"*.mynote\"/>"), "{xml}");
        assert!(!xml.contains("markdown"));
        let cats = vec!["Utility".to_string()];
        let e = DesktopEntry { exec: "myapp".into(), icon: Some("myapp".into()), categories: &cats, terminal: false, wm_class: None, mime_types: handled_mime_types(&app, &types), keywords: &[] };
        let d = desktop_entry(&app, &e);
        assert!(d.contains("Exec=myapp %U\n"), "{d}");
        assert!(d.contains("MimeType=text/markdown;application/x-myapp-mynote;x-scheme-handler/myapp;\n"), "{d}");
        assert!(d.contains("Categories=Utility;\n"));
    }

    #[test]
    fn tree_completion() {
        let f = |p: &str| Node { path: p.into(), kind: NodeKind::File(vec![]), perm: 0o644, uid: 0, gid: 0, mtime: 0 };
        let t = complete_tree(vec![f("./usr/share/doc/x/copyright"), f("./opt/x/bin"), f("./usr/bin-x")], 0).unwrap();
        let paths: Vec<&str> = t.iter().map(|n| n.path.as_str()).collect();
        assert_eq!(paths, [".", "./opt", "./opt/x", "./opt/x/bin", "./usr", "./usr/bin-x", "./usr/share", "./usr/share/doc", "./usr/share/doc/x", "./usr/share/doc/x/copyright"]);
        assert!(complete_tree(vec![f("./a"), f("./a")], 0).is_err());
    }
}
