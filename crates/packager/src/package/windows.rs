//! What every Windows package shares: the app's executable with its icon and version
//! information set and an Authenticode signature (in that order), and the app's files.

use crate::app::{App, Arch};
use crate::error::IoContext;
use crate::format::pe::{Image, VersionInfo};
use crate::sign::{authenticode, Authenticode};
use crate::util::{slash_path, walk, EntryKind};
use crate::{Error, Result};

/// The Windows architectures `app` has binaries for, in a stable order.
pub fn windows_archs(app: &App) -> Vec<Arch> {
    let mut v: Vec<Arch> = app.binaries.iter().map(|(a, _)| *a).filter(|a| matches!(a, Arch::WindowsX64 | Arch::WindowsArm64)).collect();
    v.sort_by_key(|a| a.name());
    v.dedup();
    v
}

/// `x64` / `arm64`, as MSIX and MSI name them.
pub fn arch_label(a: Arch) -> &'static str {
    match a {
        Arch::WindowsArm64 => "arm64",
        _ => "x64",
    }
}

/// The executable's file name in the package (`my-app.exe`).
pub fn exe_name(app: &App) -> String {
    let n = app.executable_name();
    if n.to_lowercase().ends_with(".exe") { n } else { format!("{n}.exe") }
}

/// The app's executable for `arch`, ready to package: icon and version info set, then signed.
pub fn prepare_exe(app: &App, arch: Arch, signing: Option<&Authenticode>) -> Result<Vec<u8>> {
    let path = app.binaries.iter().find(|(a, _)| *a == arch).map(|(_, p)| p).ok_or_else(|| Error::invalid("app", "binaries", format!("no {arch} binary")))?;
    let mut img = Image::read(path)?;
    let want = match arch {
        Arch::WindowsArm64 => crate::format::pe::machine::ARM64,
        _ => crate::format::pe::machine::AMD64,
    };
    if img.machine() != want {
        return Err(Error::invalid("app", "binaries", format!("{} isn't a {arch} executable (machine {:#x})", path.display(), img.machine())));
    }
    if let Some(icon) = &app.icon
        && icon.extension().is_some_and(|e| e.eq_ignore_ascii_case("png"))
    {
        img.set_icon(&crate::image::ico_from_png(icon)?)?;
    }
    let mut v = VersionInfo::new(&app.parsed_version()?.triple())?.product(&app.name).string("OriginalFilename", exe_name(app)).string("InternalName", app.executable_name());
    if let Some(p) = &app.publisher {
        v = v.string("CompanyName", p.clone());
    }
    if let Some(c) = &app.copyright {
        v = v.string("LegalCopyright", c.clone());
    }
    if let Some(d) = &app.description {
        v = v.string("FileDescription", d.clone());
    }
    img.set_version_info(&v)?;
    if let Some(s) = signing {
        authenticode::sign_pe(&mut img, s.signer.as_ref(), &s.options().description(app.name.clone()))?;
    }
    Ok(img.into_bytes())
}

/// The app's resources as (`/`-separated path in the install directory, bytes).
pub fn resource_files(app: &App) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for r in &app.resources {
        let dest = r.dest.trim_matches('/');
        if r.dest.split('/').any(|c| c == "..") || r.dest.starts_with('/') {
            return Err(Error::invalid("app", "resources", format!("destination `{}` leaves the install directory", r.dest)));
        }
        let join = |rel: &str| if dest.is_empty() { rel.to_string() } else if rel.is_empty() { dest.to_string() } else { format!("{dest}/{rel}") };
        if std::fs::metadata(&r.source).at(&r.source)?.is_dir() {
            for e in walk(&r.source)? {
                match e.kind {
                    EntryKind::File { .. } => out.push((join(&slash_path(&e.rel)), std::fs::read(&e.path).at(&e.path)?)),
                    EntryKind::Dir => {}
                    EntryKind::Symlink(_) => return Err(Error::invalid("app", "resources", format!("{}: Windows packages can't hold symlinks", e.path.display()))),
                }
            }
        } else {
            let name = r.source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            out.push((if dest.is_empty() { name } else { dest.to_string() }, std::fs::read(&r.source).at(&r.source)?));
        }
    }
    Ok(out)
}
