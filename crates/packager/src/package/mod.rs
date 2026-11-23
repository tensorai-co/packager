//! The high-level builders: each maps an [`App`](crate::App) to one package format.

pub mod app_bundle;
pub mod dmg;
pub mod pkg;

use std::fmt;
use std::path::{Path, PathBuf};

pub use app_bundle::AppBundle;
pub use dmg::Dmg;
pub use pkg::Pkg;

use crate::app::App;
use crate::crypto::{hex, Sha256};
use crate::error::IoContext;
use crate::sign::Apple;
use crate::Result;

/// The kind of a built package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageKind {
    /// A macOS `.app` bundle (a directory).
    App,
    /// A macOS disk image.
    Dmg,
    /// A macOS installer package.
    Pkg,
}

impl fmt::Display for PackageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PackageKind::App => "app",
            PackageKind::Dmg => "dmg",
            PackageKind::Pkg => "pkg",
        })
    }
}

/// A built package: data about what was written.
#[derive(Debug, Clone)]
pub struct Package {
    kind: PackageKind,
    arch: String,
    path: PathBuf,
    size: u64,
    sha256: Option<[u8; 32]>,
    signed: bool,
    notarized: bool,
}

impl Package {
    pub(crate) fn file(kind: PackageKind, arch: impl Into<String>, path: PathBuf, signed: bool) -> Result<Package> {
        let data = std::fs::read(&path).at(&path)?;
        let mut h = Sha256::new();
        h.update(&data);
        Ok(Package { kind, arch: arch.into(), path, size: data.len() as u64, sha256: Some(h.finish()), signed, notarized: false })
    }
    pub(crate) fn dir(kind: PackageKind, arch: impl Into<String>, path: PathBuf, signed: bool) -> Result<Package> {
        let mut size = 0;
        for e in crate::util::walk(&path)? {
            if let crate::util::EntryKind::File { .. } = e.kind {
                size += std::fs::metadata(&e.path).at(&e.path)?.len();
            }
        }
        Ok(Package { kind, arch: arch.into(), path, size, sha256: None, signed, notarized: false })
    }
    /// The format.
    pub fn kind(&self) -> PackageKind {
        self.kind
    }
    /// The architecture(s) it holds (`macos-universal`, `macos-arm64`…).
    pub fn arch(&self) -> &str {
        &self.arch
    }
    /// Where it was written.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Size in bytes (total of all files for a directory).
    pub fn size(&self) -> u64 {
        self.size
    }
    /// SHA-256 of the file; `None` for directories.
    pub fn sha256(&self) -> Option<[u8; 32]> {
        self.sha256
    }
    /// SHA-256 as lowercase hex, or `-` for directories.
    pub fn sha256_hex(&self) -> String {
        self.sha256.map(|h| hex(&h)).unwrap_or_else(|| "-".into())
    }
    /// Whether it carries a signature (an ad-hoc one counts).
    pub fn signed(&self) -> bool {
        self.signed
    }
    /// Whether a notarization ticket is stapled.
    pub fn notarized(&self) -> bool {
        self.notarized
    }
}

/// What each builder gets while running.
pub struct Context<'a> {
    /// The app being packaged.
    pub app: &'a App,
    /// Where finished packages go.
    pub out_dir: PathBuf,
    /// Scratch space, removed afterwards.
    pub work_dir: PathBuf,
    /// Apple signing, if configured. Without it, Mach-O code is still signed ad hoc, since Apple
    /// silicon won't run unsigned code.
    pub apple: Option<&'a Apple>,
    /// The `.app` settings shared by the `.dmg` and `.pkg` builders.
    pub app_bundle: AppBundle,
    built_app: Option<PathBuf>,
}

impl<'a> Context<'a> {
    /// A context writing into `out_dir`, with scratch space in `work_dir`.
    pub fn new(app: &'a App, out_dir: PathBuf, work_dir: PathBuf, apple: Option<&'a Apple>, app_bundle: AppBundle) -> Self {
        Context { app, out_dir, work_dir, apple, app_bundle, built_app: None }
    }

    /// The signed `.app`, built once into the scratch directory and shared by every builder.
    pub fn signed_app(&mut self) -> Result<PathBuf> {
        if let Some(p) = &self.built_app {
            return Ok(p.clone());
        }
        let dir = self.work_dir.join("app");
        std::fs::create_dir_all(&dir).at(&dir)?;
        let p = self.app_bundle.write(self.app, &dir, self.apple)?;
        self.built_app = Some(p.clone());
        Ok(p)
    }

    /// Records an already built and signed `.app` for the other builders to reuse.
    pub fn set_signed_app(&mut self, path: PathBuf) {
        self.built_app = Some(path);
    }
}

/// A package format the builder can produce.
pub trait PackageBuilder {
    /// The format.
    fn kind(&self) -> PackageKind;
    /// Checks the app against this format's rules before anything is written.
    fn validate(&self, app: &App) -> Result<()>;
    /// Writes the package(s).
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>>;
}

/// File-name-safe version of `s` (keeps spaces, which macOS file names allow).
pub(crate) fn file_name(s: &str) -> String {
    s.chars().map(|c| if c == '/' || c == ':' || c.is_control() { '-' } else { c }).collect()
}
