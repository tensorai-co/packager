//! The platform-neutral app description every package is built from.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// A target architecture (and the OS it belongs to).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Arch {
    /// macOS on Apple silicon.
    MacosArm64,
    /// macOS on Intel.
    MacosX64,
    /// A macOS universal binary (arm64 + x86_64) supplied already merged.
    MacosUniversal,
    /// Windows x64.
    WindowsX64,
    /// Windows on Arm.
    WindowsArm64,
    /// Linux x86_64.
    LinuxX64,
    /// Linux arm64.
    LinuxArm64,
}

impl Arch {
    /// Whether this is a macOS architecture.
    pub fn is_macos(self) -> bool {
        matches!(self, Arch::MacosArm64 | Arch::MacosX64 | Arch::MacosUniversal)
    }
    /// The name used in config files and output listings.
    pub fn name(self) -> &'static str {
        match self {
            Arch::MacosArm64 => "macos-arm64",
            Arch::MacosX64 => "macos-x64",
            Arch::MacosUniversal => "macos-universal",
            Arch::WindowsX64 => "windows-x64",
            Arch::WindowsArm64 => "windows-arm64",
            Arch::LinuxX64 => "linux-x64",
            Arch::LinuxArm64 => "linux-arm64",
        }
    }
    /// Parses [`Arch::name`].
    pub fn parse(s: &str) -> Option<Arch> {
        [
            Arch::MacosArm64,
            Arch::MacosX64,
            Arch::MacosUniversal,
            Arch::WindowsX64,
            Arch::WindowsArm64,
            Arch::LinuxX64,
            Arch::LinuxArm64,
        ]
        .into_iter()
        .find(|a| a.name() == s)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A version: `major.minor.patch`, an optional pre-release (`-beta.1`) and build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
    /// Pre-release identifiers after `-`, if any.
    pub pre: Option<String>,
    /// Build metadata after `+`, if any (ignored for ordering).
    pub build: Option<String>,
}

impl Version {
    /// Parses `1.4`, `1.4.0`, `1.4.0-beta.1+42`.
    pub fn parse(s: &str) -> Result<Version> {
        let err = |m: &str| Error::invalid("version", s, m.to_string());
        let (rest, build) = match s.split_once('+') {
            Some((a, b)) => (a, Some(b.to_string())),
            None => (s, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((a, b)) if !b.is_empty() => (a, Some(b.to_string())),
            Some(_) => return Err(err("has an empty pre-release")),
            None => (rest, None),
        };
        let nums: Vec<&str> = core.split('.').collect();
        if nums.is_empty() || nums.len() > 3 {
            return Err(err("must be `major.minor.patch`"));
        }
        let mut n = [0u64; 3];
        for (i, p) in nums.iter().enumerate() {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
                return Err(err("must be numbers separated by dots"));
            }
            n[i] = p.parse().map_err(|_| err("number too large"))?;
        }
        Ok(Version { major: n[0], minor: n[1], patch: n[2], pre, build })
    }

    /// `major.minor.patch`.
    pub fn triple(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.triple())?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        if let Some(b) = &self.build {
            write!(f, "+{b}")?;
        }
        Ok(())
    }
}

/// A document type the app opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileType {
    /// Extension without the dot (`md`).
    pub extension: String,
    /// Human-readable name (`Markdown document`).
    pub name: String,
    /// `Editor` or `Viewer`.
    pub role: String,
}

/// Resources copied into the app: a file or directory, and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Source path on disk.
    pub source: PathBuf,
    /// Destination relative to the app's resource directory.
    pub dest: String,
}

/// One app, described once; every package builder maps it to its format.
#[derive(Debug, Clone)]
pub struct App {
    /// Display name (`My App`).
    pub name: String,
    /// Reverse-DNS identifier (`com.example.myapp`).
    pub identifier: String,
    /// Version as given (`1.4.0`).
    pub version: String,
    /// Build number (`CFBundleVersion`); defaults to the version.
    pub build_number: Option<String>,
    /// Publisher / company.
    pub publisher: Option<String>,
    /// One-line description.
    pub description: Option<String>,
    /// Executable name; defaults to the file name of the first binary.
    pub executable: Option<String>,
    /// Binaries per architecture.
    pub binaries: Vec<(Arch, PathBuf)>,
    /// Source icon: a square PNG (ideally 1024×1024), or a ready `.icns` for macOS.
    pub icon: Option<PathBuf>,
    /// Extra resources.
    pub resources: Vec<Resource>,
    /// URL schemes the app handles (`myapp` for `myapp://`).
    pub url_schemes: Vec<String>,
    /// Document types the app opens.
    pub file_types: Vec<FileType>,
    /// Copyright line.
    pub copyright: Option<String>,
}

impl App {
    /// A new app with its name, identifier and version.
    pub fn new(name: impl Into<String>, identifier: impl Into<String>, version: impl Into<String>) -> Self {
        App {
            name: name.into(),
            identifier: identifier.into(),
            version: version.into(),
            build_number: None,
            publisher: None,
            description: None,
            executable: None,
            binaries: Vec::new(),
            icon: None,
            resources: Vec::new(),
            url_schemes: Vec::new(),
            file_types: Vec::new(),
            copyright: None,
        }
    }
    /// Sets the publisher.
    pub fn publisher(mut self, p: impl Into<String>) -> Self {
        self.publisher = Some(p.into());
        self
    }
    /// Sets the description.
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
    /// Sets the build number (`CFBundleVersion`).
    pub fn build_number(mut self, b: impl Into<String>) -> Self {
        self.build_number = Some(b.into());
        self
    }
    /// Sets the executable name inside packages.
    pub fn executable(mut self, e: impl Into<String>) -> Self {
        self.executable = Some(e.into());
        self
    }
    /// Adds a binary for an architecture.
    pub fn binary(mut self, arch: Arch, path: impl Into<PathBuf>) -> Self {
        self.binaries.push((arch, path.into()));
        self
    }
    /// Sets the icon source.
    pub fn icon(mut self, path: impl Into<PathBuf>) -> Self {
        self.icon = Some(path.into());
        self
    }
    /// Copies `source` (file or directory) to `dest` in the resource directory.
    pub fn resources(mut self, source: impl Into<PathBuf>, dest: impl Into<String>) -> Self {
        self.resources.push(Resource { source: source.into(), dest: dest.into() });
        self
    }
    /// Registers a URL scheme.
    pub fn url_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.url_schemes.push(scheme.into());
        self
    }
    /// Registers a document type the app edits.
    pub fn file_type(mut self, extension: impl Into<String>, name: impl Into<String>) -> Self {
        let extension = extension.into().trim_start_matches('.').to_string();
        self.file_types.push(FileType { extension, name: name.into(), role: "Editor".into() });
        self
    }
    /// Sets the copyright line.
    pub fn copyright(mut self, c: impl Into<String>) -> Self {
        self.copyright = Some(c.into());
        self
    }

    /// The parsed version.
    pub fn parsed_version(&self) -> Result<Version> {
        Version::parse(&self.version)
    }

    /// The executable name: explicit, else the first binary's file stem, else the name.
    pub fn executable_name(&self) -> String {
        self.executable.clone().unwrap_or_else(|| {
            self.binaries
                .first()
                .and_then(|(_, p)| p.file_stem())
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.name.clone())
        })
    }

    /// The binaries for macOS.
    pub fn macos_binaries(&self) -> Vec<(Arch, &Path)> {
        self.binaries.iter().filter(|(a, _)| a.is_macos()).map(|(a, p)| (*a, p.as_path())).collect()
    }

    /// Checks the fields every format needs.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::invalid("app", "name", "is empty"));
        }
        if self.name.contains('/') || self.name.contains(':') {
            return Err(Error::invalid("app", "name", "can't contain `/` or `:` (it names files and bundles)"));
        }
        let id_ok = !self.identifier.is_empty()
            && self.identifier.split('.').count() >= 2
            && self.identifier.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !id_ok {
            return Err(Error::invalid("app", "identifier", format!("`{}` must be reverse-DNS like `com.example.myapp` (letters, digits, `-`)", self.identifier)));
        }
        self.parsed_version()?;
        for s in &self.url_schemes {
            let ok = s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
            if !ok {
                return Err(Error::invalid("app", "url_scheme", format!("`{s}` isn't a valid URL scheme")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        let v = Version::parse("1.4.0-beta.1+42").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 4, 0));
        assert_eq!(v.pre.as_deref(), Some("beta.1"));
        assert_eq!(v.to_string(), "1.4.0-beta.1+42");
        assert_eq!(Version::parse("2").unwrap().triple(), "2.0.0");
        assert!(Version::parse("1.02").is_err());
        assert!(Version::parse("1.2.3.4").is_err());
        assert!(Version::parse("1.x").is_err());
    }

    #[test]
    fn validation() {
        assert!(App::new("My App", "com.example.myapp", "1.0.0").validate().is_ok());
        assert!(App::new("My App", "myapp", "1.0.0").validate().is_err());
        assert!(App::new("A/B", "com.example.x", "1.0.0").validate().is_err());
        assert!(App::new("A", "com.example.x", "1.0.0").url_scheme("my app").validate().is_err());
    }
}
