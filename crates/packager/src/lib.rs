//! Native OS packages from scratch, in pure Rust, with zero dependencies: `.app`, `.dmg` and
//! `.pkg` for macOS, `.msi`, `.msix` and `.msixbundle` for Windows, `.deb` and `.snap` for Linux,
//! built and signed from any host.
//!
//! ```no_run
//! use packager::package::{Deb, Dmg, Msi};
//! use packager::{App, Arch};
//!
//! let app = App::new("My App", "com.example.myapp", "1.4.0")
//!     .publisher("Example Ltd")
//!     .binary(Arch::MacosArm64, "target/aarch64-apple-darwin/release/my-app")
//!     .binary(Arch::WindowsX64, "target/x86_64-pc-windows-msvc/release/my-app.exe")
//!     .binary(Arch::LinuxX64, "target/x86_64-unknown-linux-gnu/release/my-app")
//!     .icon("assets/icon.png");
//! let out = packager::build(&app).package(Dmg::new()).package(Msi::new()).package(Deb::new()).out_dir("target/dist").run()?;
//! for p in out.packages() {
//!     println!("{} {} {}", p.kind(), p.arch(), p.path().display());
//! }
//! # Ok::<(), packager::Error>(())
//! ```
//!
//! Layers, each usable on its own:
//! - [`compress`]: DEFLATE, zlib, gzip, LZMA2 and xz.
//! - [`crypto`]: hashes, RSA, ECDSA, X.509, CMS, PKCS#12 and the ciphers they need.
//! - [`mod@format`]: byte-level readers and writers (plist, PNG, ICNS, Mach-O, PE, ELF, cpio, XAR,
//!   Bom, HFS+, UDIF, ZIP, CAB, Compound File, MSI, tar, `ar`, SquashFS…).
//! - [`sign`]: the [`sign::Signer`] trait, Apple code signing and Authenticode.
//! - [`notary`] and [`staple`]: Apple notarization.
//! - [`package`]: the high-level builders, one per format.
//!
//! [`build()`] ties them together from one platform-neutral [`App`].

// `unsafe` only in `sign::keychain` (Security.framework FFI), which opts in explicitly.
#![deny(unsafe_code)]

pub mod app;
mod build;
pub mod compress;
pub mod crypto;
mod error;
pub mod format;
pub mod identity;
pub mod image;
pub mod notary;
pub mod package;
pub mod sign;
pub mod staple;
pub mod transport;
pub mod util;

pub use app::{App, Arch, FileType, Version};
pub use build::{Builder, Output, Signing, build};
pub use error::{Error, Result};
pub use package::{Package, PackageKind};
