//! Native OS packages from scratch, in pure Rust, with zero dependencies.
//!
//! Layers, each usable on its own:
//! - [`compress`]: DEFLATE, zlib, gzip.
//! - [`crypto`]: hashes and checksums.
//! - [`format`]: byte-level readers and writers (plist, PNG, ICNS, Mach-O, cpio, XAR, Bom, HFS+, UDIF…).
//! - [`sign`]: the [`sign::Signer`] trait and Apple code signing.
//! - [`package`]: the high-level builders (`.app`, `.pkg`, `.dmg`).
//!
//! [`build`] ties them together from one platform-neutral [`App`].

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
pub mod package;
pub mod sign;
pub mod transport;
pub mod util;

pub use app::{App, Arch, FileType, Version};
pub use build::{build, Builder, Output};
pub use package::{Package, PackageKind};
pub use error::{Error, Result};
