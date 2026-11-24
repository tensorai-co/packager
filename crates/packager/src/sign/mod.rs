//! Signing: the [`Signer`] trait every key source implements, and the per-platform signing
//! configurations the builder runs.
//!
//! Since June 2023 publicly trusted code-signing keys live in HSMs or cloud key services, so a
//! signer only ever signs a digest the packager computed: the key never has to leave its store.

pub mod apple;
pub mod assess;
pub mod authenticode;
pub mod bundle;
pub mod cms;
pub mod disk_image;
pub mod installer;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod msi;
pub mod requirement;
pub mod signer;
pub mod timestamp;

use std::sync::Arc;

use crate::Result;
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::PublicKey;
use crate::crypto::x509::Certificate;

pub use signer::KeySigner;

/// A source of signatures: a key file, a token, an OS key store or a cloud service.
pub trait Signer: Send + Sync {
    /// The leaf certificate first, then intermediates (and the anchor, when known).
    fn certificate_chain(&self) -> &[Certificate];
    /// Signs a digest the packager computed, so the key never leaves its store. RSA keys return
    /// PKCS#1 v1.5 signatures, EC keys a DER `Ecdsa-Sig-Value`.
    fn sign_digest(&self, digest: &[u8], hash: HashAlg) -> Result<Vec<u8>>;
}

impl<'a> dyn Signer + 'a {
    /// The leaf certificate.
    pub fn leaf(&self) -> Option<&Certificate> {
        self.certificate_chain().first()
    }
    /// The `AlgorithmIdentifier` (DER) of this signer's signatures with `hash`.
    pub fn signature_algorithm(&self, hash: HashAlg) -> Vec<u8> {
        use crate::crypto::der::{self, oids};
        match self.leaf().map(|c| &c.public_key) {
            Some(PublicKey::Ec(_)) => der::seq(&[&der::oid(if hash == HashAlg::Sha384 { oids::ECDSA_SHA384 } else { oids::ECDSA_SHA256 })]),
            _ => {
                let o = match hash {
                    HashAlg::Sha1 => oids::SHA1_WITH_RSA,
                    HashAlg::Sha256 => oids::SHA256_WITH_RSA,
                    HashAlg::Sha384 => oids::SHA384_WITH_RSA,
                    HashAlg::Sha512 => oids::SHA512_WITH_RSA,
                };
                der::seq(&[&der::oid(o), &der::null()])
            }
        }
    }
    /// The most bytes a signature from this signer can take.
    pub fn max_signature_len(&self) -> usize {
        match self.leaf().map(|c| &c.public_key) {
            Some(PublicKey::Rsa(k)) => k.size(),
            Some(PublicKey::Ec(k)) => 2 * k.curve.size() + 9,
            None => 512,
        }
    }
}

/// The identity an Apple signature is made with.
#[derive(Clone)]
pub enum AppleIdentity {
    /// An ad-hoc signature: hashes only, no certificate. Enough to run locally (Apple Silicon
    /// refuses unsigned code), not enough for Gatekeeper or notarization.
    AdHoc,
    /// A certificate-backed identity (Developer ID Application, Apple Development…).
    Signer(Arc<dyn Signer>),
}

impl std::fmt::Debug for AppleIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppleIdentity::AdHoc => f.write_str("AdHoc"),
            AppleIdentity::Signer(s) => write!(f, "Signer({:?})", s.leaf().and_then(|c| c.common_name())),
        }
    }
}

/// Whether and where secure timestamps come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Timestamp {
    /// What `codesign` does: Apple's server for Developer ID signatures, none otherwise.
    #[default]
    Auto,
    /// Never timestamp (`--timestamp=none`).
    None,
    /// Always use Apple's server (`--timestamp`), which notarization requires.
    Apple,
    /// An RFC 3161 server at this URL.
    Url(String),
}

/// How Apple code is signed: the identity for binaries, bundles and disk images, the optional
/// installer identity for `.pkg`, and the runtime options.
#[derive(Debug, Clone)]
pub struct Apple {
    /// Signs Mach-O binaries, `.app` bundles and `.dmg` images.
    pub application: AppleIdentity,
    /// Signs `.pkg` installers (Developer ID Installer / Mac App Store).
    pub installer: Option<AppleIdentity>,
    /// Opt executables into the hardened runtime (required for notarization).
    pub hardened_runtime: bool,
    /// Entitlements plist (XML) for the main executable.
    pub entitlements: Option<Vec<u8>>,
    /// Secure timestamps.
    pub timestamp: Timestamp,
    /// Explicit requirements (`codesign -r`), in the requirement language.
    pub requirements: Option<String>,
}

impl Apple {
    /// Ad-hoc signing: what local builds and CI without certificates use.
    pub fn ad_hoc() -> Self {
        Apple { application: AppleIdentity::AdHoc, installer: None, hardened_runtime: false, entitlements: None, timestamp: Timestamp::Auto, requirements: None }
    }
    /// Signing with a certificate identity (Developer ID Application, Apple Development…).
    pub fn developer_id(signer: Arc<dyn Signer>) -> Self {
        Apple { application: AppleIdentity::Signer(signer), ..Apple::ad_hoc() }
    }
    /// The identity for `.pkg` files.
    pub fn installer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.installer = Some(AppleIdentity::Signer(signer));
        self
    }
    /// Turns on the hardened runtime.
    pub fn hardened_runtime(mut self) -> Self {
        self.hardened_runtime = true;
        self
    }
    /// Sets the timestamp policy.
    pub fn timestamp(mut self, t: Timestamp) -> Self {
        self.timestamp = t;
        self
    }
    /// Explicit requirements in the requirement language.
    pub fn requirements(mut self, text: impl Into<String>) -> Self {
        self.requirements = Some(text.into());
        self
    }
    /// Entitlements for the main executable, read from an XML or binary plist file.
    pub fn entitlements(mut self, path: impl AsRef<std::path::Path>) -> Result<Self> {
        use crate::error::IoContext;
        let p = path.as_ref();
        let bytes = std::fs::read(p).at(p)?;
        // Normalize to XML: the entitlements blob must be XML.
        let v = crate::format::plist::Value::parse(&bytes)?;
        self.entitlements = Some(v.to_xml().into_bytes());
        Ok(self)
    }
    /// Entitlements given as XML plist bytes.
    pub fn entitlements_xml(mut self, xml: impl Into<Vec<u8>>) -> Self {
        self.entitlements = Some(xml.into());
        self
    }

    /// The timestamp server this configuration resolves to for `identity`, if any.
    pub fn timestamp_url(&self, identity: &AppleIdentity) -> Option<String> {
        let AppleIdentity::Signer(s) = identity else { return None };
        match &self.timestamp {
            Timestamp::None => None,
            Timestamp::Apple => Some(timestamp::APPLE_TSA.to_string()),
            Timestamp::Url(u) => Some(u.clone()),
            Timestamp::Auto => {
                // Developer ID Application or Installer certificates.
                let is_devid = [requirement::apple_oids::DEVELOPER_ID_LEAF, assess::DEVELOPER_ID_INSTALLER_LEAF]
                    .iter()
                    .filter_map(|o| crate::crypto::der::oid_from_str(o).ok())
                    .any(|o| s.leaf().is_some_and(|c| c.extension(&o).is_some()));
                is_devid.then(|| timestamp::APPLE_TSA.to_string())
            }
        }
    }

    /// Options for signing a bundle with the application identity.
    pub fn bundle_options(&self) -> bundle::BundleSignOptions {
        bundle::BundleSignOptions {
            identity: self.application.clone(),
            hardened_runtime: self.hardened_runtime,
            entitlements: self.entitlements.clone(),
            requirements: self.requirements.clone(),
            timestamp_url: self.timestamp_url(&self.application),
        }
    }
}

/// How Windows code is signed: one identity for every `.exe`, `.dll`, `.msix` and `.msi`.
#[derive(Clone)]
pub struct Authenticode {
    /// The code-signing identity (an OV/EV certificate, or Artifact Signing via a command).
    pub signer: Arc<dyn Signer>,
    /// RFC 3161 server (`/tr`); any public one works for Windows.
    pub timestamp_url: Option<String>,
    /// File digest (`/fd`).
    pub digest: HashAlg,
}

impl std::fmt::Debug for Authenticode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authenticode({:?}, timestamp {:?})", self.signer.leaf().and_then(|c| c.common_name()), self.timestamp_url)
    }
}

impl Authenticode {
    /// SHA-256 signatures with `signer`, untimestamped until [`Authenticode::timestamp`].
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Authenticode { signer, timestamp_url: None, digest: HashAlg::Sha256 }
    }
    /// Timestamps with the RFC 3161 server at `url`.
    pub fn timestamp(mut self, url: impl Into<String>) -> Self {
        self.timestamp_url = Some(url.into());
        self
    }
    /// The library options for one signature.
    pub fn options(&self) -> authenticode::Options<'static> {
        let mut o = authenticode::Options::sha256();
        o.digest = self.digest;
        o.timestamp_url = self.timestamp_url.clone();
        o
    }
}
