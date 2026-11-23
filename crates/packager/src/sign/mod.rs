//! Signing: the [`Signer`] trait every key source implements, and the per-platform signing
//! configurations the builder runs.
//!
//! Since June 2023 publicly trusted code-signing keys live in HSMs or cloud key services, so a
//! signer only ever signs a digest the packager computed: the key never has to leave its store.

pub mod apple;
pub mod bundle;
pub mod der;

use std::sync::Arc;

use crate::Result;

/// A DER-encoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The DER bytes.
    pub der: Vec<u8>,
}

/// Signature algorithms a [`Signer`] may be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSA PKCS#1 v1.5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// ECDSA P-256 over a SHA-256 digest.
    EcdsaP256Sha256,
}

/// A source of signatures: a key file, a token, an OS key store or a cloud service.
pub trait Signer: Send + Sync {
    /// The leaf certificate first, then intermediates.
    fn certificate_chain(&self) -> &[Certificate];
    /// Signs a digest the packager computed, so the key never leaves its HSM.
    fn sign_digest(&self, digest: &[u8], alg: SignatureAlgorithm) -> Result<Vec<u8>>;
}

/// The identity an Apple signature is made with.
#[derive(Clone)]
pub enum AppleIdentity {
    /// An ad-hoc signature: hashes only, no certificate. Enough to run locally (Apple Silicon
    /// refuses unsigned code), not enough for Gatekeeper or notarization.
    AdHoc,
    /// A certificate-backed identity (Developer ID Application, Apple Distribution…).
    Signer(Arc<dyn Signer>),
}

impl std::fmt::Debug for AppleIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppleIdentity::AdHoc => f.write_str("AdHoc"),
            AppleIdentity::Signer(_) => f.write_str("Signer(..)"),
        }
    }
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
}

impl Apple {
    /// Ad-hoc signing: what local builds and CI without certificates use.
    pub fn ad_hoc() -> Self {
        Apple { application: AppleIdentity::AdHoc, installer: None, hardened_runtime: false, entitlements: None }
    }
    /// Signing with a Developer ID Application identity.
    pub fn developer_id(signer: Arc<dyn Signer>) -> Self {
        Apple { application: AppleIdentity::Signer(signer), installer: None, hardened_runtime: false, entitlements: None }
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
}
