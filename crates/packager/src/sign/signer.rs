//! In-process signers: a key held in memory (from PEM, PKCS#12 or generated), plus certificate
//! chain completion through each certificate's Authority Information Access URL.

use std::path::Path;
use std::sync::Arc;

use crate::crypto::der::{self, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::PrivateKey;
use crate::crypto::pkcs12::Pkcs12;
use crate::crypto::x509::Certificate;
use crate::error::IoContext;
use crate::sign::Signer;
use crate::transport::Transport;
use crate::{Error, Result};

/// A signer whose private key is in memory.
pub struct KeySigner {
    chain: Vec<Certificate>,
    key: PrivateKey,
}

impl std::fmt::Debug for KeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeySigner({:?})", self.chain.first().and_then(|c| c.common_name()))
    }
}

impl KeySigner {
    /// From a key and its chain (leaf first). Fails if the key doesn't match the leaf.
    pub fn new(key: PrivateKey, chain: Vec<Certificate>) -> Result<Self> {
        let leaf = chain.first().ok_or_else(|| Error::Other("signer: no certificate".into()))?;
        if leaf.public_key != key.public() {
            return Err(Error::Other("signer: the private key doesn't match the certificate".into()));
        }
        Ok(KeySigner { chain: order_chain(chain), key })
    }

    /// From PEM files: certificates (leaf first, intermediates after) and a private key
    /// (PKCS#8, PKCS#1, SEC1, or encrypted PKCS#8 with `password`).
    pub fn pem(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>, password: Option<&str>) -> Result<Self> {
        let (cp, kp) = (cert_path.as_ref(), key_path.as_ref());
        let certs = Certificate::from_pem_all(&std::fs::read_to_string(cp).at(cp)?)?;
        let key = PrivateKey::from_pem(&std::fs::read_to_string(kp).at(kp)?, password)?;
        // Put the certificate matching the key first.
        let public = key.public();
        let (mut leaf, others): (Vec<_>, Vec<_>) = certs.into_iter().partition(|c| c.public_key == public);
        let leaf = leaf.pop().ok_or_else(|| Error::Other(format!("{}: no certificate matches the key in {}", cp.display(), kp.display())))?;
        Self::new(key, std::iter::once(leaf).chain(others).collect())
    }

    /// From a `.p12` / `.pfx` file.
    pub fn pkcs12(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let p = path.as_ref();
        let pfx = Pkcs12::parse(&std::fs::read(p).at(p)?, password)?;
        Self::new(pfx.key, std::iter::once(pfx.leaf).chain(pfx.others).collect())
    }

    /// A throwaway self-signed code-signing identity, for tests and local builds that need a
    /// stable certificate signature rather than an ad-hoc one.
    pub fn self_signed(common_name: &str, team_id: Option<&str>) -> Result<Self> {
        let key = PrivateKey::Rsa(crate::crypto::rsa::RsaPrivateKey::generate(2048)?);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cert = Certificate::self_signed(common_name, team_id, &key, now - 86_400, 3650)?;
        Self::new(key, vec![cert])
    }

    /// Fills in missing issuers by following Authority Information Access URLs (as macOS does),
    /// until a self-issued anchor or a certificate with no URL.
    pub fn complete_chain(mut self, transport: &dyn Transport) -> Result<Self> {
        self.chain = complete_chain(self.chain, transport)?;
        Ok(self)
    }

    /// Wraps as a shared [`Signer`].
    pub fn into_arc(self) -> Arc<dyn Signer> {
        Arc::new(self)
    }

    /// The private key (for writing it back out, e.g. after generating).
    pub fn key(&self) -> &PrivateKey {
        &self.key
    }
}

impl Signer for KeySigner {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }
    fn sign_digest(&self, digest: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
        self.key.sign(hash, digest)
    }
}

/// Orders certificates leaf first, each followed by its issuer; unrelated ones are dropped.
pub fn order_chain(certs: Vec<Certificate>) -> Vec<Certificate> {
    let mut rest = certs;
    if rest.is_empty() {
        return rest;
    }
    let mut out = vec![rest.remove(0)];
    while let Some(cur) = out.last() {
        if cur.is_self_issued() {
            break;
        }
        let Some(i) = rest.iter().position(|c| c.subject_raw == cur.issuer_raw) else { break };
        out.push(rest.remove(i));
    }
    out
}

const AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const CA_ISSUERS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];

/// The caIssuers URLs of a certificate's Authority Information Access extension.
pub fn ca_issuer_urls(cert: &Certificate) -> Vec<String> {
    let Some(ext) = cert.extension(AIA) else { return Vec::new() };
    let Ok(t) = der::parse(&ext.value) else { return Vec::new() };
    let mut out = Vec::new();
    let mut r = t.reader();
    while let Ok(ad) = r.expect(tag::SEQUENCE) {
        let mut ar = ad.reader();
        if let (Ok(m), Ok(loc)) = (ar.expect(tag::OID), ar.read())
            && m.value == CA_ISSUERS
            && loc.tag == 0x86
        {
            out.push(String::from_utf8_lossy(loc.value).into_owned());
        }
    }
    out
}

/// Completes `chain` up to a self-issued anchor using AIA URLs.
pub fn complete_chain(chain: Vec<Certificate>, transport: &dyn Transport) -> Result<Vec<Certificate>> {
    let mut chain = order_chain(chain);
    for _ in 0..8 {
        let Some(top) = chain.last() else { break };
        if top.is_self_issued() {
            break;
        }
        let Some(url) = ca_issuer_urls(top).into_iter().find(|u| u.starts_with("http")) else { break };
        let body = transport.get(&url)?;
        // Usually DER; some CAs serve PEM or a PKCS#7 bundle.
        let issuer = match Certificate::from_der(&body) {
            Ok(c) => c,
            Err(_) => Certificate::from_pem_all(&String::from_utf8_lossy(&body))?.into_iter().next().ok_or_else(|| Error::Other(format!("{url}: no certificate in the response")))?,
        };
        if issuer.subject_raw != top.issuer_raw || !top.is_signed_by(&issuer) {
            return Err(Error::Other(format!("{url}: the downloaded certificate doesn't issue {:?}", top.common_name())));
        }
        chain.push(issuer);
    }
    Ok(chain)
}
