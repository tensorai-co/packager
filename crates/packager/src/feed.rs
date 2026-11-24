//! Signed update feeds: a P-256 signing key, and a JSON feed announcing a release whose
//! signature an app checks with the public key it embeds (as `ui::update::check` does).
//!
//! ```json
//! { "payload": "{\"version\":\"1.3.0\",\"url\":\"https://…\",\"notes\":\"…\"}",
//!   "signature": "<base64 DER ECDSA-SHA256 signature of the payload string's bytes>" }
//! ```
//!
//! The signature covers the payload's exact bytes, so nothing needs to be canonicalized.
//! Keys are PKCS#8 PEM, so ones made with `openssl ecparam -name prime256v1 -genkey` work too.

use std::path::{Path, PathBuf};

use crate::crypto::ec::{Curve, EcPrivateKey};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::error::IoContext;
use crate::format::base64;
use crate::format::json::Json;
use crate::{Error, Result};

/// A new signing key as PKCS#8 PEM, and its public key for the app ([`public_key`]).
pub fn generate_key() -> Result<(String, String)> {
    let key = PrivateKey::Ec(EcPrivateKey::generate(Curve::P256)?);
    let public = public_key_of(&key)?;
    Ok((key.to_pem(), public))
}

/// Writes a new key to `<dir>/update-private.pem` (refusing to overwrite one) and returns its
/// path and public key.
pub fn write_key(dir: &Path) -> Result<(PathBuf, String)> {
    std::fs::create_dir_all(dir).at(dir)?;
    let path = dir.join("update-private.pem");
    if path.exists() {
        return Err(Error::Other(format!("{} already exists; not overwriting it", path.display())));
    }
    let (pem, public) = generate_key()?;
    std::fs::write(&path, pem).at(&path)?;
    crate::util::set_mode(&path, 0o600)?;
    Ok((path, public))
}

/// The public key an app embeds: the base64 uncompressed P-256 point of a private key (PEM).
pub fn public_key(private_pem: &str) -> Result<String> {
    public_key_of(&PrivateKey::from_pem(private_pem, None)?)
}

fn public_key_of(key: &PrivateKey) -> Result<String> {
    match key.public() {
        PublicKey::Ec(k) if k.curve == Curve::P256 => Ok(base64::encode(&k.to_sec1())),
        _ => Err(Error::invalid("feed", "key", "update keys must be P-256 (prime256v1) EC keys")),
    }
}

/// The signed feed for `version` at `url`, with optional release notes.
pub fn sign(private_pem: &str, version: &str, url: &str, notes: Option<&str>) -> Result<String> {
    let key = PrivateKey::from_pem(private_pem, None)?;
    public_key_of(&key)?;
    let mut fields = vec![("version", Json::str(version)), ("url", Json::str(url))];
    if let Some(n) = notes {
        fields.push(("notes", Json::str(n)));
    }
    let payload = Json::object(fields).to_string_compact();
    let sig = key.sign(HashAlg::Sha256, &crate::crypto::sha256(payload.as_bytes()))?;
    Ok(format!("{}\n", Json::object(vec![("payload", Json::str(payload.clone())), ("signature", Json::str(base64::encode(&sig)))]).to_string_compact()))
}

/// Checks a feed against a public key ([`public_key`]'s form) and returns its payload.
pub fn verify(feed: &str, public_key: &str) -> Result<Json> {
    let bad = |m: &str| Error::malformed("feed", m);
    let doc = Json::parse(feed)?;
    let payload = doc.get("payload").and_then(Json::as_str).ok_or_else(|| bad("no \"payload\""))?;
    let sig = base64::decode(doc.get("signature").and_then(Json::as_str).ok_or_else(|| bad("no \"signature\""))?)?;
    let point = base64::decode(public_key.trim())?;
    let key = crate::crypto::ec::EcPublicKey::from_sec1(Curve::P256, &point)?;
    if !key.verify(&crate::crypto::sha256(payload.as_bytes()), &sig) {
        return Err(bad("signature doesn't match the key"));
    }
    Json::parse(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (pem, public) = generate_key().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(public_key(&pem).unwrap(), public);
        assert_eq!(base64::decode(&public).unwrap().len(), 65);
        let feed = sign(&pem, "1.3.0", "https://example.com/App-1.3.0.zip", Some("Fixes \"quotes\"\nand lines")).unwrap();
        let payload = verify(&feed, &public).unwrap();
        assert_eq!(payload.get("version").and_then(Json::as_str), Some("1.3.0"));
        assert_eq!(payload.get("notes").and_then(Json::as_str), Some("Fixes \"quotes\"\nand lines"));
        let (_, other) = generate_key().unwrap();
        assert!(verify(&feed, &other).is_err());
        assert!(verify(&feed.replace("1.3.0", "1.3.1"), &public).is_err());
    }
}
