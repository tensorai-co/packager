//! A [`Signer`] backed by the macOS Keychain, through Security.framework's C API (loaded by the
//! linker, not a crate). The private key never leaves the Keychain: it signs digests in place,
//! and macOS may ask the user to allow access to the key.
//!
//! This is the one module with `unsafe` code: FFI calls into CoreFoundation and Security.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr;

use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::PublicKey;
use crate::crypto::x509::Certificate;
use crate::sign::Signer;
use crate::{Error, Result};

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;

#[repr(C)]
struct CFDictionaryCallBacks {
    _private: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, len: CFIndex) -> CFTypeRef;
    fn CFDataGetLength(d: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(d: CFTypeRef) -> *const u8;
    fn CFArrayGetCount(a: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(a: CFTypeRef, i: CFIndex) -> CFTypeRef;
    fn CFArrayCreate(alloc: CFTypeRef, values: *const CFTypeRef, n: CFIndex, callbacks: *const c_void) -> CFTypeRef;
    fn CFDictionaryCreate(alloc: CFTypeRef, keys: *const CFTypeRef, values: *const CFTypeRef, n: CFIndex, kcb: *const CFDictionaryCallBacks, vcb: *const CFDictionaryCallBacks) -> CFTypeRef;
    fn CFErrorCopyDescription(e: CFTypeRef) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut u8, size: CFIndex, encoding: u32) -> u8;
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
    static kCFTypeArrayCallBacks: c_void;
    static kCFBooleanTrue: CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CFTypeRef;
    static kSecClassIdentity: CFTypeRef;
    static kSecMatchLimit: CFTypeRef;
    static kSecMatchLimitAll: CFTypeRef;
    static kSecReturnRef: CFTypeRef;
    static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1: CFTypeRef;
    static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256: CFTypeRef;
    static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384: CFTypeRef;
    static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512: CFTypeRef;
    static kSecKeyAlgorithmECDSASignatureDigestX962SHA256: CFTypeRef;
    static kSecKeyAlgorithmECDSASignatureDigestX962SHA384: CFTypeRef;
    fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecIdentityCopyCertificate(identity: CFTypeRef, cert: *mut CFTypeRef) -> OSStatus;
    fn SecIdentityCopyPrivateKey(identity: CFTypeRef, key: *mut CFTypeRef) -> OSStatus;
    fn SecCertificateCopyData(cert: CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateSignature(key: CFTypeRef, alg: CFTypeRef, data: CFTypeRef, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecPolicyCreateBasicX509() -> CFTypeRef;
    fn SecTrustCreateWithCertificates(certs: CFTypeRef, policies: CFTypeRef, trust: *mut CFTypeRef) -> OSStatus;
    fn SecTrustEvaluateWithError(trust: CFTypeRef, error: *mut CFTypeRef) -> u8;
    fn SecTrustGetCertificateCount(trust: CFTypeRef) -> CFIndex;
    fn SecTrustGetCertificateAtIndex(trust: CFTypeRef, i: CFIndex) -> CFTypeRef;
}

/// An owned CoreFoundation reference, released on drop.
struct Cf(CFTypeRef);

impl Cf {
    fn new(r: CFTypeRef) -> Option<Cf> {
        if r.is_null() { None } else { Some(Cf(r)) }
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null CF object this wrapper owns one reference to.
        unsafe { CFRelease(self.0) }
    }
}

// SAFETY: CoreFoundation and Security objects used here (identities, keys, data) are immutable
// and documented thread-safe for these calls.
unsafe impl Send for Cf {}
// SAFETY: as above; the wrapper exposes no interior mutation.
unsafe impl Sync for Cf {}

fn data_bytes(d: &Cf) -> Vec<u8> {
    // SAFETY: `d` is a live CFData; the pointer is valid for `len` bytes while it lives.
    unsafe {
        let len = CFDataGetLength(d.0);
        let p = CFDataGetBytePtr(d.0);
        if p.is_null() || len <= 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(p, len as usize).to_vec()
    }
}

fn error_text(e: CFTypeRef) -> String {
    if e.is_null() {
        return "unknown error".into();
    }
    let err = Cf(e);
    // SAFETY: `err` is a live CFError; CFErrorCopyDescription returns a new CFString (or null),
    // and the buffer outlives the call.
    unsafe {
        let Some(desc) = Cf::new(CFErrorCopyDescription(err.0)) else { return "unknown error".into() };
        let mut buf = vec![0u8; 1024];
        if CFStringGetCString(desc.0, buf.as_mut_ptr(), buf.len() as CFIndex, 0x0800_0100) == 0 {
            return "unknown error".into();
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}

/// A code-signing identity in the Keychain.
pub struct KeychainSigner {
    chain: Vec<Certificate>,
    key: Cf,
}

impl std::fmt::Debug for KeychainSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeychainSigner({:?})", self.chain.first().and_then(|c| c.common_name()))
    }
}

/// Every identity (certificate with a private key) in the user's keychains, with its certificate.
fn identities() -> Result<Vec<(Cf, Certificate)>> {
    // SAFETY: the query dictionary is built from static CF constants; SecItemCopyMatching returns
    // a retained CFArray we own; array elements are borrowed, so each kept one is retained.
    unsafe {
        let keys = [kSecClass, kSecMatchLimit, kSecReturnRef];
        let values = [kSecClassIdentity, kSecMatchLimitAll, kCFBooleanTrue];
        let query = Cf::new(CFDictionaryCreate(ptr::null(), keys.as_ptr(), values.as_ptr(), 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks))
            .ok_or_else(|| Error::Other("keychain: can't build query".into()))?;
        let mut result: CFTypeRef = ptr::null();
        let status = SecItemCopyMatching(query.0, &mut result);
        if status == -25300 {
            return Ok(Vec::new()); // errSecItemNotFound
        }
        if status != 0 {
            return Err(Error::Other(format!("keychain: searching identities failed (OSStatus {status})")));
        }
        let array = Cf::new(result).ok_or_else(|| Error::Other("keychain: no result".into()))?;
        let mut out = Vec::new();
        for i in 0..CFArrayGetCount(array.0) {
            let identity = CFArrayGetValueAtIndex(array.0, i);
            let mut cert: CFTypeRef = ptr::null();
            if SecIdentityCopyCertificate(identity, &mut cert) != 0 {
                continue;
            }
            let Some(cert) = Cf::new(cert) else { continue };
            let Some(data) = Cf::new(SecCertificateCopyData(cert.0)) else { continue };
            if let Ok(c) = Certificate::from_der(&data_bytes(&data)) {
                out.push((Cf(CFRetain(identity)), c));
            }
        }
        Ok(out)
    }
}

/// Lists code-signing identities as (SHA-1 hex, common name), like `security find-identity`.
pub fn list_identities() -> Result<Vec<(String, String)>> {
    Ok(identities()?
        .into_iter()
        .filter(|(_, c)| c.extension(crate::crypto::der::oids::EXT_KEY_USAGE).is_some_and(|e| e.value.windows(8).any(|w| w == crate::crypto::der::oids::KP_CODE_SIGNING)))
        .map(|(_, c)| (crate::crypto::hex(&c.sha1()).to_uppercase(), c.common_name().unwrap_or("").to_string()))
        .collect())
}

/// The certificate chain macOS builds for `leaf` (leaf first, anchor last).
fn trust_chain(leaf_ref: &Cf, leaf: &Certificate) -> Vec<Certificate> {
    // SAFETY: all CF objects are created here and owned by `Cf` wrappers; returned certificates
    // from the trust object are borrowed and only read while `trust` lives.
    unsafe {
        let certs = [leaf_ref.0];
        let Some(array) = Cf::new(CFArrayCreate(ptr::null(), certs.as_ptr(), 1, &kCFTypeArrayCallBacks as *const c_void)) else { return vec![leaf.clone()] };
        let Some(policy) = Cf::new(SecPolicyCreateBasicX509()) else { return vec![leaf.clone()] };
        let mut trust: CFTypeRef = ptr::null();
        if SecTrustCreateWithCertificates(array.0, policy.0, &mut trust) != 0 {
            return vec![leaf.clone()];
        }
        let Some(trust) = Cf::new(trust) else { return vec![leaf.clone()] };
        let mut err: CFTypeRef = ptr::null();
        let _ = SecTrustEvaluateWithError(trust.0, &mut err);
        if !err.is_null() {
            CFRelease(err);
        }
        let mut out = Vec::new();
        for i in 0..SecTrustGetCertificateCount(trust.0) {
            let c = SecTrustGetCertificateAtIndex(trust.0, i);
            if let Some(data) = Cf::new(SecCertificateCopyData(c))
                && let Ok(cert) = Certificate::from_der(&data_bytes(&data))
            {
                out.push(cert);
            }
        }
        if out.is_empty() { vec![leaf.clone()] } else { out }
    }
}

impl KeychainSigner {
    /// Finds an identity the way `codesign -s` does: by SHA-1 fingerprint (hex), by exact
    /// common name, or by a unique substring of the common name.
    pub fn find(selector: &str) -> Result<Self> {
        let all = identities()?;
        let sel_hex = selector.replace(' ', "").to_lowercase();
        let by_hash: Vec<&(Cf, Certificate)> = all.iter().filter(|(_, c)| crate::crypto::hex(&c.sha1()) == sel_hex).collect();
        let exact: Vec<&(Cf, Certificate)> = all.iter().filter(|(_, c)| c.common_name() == Some(selector)).collect();
        let partial: Vec<&(Cf, Certificate)> = all.iter().filter(|(_, c)| c.common_name().is_some_and(|n| n.contains(selector))).collect();
        let pick = [by_hash, exact, partial].into_iter().find(|v| !v.is_empty()).unwrap_or_default();
        let mut distinct: Vec<&(Cf, Certificate)> = Vec::new();
        for p in pick {
            if !distinct.iter().any(|d| d.1.der == p.1.der) {
                distinct.push(p);
            }
        }
        match distinct.as_slice() {
            [] => Err(Error::Other(format!("{selector}: no identity found in the keychain"))),
            [(identity, leaf)] => {
                // SAFETY: `identity` is a live SecIdentity; both copy functions return retained
                // objects we own (wrapped immediately).
                let (key, cert_ref) = unsafe {
                    let mut key: CFTypeRef = ptr::null();
                    let st = SecIdentityCopyPrivateKey(identity.0, &mut key);
                    if st != 0 {
                        return Err(Error::Other(format!("{selector}: can't access the private key (OSStatus {st})")));
                    }
                    let mut cert: CFTypeRef = ptr::null();
                    SecIdentityCopyCertificate(identity.0, &mut cert);
                    (Cf::new(key), Cf::new(cert))
                };
                let key = key.ok_or_else(|| Error::Other(format!("{selector}: identity has no private key")))?;
                let chain = match cert_ref {
                    Some(c) => trust_chain(&c, leaf),
                    None => vec![leaf.clone()],
                };
                Ok(KeychainSigner { chain, key })
            }
            many => Err(Error::Other(format!(
                "{selector}: ambiguous ({} identities match: {})",
                many.len(),
                many.iter().map(|(_, c)| c.common_name().unwrap_or("?")).collect::<Vec<_>>().join(", ")
            ))),
        }
    }
}

impl Signer for KeychainSigner {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }
    fn sign_digest(&self, digest: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
        let ec = matches!(self.chain.first().map(|c| &c.public_key), Some(PublicKey::Ec(_)));
        // SAFETY: algorithm constants are static CFStrings; `data` and the returned signature
        // are owned via `Cf`; `err` is released by `error_text` when set.
        unsafe {
            let alg = match (ec, hash) {
                (false, HashAlg::Sha1) => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
                (false, HashAlg::Sha256) => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
                (false, HashAlg::Sha384) => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
                (false, HashAlg::Sha512) => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
                (true, HashAlg::Sha384) => kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
                (true, _) => kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            };
            let data = Cf::new(CFDataCreate(ptr::null(), digest.as_ptr(), digest.len() as CFIndex)).ok_or_else(|| Error::Other("keychain: out of memory".into()))?;
            let mut err: CFTypeRef = ptr::null();
            let sig = SecKeyCreateSignature(self.key.0, alg, data.0, &mut err);
            match Cf::new(sig) {
                Some(s) => Ok(data_bytes(&s)),
                None => Err(Error::Other(format!("keychain: signing failed: {}", error_text(err)))),
            }
        }
    }
}
