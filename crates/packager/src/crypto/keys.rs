//! Key formats: PEM armor, PKCS#1 and SEC1 private keys, PKCS#8 (plain and PBES2-encrypted)
//! and SubjectPublicKeyInfo.

use crate::crypto::bigint::BigUint;
use crate::crypto::der::{self, oids, tag};
use crate::crypto::ec::{Curve, EcPrivateKey, EcPublicKey};
use crate::crypto::hmac::HashAlg;
use crate::crypto::rsa::{RsaPrivateKey, RsaPublicKey};
use crate::format::base64;
use crate::{Error, Result};

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("key", m)
}

/// A PEM block: its label and decoded body.
#[derive(Debug, Clone)]
pub struct PemBlock {
    /// `CERTIFICATE`, `PRIVATE KEY`…
    pub label: String,
    /// The DER bytes.
    pub der: Vec<u8>,
}

/// Every PEM block in `text`.
pub fn pem_decode(text: &str) -> Result<Vec<PemBlock>> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line.trim().strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else { continue };
        let mut body = String::new();
        let end = format!("-----END {label}-----");
        loop {
            let l = lines.next().ok_or_else(|| bad(format!("unterminated PEM block {label}")))?;
            if l.trim() == end {
                break;
            }
            if l.contains(':') {
                return Err(bad("encrypted legacy PEM (Proc-Type) isn't supported; use PKCS#8"));
            }
            body.push_str(l.trim());
        }
        out.push(PemBlock { label: label.to_string(), der: base64::decode(&body)? });
    }
    Ok(out)
}

/// PEM-armors `der` with `label`.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b = base64::encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// A public key of a supported type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA.
    Rsa(RsaPublicKey),
    /// ECDSA.
    Ec(EcPublicKey),
}

/// A private key of a supported type.
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA.
    Rsa(RsaPrivateKey),
    /// ECDSA.
    Ec(EcPrivateKey),
}

impl PublicKey {
    /// Parses a DER `SubjectPublicKeyInfo`.
    pub fn from_spki(der_bytes: &[u8]) -> Result<Self> {
        let t = der::parse(der_bytes)?;
        let mut r = t.reader();
        let alg = r.expect(tag::SEQUENCE)?;
        let bits = r.expect(tag::BIT_STRING)?.as_bit_string()?;
        let mut ar = alg.reader();
        let alg_oid = ar.expect(tag::OID)?.value;
        if alg_oid == oids::RSA_ENCRYPTION {
            let k = der::parse(bits)?;
            let mut kr = k.reader();
            let n = kr.expect(tag::INTEGER)?.as_biguint()?;
            let e = kr.expect(tag::INTEGER)?.as_biguint()?;
            Ok(PublicKey::Rsa(RsaPublicKey { n, e }))
        } else if alg_oid == oids::EC_PUBLIC_KEY {
            let curve_oid = ar.expect(tag::OID)?.value;
            let curve = Curve::from_oid(curve_oid).ok_or_else(|| bad(format!("unsupported curve {}", der::oid_to_string(curve_oid))))?;
            Ok(PublicKey::Ec(EcPublicKey::from_sec1(curve, bits)?))
        } else {
            Err(bad(format!("unsupported public key algorithm {}", der::oid_to_string(alg_oid))))
        }
    }

    /// The DER `SubjectPublicKeyInfo`.
    pub fn to_spki(&self) -> Vec<u8> {
        match self {
            PublicKey::Rsa(k) => {
                let key = der::seq(&[&der::integer_big(&k.n), &der::integer_big(&k.e)]);
                der::seq(&[&der::seq(&[&der::oid(oids::RSA_ENCRYPTION), &der::null()]), &der::bit_string(&key)])
            }
            PublicKey::Ec(k) => der::seq(&[&der::seq(&[&der::oid(oids::EC_PUBLIC_KEY), &der::oid(k.curve.oid())]), &der::bit_string(&k.to_sec1())]),
        }
    }

    /// Verifies `sig` over `digest` made with the signature algorithm `sig_alg` (an OID body).
    pub fn verify(&self, sig_alg: &[u8], digest: &[u8], sig: &[u8]) -> bool {
        let Some(h) = hash_for_signature_oid(sig_alg) else { return false };
        match self {
            PublicKey::Rsa(k) => k.verify_pkcs1_v15(h, digest, sig),
            PublicKey::Ec(k) => k.verify(digest, sig),
        }
    }
}

/// The hash a signature-algorithm OID implies (`rsaEncryption` → SHA-256, as CMS signers use it).
pub fn hash_for_signature_oid(o: &[u8]) -> Option<HashAlg> {
    Some(match o {
        x if x == oids::SHA256_WITH_RSA || x == oids::ECDSA_SHA256 || x == oids::RSA_ENCRYPTION => HashAlg::Sha256,
        x if x == oids::SHA1_WITH_RSA => HashAlg::Sha1,
        x if x == oids::SHA384_WITH_RSA || x == oids::ECDSA_SHA384 => HashAlg::Sha384,
        x if x == oids::SHA512_WITH_RSA => HashAlg::Sha512,
        _ => return None,
    })
}

/// The hash for a digest-algorithm OID.
pub fn hash_for_digest_oid(o: &[u8]) -> Option<HashAlg> {
    Some(match o {
        x if x == oids::SHA1 => HashAlg::Sha1,
        x if x == oids::SHA256 => HashAlg::Sha256,
        x if x == oids::SHA384 => HashAlg::Sha384,
        x if x == oids::SHA512 => HashAlg::Sha512,
        _ => return None,
    })
}

/// The digest-algorithm OID for a hash.
pub fn digest_oid(h: HashAlg) -> &'static [u8] {
    match h {
        HashAlg::Sha1 => oids::SHA1,
        HashAlg::Sha256 => oids::SHA256,
        HashAlg::Sha384 => oids::SHA384,
        HashAlg::Sha512 => oids::SHA512,
    }
}

impl PrivateKey {
    /// The public half.
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public()),
            PrivateKey::Ec(k) => PublicKey::Ec(k.public()),
        }
    }

    /// PEM of the unencrypted PKCS#8 encoding (`-----BEGIN PRIVATE KEY-----`), what `openssl`
    /// writes and [`PrivateKey::from_pem`] reads.
    pub fn to_pem(&self) -> String {
        pem_encode("PRIVATE KEY", &self.to_pkcs8())
    }

    /// Signs a precomputed digest. RSA gives PKCS#1 v1.5, ECDSA a DER `Ecdsa-Sig-Value`.
    pub fn sign(&self, alg: HashAlg, digest: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Rsa(k) => k.sign_pkcs1_v15(alg, digest),
            PrivateKey::Ec(k) => k.sign(digest, alg),
        }
    }

    /// The `AlgorithmIdentifier` (DER) for signatures with `alg` by this key.
    pub fn signature_algorithm(&self, alg: HashAlg) -> Vec<u8> {
        match self {
            PrivateKey::Rsa(_) => {
                let o = match alg {
                    HashAlg::Sha1 => oids::SHA1_WITH_RSA,
                    HashAlg::Sha256 => oids::SHA256_WITH_RSA,
                    HashAlg::Sha384 => oids::SHA384_WITH_RSA,
                    HashAlg::Sha512 => oids::SHA512_WITH_RSA,
                };
                der::seq(&[&der::oid(o), &der::null()])
            }
            PrivateKey::Ec(_) => der::seq(&[&der::oid(if alg == HashAlg::Sha384 { oids::ECDSA_SHA384 } else { oids::ECDSA_SHA256 })]),
        }
    }

    /// Parses PKCS#8 `PrivateKeyInfo`, PKCS#1 `RSAPrivateKey` or SEC1 `ECPrivateKey` DER.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        Self::from_pkcs8(der_bytes).or_else(|_| Self::from_pkcs1(der_bytes)).or_else(|_| Self::from_sec1(der_bytes, None))
    }

    /// Parses PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8(der_bytes: &[u8]) -> Result<Self> {
        let t = der::parse(der_bytes)?;
        let mut r = t.reader();
        if r.expect(tag::INTEGER)?.as_i64()? > 1 {
            return Err(bad("unsupported PKCS#8 version"));
        }
        let alg = r.expect(tag::SEQUENCE)?;
        let key = r.expect(tag::OCTET_STRING)?.value;
        let mut ar = alg.reader();
        let o = ar.expect(tag::OID)?.value;
        if o == oids::RSA_ENCRYPTION {
            Self::from_pkcs1(key)
        } else if o == oids::EC_PUBLIC_KEY {
            let curve = ar.expect(tag::OID).ok().and_then(|c| Curve::from_oid(c.value));
            Self::from_sec1(key, curve)
        } else {
            Err(bad(format!("unsupported key algorithm {}", der::oid_to_string(o))))
        }
    }

    /// Parses PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs1(der_bytes: &[u8]) -> Result<Self> {
        let t = der::parse(der_bytes)?;
        let mut r = t.reader();
        r.expect(tag::INTEGER)?;
        let mut v: Vec<BigUint> = Vec::new();
        for _ in 0..5 {
            v.push(r.expect(tag::INTEGER)?.as_biguint()?);
        }
        let mut it = v.into_iter();
        let (n, e, d, p, q) = (it.next().unwrap_or_default(), it.next().unwrap_or_default(), it.next().unwrap_or_default(), it.next().unwrap_or_default(), it.next().unwrap_or_default());
        Ok(PrivateKey::Rsa(RsaPrivateKey::from_components(n, e, d, p, q)?))
    }

    /// Parses SEC1 `ECPrivateKey`; `curve` comes from PKCS#8 when the key omits it.
    pub fn from_sec1(der_bytes: &[u8], curve: Option<Curve>) -> Result<Self> {
        let t = der::parse(der_bytes)?;
        let mut r = t.reader();
        if r.expect(tag::INTEGER)?.as_i64()? != 1 {
            return Err(bad("unsupported ECPrivateKey version"));
        }
        let d = BigUint::from_be_bytes(r.expect(tag::OCTET_STRING)?.value);
        let mut curve = curve;
        while !r.is_empty() {
            let el = r.read()?;
            if el.is_context(0) {
                curve = Curve::from_oid(der::parse(el.value)?.value).or(curve);
            }
        }
        let curve = curve.ok_or_else(|| bad("EC key doesn't name its curve"))?;
        Ok(PrivateKey::Ec(EcPrivateKey { curve, d }))
    }

    /// PKCS#8 DER (unencrypted).
    pub fn to_pkcs8(&self) -> Vec<u8> {
        match self {
            PrivateKey::Rsa(k) => {
                let pkcs1 = der::seq(&[
                    &der::integer(0),
                    &der::integer_big(&k.n),
                    &der::integer_big(&k.e),
                    &der::integer_big(&k.d),
                    &der::integer_big(&k.p),
                    &der::integer_big(&k.q),
                    &der::integer_big(&k.dp),
                    &der::integer_big(&k.dq),
                    &der::integer_big(&k.qinv),
                ]);
                der::seq(&[&der::integer(0), &der::seq(&[&der::oid(oids::RSA_ENCRYPTION), &der::null()]), &der::octet_string(&pkcs1)])
            }
            PrivateKey::Ec(k) => {
                let sec1 = der::seq(&[&der::integer(1), &der::octet_string(&k.d.to_be_bytes_padded(k.curve.size())), &der::context(1, &der::bit_string(&k.public().to_sec1()))]);
                der::seq(&[&der::integer(0), &der::seq(&[&der::oid(oids::EC_PUBLIC_KEY), &der::oid(k.curve.oid())]), &der::octet_string(&sec1)])
            }
        }
    }

    /// Parses the first private key in PEM text (`PRIVATE KEY`, `RSA PRIVATE KEY`,
    /// `EC PRIVATE KEY`, or `ENCRYPTED PRIVATE KEY` with `password`).
    pub fn from_pem(text: &str, password: Option<&str>) -> Result<Self> {
        for b in pem_decode(text)? {
            match b.label.as_str() {
                "PRIVATE KEY" => return Self::from_pkcs8(&b.der),
                "RSA PRIVATE KEY" => return Self::from_pkcs1(&b.der),
                "EC PRIVATE KEY" => return Self::from_sec1(&b.der, None),
                "ENCRYPTED PRIVATE KEY" => {
                    let pw = password.ok_or_else(|| bad("the key is encrypted; a password is needed"))?;
                    let plain = crate::crypto::pkcs12::decrypt_pkcs8(&b.der, pw)?;
                    return Self::from_pkcs8(&plain);
                }
                _ => {}
            }
        }
        Err(bad("no private key in the PEM text"))
    }
}
