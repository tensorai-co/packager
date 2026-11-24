//! PKCS#12 (`.p12` / `.pfx`, RFC 7292): reading the certificate chain and private key that
//! Keychain Access and `openssl pkcs12` export, plus encrypted PKCS#8 (PBES2).

use crate::crypto::cipher::{aes_cbc_decrypt, des3_cbc_decrypt, rc2_cbc_decrypt};
use crate::crypto::der::{self, oids, tag};
use crate::crypto::hmac::{HashAlg, hmac, pbkdf2};
use crate::crypto::keys::{PrivateKey, hash_for_digest_oid};
use crate::crypto::x509::Certificate;
use crate::{Error, Result};

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("pkcs12", m)
}

const PBE_SHA1_3DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
const PBE_SHA1_RC2_128: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05];
const PBE_SHA1_RC2_40: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06];
const PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const HMAC_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07];
const HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
const HMAC_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a];
const HMAC_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
const AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
const AES192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
const AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
const KEY_BAG: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01];
const SHROUDED_KEY_BAG: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02];
const CERT_BAG: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03];
const X509_CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];
const LOCAL_KEY_ID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15];

/// The password as PKCS#12 wants it: UTF-16BE with a terminating NUL.
fn bmp_password(pw: &str) -> Vec<u8> {
    let mut out: Vec<u8> = pw.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

/// The PKCS#12 key derivation function (RFC 7292 appendix B.2). `id`: 1 key, 2 IV, 3 MAC.
fn kdf(alg: HashAlg, password: &[u8], salt: &[u8], iterations: u32, id: u8, len: usize) -> Vec<u8> {
    let (u, v) = (alg.len(), alg.block_len());
    let d = vec![id; v];
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let n = v * src.len().div_ceil(v);
        src.iter().cycle().take(n).copied().collect()
    };
    let mut i_buf = [fill(salt), fill(password)].concat();
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut a = alg.digest_parts(&[&d, &i_buf]);
        for _ in 1..iterations {
            a = alg.digest(&a);
        }
        out.extend_from_slice(&a[..u.min(len - out.len())]);
        if out.len() >= len {
            break;
        }
        let b: Vec<u8> = a.iter().cycle().take(v).copied().collect();
        for chunk in i_buf.chunks_mut(v) {
            // chunk = (chunk + b + 1) mod 2^(8v)
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let s = chunk[k] as u16 + b[k] as u16 + carry;
                chunk[k] = s as u8;
                carry = s >> 8;
            }
        }
    }
    out
}

/// Decrypts `data` under an `AlgorithmIdentifier` (DER) for one of the PKCS#12 PBE schemes or PBES2.
fn pbe_decrypt(alg_id: &[u8], password: &str, data: &[u8]) -> Result<Vec<u8>> {
    let t = der::parse(alg_id)?;
    let mut r = t.reader();
    let alg = r.expect(tag::OID)?.value.to_vec();
    let params = r.read()?;
    if alg == PBES2 {
        let mut pr = params.reader();
        let kdf_alg = pr.expect(tag::SEQUENCE)?;
        let enc_alg = pr.expect(tag::SEQUENCE)?;
        let mut kr = kdf_alg.reader();
        if kr.expect(tag::OID)?.value != PBKDF2 {
            return Err(bad("only PBKDF2 is supported for PBES2"));
        }
        let kp = kr.expect(tag::SEQUENCE)?;
        let mut kpr = kp.reader();
        let salt = kpr.expect(tag::OCTET_STRING)?.value.to_vec();
        let iterations = kpr.expect(tag::INTEGER)?.as_i64()? as u32;
        let mut key_len = None;
        let mut prf = HashAlg::Sha1;
        while !kpr.is_empty() {
            let el = kpr.read()?;
            if el.tag == tag::INTEGER {
                key_len = Some(el.as_i64()? as usize);
            } else if el.tag == tag::SEQUENCE {
                let o = el.reader().expect(tag::OID)?.value.to_vec();
                prf = match o.as_slice() {
                    x if x == HMAC_SHA1 => HashAlg::Sha1,
                    x if x == HMAC_SHA256 => HashAlg::Sha256,
                    x if x == HMAC_SHA384 => HashAlg::Sha384,
                    x if x == HMAC_SHA512 => HashAlg::Sha512,
                    _ => return Err(bad("unsupported PBKDF2 PRF")),
                };
            }
        }
        let mut er = enc_alg.reader();
        let cipher = er.expect(tag::OID)?.value.to_vec();
        let iv = er.expect(tag::OCTET_STRING)?.value.to_vec();
        // PBES2 passwords are UTF-8 bytes, unlike the PKCS#12 schemes.
        let pw = password.as_bytes();
        let key_size = match cipher.as_slice() {
            x if x == AES128_CBC => 16,
            x if x == AES192_CBC => 24,
            x if x == AES256_CBC => 32,
            x if x == DES_EDE3_CBC => 24,
            _ => return Err(bad(format!("unsupported cipher {}", der::oid_to_string(&cipher)))),
        };
        let key = pbkdf2(prf, pw, &salt, iterations, key_len.unwrap_or(key_size));
        return if cipher == DES_EDE3_CBC { des3_cbc_decrypt(&key, &iv, data) } else { aes_cbc_decrypt(&key, &iv, data) };
    }
    let mut pr = params.reader();
    let salt = pr.expect(tag::OCTET_STRING)?.value.to_vec();
    let iterations = pr.expect(tag::INTEGER)?.as_i64()? as u32;
    let pw = bmp_password(password);
    match alg.as_slice() {
        x if x == PBE_SHA1_3DES => {
            let key = kdf(HashAlg::Sha1, &pw, &salt, iterations, 1, 24);
            let iv = kdf(HashAlg::Sha1, &pw, &salt, iterations, 2, 8);
            des3_cbc_decrypt(&key, &iv, data)
        }
        x if x == PBE_SHA1_RC2_40 || x == PBE_SHA1_RC2_128 => {
            let n = if x == PBE_SHA1_RC2_40 { 5 } else { 16 };
            let key = kdf(HashAlg::Sha1, &pw, &salt, iterations, 1, n);
            let iv = kdf(HashAlg::Sha1, &pw, &salt, iterations, 2, 8);
            rc2_cbc_decrypt(&key, n * 8, &iv, data)
        }
        _ => Err(bad(format!("unsupported encryption {}", der::oid_to_string(&alg)))),
    }
}

/// Decrypts an `EncryptedPrivateKeyInfo` into PKCS#8 `PrivateKeyInfo` DER.
pub fn decrypt_pkcs8(der_bytes: &[u8], password: &str) -> Result<Vec<u8>> {
    let t = der::parse(der_bytes)?;
    let mut r = t.reader();
    let alg = r.expect(tag::SEQUENCE)?;
    let data = r.expect(tag::OCTET_STRING)?;
    pbe_decrypt(alg.raw, password, data.value)
}

/// What a `.p12` holds.
#[derive(Debug, Clone)]
pub struct Pkcs12 {
    /// The private key.
    pub key: PrivateKey,
    /// The certificate matching the key.
    pub leaf: Certificate,
    /// Other certificates (intermediates, roots).
    pub others: Vec<Certificate>,
}

fn octets_of(content_info: der::Tlv<'_>) -> Result<Vec<u8>> {
    // ContentInfo { data, [0] OCTET STRING } — the OCTET STRING may be constructed (BER).
    let mut r = content_info.reader();
    let ty = r.expect(tag::OID)?.value.to_vec();
    if ty != oids::PKCS7_DATA {
        return Err(bad("expected a data ContentInfo"));
    }
    let wrapped = r.read()?;
    let inner = der::parse(wrapped.value)?;
    flatten_octets(inner)
}

fn flatten_octets(t: der::Tlv<'_>) -> Result<Vec<u8>> {
    match t.tag {
        tag::OCTET_STRING => Ok(t.value.to_vec()),
        0x24 => {
            let mut out = Vec::new();
            let mut r = t.reader();
            while !r.is_empty() {
                out.extend(flatten_octets(r.read()?)?);
            }
            Ok(out)
        }
        _ => Err(bad("expected OCTET STRING")),
    }
}

impl Pkcs12 {
    /// Parses and decrypts a PFX, checking its MAC.
    pub fn parse(pfx: &[u8], password: &str) -> Result<Self> {
        let t = der::parse(pfx)?;
        let mut r = t.reader();
        if r.expect(tag::INTEGER)?.as_i64()? != 3 {
            return Err(bad("unsupported PFX version"));
        }
        let auth_safe = r.expect(tag::SEQUENCE)?;
        let auth_bytes = octets_of(auth_safe)?;
        if let Some(mac) = r.optional(tag::SEQUENCE)? {
            let mut mr = mac.reader();
            let digest_info = mr.expect(tag::SEQUENCE)?;
            let salt = mr.expect(tag::OCTET_STRING)?.value.to_vec();
            let iterations = match mr.optional(tag::INTEGER)? {
                Some(i) => i.as_i64()? as u32,
                None => 1,
            };
            let mut dr = digest_info.reader();
            let alg = dr.expect(tag::SEQUENCE)?;
            let want = dr.expect(tag::OCTET_STRING)?.value.to_vec();
            let h = hash_for_digest_oid(alg.reader().expect(tag::OID)?.value).ok_or_else(|| bad("unsupported MAC digest"))?;
            let key = kdf(h, &bmp_password(password), &salt, iterations, 3, h.len());
            if hmac(h, &key, &auth_bytes) != want {
                return Err(Error::Other("pkcs12: MAC check failed (wrong password?)".into()));
            }
        }
        let safes = der::parse(&auth_bytes)?;
        let mut keys: Vec<(Option<Vec<u8>>, PrivateKey)> = Vec::new();
        let mut certs: Vec<(Option<Vec<u8>>, Certificate)> = Vec::new();
        let mut sr = safes.reader();
        while !sr.is_empty() {
            let ci = sr.expect(tag::SEQUENCE)?;
            let mut cr = ci.reader();
            let ty = cr.expect(tag::OID)?.value.to_vec();
            let bags_der = if ty == oids::PKCS7_DATA {
                octets_of(ci)?
            } else if ty == oids::PKCS7_ENCRYPTED_DATA {
                let content = der::parse(cr.read()?.value)?;
                let mut er = content.reader();
                er.expect(tag::INTEGER)?;
                let eci = er.expect(tag::SEQUENCE)?;
                let mut eir = eci.reader();
                eir.expect(tag::OID)?;
                let alg = eir.expect(tag::SEQUENCE)?;
                let enc = eir.read()?;
                let data = if enc.tag == 0x80 { enc.value.to_vec() } else { flatten_octets(der::Tlv { tag: 0x24, ..enc })? };
                pbe_decrypt(alg.raw, password, &data)?
            } else {
                continue;
            };
            let bags = der::parse(&bags_der)?;
            let mut br = bags.reader();
            while !br.is_empty() {
                let bag = br.expect(tag::SEQUENCE)?;
                let mut bagr = bag.reader();
                let bag_id = bagr.expect(tag::OID)?.value.to_vec();
                let value = der::parse(bagr.read()?.value)?;
                let mut local_id = None;
                if let Some(attrs) = bagr.optional(tag::SET)? {
                    let mut ar = attrs.reader();
                    while !ar.is_empty() {
                        let a = ar.expect(tag::SEQUENCE)?;
                        let mut aar = a.reader();
                        if aar.expect(tag::OID)?.value == LOCAL_KEY_ID {
                            local_id = aar.expect(tag::SET)?.reader().expect(tag::OCTET_STRING).ok().map(|o| o.value.to_vec());
                        }
                    }
                }
                match bag_id.as_slice() {
                    x if x == KEY_BAG => keys.push((local_id, PrivateKey::from_pkcs8(value.raw)?)),
                    x if x == SHROUDED_KEY_BAG => keys.push((local_id, PrivateKey::from_pkcs8(&decrypt_pkcs8(value.raw, password)?)?)),
                    x if x == CERT_BAG => {
                        let mut cr2 = value.reader();
                        if cr2.expect(tag::OID)?.value == X509_CERT {
                            let c = der::parse(cr2.read()?.value)?;
                            certs.push((local_id, Certificate::from_der(c.value)?));
                        }
                    }
                    _ => {}
                }
            }
        }
        let (key_id, key) = keys.into_iter().next().ok_or_else(|| bad("no private key in the file"))?;
        let public = key.public();
        let leaf_idx = certs.iter().position(|(id, c)| (key_id.is_some() && *id == key_id) || c.public_key == public).ok_or_else(|| bad("no certificate matches the private key"))?;
        let (_, leaf) = certs.remove(leaf_idx);
        Ok(Pkcs12 { key, leaf, others: certs.into_iter().map(|(_, c)| c).collect() })
    }
}
