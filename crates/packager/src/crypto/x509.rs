//! X.509 certificates: parsing what code signing needs (names, keys, extensions, Apple's
//! marker OIDs), checking issuer signatures, and creating self-signed code-signing certificates.

use crate::Result;
use crate::crypto::der::{self, Tlv, oids, tag};
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::{PrivateKey, PublicKey, hash_for_signature_oid, pem_decode};

/// A certificate extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// OID body.
    pub oid: Vec<u8>,
    /// Critical flag.
    pub critical: bool,
    /// The extnValue contents.
    pub value: Vec<u8>,
}

/// A parsed certificate. The DER is kept so it can be embedded byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The whole certificate.
    pub der: Vec<u8>,
    tbs: Vec<u8>,
    /// The serial number's INTEGER contents.
    pub serial: Vec<u8>,
    /// The issuer `Name`, as encoded.
    pub issuer_raw: Vec<u8>,
    /// The subject `Name`, as encoded.
    pub subject_raw: Vec<u8>,
    /// Subject attributes in order: (OID body, value).
    pub subject: Vec<(Vec<u8>, String)>,
    /// Issuer attributes in order.
    pub issuer: Vec<(Vec<u8>, String)>,
    /// notBefore as written.
    pub not_before: String,
    /// notAfter as written.
    pub not_after: String,
    /// The subject public key.
    pub public_key: PublicKey,
    /// Extensions.
    pub extensions: Vec<Extension>,
    /// Signature algorithm OID body.
    pub signature_algorithm: Vec<u8>,
    /// Signature bits.
    pub signature: Vec<u8>,
}

fn parse_name(t: &Tlv) -> Result<Vec<(Vec<u8>, String)>> {
    let mut out = Vec::new();
    let mut r = t.reader();
    while !r.is_empty() {
        let rdn = r.expect(tag::SET)?;
        let mut rr = rdn.reader();
        while !rr.is_empty() {
            let atv = rr.expect(tag::SEQUENCE)?;
            let mut ar = atv.reader();
            let o = ar.expect(tag::OID)?.value.to_vec();
            let v = ar.read()?.as_string().unwrap_or_default();
            out.push((o, v));
        }
    }
    Ok(out)
}

impl Certificate {
    /// Parses DER.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let t = der::parse(bytes)?;
        let mut r = t.reader();
        let tbs = r.expect(tag::SEQUENCE)?;
        let sig_alg = r.expect(tag::SEQUENCE)?;
        let sig = r.expect(tag::BIT_STRING)?.as_bit_string()?.to_vec();
        let signature_algorithm = sig_alg.reader().expect(tag::OID)?.value.to_vec();

        let mut tr = tbs.reader();
        if tr.peek_tag() == Some(0xa0) {
            tr.read()?; // version
        }
        let serial = tr.expect(tag::INTEGER)?.value.to_vec();
        tr.expect(tag::SEQUENCE)?; // signature algorithm (repeated)
        let issuer = tr.expect(tag::SEQUENCE)?;
        let validity = tr.expect(tag::SEQUENCE)?;
        let subject = tr.expect(tag::SEQUENCE)?;
        let spki = tr.expect(tag::SEQUENCE)?;
        let mut extensions = Vec::new();
        while !tr.is_empty() {
            let el = tr.read()?;
            if el.is_context(3) {
                let exts = der::parse(el.value)?;
                let mut er = exts.reader();
                while !er.is_empty() {
                    let e = er.expect(tag::SEQUENCE)?;
                    let mut xr = e.reader();
                    let oid = xr.expect(tag::OID)?.value.to_vec();
                    let critical = match xr.optional(tag::BOOLEAN)? {
                        Some(b) => b.value.first().is_some_and(|&v| v != 0),
                        None => false,
                    };
                    let value = xr.expect(tag::OCTET_STRING)?.value.to_vec();
                    extensions.push(Extension { oid, critical, value });
                }
            }
        }
        let mut vr = validity.reader();
        let not_before = vr.read()?.as_string()?;
        let not_after = vr.read()?.as_string()?;
        Ok(Certificate {
            der: bytes.to_vec(),
            tbs: tbs.raw.to_vec(),
            serial,
            issuer_raw: issuer.raw.to_vec(),
            subject_raw: subject.raw.to_vec(),
            subject: parse_name(&subject)?,
            issuer: parse_name(&issuer)?,
            not_before,
            not_after,
            public_key: PublicKey::from_spki(spki.raw)?,
            extensions,
            signature_algorithm,
            signature: sig,
        })
    }

    /// Every certificate in PEM text.
    pub fn from_pem_all(text: &str) -> Result<Vec<Self>> {
        pem_decode(text)?.into_iter().filter(|b| b.label == "CERTIFICATE" || b.label == "TRUSTED CERTIFICATE").map(|b| Self::from_der(&b.der)).collect()
    }

    /// The signed `tbsCertificate` bytes.
    pub fn tbs(&self) -> &[u8] {
        &self.tbs
    }

    /// The first value of a subject attribute.
    pub fn subject_attr(&self, oid: &[u8]) -> Option<&str> {
        self.subject.iter().find(|(o, _)| o == oid).map(|(_, v)| v.as_str())
    }

    /// The subject common name.
    pub fn common_name(&self) -> Option<&str> {
        self.subject_attr(oids::CN)
    }

    /// The Apple team identifier: the subject OU of a developer certificate.
    pub fn team_id(&self) -> Option<&str> {
        self.subject_attr(oids::OU).filter(|ou| ou.len() == 10 && ou.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
    }

    /// An extension by OID body.
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// The subject as Windows writes it (`CN=…, O=…, C=…`: RDNs in reverse order), which an
    /// MSIX manifest's `Publisher` must equal.
    pub fn windows_subject(&self) -> String {
        let key = |o: &[u8]| -> String {
            match o {
                x if x == oids::CN => "CN".into(),
                x if x == oids::O => "O".into(),
                x if x == oids::OU => "OU".into(),
                x if x == oids::C => "C".into(),
                x if x == oids::EMAIL => "E".into(),
                [0x55, 0x04, 0x07] => "L".into(),
                [0x55, 0x04, 0x08] => "S".into(),
                [0x55, 0x04, 0x09] => "STREET".into(),
                [0x55, 0x04, 0x05] => "SERIALNUMBER".into(),
                [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".into(),
                other => format!("OID.{}", crate::crypto::der::oid_to_string(other)),
            }
        };
        self.subject.iter().rev().map(|(o, v)| format!("{}={}", key(o), windows_dn_value(v))).collect::<Vec<_>>().join(", ")
    }

    /// SHA-1 of the DER (what requirements call `H"…"` for certificates).
    pub fn sha1(&self) -> [u8; 20] {
        crate::crypto::sha1(&self.der)
    }

    /// SHA-256 of the DER.
    pub fn sha256(&self) -> [u8; 32] {
        crate::crypto::sha256(&self.der)
    }

    /// Whether subject and issuer are the same name.
    pub fn is_self_issued(&self) -> bool {
        self.subject_raw == self.issuer_raw
    }

    /// Whether `issuer`'s key verifies this certificate's signature.
    pub fn is_signed_by(&self, issuer: &Certificate) -> bool {
        let Some(h) = hash_for_signature_oid(&self.signature_algorithm) else { return false };
        issuer.public_key.verify(&self.signature_algorithm, &h.digest(&self.tbs), &self.signature)
    }

    /// Creates a self-signed certificate for code signing: subject CN (and OU if given),
    /// valid from `not_before` for `days`, with the codeSigning extended key usage.
    pub fn self_signed(common_name: &str, org_unit: Option<&str>, key: &PrivateKey, not_before: i64, days: i64) -> Result<Certificate> {
        let mut rdns = vec![der::set_of(vec![der::seq(&[&der::oid(oids::CN), &der::utf8(common_name)])])];
        if let Some(ou) = org_unit {
            rdns.push(der::set_of(vec![der::seq(&[&der::oid(oids::OU), &der::utf8(ou)])]));
        }
        let name = der::sequence(&rdns.concat());
        let serial = {
            let mut s = crate::crypto::random_bytes(16)?;
            s[0] &= 0x7f;
            s[0] |= 0x40;
            s
        };
        let alg = key.signature_algorithm(HashAlg::Sha256);
        let spki = key.public().to_spki();
        let ku = der::seq(&[&der::oid(oids::KEY_USAGE), &der::boolean(true), &der::octet_string(&der::tlv(&[tag::BIT_STRING], &[7, 0x80]))]);
        let eku = der::seq(&[&der::oid(oids::EXT_KEY_USAGE), &der::boolean(true), &der::octet_string(&der::seq(&[&der::oid(oids::KP_CODE_SIGNING)]))]);
        let bc = der::seq(&[&der::oid(oids::BASIC_CONSTRAINTS), &der::boolean(true), &der::octet_string(&der::seq(&[]))]);
        let ski = der::seq(&[&der::oid(oids::SUBJECT_KEY_ID), &der::octet_string(&der::octet_string(&crate::crypto::sha1(&spki)))]);
        let exts = der::context(3, &der::seq(&[&bc, &ku, &eku, &ski]));
        let validity = der::seq(&[&der::utc_time(not_before), &der::utc_time(not_before + days * 86_400)]);
        let tbs = der::seq(&[&der::context(0, &der::integer(2)), &der::integer_unsigned_bytes(&serial), &alg, &name, &validity, &name, &spki, &exts]);
        let sig = key.sign(HashAlg::Sha256, &HashAlg::Sha256.digest(&tbs))?;
        let cert = der::seq(&[&tbs, &alg, &der::bit_string(&sig)]);
        Certificate::from_der(&cert)
    }
}

/// A DN value quoted the way Windows' `CertNameToStr` does when it needs to be.
pub fn windows_dn_value(v: &str) -> String {
    let needs = v.is_empty() || v.starts_with(' ') || v.ends_with(' ') || v.contains([',', '+', '=', '"', '\n', '<', '>', '#', ';']);
    if needs { format!("\"{}\"", v.replace('"', "\"\"")) } else { v.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ec::{Curve, EcPrivateKey};

    #[test]
    fn self_signed_round_trip() {
        let key = PrivateKey::Ec(EcPrivateKey::generate(Curve::P256).unwrap());
        let c = Certificate::self_signed("Packager Test", Some("ABCDE12345"), &key, 1_700_000_000, 365).unwrap();
        assert_eq!(c.common_name(), Some("Packager Test"));
        assert_eq!(c.team_id(), Some("ABCDE12345"));
        assert!(c.is_self_issued());
        assert!(c.is_signed_by(&c));
        assert!(c.extension(oids::EXT_KEY_USAGE).is_some());
        assert_eq!(c.public_key, key.public());
    }
}
