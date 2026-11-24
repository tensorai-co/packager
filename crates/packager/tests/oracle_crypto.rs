//! `openssl` as a test oracle for the crypto layer: its keys, certificates and PKCS#12 files
//! must parse, and our signatures and certificates must pass its verification.

use std::path::{Path, PathBuf};
use std::process::Command;

use packager::crypto::ec::{Curve, EcPrivateKey};
use packager::crypto::hmac::HashAlg;
use packager::crypto::keys::{PrivateKey, pem_encode};
use packager::crypto::pkcs12::Pkcs12;
use packager::crypto::x509::Certificate;

fn openssl(args: &[&str], dir: &Path) -> Option<String> {
    let out = Command::new("openssl").args(args).current_dir(dir).output().ok()?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "openssl {args:?} failed:\n{text}");
    Some(text)
}

fn scratch(name: &str) -> Option<PathBuf> {
    Command::new("openssl").arg("version").output().ok()?;
    let d = std::env::temp_dir().join(format!("packager-crypto-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok()?;
    Some(d)
}

fn sign_and_check(key: &PrivateKey, dir: &Path) {
    let msg = b"packager signs this";
    std::fs::write(dir.join("msg"), msg).unwrap();
    let sig = key.sign(HashAlg::Sha256, &HashAlg::Sha256.digest(msg)).unwrap();
    std::fs::write(dir.join("sig"), sig).unwrap();
    std::fs::write(dir.join("pub.pem"), pem_encode("PUBLIC KEY", &key.public().to_spki())).unwrap();
    let out = openssl(&["dgst", "-sha256", "-verify", "pub.pem", "-signature", "sig", "msg"], dir).unwrap();
    assert!(out.contains("Verified OK"), "{out}");
}

#[test]
fn rsa_keys_and_signatures_interoperate() {
    let Some(dir) = scratch("rsa") else { return };
    openssl(&["genrsa", "-out", "rsa1.pem", "2048"], &dir);
    openssl(&["pkcs8", "-topk8", "-nocrypt", "-in", "rsa1.pem", "-out", "rsa8.pem"], &dir);
    for f in ["rsa1.pem", "rsa8.pem"] {
        let key = PrivateKey::from_pem(&std::fs::read_to_string(dir.join(f)).unwrap(), None).unwrap();
        sign_and_check(&key, &dir);
    }
    // Encrypted PKCS#8 (PBES2, PBKDF2 + AES-256-CBC).
    openssl(&["pkcs8", "-topk8", "-v2", "aes-256-cbc", "-passout", "pass:s3cret", "-in", "rsa1.pem", "-out", "enc.pem"], &dir);
    let key = PrivateKey::from_pem(&std::fs::read_to_string(dir.join("enc.pem")).unwrap(), Some("s3cret")).unwrap();
    sign_and_check(&key, &dir);
    // Our own generated key, exported as PKCS#8, read by openssl.
    let ours = PrivateKey::Rsa(packager::crypto::rsa::RsaPrivateKey::generate(2048).unwrap());
    std::fs::write(dir.join("ours.pem"), pem_encode("PRIVATE KEY", &ours.to_pkcs8())).unwrap();
    openssl(&["rsa", "-check", "-noout", "-in", "ours.pem"], &dir);
    sign_and_check(&ours, &dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ecdsa_keys_and_signatures_interoperate() {
    let Some(dir) = scratch("ec") else { return };
    openssl(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ec.pem"], &dir);
    let key = PrivateKey::from_pem(&std::fs::read_to_string(dir.join("ec.pem")).unwrap(), None).unwrap();
    sign_and_check(&key, &dir);
    let ours = PrivateKey::Ec(EcPrivateKey::generate(Curve::P384).unwrap());
    std::fs::write(dir.join("ours.pem"), pem_encode("PRIVATE KEY", &ours.to_pkcs8())).unwrap();
    openssl(&["ec", "-noout", "-text", "-in", "ours.pem"], &dir);
    let msg = b"p384";
    std::fs::write(dir.join("msg"), msg).unwrap();
    std::fs::write(dir.join("sig"), ours.sign(HashAlg::Sha384, &HashAlg::Sha384.digest(msg)).unwrap()).unwrap();
    std::fs::write(dir.join("pub.pem"), pem_encode("PUBLIC KEY", &ours.public().to_spki())).unwrap();
    let out = openssl(&["dgst", "-sha384", "-verify", "pub.pem", "-signature", "sig", "msg"], &dir).unwrap();
    assert!(out.contains("Verified OK"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn certificates_interoperate() {
    let Some(dir) = scratch("x509") else { return };
    // Ours → openssl.
    let key = PrivateKey::Rsa(packager::crypto::rsa::RsaPrivateKey::generate(2048).unwrap());
    let cert = Certificate::self_signed("Packager Test Signing", Some("TEAM123456"), &key, 1_700_000_000, 3650).unwrap();
    std::fs::write(dir.join("ours.crt"), pem_encode("CERTIFICATE", &cert.der)).unwrap();
    let text = openssl(&["x509", "-in", "ours.crt", "-noout", "-text"], &dir).unwrap();
    assert!(text.contains("Code Signing"), "{text}");
    // openssl extracts the key itself and checks the self-signature over the TBS bytes.
    let pubkey = openssl(&["x509", "-in", "ours.crt", "-noout", "-pubkey"], &dir).unwrap();
    std::fs::write(dir.join("cert-pub.pem"), pubkey).unwrap();
    std::fs::write(dir.join("tbs"), cert.tbs()).unwrap();
    std::fs::write(dir.join("cert-sig"), &cert.signature).unwrap();
    let v = openssl(&["dgst", "-sha256", "-verify", "cert-pub.pem", "-signature", "cert-sig", "tbs"], &dir).unwrap();
    assert!(v.contains("Verified OK"), "{v}");
    // openssl → ours.
    openssl(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-days", "2", "-subj", "/CN=Oracle Cert/OU=ABCDEFGHIJ/O=Example"], &dir);
    let c = Certificate::from_pem_all(&std::fs::read_to_string(dir.join("c.pem")).unwrap()).unwrap().remove(0);
    assert_eq!(c.common_name(), Some("Oracle Cert"));
    assert_eq!(c.team_id(), Some("ABCDEFGHIJ"));
    assert!(c.is_signed_by(&c));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pkcs12_files_open() {
    let Some(dir) = scratch("p12") else { return };
    openssl(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-days", "2", "-subj", "/CN=P12 Test"], &dir);
    // Default (legacy 3DES key + RC2-40 certs on LibreSSL), and modern AES-256 with SHA-256 MAC.
    openssl(&["pkcs12", "-export", "-inkey", "k.pem", "-in", "c.pem", "-passout", "pass:pw", "-out", "legacy.p12"], &dir);
    let aes = Command::new("openssl")
        .args(["pkcs12", "-export", "-inkey", "k.pem", "-in", "c.pem", "-passout", "pass:pw", "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256", "-out", "aes.p12"])
        .current_dir(&dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let mut files = vec!["legacy.p12"];
    if aes {
        files.push("aes.p12");
    }
    for f in files {
        let p = Pkcs12::parse(&std::fs::read(dir.join(f)).unwrap(), "pw").unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(p.leaf.common_name(), Some("P12 Test"), "{f}");
        assert_eq!(p.key.public(), p.leaf.public_key, "{f}");
        assert!(Pkcs12::parse(&std::fs::read(dir.join(f)).unwrap(), "wrong").is_err());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Apple's own requirement compiler as the oracle for ours.
#[test]
#[cfg(target_os = "macos")]
fn requirements_match_csreq() {
    use packager::sign::requirement::compile;
    let Some(dir) = scratch("csreq") else { return };
    for src in [
        r#"anchor apple or (identifier com.a and ! info[CFBundleVersion] < "2")"#,
        r#"certificate leaf[subject.CN] = "*Dev*" and certificate root = H"611e5b662c593a08ff58d14ae22452d198df6c60""#,
        r#"entitlement["com.apple.security.app-sandbox"] exists or cdhash H"0102030405060708090a0b0c0d0e0f1011121314""#,
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = ABCDE12345 or notarized",
        "identifier com.example and certificate leaf[subject.CN] = *Developer* and certificate 1 trusted",
        r#"anchor trusted and info[CFBundleShortVersionString] >= "1.2" and platform = 1"#,
    ] {
        let out = dir.join("req.bin");
        let st = Command::new("csreq").arg(format!("-r={src}")).arg("-b").arg(&out).status().unwrap();
        assert!(st.success(), "csreq rejected {src}");
        let apple = std::fs::read(&out).unwrap();
        assert_eq!(compile(src).unwrap().to_blob(), apple, "{src}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
