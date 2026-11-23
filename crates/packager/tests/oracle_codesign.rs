//! Certificate-backed signing checked by Apple's `codesign` (oracle only). Uses a throwaway
//! self-signed identity, so it needs no keychain access; the keychain path has its own ignored
//! test that asks the user for access.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use packager::sign::apple::{sign_macho, verify_macho, CodeSignOptions};
use packager::sign::{AppleIdentity, KeySigner};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("packager-cs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn compile(dir: &Path, archs: &[&str]) -> Option<PathBuf> {
    std::fs::write(dir.join("m.c"), "int main(void){return 0;}\n").ok()?;
    let out = dir.join("bin");
    let mut cmd = Command::new("cc");
    for a in archs {
        cmd.args(["-arch", a]);
    }
    cmd.arg("-O2").arg("-o").arg(&out).arg(dir.join("m.c"));
    cmd.status().ok()?.success().then_some(out)
}

fn codesign(args: &[&str], path: &Path) -> (bool, String) {
    let out = Command::new("codesign").args(args).arg(path).output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn self_signed_certificate_signature_verifies() {
    let dir = scratch("selfsigned");
    let Some(bin) = compile(&dir, &["arm64", "x86_64"]) else { return };
    let signer = KeySigner::self_signed("Packager Oracle Signing", Some("PKGTEST123")).unwrap().into_arc();
    let mut opts = CodeSignOptions::ad_hoc("com.example.oracle");
    opts.identity = AppleIdentity::Signer(signer.clone());
    opts.hardened_runtime = true;
    let signed = sign_macho(&std::fs::read(&bin).unwrap(), &opts).unwrap();
    let out = dir.join("signed");
    std::fs::write(&out, &signed.data).unwrap();
    packager::util::set_mode(&out, 0o755).unwrap();

    let (ok, text) = codesign(&["--verify", "--strict", "--verbose=4"], &out);
    assert!(ok, "{text}");
    let (_, info) = codesign(&["-dvvv", "-r-"], &out);
    assert!(info.contains("Authority=Packager Oracle Signing"), "{info}");
    // Like codesign, no team ID for a certificate Apple didn't issue (macOS would kill the
    // process if the CodeDirectory claimed one).
    assert!(info.contains("TeamIdentifier=not set"), "{info}");
    assert!(info.contains("flags=0x10000(runtime)"), "{info}");
    let leaf_sha1 = packager::crypto::hex(&signer.leaf().unwrap().sha1());
    assert!(info.contains(&format!("designated => identifier \"com.example.oracle\" and certificate leaf = H\"{leaf_sha1}\"")), "{info}");
    assert!(Command::new(&out).status().unwrap().success());

    // Our verifier agrees, and checks the CMS signature itself.
    for s in verify_macho(&signed.data).unwrap() {
        assert!(s.has_cms);
        let cms = s.cms.as_ref().unwrap();
        assert_eq!(cms.signer.common_name(), Some("Packager Oracle Signing"));
        assert_eq!(cms.cdhashes[0], s.cdhash[..20].to_vec());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explicit_requirements_are_embedded() {
    let dir = scratch("reqs");
    let Some(bin) = compile(&dir, &["arm64"]) else { return };
    let mut opts = CodeSignOptions::ad_hoc("com.example.req");
    opts.requirements = Some(r#"designated => identifier "com.example.req" and anchor apple generic"#.into());
    let signed = sign_macho(&std::fs::read(&bin).unwrap(), &opts).unwrap();
    let out = dir.join("signed");
    std::fs::write(&out, &signed.data).unwrap();
    let (_, info) = codesign(&["-d", "-r-"], &out);
    assert!(info.contains(r#"designated => identifier "com.example.req" and anchor apple generic"#), "{info}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_deployment_targets_get_sha1_and_sha256() {
    let dir = scratch("legacy");
    std::fs::write(dir.join("m.c"), "int main(void){return 0;}\n").unwrap();
    let bin = dir.join("bin");
    let ok = Command::new("cc").args(["-arch", "x86_64", "-mmacosx-version-min=10.9", "-o"]).arg(&bin).arg(dir.join("m.c")).status().is_ok_and(|s| s.success());
    if !ok {
        return;
    }
    let signer = KeySigner::self_signed("Packager Legacy", None).unwrap().into_arc();
    for identity in [AppleIdentity::AdHoc, AppleIdentity::Signer(signer)] {
        let mut opts = CodeSignOptions::ad_hoc("com.example.legacy");
        opts.identity = identity;
        let signed = sign_macho(&std::fs::read(&bin).unwrap(), &opts).unwrap();
        let out = dir.join("signed");
        std::fs::write(&out, &signed.data).unwrap();
        let (ok, text) = codesign(&["--verify", "--strict"], &out);
        assert!(ok, "{text}");
        let (_, info) = codesign(&["-dvvv"], &out);
        assert!(info.contains("Hash choices=sha1,sha256"), "{info}");
        verify_macho(&signed.data).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disk_images_sign_and_verify() {
    use packager::sign::disk_image::{sign_disk_image, verify_disk_image, DiskImageSignOptions};
    let dir = scratch("dmg");
    let Some(bin) = compile(&dir, &["arm64"]) else { return };
    let app = packager::App::new("Dmg Sig", "com.example.dmgsig", "1.0.0").binary(packager::Arch::MacosArm64, &bin);
    let built = packager::build(&app).package(packager::package::Dmg::new()).out_dir(dir.join("dist")).run().unwrap();
    let dmg = built.packages()[0].path().to_path_buf();
    let image = std::fs::read(&dmg).unwrap();
    let signer = KeySigner::self_signed("Packager Dmg", None).unwrap().into_arc();
    for identity in [AppleIdentity::AdHoc, AppleIdentity::Signer(signer)] {
        let signed = sign_disk_image(&image, &DiskImageSignOptions::new("com.example.dmgsig", identity)).unwrap();
        // Re-signing replaces the old signature rather than stacking a second one.
        let resigned = sign_disk_image(&signed, &DiskImageSignOptions::new("com.example.dmgsig", AppleIdentity::AdHoc)).unwrap();
        assert!(resigned.len() < signed.len() + 64);
        let out = dir.join("signed.dmg");
        std::fs::write(&out, &signed).unwrap();
        let (ok, text) = codesign(&["--verify", "--strict", "--verbose=2"], &out);
        assert!(ok, "{text}");
        let hd = Command::new("hdiutil").arg("verify").arg(&out).output().unwrap();
        assert!(hd.status.success(), "{}", String::from_utf8_lossy(&hd.stderr));
        let sig = verify_disk_image(&signed).unwrap();
        assert_eq!(sig.identifier, "com.example.dmgsig");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_accepts_codesign_command_lines() {
    let dir = scratch("cli");
    let Some(bin) = compile(&dir, &["arm64"]) else { return };
    let exe = env!("CARGO_MANIFEST_DIR").to_string() + "/../../target/debug/packager";
    if !Path::new(&exe).exists() {
        return; // the CLI binary is built by `cargo build`; skip when testing the library alone
    }
    let ent = dir.join("e.plist");
    std::fs::write(&ent, r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>"#).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(&exe).args(args).arg(&bin).output().unwrap();
        (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    };
    let (ok, text) = run(&["codesign", "-fs", "-", "-i", "com.example.cli", "-o", "runtime", "--entitlements", ent.to_str().unwrap()]);
    assert!(ok, "{text}");
    let (ok, text) = codesign(&["--verify", "--strict"], &bin);
    assert!(ok, "{text}");
    let (ok, text) = run(&["codesign", "-vvv"]);
    assert!(ok && text.contains("satisfies its Designated Requirement"), "{text}");
    let (ok, text) = run(&["codesign", "-d", "--entitlements", "-"]);
    assert!(ok && text.contains("allow-jit"), "{text}");
    let (ok, text) = run(&["codesign", "-v", "-R=identifier com.example.cli"]);
    assert!(ok, "{text}");
    let (ok, _) = run(&["codesign", "-v", "-R=identifier com.example.other"]);
    assert!(!ok);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Signs with the first code-signing identity in the login keychain (macOS may ask to allow
/// access to the key). Run with `cargo test -- --ignored keychain`.
#[test]
#[ignore]
fn keychain_identity_signs_like_codesign() {
    let list = packager::sign::keychain::list_identities().unwrap();
    let Some((sha1, _)) = list.first() else { return };
    let dir = scratch("keychain");
    let Some(bin) = compile(&dir, &["arm64", "x86_64"]) else { return };
    let signer = std::sync::Arc::new(packager::sign::keychain::KeychainSigner::find(sha1).unwrap());
    let mut opts = CodeSignOptions::ad_hoc("com.example.keychain");
    opts.identity = AppleIdentity::Signer(signer);
    opts.hardened_runtime = true;
    opts.timestamp_url = Some(packager::sign::timestamp::APPLE_TSA.into());
    let signed = sign_macho(&std::fs::read(&bin).unwrap(), &opts).unwrap();
    let out = dir.join("signed");
    std::fs::write(&out, &signed.data).unwrap();
    packager::util::set_mode(&out, 0o755).unwrap();
    let (ok, text) = codesign(&["--verify", "--strict", "--verbose=4"], &out);
    assert!(ok, "{text}");
    let (_, info) = codesign(&["-dvvv"], &out);
    assert!(info.contains("Authority=Apple Root CA") && info.contains("Timestamp="), "{info}");
    assert!(Command::new(&out).status().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}
