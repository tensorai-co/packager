//! Notarization-side formats checked by Apple's tools (oracles only): stapled disk images
//! (`codesign`, `hdiutil`), installer signatures (`pkgutil`, `installer`), stapled flat packages,
//! and the ZIP used to submit app bundles (`ditto`). A real notarization needs a Developer ID and
//! an API key, so the end-to-end check against Apple's own stapler uses an already-notarized
//! package on this Mac and the network (`cargo test -- --ignored network`).

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use packager::sign::disk_image::{sign_disk_image, verify_disk_image, DiskImageSignOptions};
use packager::sign::installer::{sign_pkg, verify_pkg, InstallerSignOptions};
use packager::sign::{AppleIdentity, KeySigner};
use packager::staple;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("packager-notary-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn compile(dir: &Path) -> Option<PathBuf> {
    std::fs::write(dir.join("m.c"), "int main(void){return 0;}\n").ok()?;
    let out = dir.join("bin");
    Command::new("cc").args(["-arch", "arm64", "-O2", "-o"]).arg(&out).arg(dir.join("m.c")).status().ok()?.success().then_some(out)
}

fn tool(cmd: &str, args: &[&str], path: &Path) -> (bool, String) {
    let out = Command::new(cmd).args(args).arg(path).output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// A ticket-shaped blob naming `digest`, as Apple's tickets list the hashes they cover.
fn fake_ticket(digest: &[u8]) -> Vec<u8> {
    let mut t = b"s8ch".to_vec();
    t.extend_from_slice(&[1, 0, 0, 0, 0x20, 0, 0, 0, 0x40, 0, 0, 0]);
    t.extend_from_slice(&digest[..20]);
    t.extend_from_slice(&[0x5a; 64]);
    t
}

fn built(dir: &Path, bin: &Path, pkg: bool) -> PathBuf {
    let app = packager::App::new("Notary Oracle", "com.example.notaryoracle", "1.0.0").binary(packager::Arch::MacosArm64, bin);
    let b = packager::build(&app).out_dir(dir.join("dist"));
    let b = if pkg { b.package(packager::package::Pkg::new()) } else { b.package(packager::package::Dmg::new()) };
    b.run().unwrap().packages()[0].path().to_path_buf()
}

#[test]
fn stapled_disk_image_still_verifies() {
    let dir = scratch("dmg");
    let Some(bin) = compile(&dir) else { return };
    let dmg = built(&dir, &bin, false);
    let signer = KeySigner::self_signed("Packager Notary Dmg", None).unwrap().into_arc();
    let signed = sign_disk_image(&std::fs::read(&dmg).unwrap(), &DiskImageSignOptions::new("com.example.notaryoracle", AppleIdentity::Signer(signer))).unwrap();
    std::fs::write(&dmg, &signed).unwrap();
    let (kind, record) = staple::ticket_record(&dmg).unwrap();
    assert_eq!(kind, staple::Kind::DiskImage);
    assert!(record.starts_with("2/2/"), "{record}");
    let (_, cdhash) = packager::sign::disk_image::code_directory_hash(&signed).unwrap();
    staple::attach(&dmg, &fake_ticket(&cdhash)).unwrap();
    staple::attach(&dmg, &fake_ticket(&cdhash)).unwrap(); // replaces, doesn't stack

    let (ok, text) = tool("codesign", &["--verify", "--strict", "--verbose=2"], &dmg);
    assert!(ok, "codesign rejected the stapled image:\n{text}");
    let (_, text) = tool("codesign", &["-dvv"], &dmg);
    assert!(text.contains("Notarization Ticket=stapled"), "codesign doesn't see the ticket:\n{text}");
    let (ok, text) = tool("hdiutil", &["verify"], &dmg);
    assert!(ok, "{text}");
    staple::validate(&dmg).unwrap();
    verify_disk_image(&std::fs::read(&dmg).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn installer_signature_is_read_by_pkgutil() {
    let dir = scratch("pkg");
    let Some(bin) = compile(&dir) else { return };
    let pkg = built(&dir, &bin, true);
    let signer = KeySigner::self_signed("Packager Notary Installer", Some("ABCDE12345")).unwrap();
    let mut o = InstallerSignOptions::new(&signer);
    o.timestamp_url = None;
    let signed = sign_pkg(&std::fs::read(&pkg).unwrap(), &o).unwrap();
    std::fs::write(&pkg, &signed).unwrap();

    // pkgutil parses both signatures and reports the (untrusted) signer.
    let (_, text) = tool("pkgutil", &["--check-signature"], &pkg);
    assert!(text.contains("Packager Notary Installer"), "pkgutil didn't read the signature:\n{text}");
    assert!(!text.contains("no signature"), "{text}");
    let (ok, text) = tool("installer", &["-pkginfo", "-pkg"], &pkg);
    assert!(ok, "{text}");
    let expanded = dir.join("expanded");
    let out = Command::new("pkgutil").arg("--expand-full").arg(&pkg).arg(&expanded).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(expanded.join("Distribution").is_file());

    // A stapled ticket sits after the archive and leaves the signature intact.
    let checksum = packager::format::xar::toc_checksum(&signed).unwrap();
    staple::attach(&pkg, &fake_ticket(&checksum)).unwrap();
    staple::validate(&pkg).unwrap();
    let (_, text) = tool("pkgutil", &["--check-signature"], &pkg);
    assert!(text.contains("Packager Notary Installer"), "{text}");
    let v = verify_pkg(&std::fs::read(&pkg).unwrap()).unwrap().unwrap();
    assert_eq!(v.checksum, checksum);
    let (ok, text) = tool("installer", &["-pkginfo", "-pkg"], &pkg);
    assert!(ok, "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn app_zip_extracts_with_ditto_and_keeps_the_signature() {
    let dir = scratch("zip");
    let Some(bin) = compile(&dir) else { return };
    let app = packager::App::new("Zip Oracle", "com.example.ziporacle", "1.0.0").binary(packager::Arch::MacosArm64, &bin);
    let out = packager::build(&app).package(packager::package::AppBundle::new()).out_dir(dir.join("dist")).run().unwrap();
    let bundle = out.packages()[0].path().to_path_buf();
    // A symlink, as frameworks carry (outside the signed bundle's seal, so add it to a copy).
    let plain = dir.join("plain");
    std::fs::create_dir_all(plain.join("Contents")).unwrap();
    std::os::unix::fs::symlink("MacOS", plain.join("Contents/Link")).unwrap();
    let pz = dir.join("p.zip");
    std::fs::write(&pz, packager::format::zip::from_dir(&plain, 0).unwrap()).unwrap();
    let px = dir.join("px");
    std::fs::create_dir_all(&px).unwrap();
    assert!(Command::new("ditto").args(["-x", "-k"]).arg(&pz).arg(&px).status().unwrap().success());
    assert!(std::fs::symlink_metadata(px.join("plain/Contents/Link")).unwrap().file_type().is_symlink());

    let zip = dir.join("a.zip");
    std::fs::write(&zip, packager::format::zip::from_dir(&bundle, 0).unwrap()).unwrap();
    let x = dir.join("x");
    std::fs::create_dir_all(&x).unwrap();
    let o = Command::new("ditto").args(["-x", "-k"]).arg(&zip).arg(&x).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let extracted = x.join(bundle.file_name().unwrap());
    let (ok, text) = tool("codesign", &["--verify", "--deep", "--strict", "--verbose=2"], &extracted);
    assert!(ok, "the extracted app's signature broke:\n{text}");
    let exe = std::fs::read_dir(extracted.join("Contents/MacOS")).unwrap().next().unwrap().unwrap().path();
    use std::os::unix::fs::PermissionsExt;
    assert!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o111 != 0, "executable bit lost");
    let (ok, text) = tool("unzip", &["-tq"], &zip);
    assert!(ok, "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stapling a real notarized package from this Mac, checked by Apple's `stapler` and `spctl`.
#[test]
#[ignore = "network: fetches a ticket from Apple"]
fn network_staple_matches_apples_stapler() {
    let src = Path::new("/Applications/Microsoft Teams.app/Contents/SharedSupport/MSTeamsAudioDevice.pkg");
    if !src.is_file() {
        eprintln!("skipped: no notarized reference package on this Mac");
        return;
    }
    let dir = scratch("real");
    let pkg = dir.join("ref.pkg");
    std::fs::copy(src, &pkg).unwrap();
    let data = std::fs::read(&pkg).unwrap();
    let sig = verify_pkg(&data).unwrap().expect("reference package is signed");
    assert!(sig.cms.as_ref().is_some_and(|c| c.timestamp.is_some()));
    match staple::staple(&packager::transport::Curl, &pkg).unwrap() {
        staple::Lookup::Ticket(_) => {}
        staple::Lookup::Missing(why) => panic!("no ticket: {why}"),
    }
    let (ok, text) = tool("xcrun", &["stapler", "validate"], &pkg);
    assert!(ok && text.contains("worked"), "{text}");
    let (ok, text) = tool("spctl", &["-a", "-vv", "-t", "install"], &pkg);
    assert!(ok && text.contains("Notarized Developer ID"), "{text}");
    let a = packager::sign::assess::assess(&pkg, None).unwrap();
    assert!(a.accepted(), "{:?}", a.checks);
    let _ = std::fs::remove_dir_all(&dir);
}
