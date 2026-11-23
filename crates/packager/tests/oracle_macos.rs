//! Native tools as test oracles (never runtime dependencies): build real packages through the
//! public API, then check them with `codesign`, `hdiutil`, `fsck_hfs`-backed mounting, `pkgutil`,
//! `lsbom` and `installer`. Runs on macOS hosts with the command-line tools; skips elsewhere.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use packager::package::{AppBundle, Dmg, Pkg};
use packager::{App, Arch};

fn have(tool: &str) -> bool {
    Command::new("/usr/bin/which").arg(tool).output().map(|o| o.status.success()).unwrap_or(false)
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{cmd:?} failed:\n{text}");
    text
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("packager-oracle-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A universal (arm64 + x86_64) executable and a dylib, compiled with the system compiler.
fn fixtures(dir: &Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if !have("cc") {
        return None;
    }
    std::fs::write(dir.join("main.c"), "int main(void){return 0;}\n").unwrap();
    std::fs::write(dir.join("lib.c"), "int f(void){return 1;}\n").unwrap();
    let arm = dir.join("app-arm64");
    let x86 = dir.join("app-x86_64");
    for (arch, out) in [("arm64", &arm), ("x86_64", &x86)] {
        let ok = Command::new("cc").args(["-arch", arch, "-O2", "-o"]).arg(out).arg(dir.join("main.c")).status().ok()?.success();
        if !ok {
            return None;
        }
    }
    let lib = dir.join("libhelper.dylib");
    run(Command::new("cc").args(["-dynamiclib", "-o"]).arg(&lib).arg(dir.join("lib.c")));
    Some((arm, x86, lib))
}

fn icon(dir: &Path) -> PathBuf {
    let mut img = packager::image::Image::new(256, 256);
    for (i, p) in img.rgba.chunks_mut(4).enumerate() {
        let (x, y) = (i % 256, i / 256);
        let inside = (x as i32 - 128).pow(2) + (y as i32 - 128).pow(2) < 110 * 110;
        p.copy_from_slice(&[x as u8, y as u8, 200, if inside { 255 } else { 0 }]);
    }
    let path = dir.join("icon.png");
    std::fs::write(&path, img.to_png()).unwrap();
    path
}

#[test]
fn app_dmg_pkg_pass_native_checks() {
    let dir = scratch("all");
    let Some((arm, x86, lib)) = fixtures(&dir) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let res = dir.join("res");
    std::fs::create_dir_all(res.join("en.lproj")).unwrap();
    std::fs::write(res.join("index.html"), "<h1>hi</h1>").unwrap();
    std::fs::write(res.join("en.lproj/Localizable.strings"), "\"a\" = \"b\";").unwrap();
    let app = App::new("Oracle Test", "com.example.oracle", "2.3.4")
        .binary(Arch::MacosArm64, &arm)
        .binary(Arch::MacosX64, &x86)
        .icon(icon(&dir))
        .resources(&res, "web")
        .url_scheme("oracle")
        .file_type("txt", "Text");
    let out = dir.join("dist");
    let built = packager::build(&app)
        .app_bundle(AppBundle::new().framework(&lib))
        .package(AppBundle::new().framework(&lib))
        .package(Dmg::new())
        .package(Pkg::new())
        .out_dir(&out)
        .run()
        .unwrap();
    let path_of = |k: packager::PackageKind| built.packages().iter().find(|p| p.kind() == k).unwrap().path().to_path_buf();
    let app_path = path_of(packager::PackageKind::App);
    let dmg = path_of(packager::PackageKind::Dmg);
    let pkg = path_of(packager::PackageKind::Pkg);

    // .app: Apple's verifier, our verifier, and it runs.
    run(Command::new("codesign").args(["--verify", "--deep", "--strict", "--verbose=2"]).arg(&app_path));
    packager::sign::bundle::verify_bundle(&app_path).unwrap();
    run(&mut Command::new(app_path.join("Contents/MacOS/app-arm64")));
    let lipo = run(Command::new("lipo").arg("-archs").arg(app_path.join("Contents/MacOS/app-arm64")));
    assert!(lipo.contains("x86_64") && lipo.contains("arm64"), "{lipo}");
    run(Command::new("plutil").arg("-lint").arg(app_path.join("Contents/Info.plist")));

    // .dmg: checksum, mount, contents.
    if have("hdiutil") {
        run(Command::new("hdiutil").arg("verify").arg(&dmg));
        let mnt = dir.join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        run(Command::new("hdiutil").args(["attach", "-readonly", "-nobrowse", "-mountpoint"]).arg(&mnt).arg(&dmg));
        // Always detach, even when a check fails, then report the failure.
        let check = std::panic::catch_unwind(|| {
            let mounted_app = mnt.join("Oracle Test.app");
            run(Command::new("codesign").args(["--verify", "--deep", "--strict"]).arg(&mounted_app));
            assert_eq!(std::fs::read_link(mnt.join("Applications")).unwrap(), Path::new("/Applications"));
            assert!(mnt.join(".VolumeIcon.icns").is_file());
            assert!(mnt.join(".DS_Store").is_file());
        });
        run(Command::new("hdiutil").args(["detach", "-quiet"]).arg(&mnt));
        if let Err(p) = check {
            std::panic::resume_unwind(p);
        }
    }

    // .pkg: structure, Bom, payload round trip.
    // Exits non-zero for unsigned packages; the output says why.
    let sig = Command::new("pkgutil").arg("--check-signature").arg(&pkg).output().unwrap();
    let sig = String::from_utf8_lossy(&sig.stdout);
    assert!(sig.contains("no signature"), "{sig}");
    run(Command::new("installer").args(["-pkginfo", "-pkg"]).arg(&pkg));
    let ex = dir.join("expanded");
    run(Command::new("pkgutil").arg("--expand-full").arg(&pkg).arg(&ex));
    let comp = std::fs::read_dir(&ex).unwrap().map(|e| e.unwrap().path()).find(|p| p.extension().is_some_and(|e| e == "pkg")).unwrap();
    let bom = run(Command::new("lsbom").arg(comp.join("Bom")));
    assert!(bom.contains("./Oracle Test.app/Contents/MacOS/app-arm64\t100755\t0/0"), "{bom}");
    run(Command::new("diff").arg("-r").arg(&app_path).arg(comp.join("Payload/Oracle Test.app")));
    run(Command::new("codesign").args(["--verify", "--deep", "--strict"]).arg(comp.join("Payload/Oracle Test.app")));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hardened_runtime_with_entitlements() {
    let dir = scratch("ent");
    let Some((arm, _, _)) = fixtures(&dir) else { return };
    let ent = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>"#;
    let app = App::new("Ent", "com.example.ent", "1.0.0").binary(Arch::MacosArm64, &arm);
    let out = packager::build(&app)
        .package(AppBundle::new())
        .sign(packager::sign::Apple::ad_hoc().hardened_runtime().entitlements_xml(ent))
        .out_dir(dir.join("dist"))
        .run()
        .unwrap();
    let p = out.packages()[0].path();
    run(Command::new("codesign").args(["--verify", "--deep", "--strict"]).arg(p));
    let info = run(Command::new("codesign").args(["-d", "--entitlements", "-", "--verbose=4"]).arg(p));
    assert!(info.contains("runtime"), "{info}");
    assert!(info.contains("com.apple.security.cs.allow-jit"), "{info}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deterministic_output() {
    let dir = scratch("det");
    let Some((arm, _, _)) = fixtures(&dir) else { return };
    let app = App::new("Det", "com.example.det", "1.0.0").binary(Arch::MacosArm64, &arm);
    let hashes = |sub: &str| {
        let out = packager::build(&app).package(Dmg::new()).package(Pkg::new()).out_dir(dir.join(sub)).run().unwrap();
        out.packages().iter().map(|p| p.sha256_hex()).collect::<Vec<_>>()
    };
    assert_eq!(hashes("a"), hashes("b"));
    let _ = std::fs::remove_dir_all(&dir);
}
