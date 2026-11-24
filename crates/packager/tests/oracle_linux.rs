//! Linux packages checked with the native tools: `xz`, and on Linux `unsquashfs`, `dpkg-deb`,
//! `lintian`, `apt` and `snap`. Tools that aren't installed skip their checks.

use std::path::{Path, PathBuf};

use std::process::Command;

use packager::compress::lzma::Options;
use packager::compress::xz::{self, Check};
use packager::package::{Deb, DebCompression, Snap};
use packager::{App, Arch};

fn have(tool: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {tool}")).output().is_ok_and(|o| o.status.success())
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("packager-linux-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sample(n: usize) -> Vec<u8> {
    // Text-like data with repeats and noise, plus a run of zeros.
    let mut x = 12345u32;
    let mut out = Vec::new();
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        match x >> 29 {
            0 => out.push((x >> 8) as u8),
            1 => out.extend_from_slice(b"/usr/share/applications/"),
            2 => out.extend(std::iter::repeat_n(0u8, (x >> 20) as usize % 300)),
            _ => out.extend_from_slice(format!("line {} of the file\n", x % 1000).as_bytes()),
        }
    }
    out.truncate(n);
    out
}

fn run(cmd: &mut Command) -> std::process::Output {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(out.status.success(), "{cmd:?} failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    out
}

#[test]
fn xz_matches_xz_utils() {
    if !have("xz") {
        eprintln!("skipping: no xz");
        return;
    }
    let dir = scratch("xz");
    for (i, n) in [1usize, 5000, 131_072, 1_500_000].into_iter().enumerate() {
        let data = sample(n);
        for (j, check) in [Check::Crc32, Check::Crc64, Check::None].into_iter().enumerate() {
            let ours = xz::xz_with(&data, &Options::DEFAULT, check);
            let f = dir.join(format!("ours-{i}-{j}.xz"));
            std::fs::write(&f, &ours).unwrap();
            let out = run(Command::new("xz").args(["-dc"]).arg(&f));
            assert!(out.stdout == data, "xz -d of our stream differs (n={n}, {check:?})");
        }
        // And theirs through our decoder.
        let raw = dir.join(format!("theirs-{i}"));
        std::fs::write(&raw, &data).unwrap();
        run(Command::new("xz").args(["-k", "-6", "-f"]).arg(&raw));
        let theirs = std::fs::read(dir.join(format!("theirs-{i}.xz"))).unwrap();
        assert!(xz::unxz(&theirs, usize::MAX).unwrap() == data, "our decoder on xz's stream (n={n})");
        let ours = xz::xz(&data, &Options::DEFAULT);
        eprintln!("n={n}: xz -6 {} bytes, ours {} bytes", theirs.len(), ours.len());
    }
}

fn node(path: &str, kind: packager::format::cpio::NodeKind, perm: u32) -> packager::format::cpio::Node {
    packager::format::cpio::Node { path: path.into(), kind, perm, uid: 0, gid: 0, mtime: 315_532_800 }
}

/// Our images through `unsquashfs` (listing and extraction), and `mksquashfs` images through
/// our reader.
#[test]
fn squashfs_matches_squashfs_tools() {
    use packager::format::cpio::NodeKind;
    use packager::format::squashfs::{self, Compression, Options};
    if !have("unsquashfs") {
        eprintln!("skipping: no unsquashfs");
        return;
    }
    let dir = scratch("squashfs");
    let mut nodes = vec![
        node(".", NodeKind::Dir, 0o755),
        node("./bin", NodeKind::Dir, 0o755),
        node("./bin/tool", NodeKind::File(sample(400_000)), 0o755),
        node("./bin/alias", NodeKind::Symlink("tool".into()), 0o777),
        node("./meta", NodeKind::Dir, 0o755),
        node("./meta/snap.yaml", NodeKind::File(b"name: x\n".to_vec()), 0o644),
        node("./empty", NodeKind::File(Vec::new()), 0o644),
        node("./zeros", NodeKind::File(vec![0; 300_000]), 0o644),
        node("./lots", NodeKind::Dir, 0o755),
    ];
    for i in 0..1500 {
        nodes.push(node(&format!("./lots/entry-number-{i:05}-with-a-long-name.txt"), NodeKind::File(format!("{i}\n").into_bytes()), 0o644));
    }
    for compression in [Compression::Xz, Compression::Gzip] {
        let img = squashfs::write(&nodes, &Options { compression, block_size: 1 << 17, mkfs_time: 315_532_800 }).unwrap();
        let f = dir.join(format!("ours-{}.sqfs", compression.name()));
        std::fs::write(&f, &img).unwrap();
        let s = String::from_utf8_lossy(&run(Command::new("unsquashfs").arg("-s").arg(&f)).stdout).into_owned();
        assert!(s.contains(&format!("Compression {}", compression.name())), "{s}");
        let out = dir.join(format!("x-{}", compression.name()));
        run(Command::new("unsquashfs").arg("-n").arg("-d").arg(&out).arg(&f));
        for nd in &nodes {
            let p = out.join(nd.path.trim_start_matches("./"));
            match &nd.kind {
                NodeKind::File(d) => assert!(std::fs::read(&p).unwrap() == *d, "{}", nd.path),
                NodeKind::Symlink(t) => assert_eq!(std::fs::read_link(&p).unwrap(), Path::new(t)),
                NodeKind::Dir => assert!(p.is_dir()),
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if !matches!(nd.kind, NodeKind::Symlink(_)) && nd.path != "." {
                    assert_eq!(std::fs::symlink_metadata(&p).unwrap().permissions().mode() & 0o7777, nd.perm, "{}", nd.path);
                }
            }
        }
    }
    if have("mksquashfs") {
        let src = dir.join("x-xz");
        let theirs = dir.join("theirs.sqfs");
        run(Command::new("mksquashfs").arg(&src).arg(&theirs).args(["-comp", "xz", "-no-fragments", "-no-xattrs", "-all-root", "-noappend", "-quiet"]));
        let back = squashfs::read(&std::fs::read(&theirs).unwrap()).unwrap();
        assert_eq!(back.len(), nodes.len());
        let tool = back.iter().find(|n| n.path == "./bin/tool").unwrap();
        assert!(tool.kind == NodeKind::File(sample(400_000)));
    }
}

/// Compiles a small program that prints its version and arguments (x86_64 Linux only).
fn hello_binary(dir: &Path, version: &str) -> Option<PathBuf> {
    if !(cfg!(target_os = "linux") && cfg!(target_arch = "x86_64")) || !have("cc") {
        eprintln!("skipping: needs cc on x86_64 Linux");
        return None;
    }
    std::fs::create_dir_all(dir).unwrap();
    let src = dir.join("hello.c");
    std::fs::write(
        &src,
        "#include <stdio.h>\nint main(int argc, char **argv) {\n  printf(\"hello from packager %s\\n\", VERSION);\n  for (int i = 1; i < argc; i++) printf(\"arg %s\\n\", argv[i]);\n  return 0;\n}\n",
    )
    .unwrap();
    let bin = dir.join(format!("hello-{version}")).join("my-app");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    run(Command::new("cc")
        .args(["-O2", "-s", "-Wl,-z,relro,-z,now", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie"])
        .arg(format!("-DVERSION=\"{version}\""))
        .arg(&src)
        .arg("-o")
        .arg(&bin));
    Some(bin)
}

fn test_app(dir: &Path, version: &str) -> Option<App> {
    let bin = hello_binary(dir, version)?;
    let icon = dir.join("icon.png");
    let mut img = packager::image::Image::new(256, 256);
    for (i, px) in img.rgba.chunks_mut(4).enumerate() {
        let (x, y) = (i % 256, i / 256);
        px.copy_from_slice(&[(x as u8), (y as u8), 180, if (x as i32 - 128).pow(2) + (y as i32 - 128).pow(2) < 120 * 120 { 255 } else { 0 }]);
    }
    std::fs::write(&icon, img.to_png()).unwrap();
    let web = dir.join("web");
    std::fs::create_dir_all(web.join("assets")).unwrap();
    std::fs::write(web.join("index.html"), "<!doctype html><p>hello</p>\n").unwrap();
    std::fs::write(web.join("assets/app.js"), "console.log(1);\n").unwrap();
    // Incompressible bytes: the Snap Store's review wants snaps of at least 16 KiB.
    let mut x = 0x9E37_79B9u32;
    let noise: Vec<u8> = (0..40_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    std::fs::write(web.join("assets/noise.bin"), noise).unwrap();
    std::fs::write(dir.join("my-app.1"), ".TH MY-APP 1\n.SH NAME\nmy-app \\- says hello\n.SH SYNOPSIS\n.B my-app\n[\\fIargs\\fR]\n").unwrap();
    Some(
        App::new("Packager Hello", "com.example.packagerhello", version)
            .publisher("Example Ltd")
            .description("Says hello from a packager-built package.\n\nBuilt by the packager oracle tests to check Debian and snap packages.")
            .copyright("2026 Example Ltd")
            .binary(Arch::LinuxX64, bin)
            .icon(&icon)
            .resources(&web, "web")
            .url_scheme("packagerhello")
            .file_type("md", "Markdown document")
            .file_type("phello", "Packager Hello document"),
    )
}

fn test_deb(dir: &Path) -> Deb {
    Deb::new().man_page(dir.join("my-app.1")).maintainer("Example Ltd <packages@example.com>").homepage("https://example.com/hello").license("MIT")
}

fn build_one(app: &App, pkg: impl packager::package::PackageBuilder + 'static, out: &Path) -> PathBuf {
    let built = packager::build(app).package(pkg).out_dir(out).run().unwrap();
    built.packages()[0].path().to_path_buf()
}

/// `dpkg-deb` reads the package and extracts the same files; `lintian` finds nothing to report;
/// `desktop-file-validate` accepts the menu entry.
#[test]
fn deb_passes_dpkg_and_lintian() {
    if !have("dpkg-deb") {
        eprintln!("skipping: no dpkg-deb");
        return;
    }
    let dir = scratch("deb");
    let Some(app) = test_app(&dir, "1.4.0") else { return };
    for (i, c) in [DebCompression::Gzip, DebCompression::Xz].into_iter().enumerate() {
        let deb = build_one(&app, test_deb(&dir).compression(c), &dir.join(format!("out{i}")));
        assert!(deb.file_name().unwrap().to_str().unwrap() == "packagerhello_1.4.0_amd64.deb", "{deb:?}");
        let info = String::from_utf8_lossy(&run(Command::new("dpkg-deb").arg("--info").arg(&deb)).stdout).into_owned();
        eprintln!("{info}");
        for want in ["Package: packagerhello", "Version: 1.4.0", "Architecture: amd64", "Depends: libc6 (>= 2.", "Installed-Size: "] {
            assert!(info.contains(want), "missing {want}");
        }
        let x = dir.join(format!("x{i}"));
        run(Command::new("dpkg-deb").arg("-x").arg(&deb).arg(&x));
        assert!(std::fs::read(x.join("opt/packagerhello/my-app")).unwrap() == std::fs::read(&app.binaries[0].1).unwrap());
        assert_eq!(std::fs::read_to_string(x.join("opt/packagerhello/web/index.html")).unwrap(), "<!doctype html><p>hello</p>\n");
        assert_eq!(std::fs::read_link(x.join("usr/bin/my-app")).unwrap(), Path::new("/opt/packagerhello/my-app"));
        assert!(x.join("usr/share/icons/hicolor/256x256/apps/packagerhello.png").is_file());
        assert!(x.join("usr/share/mime/packages/packagerhello.xml").is_file());
        let desktop = x.join("usr/share/applications/com.example.packagerhello.desktop");
        if have("desktop-file-validate") {
            run(Command::new("desktop-file-validate").arg(&desktop));
        }
        let ctl = dir.join(format!("ctl{i}"));
        run(Command::new("dpkg-deb").arg("-e").arg(&deb).arg(&ctl));
        // dpkg's own check of md5sums against the extracted tree.
        let sums = std::fs::read_to_string(ctl.join("md5sums")).unwrap();
        assert!(sums.contains("  opt/packagerhello/my-app\n"));
        if have("md5sum") {
            run(Command::new("md5sum").arg("-c").arg("--quiet").arg(ctl.join("md5sums")).current_dir(&x));
        }
    }
    if have("lintian") {
        let deb = dir.join("out0/packagerhello_1.4.0_amd64.deb");
        // /opt is where third-party apps go; lintian's distro rule against it doesn't apply.
        let out = Command::new("lintian").args(["--fail-on", "error,warning", "--display-info", "--suppress-tags", "dir-or-file-in-opt"]).arg(&deb).output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        eprintln!("lintian:\n{text}");
        assert!(out.status.success(), "lintian reported errors or warnings:\n{text}");
        // Distro-style layout under /usr/lib passes without any suppression.
        let deb = build_one(&app, test_deb(&dir).install_dir("/usr/lib/packagerhello"), &dir.join("usrlib"));
        let out = Command::new("lintian").args(["--fail-on", "error,warning"]).arg(&deb).output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "lintian (/usr/lib layout):\n{text}");
    }
}

fn sudo(args: &[&str]) -> std::process::Output {
    run(Command::new("sudo").arg("-n").args(args))
}

/// Installs with `apt`, runs the command, upgrades to a newer version, refuses nothing on a
/// downgrade without `--allow-downgrades`, and removes everything. Needs passwordless sudo:
/// `cargo test --test oracle_linux -- --ignored deb_installs`.
#[test]
#[ignore]
fn deb_installs() {
    let dir = scratch("deb-install");
    let Some(v1) = test_app(&dir, "1.4.0") else { return };
    let Some(v2) = test_app(&dir.join("v2"), "1.5.0") else { return };
    let d1 = build_one(&v1, test_deb(&dir), &dir.join("v1out"));
    let d2 = build_one(&v2, test_deb(&dir.join("v2")), &dir.join("v2out"));
    let _ = Command::new("sudo").args(["-n", "apt-get", "remove", "-y", "packagerhello"]).output();
    sudo(&["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", d1.to_str().unwrap()]);
    let out = run(Command::new("my-app").arg("x"));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello from packager 1.4.0\narg x\n");
    let status = String::from_utf8_lossy(&run(Command::new("dpkg-query").args(["-W", "-f", "${Version} ${Status}", "packagerhello"])).stdout).into_owned();
    assert_eq!(status, "1.4.0 install ok installed");
    // The triggers registered the URL scheme and the custom MIME type.
    let cache = std::fs::read_to_string("/usr/share/applications/mimeinfo.cache").unwrap_or_default();
    assert!(cache.contains("x-scheme-handler/packagerhello=com.example.packagerhello.desktop"), "mimeinfo.cache:\n{cache}");
    let globs = std::fs::read_to_string("/usr/share/mime/globs2").unwrap_or_default();
    assert!(globs.contains("application/x-packagerhello-phello:*.phello"), "globs2 lacks our type");
    assert!(Path::new("/usr/share/icons/hicolor/256x256/apps/packagerhello.png").exists());
    // Upgrade.
    sudo(&["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", d2.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&run(&mut Command::new("my-app")).stdout), "hello from packager 1.5.0\n");
    // Downgrade needs explicit permission.
    let down = Command::new("sudo").args(["-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-allow-downgrades", d1.to_str().unwrap()]).output().unwrap();
    assert!(!down.status.success(), "apt downgraded without --allow-downgrades");
    // Remove.
    sudo(&["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "remove", "-y", "packagerhello"]);
    for gone in ["/opt/packagerhello", "/usr/bin/my-app", "/usr/share/applications/com.example.packagerhello.desktop", "/usr/share/mime/packages/packagerhello.xml"] {
        assert!(!Path::new(gone).exists(), "{gone} left behind");
    }
    let cache = std::fs::read_to_string("/usr/share/applications/mimeinfo.cache").unwrap_or_default();
    assert!(!cache.contains("packagerhello"), "mimeinfo.cache still lists us");
}

/// `unsquashfs` reads the snap as root-owned xz SquashFS, and Canonical's `review-tools` (the
/// Snap Store's automated review) passes it with no errors or warnings.
///
/// One check is turned off (`SNAP_ENFORCE_RESQUASHFS=0`): the Store repacks the snap with its
/// own `mksquashfs` and liblzma and wants identical bytes, which needs an encoder that matches
/// liblzma's output exactly. Our xz is valid (the kernel, `unsquashfs` and `xz` read it) but
/// not byte-identical to liblzma's, so Store uploads aren't supported yet.
#[test]
fn snap_passes_review_tools() {
    if !have("unsquashfs") {
        eprintln!("skipping: no unsquashfs");
        return;
    }
    let dir = scratch("snap");
    let Some(app) = test_app(&dir, "1.4.0") else { return };
    let snap = build_one(&app, Snap::new().license("MIT"), &dir.join("out"));
    assert_eq!(snap.file_name().unwrap().to_str().unwrap(), "packagerhello_1.4.0_amd64.snap");
    let s = String::from_utf8_lossy(&run(Command::new("unsquashfs").arg("-s").arg(&snap)).stdout).into_owned();
    assert!(s.contains("Compression xz"), "{s}");
    let listing = String::from_utf8_lossy(&run(Command::new("unsquashfs").arg("-lls").arg(&snap)).stdout).into_owned();
    eprintln!("{listing}");
    assert!(listing.contains("root/root") && !listing.lines().filter(|l| l.contains("squashfs-root")).any(|l| l.contains("/") && !l.contains("root/root") && l.starts_with(['-', 'd', 'l'])));
    for want in ["squashfs-root/meta/snap.yaml", "squashfs-root/meta/gui/icon.png", "squashfs-root/meta/gui/packagerhello.desktop", "squashfs-root/my-app", "squashfs-root/web/index.html"] {
        assert!(listing.contains(want), "missing {want}");
    }
    let review = if have("review-tools.snap-review") {
        Some("review-tools.snap-review")
    } else if have("snap-review") {
        Some("snap-review")
    } else {
        None
    };
    if let Some(tool) = review {
        // review-tools (a strict snap) can only read files under $HOME.
        let home = PathBuf::from(std::env::var("HOME").unwrap()).join(format!("packager-review-{}.snap", std::process::id()));
        std::fs::copy(&snap, &home).unwrap();
        let out = Command::new(tool).arg(&home).env("SNAP_ENFORCE_RESQUASHFS", "0").output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let _ = std::fs::remove_file(&home);
        eprintln!("{tool}:\n{text}");
        assert!(out.status.success(), "review-tools failed:\n{text}");
    }
}

/// Installs with `snap install --dangerous`, runs it, refreshes to a newer version and removes
/// it. Needs passwordless sudo and snapd: `cargo test --test oracle_linux -- --ignored snap_installs`.
#[test]
#[ignore]
fn snap_installs() {
    let dir = scratch("snap-install");
    let Some(v1) = test_app(&dir, "1.4.0") else { return };
    let Some(v2) = test_app(&dir.join("v2"), "1.5.0") else { return };
    let s1 = build_one(&v1, Snap::new(), &dir.join("v1out"));
    let s2 = build_one(&v2, Snap::new(), &dir.join("v2out"));
    let _ = Command::new("sudo").args(["-n", "snap", "remove", "--purge", "packagerhello"]).output();
    sudo(&["snap", "install", "--dangerous", s1.to_str().unwrap()]);
    let out = run(Command::new("/snap/bin/packagerhello").arg("x"));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello from packager 1.4.0\narg x\n");
    let list = String::from_utf8_lossy(&run(Command::new("snap").args(["list", "packagerhello"])).stdout).into_owned();
    assert!(list.contains("1.4.0"), "{list}");
    let desktop = std::fs::read_to_string("/var/lib/snapd/desktop/applications/packagerhello_packagerhello.desktop").expect("snapd exported the desktop entry");
    assert!(desktop.contains("/snap/bin/packagerhello") && desktop.contains("x-scheme-handler/packagerhello"), "{desktop}");
    let conns = String::from_utf8_lossy(&run(Command::new("snap").args(["connections", "packagerhello"])).stdout).into_owned();
    assert!(conns.contains("packagerhello:wayland") && conns.contains("packagerhello:home"), "{conns}");
    sudo(&["snap", "install", "--dangerous", s2.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&run(&mut Command::new("/snap/bin/packagerhello")).stdout), "hello from packager 1.5.0\n");
    sudo(&["snap", "remove", "--purge", "packagerhello"]);
    assert!(!Path::new("/snap/bin/packagerhello").exists());
    assert!(!Path::new("/var/lib/snapd/desktop/applications/packagerhello_packagerhello.desktop").exists());
}
