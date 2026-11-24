//! Windows formats checked by Windows itself (oracles only, never runtime dependencies):
//! Authenticode on a real MSVC-built executable and MSIX packages, judged by
//! `Get-AuthenticodeSignature` (the WinVerifyTrust result) and `makeappx`. Signing uses a
//! throwaway self-signed certificate, so the expected verdict is "untrusted root", never
//! "hash mismatch"; nothing is added to any trust store. Runs on Windows hosts; skips elsewhere.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use packager::format::pe::{Image, VersionInfo};
use packager::sign::authenticode::{self, Options};
use packager::sign::{Authenticode, KeySigner};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("packager-win-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// WinVerifyTrust's verdict, through PowerShell.
fn authenticode_status(path: &Path) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &format!("(Get-AuthenticodeSignature -LiteralPath '{}').Status", path.display())])
        .output()
        .expect("powershell");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A Windows SDK tool (`makeappx`, `signtool`), if the SDK is installed.
fn sdk_tool(name: &str) -> Option<PathBuf> {
    let bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(bin).ok()?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.join("x64").join(name).is_file()).collect();
    versions.sort();
    versions.pop().map(|v| v.join("x64").join(name))
}

/// This test binary: a real MSVC-built PE to edit and sign.
fn real_exe(dir: &Path) -> PathBuf {
    let p = dir.join("app.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &p).unwrap();
    p
}

fn icon(dir: &Path) -> PathBuf {
    let mut img = packager::image::Image::new(64, 64);
    for (i, px) in img.rgba.chunks_mut(4).enumerate() {
        px.copy_from_slice(&[(i % 64 * 4) as u8, (i / 64 * 4) as u8, 200, 255]);
    }
    let p = dir.join("icon.png");
    std::fs::write(&p, img.to_png()).unwrap();
    p
}

#[test]
fn authenticode_on_a_real_executable() {
    let dir = scratch("pe");
    let exe = real_exe(&dir);
    let mut img = Image::read(&exe).unwrap();
    img.set_icon(&packager::image::ico_from_png(icon(&dir)).unwrap()).unwrap();
    img.set_version_info(&VersionInfo::new("2.3.4").unwrap().product("Oracle App").string("CompanyName", "Example Ltd")).unwrap();
    let signer = KeySigner::self_signed("Packager Windows Oracle", None).unwrap();
    authenticode::sign_pe(&mut img, &signer, &Options::sha256()).unwrap();
    img.write(&exe).unwrap();

    let status = authenticode_status(&exe);
    assert!(status != "HashMismatch" && status != "NotSigned" && status != "NotSupportedFileFormat", "WinVerifyTrust: {status}");
    let out = Command::new("powershell").args(["-NoProfile", "-Command", &format!("$v=(Get-Item -LiteralPath '{}').VersionInfo; \"$($v.ProductName)|$($v.CompanyName)|$($v.FileVersion)\"", exe.display())]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Oracle App|Example Ltd|2.3.4");
    // Still a working executable: the test harness lists its tests.
    let run = Command::new(&exe).arg("--list").output().unwrap();
    assert!(run.status.success(), "the edited, signed exe doesn't run");
    assert!(authenticode::verify_pe(&Image::read(&exe).unwrap()).unwrap().is_some());

    // A changed byte is a hash mismatch to Windows too.
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes[0x400] ^= 1;
    let bad = dir.join("bad.exe");
    std::fs::write(&bad, bytes).unwrap();
    assert_eq!(authenticode_status(&bad), "HashMismatch");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn msix_is_accepted_by_windows() {
    let dir = scratch("msix");
    let exe = real_exe(&dir);
    let app = packager::App::new("Oracle Msix", "com.example.oraclemsix", "1.2.3")
        .publisher("Example Ltd")
        .description("packager MSIX oracle")
        .binary(packager::Arch::WindowsX64, &exe)
        .icon(icon(&dir))
        .url_scheme("oraclemsix")
        .file_type("omsix", "Oracle file");
    let signer = KeySigner::self_signed("Packager Msix Oracle", None).unwrap().into_arc();
    let out = packager::build(&app).package(packager::package::Msix::new()).sign(Authenticode::new(signer)).out_dir(dir.join("dist")).run().unwrap();
    let msix = out.packages()[0].path().to_path_buf();

    assert!(packager::format::appx::verify(&std::fs::read(&msix).unwrap()).unwrap().is_some());
    let status = authenticode_status(&msix);
    assert!(status != "HashMismatch" && status != "NotSigned" && status != "NotSupportedFileFormat", "WinVerifyTrust: {status}");
    if let Some(makeappx) = sdk_tool("makeappx.exe") {
        let x = Command::new(makeappx).args(["unpack", "/o", "/p"]).arg(&msix).arg("/d").arg(dir.join("unpacked")).output().unwrap();
        assert!(x.status.success(), "makeappx unpack: {}", String::from_utf8_lossy(&x.stdout));
        let manifest = std::fs::read_to_string(dir.join("unpacked/AppxManifest.xml")).unwrap();
        assert!(manifest.contains("Publisher=\"CN=Packager Msix Oracle\""), "{manifest}");
        // The executable inside is signed too.
        assert!(authenticode_status(&dir.join("unpacked/app.exe")) != "NotSigned");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn powershell(script: &str) -> String {
    let script = format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8; {script}");
    let out = Command::new("powershell").args(["-NoProfile", "-Command", &script]).output().expect("powershell");
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).trim().to_string()
}

/// Installs, runs (through the execution alias), upgrades and removes a package, and checks a
/// downgrade is refused. Needs a code-signing certificate that's already trusted for sideloading
/// (in `LocalMachine\TrustedPeople`), given as PEM files in `PACKAGER_MSIX_CERT` and
/// `PACKAGER_MSIX_KEY`: `cargo test -- --ignored msix_installs`.
#[test]
#[ignore = "installs a package; needs PACKAGER_MSIX_CERT/KEY trusted in LocalMachine\\TrustedPeople"]
fn msix_installs_runs_upgrades_and_uninstalls() {
    let (Ok(cert), Ok(key)) = (std::env::var("PACKAGER_MSIX_CERT"), std::env::var("PACKAGER_MSIX_KEY")) else {
        panic!("set PACKAGER_MSIX_CERT and PACKAGER_MSIX_KEY to a trusted certificate's PEM files");
    };
    let signer = KeySigner::pem(&cert, &key, None).unwrap().into_arc();
    let dir = scratch("install");
    let exe = real_exe(&dir);
    let build = |version: &str, out: &str| {
        let app = packager::App::new("Oracle Install", "com.example.oracleinstall", version).binary(packager::Arch::WindowsX64, &exe).icon(icon(&dir));
        let o = packager::build(&app).package(packager::package::Msix::new().execution_alias("oracle-install")).sign(Authenticode::new(signer.clone())).out_dir(dir.join(out)).run().unwrap();
        o.packages()[0].path().display().to_string()
    };
    let (v1, v2) = (build("1.0.0", "v1"), build("1.0.1", "v2"));
    let id = "com.example.oracleinstall";
    let _ = powershell(&format!("Get-AppxPackage {id} | Remove-AppxPackage"));
    assert_eq!(authenticode_status(Path::new(&v1)), "Valid", "the certificate isn't trusted for sideloading");
    powershell(&format!("Add-AppxPackage -Path '{v1}'"));
    assert_eq!(powershell(&format!("(Get-AppxPackage {id}).Version")), "1.0.0.0");
    // The test harness, run through its alias, lists its tests.
    let listed = powershell("& \"$env:LOCALAPPDATA\\Microsoft\\WindowsApps\\oracle-install.exe\" --list");
    assert!(listed.contains("msix_installs_runs_upgrades_and_uninstalls"), "alias run: {listed}");
    powershell(&format!("Add-AppxPackage -Path '{v2}'"));
    assert_eq!(powershell(&format!("(Get-AppxPackage {id}).Version")), "1.0.1.0");
    let down = powershell(&format!("try {{ Add-AppxPackage -Path '{v1}' -ErrorAction Stop; 'allowed' }} catch {{ 'refused' }}"));
    assert_eq!(down, "refused");
    assert_eq!(powershell(&format!("(Get-AppxPackage {id}).Version")), "1.0.1.0");
    powershell(&format!("Get-AppxPackage {id} | Remove-AppxPackage"));
    assert_eq!(powershell(&format!("[bool](Get-AppxPackage {id})")), "False");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs `script` with `$db` open (read-only) on `path` through Windows Installer's COM API.
fn with_msi_db(path: &Path, script: &str) -> String {
    powershell(&format!(
        "$ErrorActionPreference = 'Stop'; $i = New-Object -ComObject WindowsInstaller.Installer; \
         $db = $i.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $i, @('{}', 0)); \
         function Q($sql) {{ $v = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql)); \
           $v.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $v, $null); $out = @(); \
           while ($r = $v.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $v, $null)) {{ \
             $n = $r.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $r, $null); \
             $f = foreach ($k in 1..$n) {{ $r.GetType().InvokeMember('StringData', 'GetProperty', $null, $r, @([int]$k)) }}; \
             $out += $f -join '|' }}; $out -join ';' }}; \
         function S($n) {{ $s = $db.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $db, @(0)); \
           $s.GetType().InvokeMember('Property', 'GetProperty', $null, $s, @($n)) }}; {script}",
        path.display()
    ))
}

#[test]
fn msi_database_opens_in_windows_installer() {
    use packager::format::msi::{col, Database, Summary, Table, Value};
    let dir = scratch("msidb");
    let mut prop = Table::new("Property", vec![col("Property", "*s72"), col("Value", "l0")]);
    prop.row(vec!["ProductName".into(), "Café Oracle".into()]).row(vec!["ALLUSERS".into(), "1".into()]);
    let mut file = Table::new("File", vec![col("File", "*s72"), col("FileSize", "i4"), col("Attributes", "i2?"), col("Sequence", "i2")]);
    file.row(vec!["b".into(), 70_000.into(), Value::Null, 2.into()]).row(vec!["a".into(), 5.into(), 512.into(), 1.into()]);
    let mut icon = Table::new("Icon", vec![col("Name", "*s72"), col("Data", "v0")]);
    icon.row(vec!["app.ico".into(), Value::Binary(vec![1, 2, 3, 4])]);
    let db = Database {
        tables: vec![prop, file, icon],
        streams: vec![],
        summary: Summary { subject: "Café Oracle".into(), author: "Example Ltd".into(), template: "x64;1033".into(), revision: "{11111111-2222-3333-4444-555555555555}".into(), page_count: 500, word_count: 2, security: 2, ..Default::default() },
    };
    let path = dir.join("t.msi");
    std::fs::write(&path, db.write(&[]).unwrap()).unwrap();
    let out = with_msi_db(
        &path,
        "Q \"SELECT `Value` FROM `Property` WHERE `Property`='ProductName'\"; \
         Q 'SELECT `File`, `FileSize`, `Attributes`, `Sequence` FROM `File` ORDER BY `Sequence`'; \
         Q 'SELECT `Name` FROM `_Tables`'; \
         S 7; S 9; S 14; S 3",
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.first(), Some(&"Café Oracle"), "{out}");
    assert_eq!(lines.get(1), Some(&"a|5|512|1;b|70000||2"), "{out}");
    assert!(lines.get(2).is_some_and(|l| l.contains("Property") && l.contains("File") && l.contains("Icon")), "{out}");
    assert_eq!(&lines[3..], ["x64;1033", "{11111111-2222-3333-4444-555555555555}", "500", "Café Oracle"], "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn msi_app(dir: &Path, exe: &Path, version: &str) -> packager::App {
    packager::App::new("Oracle Msi", "com.example.oraclemsi", version)
        .publisher("Example Ltd")
        .description("packager MSI oracle")
        .binary(packager::Arch::WindowsX64, exe)
        .icon(icon(dir))
        .url_scheme("oraclemsi")
        .file_type("omsi", "Oracle MSI file")
}

#[test]
fn msi_is_read_by_windows_installer() {
    let dir = scratch("msi");
    let exe = real_exe(&dir);
    let signer = KeySigner::self_signed("Packager Msi Oracle", None).unwrap().into_arc();
    let out = packager::build(&msi_app(&dir, &exe, "3.2.1")).package(packager::package::Msi::new()).sign(Authenticode::new(signer)).out_dir(dir.join("dist")).run().unwrap();
    let msi = out.packages()[0].path().to_path_buf();
    let status = authenticode_status(&msi);
    assert!(status != "HashMismatch" && status != "NotSigned" && status != "NotSupportedFileFormat", "WinVerifyTrust: {status}");
    assert!(packager::sign::msi::verify_msi(&std::fs::read(&msi).unwrap()).unwrap().is_some());
    let got = with_msi_db(
        &msi,
        "Q \"SELECT `Value` FROM `Property` WHERE `Property`='ProductVersion'\"; \
         Q 'SELECT `FileName`, `Version`, `Sequence` FROM `File`'; \
         Q 'SELECT `Cabinet` FROM `Media`'; \
         Q 'SELECT `Key` FROM `Registry`'; \
         S 7; S 14",
    );
    let lines: Vec<&str> = got.lines().collect();
    assert_eq!(lines.len(), 6, "{got}");
    assert_eq!(lines[..3], ["3.2.1", "app.exe|3.2.1.0|1", "#data.cab"], "{got}");
    assert!(lines[3].split(';').any(|k| k == "oraclemsi\\shell\\open\\command"), "{got}");
    assert_eq!(lines[4..], ["x64;1033", "500"], "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Installs, upgrades, blocks a downgrade and uninstalls with `msiexec` (needs an elevated
/// session): `cargo test -- --ignored msi_installs`.
#[test]
#[ignore = "installs software with msiexec; needs an elevated session"]
fn msi_installs_upgrades_blocks_downgrade_and_uninstalls() {
    let dir = scratch("msi-install");
    let exe = real_exe(&dir);
    let build = |v: &str| {
        let o = packager::build(&msi_app(&dir, &exe, v)).package(packager::package::Msi::new()).out_dir(dir.join(v)).run().unwrap();
        o.packages()[0].path().display().to_string()
    };
    let (v1, v2) = (build("1.0.0"), build("1.0.1"));
    let msiexec = |args: &str| powershell(&format!("(Start-Process msiexec -ArgumentList '{args}' -Wait -PassThru).ExitCode"));
    let installed = || powershell("@(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | ? DisplayName -eq 'Oracle Msi' | % DisplayVersion) -join ','");
    let target = r"C:\Program Files\Oracle Msi\app.exe";
    assert_eq!(msiexec(&format!("/i \"{v1}\" /qn")), "0");
    assert_eq!(installed(), "1.0.0");
    let run = Command::new(target).arg("--list").output().unwrap();
    assert!(run.status.success(), "the installed exe doesn't run");
    assert!(powershell("Test-Path 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Oracle Msi.lnk'") == "True");
    assert!(powershell("(Get-ItemProperty 'HKLM:\\Software\\Classes\\oraclemsi\\shell\\open\\command').'(default)'").contains("app.exe"));
    assert_eq!(msiexec(&format!("/i \"{v2}\" /qn")), "0");
    assert_eq!(installed(), "1.0.1", "the upgrade should replace 1.0.0");
    assert_eq!(msiexec(&format!("/i \"{v1}\" /qn")), "1603", "a downgrade must be refused");
    assert_eq!(installed(), "1.0.1");
    assert_eq!(msiexec(&format!("/x \"{v2}\" /qn")), "0");
    assert_eq!(installed(), "");
    assert!(!Path::new(target).exists());
    let _ = std::fs::remove_dir_all(&dir);
}
