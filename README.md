# packager

**Native OS packages from scratch, in pure Rust: build and sign `.app`, `.dmg`, `.pkg`, `.msi`, `.msix`, `.deb` and `.snap` from any host.**

`packager` turns one description of an app into the package each OS installs natively. Every format, compressor, filesystem, hash and signature is implemented in the repo with zero third-party crates, so a signed `.msi` builds on Linux, a `.dmg` on Windows and a `.deb` on macOS, without platform SDKs or VMs. It replaces `makeappx`, `signtool`, `rcedit`, `codesign`, `pkgbuild` / `productbuild` / `productsign`, `hdiutil`, `notarytool` / `stapler`, `spctl`, `iconutil` / `sips`, `dpkg-deb` and `snapcraft pack`.

---

## Installation

The library:

```toml
[dependencies]
packager = { git = "https://github.com/tensorai-co/packager" }
```

The `packager` command:

```sh
cargo install --git https://github.com/tensorai-co/packager packager-cli
```

Requires Rust 1.88 or newer (edition 2024).

---

## Quickstart

### From Rust

```rust
use packager::package::{Deb, Dmg, Msi, Msix, Pkg, Snap};
use packager::sign::{Apple, Authenticode, KeySigner};
use packager::{App, Arch};

fn main() -> packager::Result<()> {
    let app = App::new("My App", "com.example.myapp", "1.4.0")
        .publisher("Example Ltd")
        .description("Writes notes.")
        .binary(Arch::MacosArm64, "target/aarch64-apple-darwin/release/my-app")
        .binary(Arch::MacosX64, "target/x86_64-apple-darwin/release/my-app") // merged into a universal binary
        .binary(Arch::WindowsX64, "target/x86_64-pc-windows-msvc/release/my-app.exe")
        .binary(Arch::LinuxX64, "target/x86_64-unknown-linux-gnu/release/my-app")
        .icon("assets/icon.png") // .icns, .ico, MSIX logos and Linux icons are generated
        .resources("dist/", "web")
        .url_scheme("myapp")
        .file_type("md", "Markdown document");

    let windows = KeySigner::pkcs12("codesign.pfx", "password")?.into_arc();
    let out = packager::build(&app)
        .package(Dmg::new())
        .package(Pkg::new())
        .package(Msi::new())
        .package(Msix::new())
        .package(Deb::new().maintainer("Example Ltd <packages@example.com>"))
        .package(Snap::new())
        .sign(Apple::ad_hoc().hardened_runtime())
        .sign(Authenticode::new(windows).timestamp("http://timestamp.digicert.com"))
        .out_dir("target/dist")
        .run()?;

    for p in out.packages() {
        println!("{} {} {} {}", p.kind(), p.arch(), p.path().display(), p.sha256_hex());
    }
    Ok(())
}
```

Each builder works with no options and holds only what's specific to its format, such as `Msi::new().per_user().wizard()`, `Dmg::new().window_background("assets/dmg.png")` or `Snap::new().plug("camera")`. Everything is checked before anything is written, and errors name the format and the field.

### From the command line

`packager.toml` mirrors the library one-to-one: `[app]` is `App`, `[package.*]` are the builders and `[sign.*]` the signing settings. See [`packager.example.toml`](packager.example.toml) for every key.

```toml
[app]
name = "My App"
identifier = "com.example.myapp"
version = "1.4.0"
publisher = "Example Ltd"
icon = "assets/icon.png"

[app.binaries]
macos-arm64 = "target/aarch64-apple-darwin/release/my-app"
windows-x64 = "target/x86_64-pc-windows-msvc/release/my-app.exe"
linux-x64 = "target/x86_64-unknown-linux-gnu/release/my-app"

[package.dmg]
[package.msi]
[package.deb]
maintainer = "Example Ltd <packages@example.com>"
[package.snap]
```

The same tables can live in a crate's `Cargo.toml` under `[package.metadata.packager]`. There, the name, version (workspace versions included), description and publisher default to the crate's, and the binary defaults to its release build. `packager build` uses it when there's no `packager.toml`, and tools load either through `packager::config`.

```sh
packager build                          # every package in packager.toml (or Cargo.toml)
packager build --only dmg,deb --out dist
packager verify dist/myapp_1.4.0_amd64.deb
```

Output is deterministic: the same input gives byte-identical packages. Timestamps come from `SOURCE_DATE_EPOCH` and default to 1980-01-01. Signature timestamps are the only thing that differs between builds.

---

## Packages

| Package | What's written | Checked against |
| :--- | :--- | :--- |
| **`.app`** | `Info.plist`, universal binary merged from per-arch inputs, `.icns` from one PNG, resources, frameworks and helper apps (Chromium-style, with their own identifiers), a signature on every Mach-O and a sealed `CodeResources` | `codesign --verify --deep --strict`, `plutil -lint`, `lipo`, running it |
| **`.dmg`** | HFSX volume (catalog B-tree, NFD names), `Applications` link, volume icon, optional background and Finder layout (`.DS_Store` + alias), UDZO image, image signature | `hdiutil verify`, `fsck_hfs`, mounting, `codesign --verify`, Finder |
| **`.pkg`** | Flat package: XAR with `Distribution`, `PackageInfo` (not relocatable), `Bom`, gzip'd cpio payload, scripts; installer signature | `installer`, `pkgutil --check-signature`, `lsbom`, `sudo installer -pkg` |
| **`.msi`** | Compound File, installer database with `_Validation`, MSZIP cabinets (split at 1 GiB), one component per file, Start menu shortcut, URL schemes and file types, major upgrades with a downgrade block, per-machine or per-user, optional wizard; Authenticode with `MsiDigitalSignatureEx` | ICE validation (no errors or warnings), Windows Installer's COM API, `Get-AuthenticodeSignature`, `msiexec` install / upgrade / downgrade / uninstall |
| **`.msix`** | Signed exe, app files, logos, `AppxManifest.xml` (full trust, URL schemes, file types, execution alias; `Publisher` from the certificate), block map, `AppxSignature.p7x` in `makeappx`'s ZIP layout | `Get-AuthenticodeSignature`, `makeappx unpack`, `Add-AppxPackage` / `Remove-AppxPackage` |
| **`.msixbundle`** | Signed per-architecture `.msix` packages, `AppxBundleManifest.xml`, block map, bundle signature | `makeappx unbundle`, `Add-AppxPackage` |
| **`.exe`** | Icon, `VS_VERSIONINFO` and manifest in a rebuilt `.rsrc` (what `rcedit` does); Authenticode with RFC 3161 timestamps | `signtool verify`, `Get-AuthenticodeSignature`, running it |
| **`.deb`** | `control` (with `Depends: libc6 (>= …)` read from the binary), `md5sums`, the app in `/opt/<name>`, `/usr/bin` link, `.desktop` entry, hicolor icons, MIME types, `copyright`, `changelog`, optional man page; gzip or xz | `dpkg-deb`, `lintian` (no errors or warnings), `desktop-file-validate`, `apt install` / upgrade / remove |
| **`.snap`** | xz SquashFS with `meta/snap.yaml` (base, confinement, plugs, grade), menu entry and icon, the app at `$SNAP` | `unsquashfs`, Snap Store `review-tools`, `snap install --dangerous` / refresh / remove |

Identity codes and versions are derived from the `App`, so apps never manage GUIDs by hand:
- **MSI:** the UpgradeCode comes from the identifier and never changes. The ProductCode is new each version, so every release is a clean major upgrade. The PackageCode comes from the package's contents.
- **Versions:** checked against each format's limits up front. A pre-release such as `1.4.0-beta.1` becomes `1.4.0~beta.1` on Debian and a `devel` snap; formats that can't express one reject it.
- **MSIX:** `Publisher` is read from the signing certificate.
- **Linux:** the `.deb` and snap names are the identifier's last part (`com.example.myapp` → `myapp`).

---

## Signing and notarization

Signing goes through the `Signer` trait, so a key can stay in a keychain, an HSM or a cloud service. Built in: PKCS#12 (`.p12` / `.pfx`), PEM, the macOS Keychain (the key never leaves it) and throwaway self-signed certificates for testing. The builder signs in the order each platform requires: nested code, then bundles, then containers, then notarization and stapling.

**Apple** (`codesign`, `productsign`, `notarytool`, `stapler` and `spctl` in Rust):
- Signatures: CodeDirectories with hardened runtime, entitlements and team ID, requirements compiled like `csreq`, and CMS with Apple's attributes and timestamps.
- Notarization: preflight checks run locally before uploading, then the Notary API and the S3 upload.
- Stapling: tickets go where each format keeps them.

```sh
packager codesign -fs "Developer ID Application" -o runtime --timestamp My.app
packager notarize "dist/My App-1.4.0.dmg" --key AuthKey_ABCDE12345.p8 --issuer <issuer-uuid>
packager staple --validate "dist/My App-1.4.0.dmg"
packager assess "dist/My App-1.4.0.dmg"            # would Gatekeeper accept it?
```

**Windows:** Authenticode for `.exe` / `.dll`, `.msi`, `.msix` and bundles, with RFC 3161 timestamps from any server.

```sh
packager rcedit my-app.exe --icon icon.png --version 1.4.0 --set CompanyName="Example Ltd"
packager sign my-app.exe -s p12:codesign.pfx --timestamp http://timestamp.digicert.com
```

**Update feeds:** `packager update-key` makes a P-256 key, and `packager update-feed` writes a JSON feed whose signature an app checks with the embedded public key, as `ui::update::check` does.

**Linux:** packages aren't signed as files. Debian signs repositories, and the Snap Store signs what's uploaded. Install a local snap with `snap install --dangerous`.

---

## Command line

```text
packager build [--config packager.toml] [--only app,dmg,pkg,msi,msix,msixbundle,deb,snap] [--out DIR] [--no-notarize]
packager verify <file|bundle>        signatures and structure, without native tools
packager inspect <file|bundle>       what's inside a .app, .dmg, .pkg, .deb, .snap, Mach-O or ELF file
packager sign <file|bundle> …        Apple or Authenticode signature, by file type
packager codesign …                  codesign's own command line (sign, -v verify, -d display)
packager identities                  code-signing identities in the keychain (macOS)
packager notarize | staple | productsign | assess …
packager rcedit <file.exe> …
packager icns <icon.png> <out.icns>
packager update-key [--out DIR]      a P-256 key for signed update feeds, and its public key
packager update-feed <key.pem> <version> <url> [notes] > feed.json
```

Identities are written as `-` (ad hoc), a keychain identity name or SHA-1, `p12:FILE` or `pem:CERT,KEY`.

---

## Library layout

```text
packager
├── app        // App, Arch, Version, FileType: the platform-neutral description
├── build      // build(&app) → Builder: validation, signing order, outputs
├── config     // packager.toml / [package.metadata.packager] → Config, Config::run
├── identity   // derived MSI codes; package names and versions per format
├── package    // AppBundle, Dmg, Pkg, Msi, Msix, MsixBundle, Deb, Snap
├── sign       // Signer, KeySigner, Apple, Authenticode, requirements, installer and disk-image signatures
├── notary     // Notary API client and preflight
├── staple     // ticket lookup, stapling and validation
├── feed       // signed update feeds: P-256 keys, signing and verification
├── image      // RGBA images, Lanczos resizing, .icns and .ico from one PNG
├── format     // plist, PNG, ICNS, ICO, Mach-O, PE, ELF, cpio, XAR, Bom, HFS+, UDIF, .DS_Store,
│              // ZIP, CAB, Compound File, MSI database, APPX, tar, ar, SquashFS, XML, JSON, TOML
├── compress   // DEFLATE, zlib, gzip, LZMA2, xz
├── crypto     // SHA-1/2, MD5, HMAC, RSA, ECDSA, DER, X.509, PKCS#8/#12, AES, 3DES, RC2, SigV4
└── transport  // Transport trait for HTTPS (the default uses the system curl)
```

Every layer is public and works on its own (write a CAB, sign a PE, read a Mach-O), and the high-level builders use only those public pieces. HTTPS is the one thing not built from scratch; it's only needed for notarization, and goes through the `Transport` trait.

---

## Status

| Platform | Ready | Not done yet |
| :--- | :--- | :--- |
| **macOS** | `.app`, `.dmg`, `.pkg`; ad-hoc and certificate signing; notarization client, stapling, Gatekeeper assessment | An end-to-end notarization run (needs a Developer ID and an API key); Mac App Store packages; detached signatures; disk images over 4 GB |
| **Windows** | `.msi` (ICE-clean), `.msix`, `.msixbundle`, exe resources, Authenticode | Clicking through the MSI wizard on a desktop session; compressed MSIX payloads; files over 2 GB in an MSI |
| **Linux** | `.deb` (lintian-clean), `.snap` (local installs) | Snap Store uploads: the Store wants byte-identical repacks with its own `mksquashfs` and liblzma. GTK/WebKit apps in strict snaps (snapcraft's `gnome` extension). `Depends` beyond glibc |

---

## Run and test

```sh
cargo test                                    # unit tests, plus oracle tests for this OS
cargo test -- --ignored keychain              # sign with your Keychain identity (macOS)
cargo test -- --ignored network               # staple a notarized package from Apple (macOS)
cargo test -- --ignored msi_installs          # msiexec install / upgrade / uninstall (Windows, elevated)
cargo test --test oracle_linux -- --ignored   # apt and snap installs (Linux, passwordless sudo)
```

The oracle tests build packages through the public API and check them with each platform's own tools, which are never runtime dependencies:
- `oracle_macos.rs`, `oracle_codesign.rs` and `oracle_notary.rs`: `codesign`, `hdiutil`, `pkgutil`, `installer`, `stapler`, `spctl`.
- `oracle_crypto.rs`: `openssl` and `csreq`.
- `oracle_windows.rs`: `Get-AuthenticodeSignature`, `makeappx` and Windows Installer.
- `oracle_linux.rs`: `xz`, `unsquashfs`, `dpkg-deb`, `lintian`, `review-tools`, `apt` and `snap`.

Tools that aren't installed skip their checks. [`scripts/manual-check-macos.sh`](scripts/manual-check-macos.sh) covers what can't be automated on macOS (Finder's rendering of the `.dmg`, and a real `sudo installer` run). [`scripts/vm-sync.sh`](scripts/vm-sync.sh) copies the tree to a Linux VM for the install tests.

### Environment variables

- `SOURCE_DATE_EPOCH`: timestamp for every package (default 1980-01-01).
- `PACKAGER_P12_PASSWORD`: password for `p12:` identities.
- `PACKAGER_NOTARY_KEY`, `PACKAGER_NOTARY_KEY_ID`, `PACKAGER_NOTARY_ISSUER`: the App Store Connect API key for notarization, so it stays out of `packager.toml`.
- `PACKAGER_MSIX_CERT`, `PACKAGER_MSIX_KEY`: a sideload-trusted certificate for the MSIX install test.

---

## Repository layout

```text
packager/
├── Cargo.toml                 # workspace (edition 2024, zero external crates)
├── packager.example.toml      # every packager.toml key
├── crates/
│   ├── packager/              # the library
│   │   ├── src/
│   │   ├── examples/          # signing, HFS+ and macOS smoke-test programs
│   │   └── tests/             # oracle tests per platform
│   └── packager-cli/          # the `packager` command: arguments and packager.toml → library calls
└── scripts/                   # manual macOS checks, Linux VM sync
```

---

## License

Licensed under the [MIT License](LICENSE). © 2026 Netangular Technologies, Inc.
