# packager

Native OS packages from scratch, in pure Rust, with zero dependencies (`std` only).
The library comes first; the `packager` CLI only parses arguments and `packager.toml` and calls
the library's public API.

**Status: macOS.** `.app`, `.dmg` and `.pkg` are built, signed (ad hoc or with a real
certificate, installer signatures included), notarized and stapled without `codesign`,
`hdiutil`, `pkgbuild`, `productbuild`, `productsign`, `notarytool`, `stapler`, `spctl`, `iconutil`
or `sips`.

**Windows.** `.msi`, `.msix` and `.msixbundle` packages are built and signed, and `.exe` files get
their icon, version information and manifest (what `rcedit` does) and an Authenticode signature,
without WiX, `makeappx`, `signtool` or `rcedit`.

**Linux.** `.deb` (Debian/Ubuntu) and `.snap` packages are built without `dpkg-deb`, `snapcraft`
or `mksquashfs`, from any host: the tar, `ar`, xz (LZMA2) and SquashFS writers are in the repo.

| Package | What's written | Checked against (CI oracles, never runtime deps) |
| --- | --- | --- |
| `.app` | `Info.plist`, universal binary (merged from per-arch inputs), `.icns` from one PNG, resources, frameworks, ad-hoc signature on every Mach-O + sealed `CodeResources` | `codesign --verify --deep --strict`, `plutil -lint`, `lipo`, running it |
| `.dmg` | HFSX volume (catalog B-tree, bitmap, NFD names), `Applications` link, volume icon, optional background + Finder layout (`.DS_Store` + alias), UDZO (zlib) UDIF; code signature on the image when signing with a certificate | `hdiutil verify`, `fsck_hfs`, mounting, `codesign --verify` on the image and the app inside |
| `.pkg` | Flat product archive: XAR with `Distribution`, `PackageInfo` (not relocatable), `Bom`, gzip'd cpio payload, optional scripts; installer signature (RSA + CMS in the TOC) with an installer identity | `installer -pkginfo`, `pkgutil --expand-full`, `pkgutil --check-signature`, `lsbom`, payload diff |

| `.exe` / `.dll` | Icon group (`.ico` from one PNG), `VS_VERSIONINFO`, manifest, in a rebuilt `.rsrc`; Authenticode (SHA-256, RFC 3161 timestamp), PE checksum | `Get-AuthenticodeSignature`, `signtool verify`, `signtool`-signed files read back, running it |
| `.msi` | Compound File (mini stream, DIFAT, red-black directory), string pool and column-major tables, `\x05SummaryInformation`, MSZIP cabinet in a stream; one component per file, Start menu shortcut (own HKCU-keyed component), URL schemes and file types, ARP icon, major upgrade with downgrade block; per-machine or per-user; optional install wizard; `_Validation` table; cabinets split at 1 GiB; Authenticode in `\x05DigitalSignature` with `\x05MsiDigitalSignatureEx` | ICE validation (`darice.cub` via WiX `smoke`: 0 errors, 0 warnings), Windows Installer's COM API, `Get-AuthenticodeSignature`, `signtool`-signed MSIs read back, `msiexec` install / upgrade / downgrade / uninstall |
| `.msixbundle` | Signed per-architecture `.msix` packages stored as is, `AppxBundleManifest.xml` (offsets, device family), block map, bundle signature | `Get-AuthenticodeSignature`, `makeappx unbundle`, `Add-AppxPackage` |
| `.deb` | `ar` of `debian-binary`, `control.tar` (`control` with `Depends: libc6 (>= …)` read from the binary's symbol versions, `Installed-Size`, `md5sums`, optional maintainer scripts) and `data.tar` (gzip or xz): the app in `/opt/<name>`, `/usr/bin` link, `.desktop` entry named after the identifier, hicolor icons, shared-mime-info types, `copyright`, `changelog`, optional man page | `dpkg-deb --info`/`-x`/`-e`, `md5sum -c`, `lintian` (no errors or warnings), `desktop-file-validate`, `apt install` / upgrade / downgrade refusal / `apt remove`, the MIME and URL-scheme caches |
| `.snap` | SquashFS 4.0 (xz, no fragments, root-owned, 4 KiB padded) with `meta/snap.yaml` (base, confinement, plugs, grade), `meta/gui/<app>.desktop` and `icon.png`, the app at `$SNAP` | `unsquashfs -s`/`-lls`/extraction, `review-tools` (the Snap Store's review: no errors or warnings besides the repack check below), kernel mount via `snap install --dangerous`, running it, desktop export, interface connections, refresh, `snap remove` |
| `.msix` | Signed exe, app files, logos from the icon, `AppxManifest.xml` (full trust, URL schemes, file types; `Publisher` from the certificate), `AppxBlockMap.xml`, `[Content_Types].xml`, `AppxSignature.p7x`, ZIP64 end records like `makeappx` | `Get-AuthenticodeSignature`, `makeappx unpack`, `makeappx`+`signtool` packages read back |

Output is deterministic: same input, byte-identical packages (`SOURCE_DATE_EPOCH`, default
1980-01-01).

## Library

```rust
use packager::package::{AppBundle, Dmg, Pkg};
use packager::sign::Apple;
// use packager::notary::{ApiKey, Notarize};
use packager::{App, Arch};

let app = App::new("My App", "com.example.myapp", "1.4.0")
    .publisher("Example Ltd")
    .binary(Arch::MacosArm64, "target/aarch64-apple-darwin/release/my-app")
    .binary(Arch::MacosX64, "target/x86_64-apple-darwin/release/my-app")
    .icon("assets/icon.png")
    .resources("dist/", "web")
    .url_scheme("myapp")
    .file_type("md", "Markdown document");

let out = packager::build(&app)
    .app_bundle(AppBundle::new().category("public.app-category.productivity"))
    .package(Dmg::new().window_background("assets/dmg.png"))
    .package(Pkg::new())
    .sign(Apple::ad_hoc().hardened_runtime())
    // Shipping to other Macs: Developer ID identities and an App Store Connect API key.
    // .sign(Apple::developer_id(app_id).installer(installer_id).hardened_runtime())
    // .notarize(Notarize::new(ApiKey::from_file("AuthKey_ABCDE12345.p8", None, Some(issuer))?))
    .out_dir("target/dist")
    .run()?;
for p in out.packages() {
    println!("{} {} {} {}", p.kind(), p.arch(), p.path().display(), p.sha256_hex());
}
```

Each layer works on its own: `format::{plist, png, icns, macho, cpio, xar, bom, hfsplus, udif,
ds_store, zip, json, tar, ar, elf, squashfs}`, `compress::{deflate, zlib, gzip, lzma, xz}`,
`crypto::{sha1, sha256, md5, crc}`,
`crypto::{rsa, ec, x509, pkcs12, der, sigv4, …}`, `sign::apple::{sign_macho, verify_macho}`,
`sign::bundle::{sign_bundle, verify_bundle}`, `sign::disk_image`, `sign::installer`,
`sign::requirement`, `sign::assess`, `notary`, `staple`.

## Code signing: a `codesign` replacement

Everything `codesign` does for Mach-O files, bundles and disk images is implemented in Rust:

- **CodeDirectories** (v0x20200–0x20500): page hashes, special slots, team ID, exec segment,
  hardened runtime; SHA-1 + SHA-256 for deployment targets before macOS 10.11.4, like codesign.
- **CMS signatures** with Apple's attributes (cdhashes plist and hash-agility v2), the full
  certificate chain, and RFC 3161 timestamps from `timestamp.apple.com`.
- **Requirements**: the full requirement language, compiled byte-for-byte like `csreq`, the
  designated requirement codesign derives (Developer ID, Apple Development/Distribution,
  third-party CAs), and evaluation for `-v` / `-R`.
- **Bundles** signed inside out with `CodeResources`; **disk images** with the UDIF trailer
  binding.
- **Identities**: the macOS Keychain (Security.framework, the key never leaves it), PKCS#12
  (`.p12`, including Keychain's legacy 3DES/RC2 exports), PEM (PKCS#1/#8/SEC1, encrypted PKCS#8),
  or a generated self-signed certificate. Missing intermediates are fetched from the
  certificate's issuer URL. All the crypto (RSA, ECDSA P-256/P-384, X.509, CMS, AES, 3DES, RC2,
  SHA-2, HMAC, PBKDF2) is from scratch.

Checked against Apple's tools with a real Apple Development identity: `codesign --verify
--strict` (with full chain to Apple Root CA) passes, `codesign -dvvv -r-` shows the same
CodeDirectory, authorities, timestamp, team ID and designated requirement, the requirements blob
is byte-identical, and a signed disk image's CodeDirectory hash is identical to codesign's.

```sh
packager codesign -fs "Developer ID Application" -o runtime --timestamp My.app
packager codesign -s p12:dev.p12 -i com.example.tool --entitlements e.plist tool
packager codesign -s "Developer ID Application" "My App.dmg"
packager codesign -vvv --strict My.app
packager codesign -v -R='anchor apple generic and certificate leaf[subject.OU] = ABCDE12345' My.app
packager codesign -d -r- --entitlements - My.app
packager identities                  # like `security find-identity -v -p codesigning`
```

## Windows

```rust
use packager::package::{Msi, Msix, MsixBundle};
use packager::sign::{Authenticode, KeySigner};

let signer = KeySigner::pkcs12("codesign.pfx", "password")?.into_arc();
packager::build(&app)
    .package(Msix::new().execution_alias("my-app"))  // one .msix per Windows binary; `my-app` on PATH
    .package(Msi::new().wizard())                    // one .msi per Windows binary; codes derived
    .package(MsixBundle::all())                      // every architecture in one download
    .sign(Authenticode::new(signer).timestamp("http://timestamp.digicert.com"))
    .run()?;
```

```sh
packager rcedit my-app.exe --icon icon.png --version 1.4.0 --set CompanyName="Example Ltd"
packager sign my-app.exe -s p12:codesign.pfx --timestamp http://timestamp.digicert.com
packager verify "dist/My App-1.4.0-x64.msix"   # block map, digests, signature
```

MSI codes are derived, never hand-managed: the UpgradeCode from the identifier (stable forever),
the ProductCode from identifier, version and architecture (new every release, so each one is a
clean major upgrade), the PackageCode from the contents, and component GUIDs from each file's
install path. Versions are checked up front (at most 255.255.65535; pre-releases rejected). Checked
on Windows Server 2025: Windows Installer reads the tables and summary through its own API, the
signature is valid, and `msiexec` installs (files, shortcut, URL scheme, file type, ARP entry and
icon), upgrades in place, refuses a downgrade with "A newer version … is already installed",
installs per-user into `%LocalAppData%\Programs` without elevation, and uninstalls cleanly.
Every package carries a `_Validation` table and passes Microsoft's ICE suite with no errors or
warnings (per-machine, per-user and with the wizard). `ui = "wizard"` adds a minimal wizard
(Welcome with the install folder, progress, finished, and the error, files-in-use and cancel
dialogs Windows Installer requires); without it double-clicking shows the basic progress UI.
Signatures include `MsiDigitalSignatureEx` (the metadata hash) like `signtool`'s, and `signtool`'s
are verified. Packages over 1 GiB are split across several embedded cabinets; files over 2 GB
can't be packaged, as `File.FileSize` is 32-bit. The wizard's screens are checked by ICE but
haven't been clicked through on a desktop session yet.

What it takes to match Windows: the MSIX signature's `AXCD` digest always covers ZIP64 end
records, and Windows' package reader wants `makeappx`'s entry layout (MS-DOS "made by", ZIP64
data descriptors), so packages are written exactly that way. Payload files are stored
uncompressed for now (like `makeappx pack /nc`). Checked on Windows Server 2025: Windows
reports our signatures as valid but for the (self-signed) root, and a changed byte as a hash
mismatch; `signtool` computes the same file hash for our signatures as for its own, and our
verifier accepts `signtool`- and `makeappx`-made files. With the certificate trusted for
sideloading, `Add-AppxPackage` installs the package (no `resources.pri` needed), the Start menu
entry, URL scheme, file type and execution alias are registered, the app runs through its alias,
a higher version upgrades it, a lower one is refused, and `Remove-AppxPackage` removes it all.

## Linux

```rust
use packager::package::{Deb, Snap};

let app = app
    .binary(Arch::LinuxX64, "target/x86_64-unknown-linux-gnu/release/my-app")
    .binary(Arch::LinuxArm64, "target/aarch64-unknown-linux-gnu/release/my-app");
packager::build(&app)
    .package(Deb::new()                                  // one .deb per Linux binary
        .maintainer("Example Ltd <packages@example.com>")
        .depends(["libwebkit2gtk-4.1-0"]))               // libc6 (>= …) is added for you
    .package(Snap::new().license("MIT"))                 // one .snap per Linux binary
    .run()?;
```

```sh
packager build --only deb,snap
packager verify dist/myapp_1.4.0_amd64.deb    # members, control fields, md5sums
packager verify dist/myapp_1.4.0_amd64.snap   # every SquashFS block, snap.yaml
packager inspect dist/myapp_1.4.0_amd64.snap  # tree with modes and owners, then snap.yaml
packager inspect my-app                       # ELF: architecture, interpreter, libraries, glibc
```

Names and versions are derived: the package and snap name is the identifier's last part
(`com.example.myapp` → `myapp`), a pre-release sorts before its release on Debian (`1.4.0-beta.1`
→ `1.4.0~beta.1`) and makes the snap's grade `devel`, and build metadata is dropped. File types
with a well-known extension join the system's MIME type (`md` → `text/markdown`); others get
`application/x-<name>-<ext>`, defined in a shared-mime-info file; URL schemes become
`x-scheme-handler/<scheme>`. `dpkg`'s triggers update the menu, icon and MIME caches, so no
maintainer scripts are needed. Neither format is signed as a file: Debian signs repositories, and
the Snap Store signs what's uploaded (`snap install --dangerous` installs a local file).

Checked on Ubuntu 24.04: lintian reports no errors or warnings (in `/usr/lib/<name>` with no
suppressions; in `/opt/<name>`, the default, its distro-only `dir-or-file-in-opt` rule is
suppressed); `apt` installs, the command runs, the URL scheme and custom MIME type are registered,
a newer version upgrades it, an older one is refused without `--allow-downgrades`, and `apt
remove` leaves nothing behind. `snap install --dangerous` mounts the image, the app runs
confined, snapd exports the menu entry and connects the desktop plugs, a newer snap refreshes it,
and `snap remove` cleans up. Our xz streams decode with `xz`, our SquashFS images with
`unsquashfs` and the kernel, and our readers read theirs.

**Not done yet (Linux):**
- **Snap Store uploads.** The Store repacks every snap with its own `mksquashfs` and liblzma and
  wants byte-identical output (`squashfs_repack_checksum`). Our xz encoder is valid but doesn't
  reproduce liblzma's bytes, so uploads fail that one check; `review-tools` passes everything
  else. Matching needs liblzma's exact encoder (preset 6, BT4 match finder, optimal parsing) and
  `mksquashfs`'s exact layout.
- **GTK/WebKit apps in strict snaps.** `core24` has no GTK or WebKit; snapcraft's `gnome`
  extension adds them through a content snap and a launcher. Until that's built, such apps need
  `confinement = "classic"` (host libraries; needs Store approval) or their libraries bundled as
  resources.
- **`Depends` beyond glibc.** Other libraries are declared by hand (`depends`); mapping sonames to
  packages like `dpkg-shlibdeps` needs a package database.
- **RPM** and other distro families are out of scope (see the proposal's non-goals).

## Notarization, stapling and Gatekeeper

What `notarytool`, `stapler`, `productsign` and `spctl -a` do, in Rust:

- **Notary client**: App Store Connect API key (`.p8`, team or individual), ES256 JWT, the Notary
  REST API (submit, status, developer log), and the upload to Apple's S3 bucket with the
  temporary credentials it returns (AWS SigV4, single `PUT`). App bundles are zipped first like
  `ditto -c -k --keepParent` (symlinks and modes kept). HTTPS goes through the `Transport`
  trait; the default runs the system `curl`.
- **Preflight**: before uploading, the rules Apple enforces are checked locally (Developer ID
  chain to Apple Root CA, secure timestamp, hardened runtime, no `get-task-allow`), so a bad
  build fails in seconds with the reason, not after a round trip to Apple.
- **Stapling**: tickets are looked up in Apple's ticket service by record name
  (`2/<hash type>/<cdhash or TOC checksum>`) and attached where each format keeps them:
  `Contents/CodeResources` for bundles, SuperBlob slot `0x10002` for disk images, `t8lr`
  records after the archive for flat packages. `staple --validate` checks offline that the
  stapled ticket names this code.
- **Installer signatures**: `productsign`'s layout: SHA-1 TOC checksum, an RSA signature over it
  and a timestamped CMS signature, each with the certificate chain in the TOC's `KeyInfo`.
- **Assessment**: `packager assess` reports each Gatekeeper rule separately, offline or with an
  online ticket check.
- **Builder**: `.notarize(…)` runs after signing, containers first (a `.dmg`'s ticket also covers
  the `.app` inside, so the app is stapled without a second submission).

Checked against Apple's tools: a notarized third-party `.pkg` and a copy of a notarized app,
stapled by `packager`, pass `xcrun stapler validate` and `spctl -a` (`source=Notarized Developer
ID`); stapled disk images pass `codesign --verify --strict` and `codesign -dvv` reports
`Notarization Ticket=stapled`; `pkgutil --check-signature` reads our installer signatures; our
verifier accepts Apple-written installer signatures (BER CMS, SHA-1). A full notarization
round trip needs a Developer ID certificate and an API key, so it hasn't been run yet.

```sh
packager notarize "dist/My App-1.4.0.dmg" --key AuthKey_ABCDE12345.p8 --issuer <issuer-uuid>
packager notarize "dist/My App.app" --key AuthKey_ABCDE12345.p8   # zipped for you, then stapled
packager notarize --status <submission-id> --key …               # or --log <submission-id>
packager staple "dist/My App-1.4.0.pkg"
packager staple --validate "dist/My App-1.4.0.dmg"
packager productsign --sign "Developer ID Installer" in.pkg out.pkg
packager assess "dist/My App-1.4.0.dmg"                           # spctl -a, rule by rule
```

## CLI

```sh
packager build                       # every package in packager.toml
packager build --only dmg,pkg --out dist
packager sign path/to/My.app --hardened-runtime --entitlements app.entitlements   # ad hoc
packager sign My.app -s "Developer ID Application" --timestamp
packager sign "dist/My App-1.4.0.pkg" -s "Developer ID Installer"   # installer signature
packager verify "dist/My App-1.4.0.dmg"   # signatures and structure, without native tools
packager inspect "dist/My App.app"
packager icns icon.png AppIcon.icns
```

See [`packager.example.toml`](packager.example.toml) for every key.

## Not done yet (macOS)

- **An end-to-end notarization run.** Every piece is tested against Apple's formats and tools,
  but submitting needs a Developer ID certificate and an App Store Connect API key.
- **Mac App Store packages**: embedded provisioning profiles, Apple Distribution signing,
  sandbox entitlement defaults.
- **Ticket signatures**: stapled tickets are matched to the code, but Apple's signature over the
  ticket itself isn't checked.
- **Codesign extras** not covered: detached signatures, `--preserve-metadata`, launch
  constraints, and disk images over 4 GB. Requirement `notarized`/`platform` clauses evaluate
  false offline. ZIP64 (submissions over 4 GB) and S3 multipart uploads (over 5 GB).

## Manual checks

`scripts/manual-check-macos.sh` covers what automated tests can't: it opens the `.dmg` in Finder
(reports the window layout and takes a screenshot) and does a real `sudo installer -pkg` install,
upgrade and cleanup. Both have been run and passed: Finder shows the background, icon size and
positions as written, and the installed app verifies and runs.

## Tests

```sh
cargo test                 # unit tests (vectors, round trips) + oracle tests for this OS
```

`crates/packager/tests/oracle_macos.rs` compiles a universal binary with `cc`, builds all three
packages through the public API, and checks them with Apple's tools. `oracle_codesign.rs` checks
certificate signatures, legacy dual CodeDirectories, disk-image signatures and the CLI's codesign
command lines with `codesign`; `oracle_crypto.rs` checks keys, certificates, PKCS#12 and
requirements against `openssl` and `csreq`; `oracle_notary.rs` checks stapled disk images,
installer signatures and submission ZIPs with `codesign`, `hdiutil`, `pkgutil`, `installer` and
`ditto`. `oracle_windows.rs` (on Windows) checks Authenticode and MSIX with
`Get-AuthenticodeSignature`, `makeappx` and Windows Installer's COM API; opt-in tests run
`msiexec` (`cargo test -- --ignored msi_installs`, elevated) and (`cargo test -- --ignored
msix_installs`, with `PACKAGER_MSIX_CERT`/`PACKAGER_MSIX_KEY` naming a sideload-trusted
certificate) installs, runs, upgrades and removes a package. `oracle_linux.rs` checks xz against
`xz` (any host), and on Linux SquashFS against `unsquashfs`/`mksquashfs`, `.deb` files with
`dpkg-deb`, `lintian` and `desktop-file-validate`, and snaps with `review-tools`; opt-in tests
(`cargo test --test oracle_linux -- --ignored`, passwordless `sudo`) install, run, upgrade and
remove both with `apt` and `snap`. `scripts/vm-sync.sh` copies the tree to a Linux VM for them.
The notary tests' network test
(`cargo test -- --ignored network`) staples a notarized package on
this Mac and checks it with `stapler` and `spctl`. One test signs with your real Keychain identity and
is opt-in: `cargo test -- --ignored keychain`.
