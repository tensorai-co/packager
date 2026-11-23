# packager

Native OS packages from scratch, in pure Rust, with zero dependencies (`std` only).
The library comes first; the `packager` CLI only parses arguments and `packager.toml` and calls
the library's public API.

**Status: macOS.** `.app`, `.dmg` and `.pkg` are built, and code and disk images are signed —
ad hoc or with a real certificate — without `codesign`, `hdiutil`, `pkgbuild`, `productbuild`,
`iconutil` or `sips`. Windows and Debian/Ubuntu come later (see `proposed_packager_rs.md`).

| Package | What's written | Checked against (CI oracles, never runtime deps) |
| --- | --- | --- |
| `.app` | `Info.plist`, universal binary (merged from per-arch inputs), `.icns` from one PNG, resources, frameworks, ad-hoc signature on every Mach-O + sealed `CodeResources` | `codesign --verify --deep --strict`, `plutil -lint`, `lipo`, running it |
| `.dmg` | HFSX volume (catalog B-tree, bitmap, NFD names), `Applications` link, volume icon, optional background + Finder layout (`.DS_Store` + alias), UDZO (zlib) UDIF; code signature on the image when signing with a certificate | `hdiutil verify`, `fsck_hfs`, mounting, `codesign --verify` on the image and the app inside |
| `.pkg` | Flat product archive: XAR with `Distribution`, `PackageInfo` (not relocatable), `Bom`, gzip'd cpio payload, optional scripts | `installer -pkginfo`, `pkgutil --expand-full`, `lsbom`, payload diff |

Output is deterministic: same input, byte-identical packages (`SOURCE_DATE_EPOCH`, default
1980-01-01).

## Library

```rust
use packager::package::{AppBundle, Dmg, Pkg};
use packager::sign::Apple;
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
    .out_dir("target/dist")
    .run()?;
for p in out.packages() {
    println!("{} {} {} {}", p.kind(), p.arch(), p.path().display(), p.sha256_hex());
}
```

Each layer works on its own: `format::{plist, png, icns, macho, cpio, xar, bom, hfsplus, udif,
ds_store}`, `compress::{deflate, zlib, gzip}`, `crypto::{sha1, sha256, crc}`,
`crypto::{rsa, ec, x509, pkcs12, der, …}`, `sign::apple::{sign_macho, verify_macho}`,
`sign::bundle::{sign_bundle, verify_bundle}`, `sign::disk_image`, `sign::requirement`.

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

## CLI

```sh
packager build                       # every package in packager.toml
packager build --only dmg,pkg --out dist
packager sign path/to/My.app --hardened-runtime --entitlements app.entitlements   # ad hoc
packager sign My.app -s "Developer ID Application" --timestamp
packager verify "dist/My App-1.4.0.dmg"   # signatures and structure, without native tools
packager inspect "dist/My App.app"
packager icns icon.png AppIcon.icns
```

See [`packager.example.toml`](packager.example.toml) for every key.

## Not done yet (macOS)

- **Installer signatures** for `.pkg` (`productsign`: a signature in the XAR table of contents).
- **Notarization and stapling** (Notary REST API, JWT ES256, S3 SigV4 upload through `curl`).
- **Codesign extras** not covered: detached signatures, `--preserve-metadata`, launch
  constraints, and disk images over 4 GB. Requirement `notarized`/`platform` clauses evaluate
  false offline.

## Manual checks

`scripts/manual-check-macos.sh` covers what automated tests can't: it opens the `.dmg` in Finder
(reports the window layout and takes a screenshot) and does a real `sudo installer -pkg` install,
upgrade and cleanup. Both have been run and passed: Finder shows the background, icon size and
positions as written, and the installed app verifies and runs.

## Tests

```sh
cargo test                 # unit tests (vectors, round trips) + macOS oracle tests
```

`crates/packager/tests/oracle_macos.rs` compiles a universal binary with `cc`, builds all three
packages through the public API, and checks them with Apple's tools. `oracle_codesign.rs` checks
certificate signatures, legacy dual CodeDirectories, disk-image signatures and the CLI's codesign
command lines with `codesign`; `oracle_crypto.rs` checks keys, certificates, PKCS#12 and
requirements against `openssl` and `csreq`. One test signs with your real Keychain identity and
is opt-in: `cargo test -- --ignored keychain`.
