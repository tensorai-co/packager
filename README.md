# packager

Native OS packages from scratch, in pure Rust, with zero dependencies (`std` only).
The library comes first; the `packager` CLI only parses arguments and `packager.toml` and calls
the library's public API.

**Status: macOS.** `.app`, `.dmg` and `.pkg` are built, signed (ad hoc or with a real
certificate, installer signatures included), notarized and stapled without `codesign`,
`hdiutil`, `pkgbuild`, `productbuild`, `productsign`, `notarytool`, `stapler`, `spctl`, `iconutil`
or `sips`.

**Windows (in progress).** `.msix` packages are built and signed, and `.exe` files get their icon,
version information and manifest (what `rcedit` does) and an Authenticode signature, without
`makeappx`, `signtool` or `rcedit`. `.msixbundle` and `.msi` come next; Debian/Ubuntu after that
(see `proposed_packager_rs.md`).

| Package | What's written | Checked against (CI oracles, never runtime deps) |
| --- | --- | --- |
| `.app` | `Info.plist`, universal binary (merged from per-arch inputs), `.icns` from one PNG, resources, frameworks, ad-hoc signature on every Mach-O + sealed `CodeResources` | `codesign --verify --deep --strict`, `plutil -lint`, `lipo`, running it |
| `.dmg` | HFSX volume (catalog B-tree, bitmap, NFD names), `Applications` link, volume icon, optional background + Finder layout (`.DS_Store` + alias), UDZO (zlib) UDIF; code signature on the image when signing with a certificate | `hdiutil verify`, `fsck_hfs`, mounting, `codesign --verify` on the image and the app inside |
| `.pkg` | Flat product archive: XAR with `Distribution`, `PackageInfo` (not relocatable), `Bom`, gzip'd cpio payload, optional scripts; installer signature (RSA + CMS in the TOC) with an installer identity | `installer -pkginfo`, `pkgutil --expand-full`, `pkgutil --check-signature`, `lsbom`, payload diff |

| `.exe` / `.dll` | Icon group (`.ico` from one PNG), `VS_VERSIONINFO`, manifest, in a rebuilt `.rsrc`; Authenticode (SHA-256, RFC 3161 timestamp), PE checksum | `Get-AuthenticodeSignature`, `signtool verify`, `signtool`-signed files read back, running it |
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
ds_store, zip, json}`, `compress::{deflate, zlib, gzip}`, `crypto::{sha1, sha256, crc}`,
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
use packager::package::Msix;
use packager::sign::{Authenticode, KeySigner};

let signer = KeySigner::pkcs12("codesign.pfx", "password")?.into_arc();
packager::build(&app)
    .package(Msix::new().execution_alias("my-app"))  // one .msix per Windows binary; `my-app` on PATH
    .sign(Authenticode::new(signer).timestamp("http://timestamp.digicert.com"))
    .run()?;
```

```sh
packager rcedit my-app.exe --icon icon.png --version 1.4.0 --set CompanyName="Example Ltd"
packager sign my-app.exe -s p12:codesign.pfx --timestamp http://timestamp.digicert.com
packager verify "dist/My App-1.4.0-x64.msix"   # block map, digests, signature
```

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
cargo test                 # unit tests (vectors, round trips) + macOS oracle tests
```

`crates/packager/tests/oracle_macos.rs` compiles a universal binary with `cc`, builds all three
packages through the public API, and checks them with Apple's tools. `oracle_codesign.rs` checks
certificate signatures, legacy dual CodeDirectories, disk-image signatures and the CLI's codesign
command lines with `codesign`; `oracle_crypto.rs` checks keys, certificates, PKCS#12 and
requirements against `openssl` and `csreq`; `oracle_notary.rs` checks stapled disk images,
installer signatures and submission ZIPs with `codesign`, `hdiutil`, `pkgutil`, `installer` and
`ditto`. `oracle_windows.rs` (on Windows) checks Authenticode and MSIX with
`Get-AuthenticodeSignature` and `makeappx`; its opt-in install test (`cargo test -- --ignored
msix_installs`, with `PACKAGER_MSIX_CERT`/`PACKAGER_MSIX_KEY` naming a sideload-trusted
certificate) installs, runs, upgrades and removes a package. The notary tests' network test
(`cargo test -- --ignored network`) staples a notarized package on
this Mac and checks it with `stapler` and `spctl`. One test signs with your real Keychain identity and
is opt-in: `cargo test -- --ignored keychain`.
