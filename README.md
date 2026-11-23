# packager

Native OS packages from scratch, in pure Rust, with zero dependencies (`std` only).
The library comes first; the `packager` CLI only parses arguments and `packager.toml` and calls
the library's public API.

**Status: macOS, phase 1.** `.app`, `.dmg` and `.pkg` are built and signed ad hoc without
`codesign`, `hdiutil`, `pkgbuild`, `productbuild`, `iconutil` or `sips`. Windows and
Debian/Ubuntu come later (see `proposed_packager_rs.md`).

| Package | What's written | Checked against (CI oracles, never runtime deps) |
| --- | --- | --- |
| `.app` | `Info.plist`, universal binary (merged from per-arch inputs), `.icns` from one PNG, resources, frameworks, ad-hoc signature on every Mach-O + sealed `CodeResources` | `codesign --verify --deep --strict`, `plutil -lint`, `lipo`, running it |
| `.dmg` | HFSX volume (catalog B-tree, bitmap, NFD names), `Applications` link, volume icon, optional background + Finder layout (`.DS_Store` + alias), UDZO (zlib) UDIF | `hdiutil verify`, `fsck_hfs`, mounting, `codesign` on the mounted app |
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
`sign::apple::sign_macho`, `sign::bundle::{sign_bundle, verify_bundle}`.

## CLI

```sh
packager build                       # every package in packager.toml
packager build --only dmg,pkg --out dist
packager sign path/to/My.app --hardened-runtime --entitlements app.entitlements
packager verify "dist/My App-1.4.0.dmg"   # signatures and structure, without native tools
packager inspect "dist/My App.app"
packager icns icon.png AppIcon.icns
```

See [`packager.example.toml`](packager.example.toml) for every key.

## Not done yet (macOS)

- **Certificate-backed signing** (Developer ID / Mac App Store): needs DER/X.509, RSA/ECDSA,
  CMS, PKCS#12 and the `Signer` implementations. Until then `.app` code is signed ad hoc, which
  runs locally and on Apple silicon but not through Gatekeeper on other Macs.
- **Installer signatures** for `.pkg` and **code signatures** on `.dmg` (need the above).
- **Notarization and stapling** (Notary REST API, JWT ES256, S3 SigV4 upload through `curl`).

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
packages through the public API, and checks them with Apple's tools.
