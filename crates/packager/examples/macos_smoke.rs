//! `cargo run --example macos_smoke -- <binary> <icon.png> <out_dir> [background.png]`
use packager::package::{AppBundle, Dmg, Pkg};
use packager::{App, Arch};

fn main() -> packager::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let app = App::new("Smoke Test", "com.example.smoke", "1.4.0").publisher("Example Ltd").binary(Arch::MacosUniversal, &a[0]).icon(&a[1]).url_scheme("smoke").file_type("md", "Markdown document");
    let mut dmg = Dmg::new();
    if let Some(bg) = a.get(3) {
        dmg = dmg.window_background(bg);
    }
    let out = packager::build(&app).app_bundle(AppBundle::new().category("public.app-category.developer-tools")).package(AppBundle::new()).package(dmg).package(Pkg::new()).out_dir(&a[2]).run()?;
    for p in out.packages() {
        println!("{} {} {} {} {}", p.kind(), p.arch(), p.path().display(), p.size(), p.sha256_hex());
    }
    Ok(())
}
