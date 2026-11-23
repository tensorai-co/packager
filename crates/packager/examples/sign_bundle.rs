//! `cargo run --example sign_bundle -- <bundle> [entitlements.plist] [--runtime]`
fn main() -> packager::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = packager::sign::bundle::BundleSignOptions::ad_hoc();
    for x in &a[1..] {
        if x == "--runtime" { opts.hardened_runtime = true } else { opts.entitlements = Some(std::fs::read(x)?) }
    }
    let s = packager::sign::bundle::sign_bundle(std::path::Path::new(&a[0]), &opts)?;
    println!("{}", s.cdhash_requirement());
    Ok(())
}
