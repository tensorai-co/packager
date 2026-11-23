//! `cargo run --example sign_macho -- <in> <out> <identifier> [entitlements.plist] [--runtime]`
fn main() -> packager::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = packager::sign::apple::CodeSignOptions::ad_hoc(&a[2]);
    for x in &a[3..] {
        if x == "--runtime" { opts.hardened_runtime = true } else { opts.entitlements = Some(std::fs::read(x)?) }
    }
    let signed = packager::sign::apple::sign_macho(&std::fs::read(&a[0])?, &opts)?;
    std::fs::write(&a[1], &signed.data)?;
    packager::util::set_mode(std::path::Path::new(&a[1]), 0o755)?;
    println!("{}", signed.cdhash_requirement());
    Ok(())
}
