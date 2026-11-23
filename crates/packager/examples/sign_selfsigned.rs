//! `cargo run --example sign_selfsigned -- <in> <out> [--no-runtime]`: signs with a throwaway
//! self-signed certificate.
use packager::sign::apple::{sign_macho, CodeSignOptions};
use packager::sign::{AppleIdentity, KeySigner};

fn main() -> packager::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut o = CodeSignOptions::ad_hoc("com.example.ss");
    o.identity = AppleIdentity::Signer(KeySigner::self_signed("Packager Self Signed", std::env::var("TEAM").ok().as_deref())?.into_arc());
    o.hardened_runtime = !a.iter().any(|x| x == "--no-runtime");
    let s = sign_macho(&std::fs::read(&a[0])?, &o)?;
    std::fs::write(&a[1], &s.data)?;
    packager::util::set_mode(std::path::Path::new(&a[1]), 0o755)
}
