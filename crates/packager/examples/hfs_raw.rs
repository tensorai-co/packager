//! `cargo run --example hfs_raw -- <dir> <out.img> <volname>`: raw HFS+ volume of a directory.
fn main() -> packager::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let nodes = packager::format::cpio::tree_from_dir(std::path::Path::new(&a[0]), "", 315_532_800)?;
    let mut o = packager::format::hfsplus::VolumeOptions::new(&a[2]);
    o.time = 315_532_800;
    std::fs::write(&a[1], packager::format::hfsplus::build(&nodes, &o)?)?;
    Ok(())
}
