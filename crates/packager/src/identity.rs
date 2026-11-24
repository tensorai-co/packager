//! Identity and version rules per format, derived from the [`App`] so apps never manage them by hand.

use crate::app::App;
use crate::{Error, Result};

/// macOS bundle versions: (`CFBundleShortVersionString`, `CFBundleVersion`).
///
/// The short version is `major.minor.patch` (what users see). The build number defaults to the
/// same. A pre-release (`1.4.0-beta.1`) can't be expressed in the short version, so it needs an
/// explicit numeric build number to tell builds apart.
pub fn macos_versions(app: &App) -> Result<(String, String)> {
    let v = app.parsed_version()?;
    let short = v.triple();
    let build = match (&app.build_number, &v.pre) {
        (Some(b), _) => b.clone(),
        (None, None) => short.clone(),
        (None, Some(pre)) => {
            return Err(Error::invalid(
                "app",
                "version",
                format!("`{}` has a pre-release (`{pre}`), which macOS versions can't express; set a numeric `build_number` (CFBundleVersion) such as `{short}.1`", app.version),
            ));
        }
    };
    let ok = !build.is_empty() && build.split('.').count() <= 3 && build.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !ok {
        return Err(Error::invalid("app", "build_number", format!("`{build}` must be up to three dot-separated integers (CFBundleVersion)")));
    }
    Ok((short, build))
}

/// The MSIX `Version`: four parts, each at most 65535. The last is the numeric build number
/// when given, else 0 (what the Store requires). Pre-releases can't be expressed.
pub fn msix_version(app: &App) -> Result<String> {
    let v = app.parsed_version()?;
    if let Some(pre) = &v.pre {
        return Err(Error::invalid("msix", "version", format!("`{}` has a pre-release (`{pre}`), which MSIX versions can't express", app.version)));
    }
    let fourth = match &app.build_number {
        Some(b) => b.parse::<u64>().map_err(|_| Error::invalid("msix", "build_number", format!("`{b}` must be a number for MSIX's fourth version part")))?,
        None => 0,
    };
    for (name, n) in [("major", v.major), ("minor", v.minor), ("patch", v.patch), ("build_number", fourth)] {
        if n > 65535 {
            return Err(Error::invalid("msix", "version", format!("the {name} part ({n}) is over 65535")));
        }
    }
    Ok(format!("{}.{}.{}.{fourth}", v.major, v.minor, v.patch))
}

/// packager's namespace for name-based (version 5) UUIDs.
const NAMESPACE: [u8; 16] = [0x6b, 0x1f, 0x4a, 0x2e, 0x93, 0xc4, 0x4d, 0x0e, 0xa5, 0x7a, 0x3e, 0x11, 0x8c, 0x52, 0x60, 0xd9];

/// A name-based UUID (RFC 9562 version 5) in packager's namespace, as `{XXXXXXXX-…}` the way
/// Windows Installer writes GUIDs: stable forever for the same name.
pub fn guid(name: &str) -> String {
    let mut input = NAMESPACE.to_vec();
    input.extend_from_slice(name.as_bytes());
    let h = crate::crypto::sha1(&input);
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x = crate::crypto::hex(&b).to_uppercase();
    format!("{{{}-{}-{}-{}-{}}}", &x[..8], &x[8..12], &x[12..16], &x[16..20], &x[20..])
}

/// The MSI `ProductVersion`: `major.minor.build`, at most 255.255.65535. Windows Installer
/// ignores a fourth field, so builds differing only there wouldn't upgrade; pre-releases can't
/// be expressed.
pub fn msi_version(app: &App) -> Result<String> {
    let v = app.parsed_version()?;
    if let Some(pre) = &v.pre {
        return Err(Error::invalid("msi", "version", format!("`{}` has a pre-release (`{pre}`), which MSI versions can't express", app.version)));
    }
    if v.major > 255 || v.minor > 255 || v.patch > 65535 {
        return Err(Error::invalid("msi", "version", format!("`{}` is over 255.255.65535, the most an MSI version holds", app.version)));
    }
    Ok(v.triple())
}

/// The MSI UpgradeCode: the product family, derived from the identifier so it never changes.
pub fn msi_upgrade_code(app: &App) -> String {
    guid(&format!("msi-upgrade:{}", app.identifier))
}

/// The MSI ProductCode for one version and architecture: new every release, so every release
/// is a clean major upgrade.
pub fn msi_product_code(app: &App, arch: crate::app::Arch) -> Result<String> {
    Ok(guid(&format!("msi-product:{}:{}:{}", app.identifier, msi_version(app)?, arch.name())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_codes() {
        let app = App::new("A", "com.example.a", "1.4.0");
        let g = guid("x");
        assert_eq!(g.len(), 38);
        assert_eq!(&g[15..16], "5", "version 5: {g}");
        assert_eq!(guid("x"), g);
        assert_ne!(msi_upgrade_code(&app), msi_upgrade_code(&App::new("A", "com.example.b", "1.4.0")));
        assert_eq!(msi_upgrade_code(&app), msi_upgrade_code(&App::new("B", "com.example.a", "9.0.0")));
        assert_ne!(msi_product_code(&app, crate::app::Arch::WindowsX64).unwrap(), msi_product_code(&App::new("A", "com.example.a", "1.4.1"), crate::app::Arch::WindowsX64).unwrap());
        assert!(msi_version(&App::new("A", "com.a.b", "256.0.0")).is_err());
        assert!(msi_version(&App::new("A", "com.a.b", "1.0.0-rc.1")).is_err());
    }

    #[test]
    fn msix_versions() {
        assert_eq!(msix_version(&App::new("A", "com.a.b", "1.4.0")).unwrap(), "1.4.0.0");
        assert_eq!(msix_version(&App::new("A", "com.a.b", "1.4.0").build_number("7")).unwrap(), "1.4.0.7");
        assert!(msix_version(&App::new("A", "com.a.b", "1.4.0-beta.1")).is_err());
        assert!(msix_version(&App::new("A", "com.a.b", "70000.0.0")).is_err());
    }

    #[test]
    fn mac_versions() {
        assert_eq!(macos_versions(&App::new("A", "com.a.b", "1.4.0")).unwrap(), ("1.4.0".into(), "1.4.0".into()));
        assert_eq!(macos_versions(&App::new("A", "com.a.b", "1.4.0").build_number("812")).unwrap().1, "812");
        assert!(macos_versions(&App::new("A", "com.a.b", "1.4.0-beta.1")).is_err());
        assert!(macos_versions(&App::new("A", "com.a.b", "1.4.0-beta.1").build_number("1.4.0.1")).is_err());
        assert!(macos_versions(&App::new("A", "com.a.b", "1.4.0-beta.1").build_number("1.4.1")).is_ok());
    }
}
