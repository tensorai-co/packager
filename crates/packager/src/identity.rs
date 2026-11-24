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

#[cfg(test)]
mod tests {
    use super::*;

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
