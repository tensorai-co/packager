//! The one error type every layer returns.

use std::fmt;
use std::path::{Path, PathBuf};

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while reading, writing, signing or building.
#[derive(Debug)]
pub enum Error {
    /// A filesystem or other I/O failure, with the path involved when known.
    Io {
        /// The file or directory being read or written.
        path: Option<PathBuf>,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The app description doesn't satisfy a format's rules; checked before anything is written.
    Invalid {
        /// The format whose rule failed (`"pkg"`, `"app"`, `"version"`…).
        format: &'static str,
        /// The field at fault.
        field: String,
        /// What's wrong with it.
        message: String,
    },
    /// Input that a reader couldn't parse (truncated, corrupt or unsupported).
    Malformed {
        /// The format being read (`"png"`, `"mach-o"`, `"plist"`…).
        format: &'static str,
        /// What's wrong with it.
        message: String,
    },
    /// Anything else, described in a sentence.
    Other(String),
}

impl Error {
    /// An I/O error tagged with the path that caused it.
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Error::Io { path: Some(path.as_ref().to_path_buf()), source }
    }

    /// A validation failure, naming the format and the field.
    pub fn invalid(format: &'static str, field: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Invalid { format, field: field.into(), message: message.into() }
    }

    /// A parse failure in a reader.
    pub fn malformed(format: &'static str, message: impl Into<String>) -> Self {
        Error::Malformed { format, message: message.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path: Some(p), source } => write!(f, "{}: {source}", p.display()),
            Error::Io { path: None, source } => write!(f, "{source}"),
            Error::Invalid { format, field, message } => write!(f, "{format}: `{field}` {message}"),
            Error::Malformed { format, message } => write!(f, "malformed {format}: {message}"),
            Error::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::Io { path: None, source }
    }
}

/// Attaches a path to I/O results.
pub(crate) trait IoContext<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|e| Error::io(path, e))
    }
}
