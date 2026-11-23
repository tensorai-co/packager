//! Networking behind a trait. The default runs the OS's `curl` (on macOS, Windows 10+ and
//! Ubuntu), so the library needs no TLS stack of its own; apps can plug in their own.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::{Error, Result};

/// HTTP(S) access for timestamping, certificate fetching and notarization.
pub trait Transport: Send + Sync {
    /// `GET url`, returning the body of a 2xx response.
    fn get(&self, url: &str) -> Result<Vec<u8>>;
    /// `POST url` with `body` of `content_type`, returning the body of a 2xx response.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// The default transport: the system `curl`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Curl;

impl Curl {
    fn run(&self, args: &[&str], body: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut child = Command::new("curl")
            .args(["--silent", "--show-error", "--fail", "--location", "--max-time", "60"])
            .args(args)
            .stdin(if body.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Other(format!("can't run curl: {e}")))?;
        if let (Some(b), Some(mut stdin)) = (body, child.stdin.take()) {
            stdin.write_all(b).map_err(|e| Error::Other(format!("curl stdin: {e}")))?;
        }
        let out = child.wait_with_output().map_err(|e| Error::Other(format!("curl: {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!("curl {}: {}", args.last().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(out.stdout)
    }
}

impl Transport for Curl {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.run(&[url], None)
    }
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
        let header = format!("Content-Type: {content_type}");
        self.run(&["-H", &header, "--data-binary", "@-", url], Some(body))
    }
}
