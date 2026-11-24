//! Networking behind a trait. The default runs the OS's `curl` (on macOS, Windows 10+ and
//! Ubuntu), so the library needs no TLS stack of its own; apps can plug in their own.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::{Error, Result};

/// An HTTP request.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// `GET`, `POST`, `PUT`…
    pub method: &'a str,
    /// Full URL.
    pub url: &'a str,
    /// Header (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// The body, if any.
    pub body: Option<&'a [u8]>,
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// The body as text (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    /// The body, or an error naming the status, unless the status is 2xx.
    pub fn ok(self, what: &str) -> Result<Vec<u8>> {
        if (200..300).contains(&self.status) {
            Ok(self.body)
        } else {
            let mut text = self.text();
            text.truncate(600);
            Err(Error::Other(format!("{what}: HTTP {} {}", self.status, text.trim())))
        }
    }
}

/// HTTP(S) access for timestamping, certificate fetching, notarization and ticket lookup.
pub trait Transport: Send + Sync {
    /// Performs a request, returning the status and body whatever the status.
    fn request(&self, req: &Request) -> Result<Response>;

    /// `GET url`, returning the body of a 2xx response.
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.request(&Request { method: "GET", url, headers: Vec::new(), body: None })?.ok(url)
    }
    /// `POST url` with `body` of `content_type`, returning the body of a 2xx response.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
        self.request(&Request { method: "POST", url, headers: vec![("Content-Type".into(), content_type.into())], body: Some(body) })?.ok(url)
    }
}

/// The default transport: the system `curl`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Curl;

impl Transport for Curl {
    fn request(&self, req: &Request) -> Result<Response> {
        let out_path = std::env::temp_dir().join(format!("packager-http-{}-{}", std::process::id(), unique()));
        let mut cmd = Command::new("curl");
        cmd.args(["--silent", "--show-error", "--location", "--max-time", "1800", "--request", req.method]);
        for (k, v) in &req.headers {
            cmd.arg("--header").arg(format!("{k}: {v}"));
        }
        if req.body.is_some() {
            cmd.args(["--data-binary", "@-"]);
            // curl adds `Expect: 100-continue` for big bodies; S3 handles it, but it's one more
            // round trip and some proxies mishandle it.
            cmd.args(["--header", "Expect:"]);
        }
        cmd.arg("--output").arg(&out_path).args(["--write-out", "%{http_code}"]).arg(req.url);
        let mut child = cmd
            .stdin(if req.body.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Other(format!("can't run curl: {e}")))?;
        if let (Some(b), Some(mut stdin)) = (req.body, child.stdin.take()) {
            stdin.write_all(b).map_err(|e| Error::Other(format!("curl stdin: {e}")))?;
        }
        let out = child.wait_with_output().map_err(|e| Error::Other(format!("curl: {e}")))?;
        let body = std::fs::read(&out_path).unwrap_or_default();
        let _ = std::fs::remove_file(&out_path);
        if !out.status.success() {
            return Err(Error::Other(format!("curl {} {}: {}", req.method, req.url, String::from_utf8_lossy(&out.stderr).trim())));
        }
        let status = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
        Ok(Response { status, body })
    }
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}
