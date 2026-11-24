//! Apple's Notary service (what `notarytool` does): authenticate with an App Store Connect API
//! key (ES256 JWT), create a submission, upload the file to S3 with the temporary credentials the
//! service returns (SigV4), poll until Apple's verdict, and fetch the developer log.
//!
//! Requires a Developer ID–signed, hardened-runtime, securely timestamped `.app` / `.dmg` /
//! `.pkg` / `.zip`. Stapling the resulting ticket is in [`crate::staple`].

use std::path::Path;
use std::time::{Duration, Instant};

use crate::crypto::ec::{Curve, EcPrivateKey, der_to_raw};
use crate::crypto::hex;
use crate::crypto::hmac::HashAlg;
use crate::crypto::keys::{PrivateKey, pem_decode};
use crate::crypto::sigv4::{self, Credentials};
use crate::error::IoContext;
use crate::format::base64;
use crate::format::json::Json;
use crate::transport::{Request, Transport};
use crate::{Error, Result};

/// The Notary API base URL.
pub const API_BASE: &str = "https://appstoreconnect.apple.com/notary/v2";
const S3_REGION: &str = "us-west-2";

/// An App Store Connect API key: the `.p8` private key, its key ID, and the issuer ID (absent
/// for individual keys, which authenticate as `sub: user`).
#[derive(Clone)]
pub struct ApiKey {
    /// Key ID (the 10-character ID in `AuthKey_<ID>.p8`).
    pub key_id: String,
    /// Issuer ID (a UUID) for team keys; `None` for individual keys.
    pub issuer: Option<String>,
    key: EcPrivateKey,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiKey({}, issuer {:?})", self.key_id, self.issuer)
    }
}

impl ApiKey {
    /// From a `.p8` file's contents (PKCS#8 PEM with a P-256 key).
    pub fn from_pem(pem: &str, key_id: impl Into<String>, issuer: Option<String>) -> Result<Self> {
        let block = pem_decode(pem)?.into_iter().find(|b| b.label == "PRIVATE KEY").ok_or_else(|| Error::invalid("notary", "api key", "the .p8 file has no PRIVATE KEY block"))?;
        let key = match PrivateKey::from_pkcs8(&block.der)? {
            PrivateKey::Ec(k) if k.curve == Curve::P256 => k,
            _ => return Err(Error::invalid("notary", "api key", "App Store Connect keys are P-256 EC keys")),
        };
        Ok(ApiKey { key_id: key_id.into(), issuer, key })
    }

    /// From an `AuthKey_<ID>.p8` file. The key ID is taken from the file name when `key_id` is
    /// `None`.
    pub fn from_file(path: impl AsRef<Path>, key_id: Option<&str>, issuer: Option<&str>) -> Result<Self> {
        let p = path.as_ref();
        let id = match key_id {
            Some(k) => k.to_string(),
            None => p
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("AuthKey_"))
                .ok_or_else(|| Error::invalid("notary", "key id", "not given and the file isn't named AuthKey_<ID>.p8"))?
                .to_string(),
        };
        Self::from_pem(&std::fs::read_to_string(p).at(p)?, id, issuer.map(String::from))
    }

    /// A token valid for `lifetime_secs` (Apple allows at most 20 minutes).
    pub fn jwt(&self, now: i64, lifetime_secs: i64) -> Result<String> {
        let header = Json::object(vec![("alg", Json::str("ES256")), ("kid", Json::str(&self.key_id)), ("typ", Json::str("JWT"))]);
        let mut claims = vec![];
        match &self.issuer {
            Some(iss) => claims.push(("iss", Json::str(iss))),
            None => claims.push(("sub", Json::str("user"))),
        }
        claims.push(("iat", Json::Number(now as f64)));
        claims.push(("exp", Json::Number((now + lifetime_secs.min(1200)) as f64)));
        claims.push(("aud", Json::str("appstoreconnect-v1")));
        let signing_input = format!("{}.{}", base64::encode_url(header.to_string_compact().as_bytes()), base64::encode_url(Json::object(claims).to_string_compact().as_bytes()));
        let der = self.key.sign(&HashAlg::Sha256.digest(signing_input.as_bytes()), HashAlg::Sha256)?;
        Ok(format!("{signing_input}.{}", base64::encode_url(&der_to_raw(&der, 32)?)))
    }
}

/// A submission's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Still being checked.
    InProgress,
    /// Notarized: a ticket exists and can be stapled.
    Accepted,
    /// Problems were found; the log says which.
    Invalid,
    /// Apple rejected the submission.
    Rejected,
    /// A status this client doesn't know.
    Other(String),
}

impl Status {
    fn parse(s: &str) -> Status {
        match s {
            "In Progress" => Status::InProgress,
            "Accepted" => Status::Accepted,
            "Invalid" => Status::Invalid,
            "Rejected" => Status::Rejected,
            other => Status::Other(other.to_string()),
        }
    }
}

/// The outcome of [`Notary::notarize`].
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Submission ID.
    pub id: String,
    /// Final status.
    pub status: Status,
    /// The developer log (JSON), fetched for every finished submission.
    pub log: Option<Json>,
}

/// A Notary API client.
pub struct Notary<'a> {
    key: ApiKey,
    transport: &'a dyn Transport,
    base: String,
    /// How often to poll while waiting.
    pub poll_interval: Duration,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn json_body(body: &[u8], what: &str) -> Result<Json> {
    Json::parse(&String::from_utf8_lossy(body)).map_err(|e| Error::Other(format!("{what}: unexpected response ({e})")))
}

impl<'a> Notary<'a> {
    /// A client for `key` over `transport`.
    pub fn new(key: ApiKey, transport: &'a dyn Transport) -> Self {
        Notary { key, transport, base: API_BASE.to_string(), poll_interval: Duration::from_secs(15) }
    }

    /// Points the client at another base URL (tests, proxies).
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    fn api(&self, method: &str, path: &str, body: Option<&Json>) -> Result<Json> {
        let token = self.key.jwt(now(), 600)?;
        let url = format!("{}{path}", self.base);
        let payload = body.map(|b| b.to_string_compact().into_bytes());
        let mut headers = vec![("Authorization".to_string(), format!("Bearer {token}"))];
        if payload.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        let resp = self.transport.request(&Request { method, url: &url, headers, body: payload.as_deref() })?;
        let what = format!("notary {method} {path}");
        let body = resp.ok(&what)?;
        json_body(&body, &what)
    }

    /// Creates a submission for a file with this `name` and SHA-256; returns the submission ID
    /// and where to upload.
    pub fn create_submission(&self, name: &str, sha256: &[u8]) -> Result<(String, Credentials, String, String)> {
        let body = Json::object(vec![("submissionName", Json::str(name)), ("sha256", Json::str(hex(sha256)))]);
        let r = self.api("POST", "/submissions", Some(&body))?;
        let data = r.get("data").ok_or_else(|| Error::Other("notary: no data in submission response".into()))?;
        let id = data.get("id").and_then(Json::as_str).ok_or_else(|| Error::Other("notary: no submission id".into()))?.to_string();
        let a = data.get("attributes").ok_or_else(|| Error::Other("notary: no attributes".into()))?;
        let field = |k: &str| a.get(k).and_then(Json::as_str).map(String::from).ok_or_else(|| Error::Other(format!("notary: missing {k}")));
        let creds = Credentials { access_key: field("awsAccessKeyId")?, secret_key: field("awsSecretAccessKey")?, session_token: Some(field("awsSessionToken")?) };
        Ok((id, creds, field("bucket")?, field("object")?))
    }

    /// Uploads `data` to the submission's S3 location.
    pub fn upload(&self, data: &[u8], creds: &Credentials, bucket: &str, object: &str) -> Result<()> {
        let host = format!("{bucket}.s3.{S3_REGION}.amazonaws.com");
        let path = format!("/{object}");
        let payload_hash = hex(&HashAlg::Sha256.digest(data));
        let date = sigv4::amz_date(now());
        let mut signed: Vec<(&str, String)> = vec![("host", host.clone()), ("x-amz-content-sha256", payload_hash.clone()), ("x-amz-date", date.clone())];
        if let Some(t) = &creds.session_token {
            signed.push(("x-amz-security-token", t.clone()));
        }
        let auth = sigv4::authorization(
            &sigv4::SignRequest { method: "PUT", path: &path, query: &[], headers: &signed, payload_hash: &payload_hash, amz_date: &date, region: S3_REGION, service: "s3" },
            creds,
        );
        let mut headers: Vec<(String, String)> = signed.iter().filter(|(k, _)| *k != "host").map(|(k, v)| (k.to_string(), v.clone())).collect();
        headers.push(("Authorization".into(), auth));
        headers.push(("Content-Type".into(), "application/octet-stream".into()));
        let url = format!("https://{host}{}", sigv4::uri_encode(&path, true));
        self.transport.request(&Request { method: "PUT", url: &url, headers, body: Some(data) })?.ok("upload to Apple's notary bucket")?;
        Ok(())
    }

    /// The current status of a submission.
    pub fn status(&self, id: &str) -> Result<Status> {
        let r = self.api("GET", &format!("/submissions/{id}"), None)?;
        let s = r.path(&["data", "attributes", "status"]).and_then(Json::as_str).ok_or_else(|| Error::Other("notary: no status in response".into()))?;
        Ok(Status::parse(s))
    }

    /// The developer log of a finished submission.
    pub fn log(&self, id: &str) -> Result<Json> {
        let r = self.api("GET", &format!("/submissions/{id}/logs"), None)?;
        let url = r.path(&["data", "attributes", "developerLogUrl"]).and_then(Json::as_str).ok_or_else(|| Error::Other("notary: no log URL".into()))?;
        json_body(&self.transport.get(url)?, "notary log")
    }

    /// Polls until the submission leaves "In Progress" or `timeout` passes.
    pub fn wait(&self, id: &str, timeout: Duration) -> Result<Status> {
        let start = Instant::now();
        loop {
            let s = self.status(id)?;
            if s != Status::InProgress {
                return Ok(s);
            }
            if start.elapsed() >= timeout {
                return Err(Error::Other(format!("notary: submission {id} still in progress after {}s", timeout.as_secs())));
            }
            std::thread::sleep(self.poll_interval);
        }
    }

    /// Submits `data` (named `name`), waits for the verdict, and fetches the log.
    pub fn notarize(&self, name: &str, data: &[u8], timeout: Duration) -> Result<Outcome> {
        let (id, creds, bucket, object) = self.create_submission(name, &HashAlg::Sha256.digest(data))?;
        self.upload(data, &creds, &bucket, &object)?;
        let status = self.wait(&id, timeout)?;
        let log = self.log(&id).ok();
        Ok(Outcome { id, status, log })
    }

    /// Notarizes a file. App bundles must be zipped first (Apple accepts `.zip`, `.dmg`, `.pkg`).
    pub fn notarize_file(&self, path: impl AsRef<Path>, timeout: Duration) -> Result<Outcome> {
        let p = path.as_ref();
        if p.is_dir() {
            return Err(Error::invalid("notary", p.display().to_string(), "app bundles must be submitted as a .zip, .dmg or .pkg"));
        }
        let data = std::fs::read(p).at(p)?;
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("submission");
        self.notarize(name, &data, timeout)
    }
}

/// Notarization as a build step: checks what notarization requires before uploading, submits
/// (zipping bundles), waits, and staples the ticket.
#[derive(Clone)]
pub struct Notarize {
    /// The App Store Connect API key.
    pub key: ApiKey,
    /// How long to wait for Apple's verdict (default 30 minutes).
    pub timeout: Duration,
    /// Staple the ticket afterwards (default on).
    pub staple: bool,
    /// Network access (default: the system `curl`).
    pub transport: std::sync::Arc<dyn Transport>,
}

impl std::fmt::Debug for Notarize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notarize").field("key", &self.key).field("timeout", &self.timeout).field("staple", &self.staple).finish()
    }
}

/// What [`Notarize::run`] did.
#[derive(Debug, Clone)]
pub struct Notarized {
    /// The submission, when one was made (`None` when a ticket already existed).
    pub submission: Option<Outcome>,
    /// Whether the ticket was stapled.
    pub stapled: bool,
}

impl Notarize {
    /// Notarizes with `key`, waiting up to 30 minutes and stapling.
    pub fn new(key: ApiKey) -> Self {
        Notarize { key, timeout: Duration::from_secs(1800), staple: true, transport: std::sync::Arc::new(crate::transport::Curl) }
    }

    /// The rules notarization enforces that can be checked locally (Developer ID, Apple anchor,
    /// secure timestamp, hardened runtime, no `get-task-allow`), as errors.
    pub fn preflight(path: &Path) -> Result<()> {
        let a = crate::sign::assess::assess(path, None)?;
        let problems: Vec<String> = a.failures().filter(|c| c.name != "notarized").map(|c| format!("{}: {}", c.name, c.detail)).collect();
        if problems.is_empty() { Ok(()) } else { Err(Error::invalid("notarize", path.display().to_string(), format!("Apple would reject it:\n  {}", problems.join("\n  ")))) }
    }

    /// Notarizes and (optionally) staples an `.app`, `.dmg` or `.pkg`. If Apple already has a
    /// ticket for this exact code (for example an `.app` notarized inside its `.dmg`), it's
    /// stapled without a new submission.
    pub fn run(&self, path: impl AsRef<Path>) -> Result<Notarized> {
        let p = path.as_ref();
        Self::preflight(p)?;
        let t = self.transport.as_ref();
        let (_, record) = crate::staple::ticket_record(p)?;
        if let crate::staple::Lookup::Ticket(ticket) = crate::staple::lookup(t, &record)? {
            if self.staple {
                crate::staple::attach(p, &ticket)?;
            }
            return Ok(Notarized { submission: None, stapled: self.staple });
        }
        let notary = Notary::new(self.key.clone(), t);
        let (name, data) = if p.is_dir() {
            let base = p.file_name().and_then(|n| n.to_str()).unwrap_or("bundle");
            (format!("{base}.zip"), crate::format::zip::from_dir(p, crate::util::source_date_epoch())?)
        } else {
            (p.file_name().and_then(|n| n.to_str()).unwrap_or("submission").to_string(), std::fs::read(p).at(p)?)
        };
        let outcome = notary.notarize(&name, &data, self.timeout)?;
        if outcome.status != Status::Accepted {
            let issues = outcome.log.as_ref().map(log_issues).unwrap_or_default();
            let detail = if issues.is_empty() { String::new() } else { format!(":\n  {}", issues.join("\n  ")) };
            return Err(Error::Other(format!("notarization of {} was {:?} (submission {}){detail}", p.display(), outcome.status, outcome.id)));
        }
        let mut stapled = false;
        if self.staple {
            // The ticket can take a moment to reach the CDN after "Accepted".
            for attempt in 0..10 {
                match crate::staple::staple(t, p)? {
                    crate::staple::Lookup::Ticket(_) => {
                        stapled = true;
                        break;
                    }
                    crate::staple::Lookup::Missing(_) if attempt < 9 => std::thread::sleep(Duration::from_secs(6)),
                    crate::staple::Lookup::Missing(why) => return Err(Error::Other(format!("{}: notarized, but no ticket to staple yet ({why}); run `packager staple` later", p.display()))),
                }
            }
        }
        Ok(Notarized { submission: Some(outcome), stapled })
    }
}

/// The issues in a developer log, as "path: message" lines.
pub fn log_issues(log: &Json) -> Vec<String> {
    log.get("issues")
        .and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .map(|i| {
            let path = i.get("path").and_then(Json::as_str).unwrap_or("?");
            let msg = i.get("message").and_then(Json::as_str).unwrap_or("?");
            let arch = i.get("architecture").and_then(Json::as_str).map(|a| format!(" ({a})")).unwrap_or_default();
            format!("{path}{arch}: {msg}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::pem_encode;
    use crate::transport::Response;
    use std::sync::Mutex;

    fn key() -> ApiKey {
        let k = EcPrivateKey::generate(Curve::P256).unwrap();
        let pem = pem_encode("PRIVATE KEY", &PrivateKey::Ec(k).to_pkcs8());
        ApiKey::from_pem(&pem, "ABC123DEFG", Some("69a6de7e-0000-47e3-e053-5b8c7c11a4d1".into())).unwrap()
    }

    #[test]
    fn jwt_shape_and_signature() {
        let k = key();
        let t = k.jwt(1_700_000_000, 600).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = Json::parse(&String::from_utf8(base64::decode_url(parts[0]).unwrap()).unwrap()).unwrap();
        assert_eq!(header.get("alg").and_then(Json::as_str), Some("ES256"));
        assert_eq!(header.get("kid").and_then(Json::as_str), Some("ABC123DEFG"));
        let claims = Json::parse(&String::from_utf8(base64::decode_url(parts[1]).unwrap()).unwrap()).unwrap();
        assert_eq!(claims.get("aud").and_then(Json::as_str), Some("appstoreconnect-v1"));
        assert_eq!(claims.get("exp").and_then(Json::as_f64), Some(1_700_000_600.0));
        let sig = base64::decode_url(parts[2]).unwrap();
        assert_eq!(sig.len(), 64);
        let digest = HashAlg::Sha256.digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
        assert!(k.key.public().verify(&digest, &crate::crypto::ec::raw_to_der(&sig)));
    }

    /// (method, URL, headers) of a request the fake saw.
    type Seen = (String, String, Vec<(String, String)>);

    /// A scripted Notary service: records requests, answers in order.
    struct Fake {
        seen: Mutex<Vec<Seen>>,
        polls: Mutex<u32>,
    }

    impl Transport for Fake {
        fn request(&self, req: &Request) -> Result<Response> {
            self.seen.lock().unwrap().push((req.method.to_string(), req.url.to_string(), req.headers.clone()));
            let body = match (req.method, req.url) {
                ("POST", u) if u.ends_with("/submissions") => {
                    let b = Json::parse(&String::from_utf8_lossy(req.body.unwrap())).unwrap();
                    assert_eq!(b.get("submissionName").and_then(Json::as_str), Some("My.dmg"));
                    assert_eq!(b.get("sha256").and_then(Json::as_str), Some(hex(&HashAlg::Sha256.digest(b"dmg bytes")).as_str()));
                    r#"{"data":{"type":"newSubmissions","id":"sub-1","attributes":{"awsAccessKeyId":"AK","awsSecretAccessKey":"SK","awsSessionToken":"TOK","bucket":"notary-submissions-prod","object":"prod/AAA/sub-1"}}}"#.to_string()
                }
                ("PUT", u) => {
                    assert_eq!(u, "https://notary-submissions-prod.s3.us-west-2.amazonaws.com/prod/AAA/sub-1");
                    assert_eq!(req.body, Some(&b"dmg bytes"[..]));
                    String::new()
                }
                ("GET", u) if u.ends_with("/submissions/sub-1") => {
                    let mut n = self.polls.lock().unwrap();
                    *n += 1;
                    let st = if *n < 2 { "In Progress" } else { "Accepted" };
                    format!(r#"{{"data":{{"id":"sub-1","type":"submissions","attributes":{{"status":"{st}","name":"My.dmg"}}}}}}"#)
                }
                ("GET", u) if u.ends_with("/logs") => r#"{"data":{"attributes":{"developerLogUrl":"https://logs.example/sub-1.json"}}}"#.to_string(),
                ("GET", "https://logs.example/sub-1.json") => r#"{"status":"Accepted","issues":null}"#.to_string(),
                other => panic!("unexpected request {other:?}"),
            };
            Ok(Response { status: 200, body: body.into_bytes() })
        }
    }

    #[test]
    fn notarize_flow() {
        let fake = Fake { seen: Mutex::new(Vec::new()), polls: Mutex::new(0) };
        let mut n = Notary::new(key(), &fake);
        n.poll_interval = Duration::from_millis(1);
        let out = n.notarize("My.dmg", b"dmg bytes", Duration::from_secs(5)).unwrap();
        assert_eq!(out.status, Status::Accepted);
        assert_eq!(out.id, "sub-1");
        let seen = fake.seen.lock().unwrap();
        assert!(seen[0].2.iter().any(|(k, v)| k == "Authorization" && v.starts_with("Bearer ")));
        let put = seen.iter().find(|r| r.0 == "PUT").unwrap();
        assert!(put.2.iter().any(|(k, v)| k == "x-amz-security-token" && v == "TOK"));
        assert!(put.2.iter().any(|(k, v)| k == "Authorization" && v.starts_with("AWS4-HMAC-SHA256 Credential=AK/") && v.contains("/us-west-2/s3/aws4_request")));
    }
}
