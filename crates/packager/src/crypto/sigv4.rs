//! AWS Signature Version 4, for uploading notarization submissions to S3 with the temporary
//! credentials Apple's Notary API hands out.

use crate::crypto::hex;
use crate::crypto::hmac::{hmac, HashAlg};

/// Temporary or long-lived AWS credentials.
#[derive(Clone)]
pub struct Credentials {
    /// Access key ID.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Session token, for temporary credentials.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({}, secret hidden)", self.access_key)
    }
}

/// Percent-encodes per SigV4: unreserved characters stay, `/` stays in paths when `keep_slash`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What to sign.
#[derive(Debug, Clone)]
pub struct SignRequest<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// The (unencoded) path, starting with `/`.
    pub path: &'a str,
    /// Query parameters (unencoded).
    pub query: &'a [(&'a str, &'a str)],
    /// Headers to sign, including `host`, `x-amz-date` and `x-amz-content-sha256`.
    pub headers: &'a [(&'a str, String)],
    /// Hex SHA-256 of the payload (or `UNSIGNED-PAYLOAD`).
    pub payload_hash: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
    /// Region (`us-west-2`).
    pub region: &'a str,
    /// Service (`s3`).
    pub service: &'a str,
}

/// The `Authorization` header value for `req`.
pub fn authorization(req: &SignRequest, creds: &Credentials) -> String {
    let mut q: Vec<(String, String)> = req.query.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let mut h: Vec<(String, String)> = req.headers.iter().map(|(k, v)| (k.to_lowercase(), v.split_whitespace().collect::<Vec<_>>().join(" "))).collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical = format!("{}\n{}\n{}\n{}\n{}\n{}", req.method, uri_encode(req.path, true), canonical_query, canonical_headers, signed_headers, req.payload_hash);
    let date = &req.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{scope}\n{}", req.amz_date, hex(&HashAlg::Sha256.digest(canonical.as_bytes())));
    let k_date = hmac(HashAlg::Sha256, format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac(HashAlg::Sha256, &k_date, req.region.as_bytes());
    let k_service = hmac(HashAlg::Sha256, &k_region, req.service.as_bytes());
    let k_signing = hmac(HashAlg::Sha256, &k_service, b"aws4_request");
    let signature = hex(&hmac(HashAlg::Sha256, &k_signing, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", creds.access_key)
}

/// `YYYYMMDDTHHMMSSZ` for Unix seconds.
pub fn amz_date(unix: i64) -> String {
    crate::util::iso8601(unix).replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_s3_get_object_example() {
        // From the AWS S3 documentation, "Signature Calculations for the Authorization Header",
        // example GET Object.
        let creds = Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com".to_string()),
            ("range", "bytes=0-9".to_string()),
            ("x-amz-content-sha256", empty.to_string()),
            ("x-amz-date", "20130524T000000Z".to_string()),
        ];
        let req = SignRequest { method: "GET", path: "/test.txt", query: &[], headers: &headers, payload_hash: empty, amz_date: "20130524T000000Z", region: "us-east-1", service: "s3" };
        let auth = authorization(&req, &creds);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
    }
}
