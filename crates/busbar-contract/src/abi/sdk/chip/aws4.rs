// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4: the day's signing key and the request signature, made by the
//! credential. The canonical request is built here, so a session token signed into it never
//! passes through the plugin.

use zeroize::Zeroizing;

use super::digests;
use super::Refused;
use crate::abi::sdk::cred::{Cred, Seal};
use crate::abi::sdk::hmac::hmac_sha256;

/// `AWS4-HMAC-SHA256`.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The credential scope's terminator.
pub const TERMINATION: &str = "aws4_request";
/// The session token's header.
pub const SECURITY_TOKEN: &str = "x-amz-security-token";

/// The public parts of one request to sign.
#[derive(Debug, Clone, Copy)]
pub struct Aws4Request<'a> {
    /// The region.
    pub region: &'a str,
    /// The service.
    pub service: &'a str,
    /// The method.
    pub method: &'a str,
    /// The URI-encoded path.
    pub canonical_uri: &'a str,
    /// The sorted, encoded query (or empty).
    pub canonical_query: &'a str,
    /// The headers to sign (names case-insensitive), the session token's excepted.
    pub headers: &'a [(String, String)],
    /// The payload's SHA-256 hex.
    pub payload_hash: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amzdate: &'a str,
    /// `YYYYMMDD`.
    pub datestamp: &'a str,
}

/// A signature the chip made: its hex sealed, and the `SignedHeaders` list (public).
#[allow(missing_debug_implementations)]
pub struct Aws4Signature {
    /// The signature's lowercase hex.
    pub signature: Seal,
    /// `SignedHeaders`.
    pub signed_headers: String,
}

/// AWS's header-value canonicalization: ASCII spaces trimmed and runs collapsed; nothing else.
fn canonical_value(v: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(v.len()));
    let mut prev_space = false;
    for ch in v.chars() {
        if ch == ' ' {
            prev_space = true;
        } else {
            if prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = false;
            out.push(ch);
        }
    }
    out
}

fn string_to_sign(
    r: &Aws4Request<'_>,
    token: Option<&Cred>,
) -> Result<(Zeroizing<String>, String), Refused> {
    let mut h: Vec<(String, Zeroizing<String>)> = r
        .headers
        .iter()
        .filter(|(k, _)| token.is_none() || !k.eq_ignore_ascii_case(SECURITY_TOKEN))
        .map(|(k, v)| (k.to_lowercase(), canonical_value(v)))
        .collect();
    if let Some(t) = token {
        let text =
            std::str::from_utf8(t.wire()).map_err(|_| Refused("the session token is not text"))?;
        h.push((SECURITY_TOKEN.to_owned(), canonical_value(text)));
    }
    h.sort_by(|a, b| a.0.cmp(&b.0));
    let mut canonical_headers = Zeroizing::new(String::with_capacity(
        h.iter().map(|(k, v)| k.len() + v.len() + 2).sum(),
    ));
    let mut signed_headers = String::new();
    let mut previous = None;
    for (k, v) in &h {
        if previous == Some(k) {
            canonical_headers.pop();
            canonical_headers.push(',');
        } else {
            canonical_headers.push_str(k);
            canonical_headers.push(':');
            if !signed_headers.is_empty() {
                signed_headers.push(';');
            }
            signed_headers.push_str(k);
        }
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
        previous = Some(k);
    }
    let parts = [
        r.method,
        r.canonical_uri,
        r.canonical_query,
        canonical_headers.as_str(),
        signed_headers.as_str(),
        r.payload_hash,
    ];
    let mut canonical_request = Zeroizing::new(String::with_capacity(
        parts.iter().map(|part| part.len() + 1).sum(),
    ));
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            canonical_request.push('\n');
        }
        canonical_request.push_str(part);
    }
    let hashed = Zeroizing::new(hex::encode(
        &digests::sha256(&[canonical_request.as_bytes()])[..],
    ));
    let sts = Zeroizing::new(format!(
        "{ALGORITHM}\n{}\n{}/{}/{}/{TERMINATION}\n{}",
        r.amzdate,
        r.datestamp,
        r.region,
        r.service,
        hashed.as_str()
    ));
    Ok((sts, signed_headers))
}

impl Cred {
    /// The day's SigV4 signing key derived from this secret access key: `HMAC` over date, region,
    /// service and `aws4_request`. The key is itself a credential, held by the chip.
    pub fn aws4_day_key(&self, datestamp: &str, region: &str, service: &str) -> Cred {
        let mut seed = Zeroizing::new(Vec::with_capacity(4 + self.len()));
        seed.extend_from_slice(b"AWS4");
        seed.extend_from_slice(self.wire());
        let k_date = hmac_sha256(&seed, datestamp.as_bytes());
        let k_region = hmac_sha256(&k_date[..], region.as_bytes());
        let k_service = hmac_sha256(&k_region[..], service.as_bytes());
        let key = hmac_sha256(&k_service[..], TERMINATION.as_bytes());
        let derived = Cred::captured(Zeroizing::new(key.to_vec()));
        if self.secure_required() {
            derived.require_secure()
        } else {
            derived
        }
    }

    /// Sign `r` under this day key ([`Cred::aws4_day_key`]), the session `token` (if any) signed
    /// in as `x-amz-security-token`.
    ///
    /// # Errors
    /// The session token is not text.
    pub fn aws4_sign(
        &self,
        r: &Aws4Request<'_>,
        token: Option<&Cred>,
    ) -> Result<Aws4Signature, Refused> {
        let (sts, signed_headers) = string_to_sign(r, token)?;
        let mac = hmac_sha256(self.wire(), sts.as_bytes());
        let signature = self.seal(Zeroizing::new(hex::encode(&mac[..]).into_bytes()));
        let signature = if token.is_some_and(Cred::secure_required) {
            signature.require_secure()
        } else {
            signature
        };
        Ok(Aws4Signature {
            signature,
            signed_headers,
        })
    }

    /// Whether `presented` (lowercase hex) is this secret access key's signature of `r`, compared
    /// over SHA-256 digests (constant time).
    pub fn aws4_verify(&self, r: &Aws4Request<'_>, presented: &str) -> bool {
        let key = self.aws4_day_key(r.datestamp, r.region, r.service);
        let Ok(sig) = key.aws4_sign(r, None) else {
            return false;
        };
        let a = digests::sha256(&[sig.signature.wire()]);
        let b = digests::sha256(&[presented.as_bytes()]);
        crate::constant_time_eq(&a[..], &b[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(value: &[u8]) -> Cred {
        Cred::captured(Zeroizing::new(value.to_vec()))
    }

    fn request(headers: &[(String, String)]) -> Aws4Request<'_> {
        Aws4Request {
            region: "us-east-1",
            service: "service",
            method: "GET",
            canonical_uri: "/",
            canonical_query: "",
            headers,
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            amzdate: "20150830T123600Z",
            datestamp: "20150830",
        }
    }

    #[test]
    fn published_get_vanilla_vector_and_verification() {
        let secret = cred(b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let headers = vec![
            ("Host".into(), "example.amazonaws.com".into()),
            ("X-Amz-Date".into(), "20150830T123600Z".into()),
        ];
        let r = request(&headers);
        let key = secret.aws4_day_key(r.datestamp, r.region, r.service);
        let sig = key.aws4_sign(&r, None).expect("signs");
        let expected = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
        assert_eq!(sig.signature.wire(), expected.as_bytes());
        assert_eq!(sig.signed_headers, "host;x-amz-date");
        assert!(secret.aws4_verify(&r, expected));
        assert!(!secret.aws4_verify(&r, "00"));
    }

    #[test]
    fn session_token_replaces_supplied_header_and_carries_security_requirement() {
        let key = cred(b"secret").aws4_day_key("20150830", "us-east-1", "service");
        let token = cred(b"  token  with   spaces  ").require_secure();
        let supplied = vec![
            ("HOST".into(), "example.amazonaws.com".into()),
            ("X-Amz-Security-Token".into(), "stale".into()),
            ("x-amz-security-token".into(), "another stale token".into()),
        ];
        let expected = vec![
            ("host".into(), "example.amazonaws.com".into()),
            ("x-amz-security-token".into(), "token with spaces".into()),
        ];
        let actual = key
            .aws4_sign(&request(&supplied), Some(&token))
            .expect("signs");
        let expected = key.aws4_sign(&request(&expected), None).expect("signs");
        assert_eq!(actual.signature.wire(), expected.signature.wire());
        assert_eq!(actual.signed_headers, "host;x-amz-security-token");
        assert!(actual.signature.secure_required());
        assert!(!expected.signature.secure_required());
        assert!(key
            .aws4_sign(&request(&supplied), Some(&cred(&[0xff])))
            .is_err());
    }

    #[test]
    fn duplicate_headers_keep_value_order_and_collapse_only_ascii_spaces() {
        let key = cred(b"secret")
            .require_secure()
            .aws4_day_key("20150830", "us-east-1", "service");
        assert!(key.secure_required());
        let duplicate = vec![
            ("X-Test".into(), "  alpha   beta  ".into()),
            ("host".into(), "example.amazonaws.com".into()),
            ("x-test".into(), " \tgamma\u{a0} delta ".into()),
        ];
        let merged = vec![
            ("host".into(), "example.amazonaws.com".into()),
            ("x-test".into(), "alpha beta,\tgamma\u{a0} delta".into()),
        ];
        let actual = key.aws4_sign(&request(&duplicate), None).expect("signs");
        let expected = key.aws4_sign(&request(&merged), None).expect("signs");
        assert_eq!(actual.signature.wire(), expected.signature.wire());
        assert_eq!(actual.signed_headers, "host;x-test");
        assert!(actual.signature.secure_required());
    }
}
