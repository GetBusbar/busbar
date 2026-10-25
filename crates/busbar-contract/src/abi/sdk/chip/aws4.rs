// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4: the day's signing key and the request signature, made by the
//! credential. The canonical request is built here, so a session token signed into it never
//! passes through the plugin.

use zeroize::{Zeroize, Zeroizing};

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
    let mut merged: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(h.len());
    for (k, v) in h {
        match merged.last_mut() {
            Some((last_k, last_v)) if *last_k == k => {
                last_v.push(',');
                last_v.push_str(&v);
            }
            _ => merged.push((k, v)),
        }
    }
    let mut canonical_headers = Zeroizing::new(String::new());
    for (k, v) in &merged {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
    }
    let signed_headers = merged
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical_request = Zeroizing::new(String::new());
    for (i, part) in [
        r.method,
        r.canonical_uri,
        r.canonical_query,
        canonical_headers.as_str(),
        signed_headers.as_str(),
        r.payload_hash,
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            canonical_request.push('\n');
        }
        canonical_request.push_str(part);
    }
    let hashed = hex::encode(&digests::sha256(&[canonical_request.as_bytes()])[..]);
    let sts = Zeroizing::new(format!(
        "{ALGORITHM}\n{}\n{}/{}/{}/{TERMINATION}\n{hashed}",
        r.amzdate, r.datestamp, r.region, r.service
    ));
    Ok((sts, signed_headers))
}

impl Cred {
    /// The day's SigV4 signing key derived from this secret access key: `HMAC` over date, region,
    /// service and `aws4_request`. The key is itself a credential, held by the chip.
    pub fn aws4_day_key(&self, datestamp: &str, region: &str, service: &str) -> Cred {
        let mut seed = Zeroizing::new(b"AWS4".to_vec());
        seed.extend_from_slice(self.wire());
        let k_date = hmac_sha256(&seed, datestamp.as_bytes());
        let k_region = hmac_sha256(&k_date[..], region.as_bytes());
        let k_service = hmac_sha256(&k_region[..], service.as_bytes());
        let key = hmac_sha256(&k_service[..], TERMINATION.as_bytes());
        self.derived(Zeroizing::new(key.to_vec()))
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
        let mut hexed = hex::encode(&mac[..]);
        let signature = self.seal(Zeroizing::new(hexed.as_bytes().to_vec()));
        hexed.zeroize();
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
