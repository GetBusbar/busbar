// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4 request signing — hand-rolled with RustCrypto (sha2 + hmac), no AWS
//! SDK, ported unchanged from `busbar-substrate`'s signer. The canonical-request -> string-to-sign
//! -> signature chain is verified against AWS's own published worked example (GET iam ListUsers,
//! 2015-08-30) in the tests, so correctness does not rely on trusting the port.
//!
//! Only the OUTBOUND signer moved here. The neutral crate's INBOUND verification path
//! (`parse_authorization_header`, `verify_inbound_sigv4`, and friends) is an ingress-auth concern —
//! it checks a signature a CLIENT computed against busbar, not one busbar computes for an upstream —
//! and stays where the ingress auth chain lives; porting it into the egress-auth unit would have
//! mixed two different steps of the loop into one crate for no reason. `// contract:` if a future
//! Bedrock-facing ingress plane needs it here too, it is a second, explicit dependency, not a
//! silent inheritance.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
pub const SIGV4_TERMINATION: &str = "aws4_request";
const SIGV4_KEY_PREFIX: &str = "AWS4";

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256 of `data` under `key`. `Hmac::new_from_slice` is infallible for HMAC (the spec
/// accepts a key of any length), so the error arm is unreachable; on it we return an empty digest,
/// which yields a wrong signature and a graceful upstream 403 rather than a panic on the request
/// path.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

/// Derive the SigV4 signing key: HMAC chain over date -> region -> service -> "aws4_request".
fn signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(
        format!("{SIGV4_KEY_PREFIX}{secret}").as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, SIGV4_TERMINATION.as_bytes())
}

/// AWS URI-encode a path, preserving `/`. Unreserved chars (A-Za-z0-9-_.~) pass through; everything
/// else becomes `%XX` (uppercase hex).
pub fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Convert a Unix epoch (seconds) to (amzdate `YYYYMMDDTHHMMSSZ`, datestamp `YYYYMMDD`). Pure UTC,
/// no external date crate (a public-domain civil-from-days algorithm).
pub fn format_amz_time(epoch_secs: u64) -> (String, String) {
    let days = (epoch_secs / SECS_PER_DAY) as i64;
    let sod = epoch_secs % SECS_PER_DAY;
    let (h, mi, s) = (sod / SECS_PER_HOUR, (sod % SECS_PER_HOUR) / 60, sod % 60);

    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    (
        format!("{year:04}{month:02}{day:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

/// Canonicalize a (non-quoted) signed-header value per AWS SigV4: trim leading/trailing ASCII
/// spaces (0x20) and collapse each run of sequential ASCII spaces to a single space. Only the ASCII
/// space character is treated as whitespace — tabs, NBSP, newlines and every other Unicode
/// whitespace codepoint pass through verbatim, because AWS does the same.
fn canonicalize_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
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

/// Compute the SigV4 signature hex + the `SignedHeaders` string for a request. `headers` is the
/// full set of headers to sign (names case-insensitive); they are lowercased + sorted internally.
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or
/// empty).
#[allow(clippy::too_many_arguments)]
pub fn sign_v4(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), canonicalize_header_value(v)))
        .collect();
    h.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{region}/{service}/{SIGV4_TERMINATION}");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret, datestamp, region, service);
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    (signature, signed_headers)
}

#[cfg(test)]
mod tests;
