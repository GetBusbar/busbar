// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4 request signing — hand-rolled with RustCrypto (sha2 + hmac), no AWS
//! SDK. MOVED VERBATIM from the identity unit's `egress_auth/sigv4/mod.rs` in the kernel, staged
//! `busbar-auth-outbound::sigv4` (KERNEL<>PLUGINS step 22), then here (AUTH-SPLIT: sigv4 is its
//! own mechanism, its own crate): the canonical-request -> string-to-sign -> signature chain is
//! verified against AWS's own published worked example (GET iam ListUsers, 2015-08-30) in the
//! tests, so correctness does not rely on trusting the move.
//!
//! Two changes, both at the edge of the chain and neither touching a signed byte:
//!
//! * THE DAILY KEY (BUSBAR-1.6.0.md THE DESIGN, §6.5: "SigV4 signs per request with a daily signing key derived
//!   ahead of time"): [`sign_v4`] is split into [`signing_key`] (the HMAC chain over date, region,
//!   service) and [`sign_v4_with_key`] (the per-request part), so a caller holding the day's key
//!   signs without re-deriving it. [`sign_v4`] is the two composed, exactly the old function.
//! * THE SECRET IS ZEROISED (TODO item 586, #53/#54): the `AWS4<secret>` key material and every
//!   derived key are [`Zeroizing`] buffers, wiped on drop.
//!
//! Only the OUTBOUND signer lives here; inbound SigV4 verification is an ingress-auth concern.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
pub const SIGNATURE_TERMINATION: &str = "aws4_request";
const SIGNATURE_KEY_PREFIX: &str = "AWS4";

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256 of `data` under `key`. `Hmac::new_from_slice` is infallible for HMAC (the spec
/// accepts a key of any length), so the error arm is unreachable; on it we return an empty digest,
/// which yields a wrong signature and a graceful upstream 403 rather than a panic on the request
/// path.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

/// Derive the SigV4 signing key: HMAC chain over date -> region -> service -> "aws4_request".
/// Every intermediate key, and the `AWS4<secret>` seed, is wiped on drop.
pub(crate) fn signing_key(
    secret: &str,
    datestamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let seed = Zeroizing::new(format!("{SIGNATURE_KEY_PREFIX}{secret}"));
    let k_date = Zeroizing::new(hmac(seed.as_bytes(), datestamp.as_bytes()));
    let k_region = Zeroizing::new(hmac(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac(&k_region, service.as_bytes()));
    Zeroizing::new(hmac(&k_service, SIGNATURE_TERMINATION.as_bytes()))
}

/// Convert a epoch (1970-01-01 UTC) (seconds) to (amzdate `YYYYMMDDTHHMMSSZ`, datestamp `YYYYMMDD`). Pure UTC,
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
/// empty). The day's key derived here, then [`sign_v4_with_key`]: the composition the published
/// vector pins (the request path holds the day's key and calls [`sign_v4_with_key`] itself).
#[cfg(test)]
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
    let key = signing_key(secret, datestamp, region, service);
    sign_v4_with_key(
        &key,
        region,
        service,
        method,
        canonical_uri,
        canonical_querystring,
        headers,
        payload_hash,
        amzdate,
        datestamp,
    )
}

/// [`sign_v4`] under an already-derived [`signing_key`] for the request's date, region and service:
/// the signature hex + the `SignedHeaders` string for a request. `headers` is the
/// full set of headers to sign (names case-insensitive); they are lowercased + sorted internally.
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or
/// empty).
#[allow(clippy::too_many_arguments)]
pub fn sign_v4_with_key(
    key: &[u8],
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

    // The SigV4 canonicalisation rule does not sort the values of a header that appears more than
    // once; it combines them into one comma-separated list under that header's single entry. A
    // caller CAN hand this function the same name twice (`decorate` builds its header list by
    // pushing onto whatever the envelope already carries), so merging here rather than assuming the
    // caller never repeats a name is what keeps `SignedHeaders` and the canonical headers block in
    // the one-entry-per-name shape AWS's servers expect. The sort above already made same-named
    // entries adjacent, so a single pass merges them in their original relative order.
    let mut merged: Vec<(String, String)> = Vec::with_capacity(h.len());
    for (k, v) in h {
        match merged.last_mut() {
            Some((last_k, last_v)) if *last_k == k => {
                last_v.push(',');
                last_v.push_str(&v);
            }
            _ => merged.push((k, v)),
        }
    }
    let h = merged;

    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{region}/{service}/{SIGNATURE_TERMINATION}");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = hex::encode(hmac(key, string_to_sign.as_bytes()));
    (signature, signed_headers)
}

/// Split a signing lane's configured credential, `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`, into its
/// three parts: the non-secret access key id, the signing secret, and the optional session token
/// (everything after the second `:`, colons included). `None` — sign nothing — when either of the
/// first two is missing or empty, the same misconfiguration rule the dialect writer applied when it
/// parsed this string itself.
pub fn split_credential(raw: &str) -> Option<(&str, &str, Option<&str>)> {
    let mut parts = raw.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(access), Some(secret), token) if !access.is_empty() && !secret.is_empty() => {
            Some((access, secret, token))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/sigv4_tests.rs"]
mod tests;
