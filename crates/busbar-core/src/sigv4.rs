// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4 request signing — hand-rolled with RustCrypto (sha2 + hmac), no
//! AWS SDK. Used by the Bedrock protocol writer to sign Converse requests. The core algorithm is
//! verified against AWS's published worked example (GET iam ListUsers, 20150830) in the tests, so
//! the canonical-request → string-to-sign → signature chain is known-correct.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Seconds in a UTC day / hour, for the epoch↔civil-time conversions below. Named rather than bare
/// literals so the time arithmetic reads in canonical units. (`store` and `governance` keep their
/// own copies — layering forbids a cross-module import for a one-line constant.)
const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
/// Used as `SIGV4_TERMINATION` (&str) or `SIGV4_TERMINATION.as_bytes()` (byte slice) so the
/// value is single-sourced even when a byte literal is required.
pub const SIGV4_TERMINATION: &str = "aws4_request";
/// The key-derivation prefix prepended to the secret access key before the first HMAC: `"AWS4"`.
/// Always used via `format!("{SIGV4_KEY_PREFIX}{secret}")`, not mixed into `SIGV4_ALGORITHM`.
const SIGV4_KEY_PREFIX: &str = "AWS4";
/// The canonical lowercase name of the `x-amz-date` header.
pub const X_AMZ_DATE: &str = "x-amz-date";
/// The canonical lowercase name of the `x-amz-content-sha256` header.
pub const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
/// The canonical lowercase name of the `x-amz-security-token` header (STS session credentials).
pub const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";

/// Lowercase hex SHA-256 of `data` — re-exported from the `busbar-api` contract crate (plugins
/// hash credentials under the SAME digest facility).
pub use busbar_api::sha256_hex;

/// HMAC-SHA256 of `data` under `key`. `Hmac::new_from_slice` is infallible for HMAC — the spec
/// accepts a key of ANY length — so the `Err` arm is unreachable. We still avoid `expect()`/panic
/// here because this runs transitively on the Bedrock request hot path (via `sign_v4` →
/// `sign_request`), where the project rule forbids a panic surface: a future refactor that swaps the
/// HMAC impl or key type must not turn a signing-init failure into a task abort. On the unreachable
/// error we return an empty digest, which yields a wrong signature → AWS responds 403 → the caller's
/// existing "misconfigured key" fallback surfaces it as an upstream auth failure, exactly the same
/// graceful path it already takes for an unparseable credential.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Err(e) => {
            tracing::error!(
                "HMAC-SHA256 init failed (unreachable: HMAC accepts any key length): {e}"
            );
            Vec::new()
        }
    }
}

/// Derive the SigV4 signing key: HMAC chain over date → region → service → "aws4_request".
/// File-private: the only caller is `sign_request` below.
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
/// else becomes %XX (uppercase hex). Bedrock model IDs contain `:` and `.`, so the path must be
/// encoded identically in the canonical request and the wire request.
pub fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            // Percent-encode directly into the pre-allocated buffer (no per-byte heap allocation
            // from `format!`). Index into a static hex table — a 4-bit nibble is always 0..=15, so
            // the indexing can never go out of bounds and there is no panic on the request path.
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

    // civil_from_days: days since 1970-01-01 → (year, month, day)
    let z = days + 719_468;
    // The `z < 0` branch is UNREACHABLE for any real `u64 epoch_secs`: `days` (u64::MAX /
    // SECS_PER_DAY, cast to i64) tops out around 2.1e14, far short of i64::MAX (~9.2e18), so `days`
    // can never overflow negative on the cast and `z = days + 719_468` is always positive. Any
    // variation of the `z - 146_096` expression in this branch (`+`/`/` instead of `-`) is
    // therefore unobservable — dead code no `u64`-typed test input can reach — unlike
    // `governance::civil_from_days`, which takes a general `i64` and DOES exercise this branch for
    // pre-1970 dates (see that function's own test table).
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    (
        format!("{year:04}{month:02}{day:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

/// Canonicalize a (non-quoted) signed-header value per AWS SigV4: trim leading/trailing ASCII
/// spaces (0x20) and collapse each run of sequential ASCII spaces to a single space. ONLY the ASCII
/// space character is treated as whitespace — tabs, NBSP (U+00A0), newlines, and every other Unicode
/// whitespace codepoint are preserved verbatim, because AWS does the same. (This is intentionally
/// NOT `split_whitespace`, which would also fold tabs/NBSP/newlines and break the signature.)
fn canonicalize_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut prev_space = false;
    for ch in v.chars() {
        if ch == ' ' {
            // Defer emitting until we know it is not a trailing run; mark that a space is pending.
            prev_space = true;
        } else {
            // Emit a single collapsed space before this non-space char, but only if we have already
            // emitted at least one char (i.e. drop any leading run).
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
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or empty).
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
        // AWS SigV4 canonicalization of a (non-quoted) header value: trim leading/trailing ASCII
        // spaces (0x20) AND collapse runs of sequential ASCII spaces to a single space. AWS operates
        // on ASCII space ONLY — NBSP (U+00A0), tabs, and other Unicode whitespace are NOT treated as
        // whitespace and must pass through verbatim, byte-for-byte, into the signed value. Using
        // `split_whitespace` here would (wrongly) split on tabs/NBSP/newlines and rewrite them to
        // 0x20, producing a canonical value that differs from what AWS computes → SignatureDoesNotMatch
        // (403). `canonicalize_header_value` collapses 0x20 runs only.
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

// ============================================================================================
// INBOUND SigV4 VERIFICATION (the MinIO / S3-compatible model)
// --------------------------------------------------------------------------------------------
// A Bedrock-SDK client signs its request with an AWS-style access-key-id + secret access key that
// busbar issued (tied to a virtual key). To grant that client full virtual-key governance, busbar
// must VERIFY the inbound SigV4 signature itself. Verification RE-USES the exact signing internals
// above (`sign_v4` → `signing_key` → `hmac`, plus `sha256_hex`): we recompute the signature the
// same way the signer does and compare. There is deliberately NO second canonicalization
// implementation — a duplicate could drift from the signer and from AWS, which on the verify path
// is an AUTH BYPASS, not merely a 403. The ONLY verify-specific logic here is PARSING the inbound
// `Authorization` header and assembling `sign_v4`'s inputs from the request; the cryptographic core
// is shared, byte-for-byte, with the outbound signer that is tested against AWS's published example.
// ============================================================================================

/// Allowed clock skew (seconds) between the inbound request's `x-amz-date` and the verifier's clock.
/// AWS itself uses a 5-minute window; matching it rejects replay of a signature captured more than
/// `±CLOCK_SKEW_SECS` ago while tolerating ordinary client/server clock drift. Bounding the age of an
/// accepted signature is the replay defense (busbar does not track nonces).
pub(crate) const CLOCK_SKEW_SECS: u64 = 300;

/// Why an inbound SigV4 verification was rejected. The auth layer maps EVERY variant to the SAME
/// native-vendor auth-failure response (a 403 AccessDenied with no reason prose) — the distinction is
/// for server-side logging ONLY and must never reach the wire, or it becomes an oracle (e.g.
/// distinguishing "unknown AccessKeyId" from "bad signature" would let an attacker enumerate valid
/// AccessKeyIds). The variants carry NO secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// No `Authorization` header, or it is not an `AWS4-HMAC-SHA256` credential.
    MissingAuthorization,
    /// The `Authorization` header is present but structurally malformed (bad Credential/SignedHeaders/
    /// Signature, or a Credential scope that is not `.../aws4_request`).
    MalformedAuthorization,
    /// No usable `x-amz-date` (absent, unparseable, or wrong format).
    MissingDate,
    /// `x-amz-date` is outside the ±`CLOCK_SKEW_SECS` window (stale → possible replay, or far future).
    Expired,
    /// A header named in `SignedHeaders` is not present on the request (cannot reconstruct the
    /// canonical headers the client signed), or the mandatory `host` header is not signed.
    SignedHeadersMismatch,
    /// The recomputed signature did not match the one in the `Authorization` header (wrong secret,
    /// tampered request, or — indistinguishably — an unknown AccessKeyId verified against a dummy
    /// secret).
    SignatureMismatch,
}

/// The parsed components of an inbound SigV4 `Authorization` header. All fields are non-secret (the
/// AccessKeyId and signature both travel in plaintext on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAuthHeader {
    pub(crate) access_key_id: String,
    pub(crate) datestamp: String,
    pub(crate) region: String,
    pub(crate) service: String,
    /// The lowercase, `;`-joined SignedHeaders list, e.g. `host;x-amz-content-sha256;x-amz-date`.
    pub(crate) signed_headers: String,
    /// The hex signature the client computed.
    pub(crate) signature: String,
}

/// Parse an inbound `Authorization: AWS4-HMAC-SHA256 Credential=.../..., SignedHeaders=..., Signature=...`
/// header into its components. Returns `MissingAuthorization` when the value is not an AWS4-HMAC-SHA256
/// credential at all (so a Bearer/Basic header falls through cleanly), and `MalformedAuthorization`
/// when it claims to be SigV4 but is structurally broken.
///
/// The `Credential` field is `AccessKeyId/datestamp/region/service/aws4_request` — five `/`-separated
/// parts, the last of which MUST be `aws4_request`. The three comma-separated sections
/// (Credential / SignedHeaders / Signature) may carry optional surrounding whitespace, which we trim.
pub(crate) fn parse_authorization_header(value: &str) -> Result<ParsedAuthHeader, VerifyError> {
    // The algorithm token and the rest are split on the FIRST space. Match the algorithm
    // case-sensitively against the single spelling AWS uses; anything else is "not SigV4".
    let value = value.trim();
    let Some((algo, rest)) = value.split_once(' ') else {
        return Err(VerifyError::MissingAuthorization);
    };
    if algo != SIGV4_ALGORITHM {
        return Err(VerifyError::MissingAuthorization);
    }

    // Collect the comma-separated key=value sections into a small map. We do NOT rely on order
    // (AWS emits Credential, SignedHeaders, Signature in that order, but tolerate any order here).
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for section in rest.split(',') {
        let section = section.trim();
        let Some((k, v)) = section.split_once('=') else {
            return Err(VerifyError::MalformedAuthorization);
        };
        match k.trim() {
            "Credential" => credential = Some(v.trim().to_string()),
            "SignedHeaders" => signed_headers = Some(v.trim().to_string()),
            "Signature" => signature = Some(v.trim().to_string()),
            // An unknown section key is SKIPPED, not rejected: AWS SigV4 clients may legitimately emit
            // extra/unknown sections in the Authorization header, and the signature itself binds the
            // request (an attacker cannot forge a valid one by adding sections). The three MANDATORY
            // sections (Credential, SignedHeaders, Signature) are still required below, and all
            // existing strictness on those fields is unchanged.
            _ => continue,
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) =
        (credential, signed_headers, signature)
    else {
        return Err(VerifyError::MalformedAuthorization);
    };
    if signature.is_empty() || signed_headers.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    // Credential = AccessKeyId/datestamp/region/service/aws4_request (exactly five parts).
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != SIGV4_TERMINATION {
        return Err(VerifyError::MalformedAuthorization);
    }
    let access_key_id = parts[0].to_string();
    let datestamp = parts[1].to_string();
    let region = parts[2].to_string();
    let service = parts[3].to_string();
    if access_key_id.is_empty() || datestamp.is_empty() || region.is_empty() || service.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    Ok(ParsedAuthHeader {
        access_key_id,
        datestamp,
        region,
        service,
        signed_headers,
        signature,
    })
}

/// Parse an `x-amz-date` value (`YYYYMMDDTHHMMSSZ`, basic ISO-8601 UTC) into a Unix epoch (seconds).
/// Returns `None` on any format deviation. Self-contained (a civil-date computation, the inverse of
/// `format_amz_time`); no external date crate. Used to bound the signature's age (clock-skew check).
fn parse_amz_date(amzdate: &str) -> Option<u64> {
    // Exact shape: 8 digits, 'T', 6 digits, 'Z' — 16 chars total. Reject anything else.
    let b = amzdate.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    // The slices below index by char position; guard against a non-ASCII multi-byte char straddling a
    // boundary (`amzdate[0..4]` etc. would panic). The valid format is pure ASCII (digits + 'T'/'Z'),
    // so any non-ASCII byte is already invalid. (Defense-in-depth: callers feed `HeaderValue::to_str`,
    // which today rejects non-ASCII before this — but the guarantee now lives locally, not implicitly.)
    if !amzdate.is_ascii() {
        return None;
    }
    let digits = |s: &str| -> Option<i64> {
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    };
    let year = digits(&amzdate[0..4])?;
    let month = digits(&amzdate[4..6])?;
    let day = digits(&amzdate[6..8])?;
    let hour = digits(&amzdate[9..11])?;
    let min = digits(&amzdate[11..13])?;
    let sec = digits(&amzdate[13..15])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (public-domain, inverse of format_amz_time's civil_from_days).
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * SECS_PER_DAY as i64 + hour * SECS_PER_HOUR as i64 + min * 60 + sec;
    if epoch < 0 {
        return None;
    }
    Some(epoch as u64)
}

/// The fully-assembled inputs for verifying ONE inbound SigV4 request. The caller (the auth layer)
/// extracts these from the live HTTP request; the verifier owns none of the HTTP types so it stays
/// trivially testable. `canonical_uri` MUST already be URI-encoded the SAME way the signer encodes it
/// (use [`uri_encode_path`]); `canonical_querystring` MUST be the sorted+encoded query string (or
/// empty). `headers` carries the ACTUAL request header values for (at least) every name in the parsed
/// `SignedHeaders` list; extra headers are ignored (only the signed ones enter the canonical request).
pub(crate) struct InboundRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) canonical_uri: &'a str,
    pub(crate) canonical_querystring: &'a str,
    /// (name, value) pairs from the request; names case-insensitive. Must include every signed header.
    pub(crate) headers: &'a [(String, String)],
    /// The hex SHA-256 payload hash the client signed (its `x-amz-content-sha256` header value).
    pub(crate) payload_hash: &'a str,
    /// The request's `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
    pub(crate) amzdate: &'a str,
}

/// Verify an inbound SigV4 signature against a candidate `secret`, at wall-clock `now` (Unix seconds).
///
/// This is the SECURITY-CRITICAL core. It:
///   1. validates `x-amz-date` is within ±`CLOCK_SKEW_SECS` of `now` (replay/skew bound),
///   2. confirms the Credential's `datestamp` agrees with `x-amz-date`'s date (a signer always
///      derives the scope datestamp from the same timestamp),
///   3. selects EXACTLY the headers named in `SignedHeaders` from the request (rejecting if any is
///      absent, or if `host` is not among them — `host` MUST be signed),
///   4. recomputes the signature via the shared [`sign_v4`] (NO duplicate canonicalization), and
///   5. constant-time-compares the recomputed signature to the client's, AND constant-time-compares
///      the recomputed SignedHeaders string to the client's claimed one.
///
/// Returns `Ok(())` only when every check passes. The comparison uses
/// `crate::auth::AuthMiddleware::constant_time_eq` (the single constant-time primitive) so a partial
/// match cannot be recovered by timing. The caller MUST invoke this even for an UNKNOWN AccessKeyId
/// (with a dummy secret) so the unknown-key and bad-signature paths are timing/response
/// indistinguishable (no AccessKeyId-enumeration oracle).
pub(crate) fn verify_inbound_sigv4(
    parsed: &ParsedAuthHeader,
    req: &InboundRequest<'_>,
    secret: &str,
    now: u64,
) -> Result<(), VerifyError> {
    // (1) Clock-skew / replay bound on x-amz-date.
    let Some(req_epoch) = parse_amz_date(req.amzdate) else {
        return Err(VerifyError::MissingDate);
    };
    let skew = req_epoch.abs_diff(now);
    if skew > CLOCK_SKEW_SECS {
        return Err(VerifyError::Expired);
    }

    // (2) The Credential scope datestamp must match x-amz-date's date (YYYYMMDD prefix). A signer
    // derives both from one timestamp, so a mismatch is a malformed/forged credential. (Also ensures
    // the datestamp we feed `sign_v4` is the one the client used.)
    if req.amzdate.len() < 8 || parsed.datestamp != req.amzdate[0..8] {
        return Err(VerifyError::MalformedAuthorization);
    }

    // (3) Select exactly the signed headers, in the order the client listed them, taking each value
    // from the request. The signed-headers list is lowercase by construction (the signer lowercases);
    // match request header names case-insensitively. A missing signed header → cannot reconstruct →
    // reject. `host` MUST be signed (AWS requires it; an unsigned host would let a signature be
    // replayed against a different target).
    let signed: Vec<&str> = parsed.signed_headers.split(';').collect();
    if !signed.iter().any(|h| h.eq_ignore_ascii_case("host")) {
        return Err(VerifyError::SignedHeadersMismatch);
    }
    let mut selected: Vec<(String, String)> = Vec::with_capacity(signed.len());
    for name in &signed {
        let lname = name.to_ascii_lowercase();
        let Some((_, value)) = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lname))
        else {
            return Err(VerifyError::SignedHeadersMismatch);
        };
        selected.push((lname, value.clone()));
    }

    // (4) Recompute via the SHARED signer — same canonicalization, byte-for-byte. `sign_v4` lowercases
    // + sorts the headers and derives its own SignedHeaders string from them.
    let (computed_sig, computed_signed_headers) = sign_v4(
        secret,
        &parsed.region,
        &parsed.service,
        req.method,
        req.canonical_uri,
        req.canonical_querystring,
        &selected,
        req.payload_hash,
        req.amzdate,
        &parsed.datestamp,
    );

    // (5) Constant-time compare BOTH the SignedHeaders string the client claimed and the signature.
    // The SignedHeaders compare catches a client that lists headers in a non-sorted order or includes
    // a name it did not actually fold into the canonical request — a mismatch there means our
    // reconstruction would diverge from theirs. Run BOTH compares unconditionally (no `&&`
    // short-circuit) and fold with bitwise-OR-of-inverses so the work — and thus the timing — does not
    // depend on WHICH check failed; only the final all-pass boolean is observable.
    let headers_ok = crate::auth::AuthMiddleware::constant_time_eq(
        &computed_signed_headers,
        &parsed.signed_headers,
    );
    let sig_ok = crate::auth::AuthMiddleware::constant_time_eq(&computed_sig, &parsed.signature);
    if std::hint::black_box(u8::from(headers_ok) & u8::from(sig_ok)) == 1 {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
#[path = "tests/sigv4_tests.rs"]
mod tests;
