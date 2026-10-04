// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNATURES THEMSELVES, as pure functions: what each variant signs, and the constant-time
//! check of a presented signature against it. No ABI, no settings, no I/O. The HMACs are `ring`'s;
//! every comparison of a MAC is `ring::hmac::verify` (constant-time).
//!
//! * `twilio` (Twilio's published request-validation algorithm): HMAC-SHA1, keyed by the account's
//!   auth token, over the full URL Twilio requested followed by every POST form parameter as `name`
//!   then `value`, sorted by name; base64 (standard, padded) in `X-Twilio-Signature`. A request
//!   whose URL carries `bodySHA256` (a JSON body) signs the URL alone and binds the body through
//!   that parameter: the SHA-256 of the body, lower-case hex. A WebSocket upgrade is a GET: its
//!   signed string is the URL.
//! * `standard-webhooks` (the Standard Webhooks specification):
//!   HMAC-SHA256, keyed by the base64 secret (an optional `whsec_` prefix stripped), over
//!   `{webhook-id}.{webhook-timestamp}.{body}`; `webhook-signature` is a space-separated list of
//!   `v1,<base64>` entries, any one of which may match; the timestamp must be within a tolerance
//!   of now, in either direction (replay).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::hmac;

// ── twilio ──────────────────────────────────────────────────────────────────────────────────────

/// The string a `twilio` signature is computed over: `url`, then each parameter's name and value,
/// as Twilio's reference validators build it — the DISTINCT names sorted, and under each name its
/// DISTINCT values sorted (a repeated identical `name=value` pair is signed once).
#[must_use]
pub fn twilio_signed_string(url: &[u8], params: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut by_name: std::collections::BTreeMap<&[u8], std::collections::BTreeSet<&[u8]>> =
        std::collections::BTreeMap::new();
    for (name, value) in params {
        by_name.entry(name).or_default().insert(value);
    }
    let mut out = url.to_vec();
    for (name, values) in by_name {
        for value in values {
            out.extend_from_slice(name);
            out.extend_from_slice(value);
        }
    }
    out
}

fn twilio_key(secret: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret)
}

/// The `twilio` signature of `url` and `params` under `secret`, base64 as Twilio presents it.
#[must_use]
pub fn twilio_sign(secret: &[u8], url: &[u8], params: &[(Vec<u8>, Vec<u8>)]) -> String {
    let tag = hmac::sign(&twilio_key(secret), &twilio_signed_string(url, params));
    STANDARD.encode(tag.as_ref())
}

/// Whether `presented` (the header value, base64) is the `twilio` signature of `url` and `params`
/// under `secret`. A value that is not base64 is simply not the signature.
#[must_use]
pub fn twilio_verify(
    secret: &[u8],
    url: &[u8],
    params: &[(Vec<u8>, Vec<u8>)],
    presented: &[u8],
) -> bool {
    let Ok(tag) = STANDARD.decode(presented.trim_ascii()) else {
        return false;
    };
    hmac::verify(
        &twilio_key(secret),
        &twilio_signed_string(url, params),
        &tag,
    )
    .is_ok()
}

/// An `application/x-www-form-urlencoded` body as Twilio signs it: each `name=value` pair
/// percent-decoded (`+` is a space). `None` = not a form body (a malformed escape).
#[must_use]
pub fn form_params(body: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    body.split(|b| *b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = match pair.iter().position(|b| *b == b'=') {
                Some(at) => (&pair[..at], &pair[at + 1..]),
                None => (pair, &b""[..]),
            };
            Some((form_decode(name)?, form_decode(value)?))
        })
        .collect()
}

fn form_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                let hi = char::from(hex[0]).to_digit(16)?;
                let lo = char::from(hex[1]).to_digit(16)?;
                out.push(u8::try_from(hi * 16 + lo).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    Some(out)
}

/// The value of query parameter `name` in `query` (raw, not decoded); `None` = absent.
#[must_use]
pub fn query_param<'q>(query: &'q [u8], name: &[u8]) -> Option<&'q [u8]> {
    query.split(|b| *b == b'&').find_map(|pair| {
        let at = pair.iter().position(|b| *b == b'=')?;
        (&pair[..at] == name).then_some(&pair[at + 1..])
    })
}

/// Whether `expected_hex` (from `bodySHA256`) is the SHA-256 of `body`, hex (either case). Not a
/// secret comparison: the digest of the body is public, and what authenticates it is the signature
/// over the URL that carries it.
#[must_use]
pub fn body_sha256_matches(body: &[u8], expected_hex: &[u8]) -> bool {
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    let hex = |n: u8| b"0123456789abcdef"[usize::from(n)];
    expected_hex.len() == 64
        && digest
            .as_ref()
            .iter()
            .flat_map(|b| [hex(b >> 4), hex(b & 0xf)])
            .zip(expected_hex)
            .all(|(want, got)| want == got.to_ascii_lowercase())
}

// ── standard-webhooks ───────────────────────────────────────────────────────────────────────────

/// The signing key of a Standard Webhooks secret: base64, with an optional `whsec_` prefix.
/// `None` = not base64, or empty.
#[must_use]
pub fn standard_webhooks_key(secret: &[u8]) -> Option<Vec<u8>> {
    let b64 = secret.strip_prefix(b"whsec_").unwrap_or(secret);
    STANDARD
        .decode(b64.trim_ascii())
        .ok()
        .filter(|k| !k.is_empty())
}

fn standard_webhooks_signed(id: &[u8], timestamp: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + timestamp.len() + body.len() + 2);
    out.extend_from_slice(id);
    out.push(b'.');
    out.extend_from_slice(timestamp);
    out.push(b'.');
    out.extend_from_slice(body);
    out
}

/// The `v1,<base64>` signature of one message under `key` (the decoded secret).
#[must_use]
pub fn standard_webhooks_sign(key: &[u8], id: &[u8], timestamp: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, &standard_webhooks_signed(id, timestamp, body));
    format!("v1,{}", STANDARD.encode(tag.as_ref()))
}

/// Why a Standard Webhooks message did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardWebhooksRefusal {
    /// `webhook-timestamp` is not a decimal count of seconds.
    BadTimestamp,
    /// The timestamp is further than the tolerance from now (either direction).
    Stale,
    /// No `v1` entry of `webhook-signature` matches.
    BadSignature,
}

/// Verify one Standard Webhooks message: `signatures` is the `webhook-signature` header (a
/// space-separated list of `version,base64` entries; only `v1` is judged), `now` the wall clock in
/// seconds, `tolerance_secs` the allowed skew either way.
///
/// # Errors
/// The timestamp is malformed or outside the tolerance, or no `v1` entry matches.
pub fn standard_webhooks_verify(
    key: &[u8],
    id: &[u8],
    timestamp: &[u8],
    body: &[u8],
    signatures: &[u8],
    now: u64,
    tolerance_secs: u64,
) -> Result<(), StandardWebhooksRefusal> {
    let ts: u64 = std::str::from_utf8(timestamp.trim_ascii())
        .ok()
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse().ok())
        .ok_or(StandardWebhooksRefusal::BadTimestamp)?;
    if now.abs_diff(ts) > tolerance_secs {
        return Err(StandardWebhooksRefusal::Stale);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let signed = standard_webhooks_signed(id, timestamp.trim_ascii(), body);
    let matched = signatures
        .split(|b| *b == b' ')
        .filter_map(|entry| entry.strip_prefix(b"v1,"))
        .filter_map(|b64| STANDARD.decode(b64).ok())
        .any(|tag| hmac::verify(&key, &signed, &tag).is_ok());
    if matched {
        Ok(())
    } else {
        Err(StandardWebhooksRefusal::BadSignature)
    }
}

#[cfg(test)]
#[path = "tests/signature_tests.rs"]
mod tests;
