// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH LOGIN KIT'S SHARED CHECKS: what every login plugin that runs its own token exchange
//! must check the same way. v1.5.5 ran these ONCE, in the core's callback, for every login module
//! (v1.5.5 `auth/token.rs:529-540`); the exchange is the plugin's now (`abi::auth` `complete_login`),
//! so the one copy lives here and every login plugin calls it.

use crate::redacted::constant_time_eq;

/// The login's security check failed: a plugin answers `complete_login` with
/// [`LOGIN_SECURITY_CHECK_FAILED`](crate::abi::auth::LOGIN_SECURITY_CHECK_FAILED), and no identity
/// is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityCheckFailed;

/// THE ID-TOKEN NONCE BINDING, with v1.5.5's semantics, over one token-endpoint response body. A
/// BINDING ONLY, never a verification: it does not check the token's signature, issuer, audience
/// or expiry, and a body that passes it proves nothing about who signed the token. Whether the
/// token is authentic stays the login plugin's own job (its key-set check), before any identity is
/// trusted.
///
///
/// * the body carries no `id_token` (not a JSON object with a string `id_token`): `Ok`;
/// * it carries one: its payload's `nonce` claim is read UNVERIFIED (the plugin verifies the
///   token's issuer, audience, expiry and signature itself; this binds only the nonce the core
///   minted at `begin_login`) and compared with `expected` in constant time: equal is `Ok`;
/// * the claim absent, unreadable or unequal, or `expected` absent while an `id_token` is present:
///   `Err` (fail closed).
///
/// # Errors
/// [`SecurityCheckFailed`], as above.
pub fn check_hop_nonce(hop_body: &[u8], expected: Option<&str>) -> Result<(), SecurityCheckFailed> {
    let Some(id_token) = id_token(hop_body) else {
        return Ok(());
    };
    let Some(expected) = expected else {
        return Err(SecurityCheckFailed);
    };
    match nonce(&id_token) {
        Some(n) if constant_time_eq(&n, expected) => Ok(()),
        _ => Err(SecurityCheckFailed),
    }
}

/// The `id_token` string of a token-endpoint JSON body, if present (v1.5.5 `extract_id_token`).
fn id_token(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("id_token")?.as_str().map(str::to_string)
}

/// A JWT's payload `nonce` claim, unverified (v1.5.5 `id_token_nonce`).
fn nonce(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = b64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("nonce")?.as_str().map(str::to_string)
}

/// Strict unpadded base64url, as v1.5.5 decoded (`URL_SAFE_NO_PAD`): the URL-safe alphabet only, no
/// `=`, no length of 1 mod 4, and the final character's unused bits zero.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        }))
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                if acc & 0x3 != 0 {
                    return None;
                }
                out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]);
            }
            2 => {
                if acc & 0xF != 0 {
                    return None;
                }
                out.push((acc >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "tests/login_tests.rs"]
mod tests;
