// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compact-JWS parsing and **signature verification** over `ring` — the workspace's already-vendored
//! crypto backend, so this adds no crate to the tree and no second crypto stack (in particular no
//! `jsonwebtoken`/`rsa`, and therefore none of RUSTSEC-2023-0071's surface).
//!
//! Two algorithms are accepted, the two that IdPs actually sign access tokens with: `RS256`
//! (RSA-PKCS1-SHA256 — Okta, Entra and Auth0's default) and `ES256` (ECDSA-P256-SHA256). Everything
//! else is refused BY NAME rather than by falling through a permissive default, which is what closes
//! the two classic JWT breaks: `alg: none` (an unsigned token that a naive verifier "verifies") and
//! `RS256`→`HS256` key confusion (an HMAC token verified with the public key as the shared secret).
//!
//! This module is PURE: it decides only "did this key sign these bytes". Issuer, expiry, audience
//! and principal policy live in [`super`], because those are resource-server decisions and mixing
//! them in here is how an audience check ends up optional.

use super::jwks::{Jwk, KeyMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

/// The two accepted JWS algorithms, named once so the match arms and the error text cannot drift.
const ALG_RS256: &str = "RS256";
const ALG_ES256: &str = "ES256";

/// Whether `alg` is one this verifier will act on. Exposed so the resource server can refuse an
/// unacceptable algorithm with a NAMED refusal before it ever looks for a key — `alg: none` deserves
/// to be distinguishable in a log from "we could not find the key", and a caller who reaches key
/// selection with an unsupported alg has been carried one step further than necessary.
pub(crate) fn supported_alg(alg: &str) -> bool {
    alg == ALG_RS256 || alg == ALG_ES256
}

/// The decoded header — the fields that select verification.
#[derive(Debug, Deserialize)]
pub(crate) struct Header {
    /// Signature algorithm. Only `RS256` and `ES256` are accepted; see the module doc for why the
    /// rejection is an explicit named arm rather than a fallthrough.
    pub(crate) alg: String,
    /// Key id selecting which key signed this token. Absent is treated as the empty id, which
    /// matches only a keyless key.
    #[serde(default)]
    pub(crate) kid: Option<String>,
    /// RFC 7515 §4.1.11 `crit`: header parameters the producer marks as critical. A verifier that
    /// does not implement every one of them MUST reject the token. This verifier implements none, so
    /// a non-empty `crit` is always a rejection (see [`verify_signature`]).
    #[serde(default)]
    pub(crate) crit: Option<Vec<String>>,
}

/// The three base64url segments of a compact JWS, plus the exact bytes the signature covers.
pub(crate) struct Parts<'a> {
    pub(crate) header: Header,
    /// Raw decoded payload bytes (the claims JSON), deserialized by the caller.
    pub(crate) payload: Vec<u8>,
    /// Decoded signature bytes.
    pub(crate) signature: Vec<u8>,
    /// `header_b64 + "." + payload_b64`, sliced from the transmitted token so the verified bytes are
    /// the bytes that arrived, never a re-encoding of them.
    pub(crate) signing_input: &'a str,
}

/// Split and base64url-decode a compact JWS, decoding the header far enough to select verification.
/// Does NOT verify. A token that is not exactly three segments is refused here — which is also what
/// refuses the two-segment `alg: none` form some libraries emit, before any claim is read.
pub(crate) fn split(token: &str) -> Result<Parts<'_>, String> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed JWT: expected three dot-separated segments".to_string()),
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| "malformed JWT: header is not base64url".to_string())?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("malformed JWT header: {e}"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "malformed JWT: payload is not base64url".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "malformed JWT: signature is not base64url".to_string())?;
    let last_dot = token.rfind('.').expect("token has at least two dots here");
    Ok(Parts {
        header,
        payload,
        signature,
        signing_input: &token[..last_dot],
    })
}

/// Verify `parts` against one key, enforcing that the token's `alg` matches the key type
/// (RS256↔RSA, ES256↔EC) — the alg-confusion guard. `ring`'s verifiers are constant-time.
pub(crate) fn verify_signature(parts: &Parts, key: &Jwk) -> Result<(), String> {
    // A critical header parameter changes how the token must be processed, so it is checked before
    // the signature math rather than after: "the signature was fine but we ignored an instruction we
    // did not understand" is not an acceptable outcome.
    if let Some(crit) = &parts.header.crit {
        if !crit.is_empty() {
            return Err(format!(
                "JWT header names critical extension(s) {crit:?} (RFC 7515 §4.1.11) that this \
                 verifier does not implement; refusing to process the token"
            ));
        }
    }
    // RFC 7517 §4.2: a key published as encryption-only must not verify signatures, however valid
    // its material.
    if key.key_use.as_deref() == Some("enc") {
        return Err(
            "JWKS key has \"use\": \"enc\" (encryption-only) and must not verify signatures"
                .to_string(),
        );
    }
    let alg = parts.header.alg.as_str();
    if alg == ALG_RS256 {
        if key.kty != "RSA" {
            return Err(format!(
                "token alg {ALG_RS256} but JWKS key kty is {} (alg/key-type mismatch)",
                key.kty
            ));
        }
        let (n, e) = match key.material() {
            KeyMaterial::Rsa { n, e } => (n, e),
            KeyMaterial::Unusable(msg) => return Err(msg.clone()),
            // Unreachable: `kty == "RSA"` above pins the memoised material to Rsa or Unusable.
            KeyMaterial::Ec { .. } => {
                return Err("JWKS key material does not match its kty".to_string())
            }
        };
        ring::signature::RsaPublicKeyComponents { n, e }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                parts.signing_input.as_bytes(),
                &parts.signature,
            )
            .map_err(|_| "JWT signature verification failed".to_string())
    } else if alg == ALG_ES256 {
        if key.kty != "EC" {
            return Err(format!(
                "token alg {ALG_ES256} but JWKS key kty is {} (alg/key-type mismatch)",
                key.kty
            ));
        }
        if key.crv.as_deref() != Some("P-256") {
            return Err(format!(
                "{ALG_ES256} requires curve P-256, JWKS key has crv {:?}",
                key.crv
            ));
        }
        let point = match key.material() {
            KeyMaterial::Ec { point } => point,
            KeyMaterial::Unusable(msg) => return Err(msg.clone()),
            KeyMaterial::Rsa { .. } => {
                return Err("JWKS key material does not match its kty".to_string())
            }
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(parts.signing_input.as_bytes(), &parts.signature)
            .map_err(|_| "JWT signature verification failed".to_string())
    } else {
        // `none` (unsigned), `HS*` (accepting a symmetric alg against an asymmetric key IS the
        // key-confusion attack), and everything else.
        Err(format!(
            "unsupported/forbidden JWT alg '{alg}': only {ALG_RS256} and {ALG_ES256} are accepted"
        ))
    }
}
