//! Independent conformance harness for the busbar OAuth 2.1 authorization server.
//!
//! This crate contains NO code from `crates/oauth-as` and never links against it. It sees the
//! AS only as a black box over HTTP, exactly as a third-party client would. Three layers:
//!
//! 1. Vendored, pinned RFC test vectors (see `vectors/rfc_vectors.json`, each entry cites its
//!    RFC section). These prove the CHECKERS themselves are grounded in the published vectors,
//!    not in this repo's beliefs.
//! 2. Machine-checkable response-shape validators in this module, one per RFC-defined shape.
//!    They return a list of violations so a failing test names every deviation at once.
//! 3. Black-box tests (`tests/`) that drive the live AS, including a full device-code flow and
//!    a full authorization-code-with-PKCE flow executed by the pinned third-party `oauth2`
//!    crate, which independently judges spec legality.
//!
//! # Black-box target contract (ASSUMPTIONS, all RFC-standard)
//!
//! The harness discovers every endpoint from the RFC 8414 metadata document at
//! `{base}/.well-known/oauth-authorization-server`; nothing else is hard-coded. The AS process
//! itself is launched by `scripts/oauth-conformance.sh`, which assumes:
//!
//! * `cargo run -p oauth-as` starts an HTTP server, binding the address given in the
//!   `OAUTH_AS_ADDR` environment variable (default expected `127.0.0.1:8914`).
//! * With `OAUTH_AS_CONFORMANCE_SEED=1` the AS seeds deterministic test fixtures:
//!   * a PUBLIC client `conformance-public` with redirect URI `http://127.0.0.1:8917/cb`,
//!     allowed grants `authorization_code` (PKCE required) and
//!     `urn:ietf:params:oauth:grant-type:device_code`;
//!   * a CONFIDENTIAL client `conformance-confidential` with secret
//!     `conformance-secret-0123456789abcdef` using `client_secret_basic`;
//!   * auto-approval: a valid, complete authorization request for a seeded client returns the
//!     302 redirect with `code` immediately (no interactive login), acting as test user
//!     `conformance-user`;
//!   * device approval: an HTTP POST of form field `user_code` to the advertised
//!     `verification_uri` approves that device authorization.
//!
//! If the AS is absent or does not honor this contract the harness FAILS LOUDLY; it never
//! skips silently.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

/// The vendored RFC vector file, pinned in-tree. See its `_provenance` field.
pub const RFC_VECTORS_JSON: &str = include_str!("../vectors/rfc_vectors.json");

/// Parse the vendored vector file. Panics on corruption: a harness whose own fixtures do not
/// parse must never report green.
#[must_use]
pub fn rfc_vectors() -> Value {
    serde_json::from_str(RFC_VECTORS_JSON)
        .expect("vendored vectors/rfc_vectors.json must parse; the harness fixture is corrupt")
}

/// base64url without padding, as required by RFC 7636 s4.1 and RFC 7515 s2.
#[must_use]
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url without padding.
///
/// # Errors
/// Returns the decoder's message when `s` is not valid unpadded base64url.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())
}

/// RFC 7636 s4.2: `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`.
#[must_use]
pub fn pkce_s256_challenge(verifier: &str) -> String {
    use sha2::{Digest as _, Sha256};
    b64url(&Sha256::digest(verifier.as_bytes()))
}

/// The RFC 6749 s5.2 token-endpoint error codes, plus the RFC 8628 s3.5 device-flow additions.
pub const TOKEN_ERROR_CODES: &[&str] = &[
    // RFC 6749 s5.2
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    // RFC 8628 s3.5
    "authorization_pending",
    "slow_down",
    "access_denied",
    "expired_token",
];

fn require_string(obj: &Value, key: &str, out: &mut Vec<String>, cite: &str) {
    match obj.get(key) {
        None => out.push(format!("missing required member \"{key}\" ({cite})")),
        Some(Value::String(_)) => {}
        Some(other) => out.push(format!(
            "member \"{key}\" must be a JSON string, got {other} ({cite})"
        )),
    }
}

fn optional_string(obj: &Value, key: &str, out: &mut Vec<String>, cite: &str) {
    if let Some(v) = obj.get(key) {
        if !v.is_string() {
            out.push(format!(
                "member \"{key}\" must be a JSON string when present, got {v} ({cite})"
            ));
        }
    }
}

fn optional_number(obj: &Value, key: &str, out: &mut Vec<String>, cite: &str) {
    if let Some(v) = obj.get(key) {
        if !v.is_number() {
            out.push(format!(
                "member \"{key}\" must be a JSON number when present, got {v} ({cite})"
            ));
        }
    }
}

/// Validate an error response body against RFC 6749 s5.2 (with the RFC 8628 s3.5 device-flow
/// error codes also admitted). Returns every violation found; empty means conformant.
#[must_use]
pub fn validate_error_body(body: &Value) -> Vec<String> {
    let mut v = Vec::new();
    if !body.is_object() {
        v.push(format!(
            "error body must be a JSON object (RFC 6749 s5.2), got {body}"
        ));
        return v;
    }
    require_string(body, "error", &mut v, "RFC 6749 s5.2");
    if let Some(Value::String(code)) = body.get("error") {
        if !TOKEN_ERROR_CODES.contains(&code.as_str()) {
            v.push(format!(
                "error code \"{code}\" is not one of the RFC 6749 s5.2 / RFC 8628 s3.5 codes"
            ));
        }
    }
    optional_string(body, "error_description", &mut v, "RFC 6749 s5.2");
    optional_string(body, "error_uri", &mut v, "RFC 6749 s5.2");
    if let Some(Value::String(d)) = body.get("error_description") {
        // RFC 6749 s5.2: %x20-21 / %x23-5B / %x5D-7E
        if d.chars().any(|c| {
            let u = c as u32;
            !(0x20..=0x7e).contains(&u) || u == 0x22 || u == 0x5c
        }) {
            v.push(
                "error_description contains characters outside %x20-21 / %x23-5B / %x5D-7E \
                 (RFC 6749 s5.2)"
                    .to_string(),
            );
        }
    }
    v
}

/// Validate a successful token response body against RFC 6749 s5.1.
#[must_use]
pub fn validate_token_response(body: &Value) -> Vec<String> {
    let mut v = Vec::new();
    if !body.is_object() {
        v.push(format!(
            "token response must be a JSON object (RFC 6749 s5.1), got {body}"
        ));
        return v;
    }
    require_string(body, "access_token", &mut v, "RFC 6749 s5.1");
    require_string(body, "token_type", &mut v, "RFC 6749 s5.1");
    if let Some(Value::String(t)) = body.get("token_type") {
        if !t.eq_ignore_ascii_case("bearer") && !t.eq_ignore_ascii_case("dpop") {
            v.push(format!(
                "token_type \"{t}\" is neither Bearer (RFC 6750) nor DPoP (RFC 9449)"
            ));
        }
    }
    optional_number(body, "expires_in", &mut v, "RFC 6749 s5.1");
    optional_string(body, "refresh_token", &mut v, "RFC 6749 s5.1");
    optional_string(body, "scope", &mut v, "RFC 6749 s5.1");
    v
}

/// Validate a device authorization response against RFC 8628 s3.2.
#[must_use]
pub fn validate_device_authorization_response(body: &Value) -> Vec<String> {
    let mut v = Vec::new();
    if !body.is_object() {
        v.push(format!(
            "device authorization response must be a JSON object (RFC 8628 s3.2), got {body}"
        ));
        return v;
    }
    require_string(body, "device_code", &mut v, "RFC 8628 s3.2");
    require_string(body, "user_code", &mut v, "RFC 8628 s3.2");
    require_string(body, "verification_uri", &mut v, "RFC 8628 s3.2");
    optional_string(body, "verification_uri_complete", &mut v, "RFC 8628 s3.2");
    match body.get("expires_in") {
        None => v.push("missing required member \"expires_in\" (RFC 8628 s3.2)".to_string()),
        Some(x) if !x.is_number() => {
            v.push(format!(
                "member \"expires_in\" must be a JSON number, got {x} (RFC 8628 s3.2)"
            ));
        }
        _ => {}
    }
    optional_number(body, "interval", &mut v, "RFC 8628 s3.2");
    if let Some(Value::String(u)) = body.get("verification_uri") {
        if url::Url::parse(u).is_err() {
            v.push(format!(
                "verification_uri \"{u}\" is not a valid URI (RFC 8628 s3.2)"
            ));
        }
    }
    v
}

/// Validate an RFC 8414 authorization server metadata document for an OAuth 2.1 AS that
/// supports the device grant. `expected_issuer` is the URL the document was fetched from,
/// without the well-known component (RFC 8414 s3.3 requires the issuer to match).
#[must_use]
pub fn validate_as_metadata(body: &Value, expected_issuer: &str) -> Vec<String> {
    let mut v = Vec::new();
    if !body.is_object() {
        v.push(format!(
            "metadata must be a JSON object (RFC 8414 s2), got {body}"
        ));
        return v;
    }
    require_string(body, "issuer", &mut v, "RFC 8414 s2 (REQUIRED)");
    if let Some(Value::String(iss)) = body.get("issuer") {
        if iss.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
            v.push(format!(
                "issuer \"{iss}\" does not match the URL the metadata was retrieved from \
                 \"{expected_issuer}\" (RFC 8414 s3.3)"
            ));
        }
        if iss.contains('?') || iss.contains('#') {
            v.push("issuer must have no query or fragment (RFC 8414 s2)".to_string());
        }
    }
    // REQUIRED for an AS supporting the authorization code grant (RFC 8414 s2).
    require_string(body, "authorization_endpoint", &mut v, "RFC 8414 s2");
    require_string(body, "token_endpoint", &mut v, "RFC 8414 s2");
    // RFC 8628 s4: device flow support is advertised via device_authorization_endpoint.
    require_string(body, "device_authorization_endpoint", &mut v, "RFC 8628 s4");
    match body.get("response_types_supported") {
        None => v.push("missing required member \"response_types_supported\" (RFC 8414 s2)".into()),
        Some(Value::Array(a)) => {
            if !a.iter().any(|x| x == "code") {
                v.push(
                    "response_types_supported must include \"code\" for an OAuth 2.1 AS \
                     (RFC 8414 s2; OAuth 2.1 removes the implicit grant)"
                        .to_string(),
                );
            }
        }
        Some(other) => v.push(format!(
            "response_types_supported must be a JSON array, got {other} (RFC 8414 s2)"
        )),
    }
    if let Some(g) = body.get("grant_types_supported") {
        match g {
            Value::Array(a) => {
                for needed in [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ] {
                    if !a.iter().any(|x| x == needed) {
                        v.push(format!(
                            "grant_types_supported must include \"{needed}\" (RFC 8414 s2; \
                             device grant per RFC 8628)"
                        ));
                    }
                }
            }
            other => v.push(format!(
                "grant_types_supported must be a JSON array, got {other} (RFC 8414 s2)"
            )),
        }
    }
    match body.get("code_challenge_methods_supported") {
        None => v.push(
            "missing code_challenge_methods_supported; OAuth 2.1 requires PKCE support and \
             RFC 8414 s2 defines how it is advertised"
                .to_string(),
        ),
        Some(Value::Array(a)) => {
            if !a.iter().any(|x| x == "S256") {
                v.push(
                    "code_challenge_methods_supported must include \"S256\" (RFC 7636 s4.2; \
                     OAuth 2.1 makes S256 the baseline)"
                        .to_string(),
                );
            }
        }
        Some(other) => v.push(format!(
            "code_challenge_methods_supported must be a JSON array, got {other} (RFC 8414 s2)"
        )),
    }
    for key in [
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "jwks_uri",
        "revocation_endpoint",
        "introspection_endpoint",
    ] {
        if let Some(Value::String(u)) = body.get(key) {
            if url::Url::parse(u).is_err() {
                v.push(format!("{key} \"{u}\" is not a valid URL (RFC 8414 s2)"));
            }
        }
    }
    v
}

/// Split a compact JWS into (header JSON, payload JSON, signature bytes present).
///
/// # Errors
/// Returns a message when the token is not three base64url parts of valid JSON.
pub fn decode_jwt_unverified(token: &str) -> Result<(Value, Value), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "JWT must have exactly 3 dot-separated parts (RFC 7515 s3.1), got {}",
            parts.len()
        ));
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?)
        .map_err(|e| format!("JWS protected header is not valid JSON: {e}"))?;
    let payload: Value = serde_json::from_slice(&b64url_decode(parts[1])?)
        .map_err(|e| format!("JWS payload is not valid JSON: {e}"))?;
    b64url_decode(parts[2])?;
    Ok((header, payload))
}

/// Validate an access token's structure against RFC 9068 s2.1 (header) and s2.2 (claims).
/// Signature verification against the AS jwks_uri is done separately in the black-box tests.
#[must_use]
pub fn validate_rfc9068_access_token(token: &str) -> Vec<String> {
    let mut v = Vec::new();
    let (header, claims) = match decode_jwt_unverified(token) {
        Ok(x) => x,
        Err(e) => return vec![e],
    };
    match header.get("typ") {
        None => v.push("header missing \"typ\"; RFC 9068 s2.1 REQUIRES typ at+jwt".to_string()),
        Some(Value::String(t)) => {
            if !t.eq_ignore_ascii_case("at+jwt") && !t.eq_ignore_ascii_case("application/at+jwt") {
                v.push(format!(
                    "header typ \"{t}\" must be \"at+jwt\" or \"application/at+jwt\" (RFC 9068 s2.1)"
                ));
            }
        }
        Some(other) => v.push(format!(
            "header typ must be a string, got {other} (RFC 9068 s2.1)"
        )),
    }
    match header.get("alg") {
        None => v.push("header missing \"alg\" (RFC 7515 s4.1.1)".to_string()),
        Some(Value::String(a)) if a.eq_ignore_ascii_case("none") => {
            v.push("alg \"none\" is forbidden for access tokens (RFC 9068 s2.1)".to_string());
        }
        Some(Value::String(_)) => {}
        Some(other) => v.push(format!("header alg must be a string, got {other}")),
    }
    for (claim, kinds) in [
        ("iss", "string"),
        ("exp", "number"),
        ("aud", "string-or-array"),
        ("sub", "string"),
        ("client_id", "string"),
        ("iat", "number"),
        ("jti", "string"),
    ] {
        let ok = match (claims.get(claim), kinds) {
            (Some(Value::String(_)), "string" | "string-or-array") => true,
            (Some(Value::Array(a)), "string-or-array") => a.iter().all(Value::is_string),
            (Some(Value::Number(_)), "number") => true,
            _ => false,
        };
        if !ok {
            v.push(format!(
                "claim \"{claim}\" missing or wrong type (must be {kinds}); RFC 9068 s2.2 \
                 REQUIRES iss, exp, aud, sub, client_id, iat, jti"
            ));
        }
    }
    v
}

/// Verify a JWT's signature against a JWKS document (RFC 7517), for RS256/ES256.
///
/// # Errors
/// Returns a message when the header/JWKS are malformed, no usable key matches, or the
/// signature does not verify.
pub fn verify_jwt_against_jwks(token: &str, jwks: &Value) -> Result<(), String> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    let (header, _) = decode_jwt_unverified(token)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("missing alg header")?
        .to_string();
    let kid = header.get("kid").and_then(Value::as_str);
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("JWKS document has no \"keys\" array (RFC 7517 s5)")?;
    let candidates: Vec<&Value> = keys
        .iter()
        .filter(|k| match (kid, k.get("kid").and_then(Value::as_str)) {
            (Some(want), Some(have)) => want == have,
            _ => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(format!("no JWKS key matches kid {kid:?}"));
    }
    let algorithm = match alg.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        other => {
            return Err(format!(
                "unsupported alg \"{other}\" (harness verifies RS256/ES256)"
            ))
        }
    };
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let mut last_err = String::from("no candidate key attempted");
    for key in candidates {
        let dk = match algorithm {
            Algorithm::RS256 => {
                let n = key.get("n").and_then(Value::as_str).unwrap_or_default();
                let e = key.get("e").and_then(Value::as_str).unwrap_or_default();
                DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())
            }
            Algorithm::ES256 => {
                let x = key.get("x").and_then(Value::as_str).unwrap_or_default();
                let y = key.get("y").and_then(Value::as_str).unwrap_or_default();
                DecodingKey::from_ec_components(x, y).map_err(|e| e.to_string())
            }
            _ => unreachable!(),
        };
        match dk {
            Ok(dk) => match decode::<Value>(token, &dk, &validation) {
                Ok(_) => return Ok(()),
                Err(e) => last_err = e.to_string(),
            },
            Err(e) => last_err = e,
        }
    }
    Err(format!(
        "signature did not verify against any advertised JWK: {last_err}"
    ))
}
