// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `jwt-bearer` egress auth — OAuth 2.0 JWT-bearer grant (RFC 7523), one of busbar's OAuth auth
//! mechanisms.
//!
//! GENERIC, not Google-specific: the flow is the standard `urn:ietf:params:oauth:grant-type:jwt-bearer`
//! grant — sign a JWT with a private key, POST the assertion to a token endpoint, receive a short-lived
//! bearer. The Google service-account JSON is merely a recognized *container* for the signing material
//! (`client_email` → JWT `iss`, `private_key` → the RS256 key, `token_uri` → JWT `aud`); the scope
//! defaults to `cloud-platform`. Vertex AI is the first provider to select `auth: jwt-bearer`.
//!
//! MOVED VERBATIM from the kernel's `egress_auth/jwt_bearer.rs` (KERNEL<>PLUGINS step 22).
//! This module owns only the JWT signing and the token request it is exchanged in; the exchange
//! runs over the plugin's own need and the token cache, the per-request read and the refresh ahead
//! of expiry on `tick` live in [`super`], shared with `oauth-client-credentials`.
//!
//! The SA JSON's `token_uri` https / cloud-metadata vetting (`validate_token_uri`) did NOT move: the
//! kernel judges an auth plugin's need target at seal and at `--validate` and renders those 1.5.5
//! texts itself (ARCHITECT ruling 2026-09-28, Q2 (a); the allow-list and metadata posture are the
//! kernel's, BUSBAR-1.6.0.md THE DESIGN, §5).

use super::TokenRequest;
use base64::Engine as _;

/// Default OAuth scope when the provider does not override it — the Vertex/GCP common case.
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The signing + exchange material for one binding. Immutable after construction.
pub(crate) struct Signer {
    key_pair: ring::signature::RsaKeyPair,
    rng: ring::rand::SystemRandom,
    /// JWT `iss` — the service account's `client_email`.
    issuer: String,
    /// JWT `aud` AND the POST target — the SA JSON `token_uri`.
    token_uri: String,
    scope: String,
    /// JWT `sub` (RFC 7523 §3), emitted ONLY when the operator explicitly configures it
    /// (`ProviderCfg::subject`). Left `None` — the default, and the only case that matters for a plain
    /// (non-delegated) Google service account — the assertion carries no `sub` at all, UNCHANGED from
    /// pre-fix behavior: for a Google service account, the mere PRESENCE of `sub` (not its value)
    /// switches the grant into domain-wide-delegation/impersonation semantics, so it must never be
    /// defaulted (e.g. to `iss`) or every plain SA (the shipped Vertex AI setup) starts failing
    /// `unauthorized_client`/`invalid_grant`. Mirrors `google-auth-python`'s own opt-in `subject=`.
    subject: Option<String>,
}

/// Build a `jwt-bearer` signer: PARSES the key material (failing loud on a malformed
/// service-account JSON / PKCS#8 key, the common misconfig). It never touches the network: the first
/// mint runs on `tick`. `credential` is the SA JSON — inline (starts with `{`) or a path to a key
/// file. `scope_override` replaces the default `cloud-platform` scope when set. `subject` is the
/// operator-configured RFC 7523 `sub` — `None` (the default) omits the claim entirely; `Some` emits
/// it verbatim, for Google domain-wide-delegation impersonation or a third-party IdP that requires
/// `sub`.
pub(crate) fn build(
    credential: &str,
    scope_override: Option<&str>,
    subject: Option<&str>,
) -> Result<Signer, String> {
    let (sa, key_pair) = parse_service_account(credential)?;
    Ok(Signer {
        key_pair,
        rng: ring::rand::SystemRandom::new(),
        issuer: sa.client_email,
        token_uri: sa.token_uri,
        scope: scope_override.unwrap_or(DEFAULT_SCOPE).to_string(),
        subject: subject.map(str::to_string),
    })
}

/// Parse + fully validate a `jwt-bearer` credential: read the SA JSON (inline or `@file`) and parse
/// the PKCS#8 RSA key. Run by [`build`], which the config `--validate` dry-run
/// reaches through `open_outbound` (it never dials), so both apply IDENTICAL checks with identical
/// error messages — they can never diverge.
fn parse_service_account(
    credential: &str,
) -> Result<(ServiceAccount, ring::signature::RsaKeyPair), String> {
    let sa_json = read_credential(credential)?;
    let sa: ServiceAccount = serde_json::from_str(&sa_json)
        .map_err(|e| format!("service-account JSON is invalid: {e}"))?;
    let der = pem_to_pkcs8_der(&sa.private_key)?;
    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| format!("service-account private_key is not a valid PKCS#8 RSA key: {e}"))?;
    Ok((sa, key_pair))
}

impl Signer {
    /// Sign a JWT-bearer assertion for `now` (epoch seconds): `header.claims.signature`, RS256 over
    /// the url-safe unpadded base64 of the fixed header and the claim set (RFC 7523).
    pub(crate) fn assertion(&self, now: u64) -> Result<String, String> {
        let exp = now + 3600; // 1h assertion; the returned token's own TTL governs refresh
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims_json = jwt_claims_json(
            &self.issuer,
            &self.scope,
            &self.token_uri,
            now,
            exp,
            self.subject.as_deref(),
        )?;
        let claims = b64url(claims_json.as_bytes());
        let signing_input = format!("{header}.{claims}");

        let mut sig = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| "RS256 signing failed".to_string())?;
        Ok(format!("{signing_input}.{}", b64url(&sig)))
    }

    /// The token request for `now`: the assertion, form-encoded through `serde_urlencoded` (the exact
    /// call reqwest's `.form()` was), POSTed to the SA's `token_uri` (RFC 7523).
    pub(crate) fn request(&self, now: u64) -> Result<TokenRequest, String> {
        let assertion = self.assertion(now)?;
        let form = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .map_err(|e| format!("token request form could not be encoded: {e}"))?;
        Ok(TokenRequest::form(self.token_uri.clone(), form))
    }
}

/// Serialize the JWT-bearer assertion claim set. Built with a JSON serializer, NOT string
/// interpolation: a `"`/`\`/control char in `issuer` (the SA `client_email`) or `scope` would
/// otherwise produce malformed JSON or splice into the claim set. `scope` is the value threaded from
/// the provider's `scope:` config (or the cloud-platform default), so this is also where a configured
/// scope lands in the assertion. Extracted as a pure fn so the escaping and scope-placement are unit-
/// testable without a network round-trip.
///
/// `subject` is RFC 7523 §3's `sub` claim, threaded from the operator's optional `ProviderCfg::subject`.
/// It is emitted ONLY when `Some` — `None` (the default) produces a claim set with NO `sub` key at all,
/// byte-identical to this function's behavior before `subject` existed. This is deliberately opt-in: for
/// a Google service account, the mere PRESENCE of `sub` (regardless of value) switches the OAuth grant
/// into domain-wide-delegation/impersonation semantics, so unconditionally setting it (e.g. to `issuer`)
/// would break every plain, non-delegated service account — including the shipped Vertex AI config —
/// with `unauthorized_client`/`invalid_grant`. `google-auth-python` and friends have the same opt-in
/// `subject=` behavior; this mirrors it.
fn jwt_claims_json(
    issuer: &str,
    scope: &str,
    aud: &str,
    iat: u64,
    exp: u64,
    subject: Option<&str>,
) -> Result<String, String> {
    let mut claims = serde_json::json!({
        "iss": issuer,
        "scope": scope,
        "aud": aud,
        "iat": iat,
        "exp": exp,
    });
    if let Some(sub) = subject {
        claims["sub"] = serde_json::Value::String(sub.to_string());
    }
    serde_json::to_string(&claims).map_err(|e| format!("serializing JWT claims failed: {e}"))
}

/// SA-JSON credential material: inline JSON (`{...}`) or a filesystem path to a key file.
///
/// The failure message deliberately does NOT render `credential`. On this branch the argument is a
/// PATH only by assumption — the sole thing that distinguishes the two forms is a leading `{`, so an
/// operator who pasted the key body, or a secret ref that resolved to key material rather than to a
/// filename, lands here holding the SIGNING KEY. This error is not a swallowed one: it reaches the
/// `--validate` report (`config_validate`'s `errors` list, which the CLI prints and the admin
/// dry-run returns) and the boot/apply panic in a plane's runtime build, so interpolating the
/// argument published an RSA private key to a terminal, a CI log and a crash report in one step.
/// Callers already name the lane and the secret's configured source, so what this layer owes is the
/// io failure and nothing else.
fn read_credential(credential: &str) -> Result<String, String> {
    let trimmed = credential.trim_start();
    if trimmed.starts_with('{') {
        return Ok(credential.to_string());
    }
    std::fs::read_to_string(credential).map_err(|e| {
        format!("could not read service-account key file named by this lane's credential: {e}")
    })
}

/// Strip the PEM armor from a PKCS#8 private key and base64-decode the body to DER.
///
/// The decode failure is reported by CLASS, never by `base64::DecodeError`'s own `Display`. That
/// `Display` names a byte OF THE KEY BODY: `InvalidByte` prints the decimal byte value and its
/// offset (`Invalid symbol 126, offset 4.`), and `InvalidLastSymbol` is worse still — it prints the
/// symbol as hex AND as the character itself AND its decoded bits (`Invalid last symbol 0x7a ('z')
/// at offset 1, decoded as 0b00110011.`), and for that variant the symbol is a VALID base64
/// character, i.e. six bits of the operator's RSA private key, not a foreign character that got
/// mixed in. This error is not swallowed: [`build`] is reached by the config `--validate` entry
/// point and `config_validate` copies its string verbatim into the `errors` array that the admin
/// `config/validate` endpoint returns — a READ-SCOPE caller. Read scope may ask whether the
/// configuration is valid; it may not be told what the key contains. That is a privilege boundary,
/// not log hygiene, so the byte and the offset are withheld here.
///
/// The diagnosis is not deleted with them. Which field failed (`private_key`), that it failed to
/// base64-decode, and WHICH KIND of malformation it was all survive — enough for an operator to
/// tell a truncated key from a re-wrapped one from a missing one, which is every repair they would
/// make. Only the key's own bytes go.
fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("service-account private_key is empty or not PEM-armored".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| {
            // The CLASS of malformation, spelled here rather than taken from `e`'s Display — see
            // this fn's docs. Matched exhaustively and with no `_` arm on purpose: `DecodeError` is
            // not `#[non_exhaustive]`, so a new variant in a base64 upgrade must fail the build and
            // be classified by hand, rather than fall through a catch-all that might reinstate the
            // leak by printing it.
            let why = match e {
                base64::DecodeError::InvalidByte(..) => {
                    "it contains a character outside the base64 alphabet (a stray line-ending, \
                     whitespace inside the body, or a URL-safe `-`/`_` where `+`/`/` belong)"
                }
                base64::DecodeError::InvalidLength(..) => {
                    "its final base64 group is short — the key body looks truncated"
                }
                base64::DecodeError::InvalidLastSymbol { .. } => {
                    "its final base64 symbol carries bits that decoding would discard — the key \
                     body looks corrupted or truncated mid-group"
                }
                base64::DecodeError::InvalidPadding => "its `=` padding is absent or malformed",
            };
            format!(
                "service-account private_key base64 is invalid: {why}. (The offending byte and its \
                 offset are withheld deliberately: they are key material, and this message is \
                 returned to read-scope callers of config/validate.)"
            )
        })
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(serde::Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

#[cfg(test)]
#[path = "../tests/jwt_bearer_tests.rs"]
mod tests;
