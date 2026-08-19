// SPDX-License-Identifier: Apache-2.0
//! `jwt-bearer` egress auth — OAuth 2.0 JWT-bearer grant (RFC 7523), one of busbar's OAuth auth
//! mechanisms.
//!
//! GENERIC, not Google-specific: the flow is the standard `urn:ietf:params:oauth:grant-type:jwt-bearer`
//! grant — sign a JWT with a private key, POST the assertion to a token endpoint, receive a short-lived
//! bearer. The Google service-account JSON is merely a recognized *container* for the signing material
//! (`client_email` → JWT `iss`, `private_key` → the RS256 key, `token_uri` → JWT `aud`); the scope
//! defaults to `cloud-platform`. Vertex AI is the first provider to select `auth: jwt-bearer`.
//!
//! This module owns only the JWT signing + token exchange (the `mint`); the token cache, `headers_for`
//! read, and background refresh live in [`super::bearer_token`], shared with `oauth-client-credentials`.

use super::bearer_token::{now_epoch, CachedToken, CredentialProviderArc, Minter};
use base64::Engine as _;
use std::sync::Arc;

/// Default OAuth scope when the provider does not override it — the Vertex/GCP common case.
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The signing + exchange material for one lane. Held in an `Arc` shared by the refresh task's mint
/// calls. Immutable after construction.
struct Signer {
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
    http: reqwest::Client,
}

/// Build a `jwt-bearer` credential. SYNCHRONOUS by design — it runs on the shared
/// `build_app_from_config` path (boot AND admin config-reload apply), so it must not block on the
/// network. Note: the config `--validate` / admin dry-run path does NOT construct the app, so it does
/// not reach here; malformed key material is caught at boot/apply (and, best-effort, by
/// `validate_credential` at validate time when the credential resolves). It PARSES the key material
/// (failing loud on a malformed service-account JSON / PKCS#8 key, the common misconfig) and hands a
/// `mint` closure to [`super::bearer_token::spawn`], which mints the
/// first token in the background and refreshes it thereafter. `credential` is the SA JSON — inline
/// (starts with `{`) or a path to a key file. `scope_override` replaces the default `cloud-platform`
/// scope when set. `subject` is the operator-configured `ProviderCfg::subject` (RFC 7523 `sub`) — `None`
/// (the default) omits the claim entirely, unchanged from before this field existed; `Some` emits it
/// verbatim, for Google domain-wide-delegation impersonation or a third-party IdP that requires `sub`.
pub(crate) fn build(
    credential: &str,
    scope_override: Option<&str>,
    subject: Option<&str>,
    ssrf: &super::MetadataSsrfPolicy,
) -> Result<CredentialProviderArc, String> {
    let (sa, key_pair) = parse_service_account(credential, ssrf)?;

    let signer = Arc::new(Signer {
        key_pair,
        rng: ring::rand::SystemRandom::new(),
        issuer: sa.client_email,
        token_uri: sa.token_uri,
        scope: scope_override.unwrap_or(DEFAULT_SCOPE).to_string(),
        subject: subject.map(str::to_string),
        http: super::minter_client()?,
    });

    let minter: Minter = Arc::new(move || {
        let signer = signer.clone();
        Box::pin(async move { signer.mint().await })
    });
    Ok(super::bearer_token::spawn(minter))
}

/// Parse + fully validate a `jwt-bearer` credential: read the SA JSON (inline or `@file`), vet its
/// `token_uri` (SSRF/https), and parse the PKCS#8 RSA key. Shared by [`build`] (which keeps the key) and
/// [`validate_credential`] (which discards it), so the config `--validate` dry-run and the boot/apply
/// path apply IDENTICAL checks with identical error messages — they can never diverge.
fn parse_service_account(
    credential: &str,
    ssrf: &super::MetadataSsrfPolicy,
) -> Result<(ServiceAccount, ring::signature::RsaKeyPair), String> {
    let sa_json = read_credential(credential)?;
    let sa: ServiceAccount = serde_json::from_str(&sa_json)
        .map_err(|e| format!("service-account JSON is invalid: {e}"))?;
    // Defense in depth: the SA JSON's token_uri is the POST target for the signed assertion. Vet it the
    // same way oauth-client-credentials' token_url is vetted — https for a public host (http only for
    // loopback/private) and never a cloud-metadata/IMDS endpoint, honoring the operator's metadata
    // posture. The minter client already refuses redirects; this closes the direct-target case.
    validate_token_uri(&sa.token_uri, ssrf)?;
    let der = pem_to_pkcs8_der(&sa.private_key)?;
    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| format!("service-account private_key is not a valid PKCS#8 RSA key: {e}"))?;
    Ok((sa, key_pair))
}

/// Validate a `jwt-bearer` credential WITHOUT constructing the provider — the config `--validate`
/// dry-run entry point (which does not build the app, so it otherwise never reaches [`build`], leaving
/// malformed SA JSON / non-PKCS#8 keys to surface only at boot/apply). Runs the exact same checks as
/// [`build`].
pub(crate) fn validate_credential(
    credential: &str,
    ssrf: &super::MetadataSsrfPolicy,
) -> Result<(), String> {
    parse_service_account(credential, ssrf).map(|_| ())
}

/// Vet the service-account `token_uri` (the POST target for the signed assertion) with the same two
/// guards `oauth-client-credentials`' `token_url` gets: a case-insensitive https requirement (http only
/// for a loopback/private endpoint) and the shared cloud-metadata/IMDS denylist, honoring the operator's
/// metadata posture (`ssrf`). The token_uri is not a per-provider config field, but the DEPLOYMENT-global
/// posture still applies — a global `blocked_metadata_hosts` deny is enforced here and `allow_all_metadata`
/// uniformly disables the guard, matching oauth-client-credentials (the two mechanisms were otherwise
/// asymmetric: jwt ignored the global posture). Reuses `config_validate`'s SSRF primitives so this can
/// never diverge from the config path (`config_validate` passes the identical `ssrf` at validate time).
fn validate_token_uri(token_uri: &str, ssrf: &super::MetadataSsrfPolicy) -> Result<(), String> {
    use crate::config_validate::{
        extract_normalized_host, host_is_private_or_loopback, scheme_is, ssrf_blocked_host,
    };
    let host_private = extract_normalized_host(token_uri)
        .as_deref()
        .map(host_is_private_or_loopback)
        .unwrap_or(false);
    if !(scheme_is(token_uri, "https") || (host_private && scheme_is(token_uri, "http"))) {
        return Err(format!(
            "service-account token_uri must use https for a public host (got '{token_uri}'); it receives the signed JWT assertion, so plaintext http is permitted only for a private/loopback endpoint"
        ));
    }
    if let Some(host) = ssrf_blocked_host(
        token_uri,
        ssrf.allow_overrides,
        ssrf.allow_all,
        ssrf.blocked_hosts,
    ) {
        return Err(format!(
            "service-account token_uri '{token_uri}' targets a blocked cloud-metadata host '{host}' (the signed assertion would be POSTed there; cloud-metadata/IMDS endpoints are denied — override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)"
        ));
    }
    Ok(())
}

impl Signer {
    /// Sign a JWT-bearer assertion and exchange it for an access token (RFC 7523).
    async fn mint(&self) -> Result<CachedToken, String> {
        let now = now_epoch();
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
        let assertion = format!("{signing_input}.{}", b64url(&sig));

        // reqwest is built without the `json` feature here, so parse the response body manually.
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await
            // `.without_url()` strips the token-endpoint URL from the reqwest error Display — the URL
            // can carry query/secret material and leaking it into a surfaced/logged error is an SSRF /
            // secret-hygiene hazard. The status/body branch below already redacts.
            .map_err(|e| format!("token endpoint request failed: {}", e.without_url()))?;
        let status = resp.status();
        // The token endpoint is not fully trusted (its `expires_in` below is already treated as
        // attacker-influenced), so read the body under the shared capped-read helper rather than
        // `resp.text()`'s unbounded read — see `super::read_capped_token_response` for the cap
        // rationale and the truncated/transport-error distinction.
        let body = super::read_capped_token_response(resp).await?;
        if !status.is_success() {
            // Never log the assertion/body wholesale (may echo claims); status + a short snippet only.
            // Diagnostic-only snippet, not data-of-record: the request has already failed on `status`
            // above, nothing downstream branches on the body text — this 200-char cap only bounds what
            // a human sees in the propagated error/log line.
            return Err(format!(
                "token endpoint returned {status}: {}",
                body.chars().take(200).collect::<String>()
            ));
        }
        let tok: TokenResponse =
            serde_json::from_str(&body).map_err(|e| format!("token response JSON invalid: {e}"))?;
        Ok(CachedToken::new(
            tok.access_token,
            // saturating_add: `expires_in` is attacker-influenced (comes off the token endpoint), so a
            // huge value must clamp to u64::MAX rather than wrap/panic.
            now.saturating_add(tok.expires_in),
        ))
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
fn read_credential(credential: &str) -> Result<String, String> {
    let trimmed = credential.trim_start();
    if trimmed.starts_with('{') {
        return Ok(credential.to_string());
    }
    std::fs::read_to_string(credential)
        .map_err(|e| format!("could not read service-account key file '{credential}': {e}"))
}

/// Strip the PEM armor from a PKCS#8 private key and base64-decode the body to DER.
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
        .map_err(|e| format!("service-account private_key base64 is invalid: {e}"))
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

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(
        default = "super::default_expires_in",
        deserialize_with = "super::deserialize_expires_in"
    )]
    expires_in: u64,
}

#[cfg(test)]
#[path = "tests/jwt_bearer_tests.rs"]
mod tests;
