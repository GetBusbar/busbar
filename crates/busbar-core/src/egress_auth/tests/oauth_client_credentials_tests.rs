// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/egress_auth/oauth_client_credentials.rs`.

use super::*;

/// The default (no operator carve-out) SSRF posture used by most tests.
fn deny() -> super::super::MetadataSsrfPolicy<'static> {
    super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: false,
        blocked_hosts: &[],
    }
}

/// The resolved `client_secret` NEVER appears in this struct's `Debug` (it is held
/// `Redacted`). A `{:?}` of the exchange material must show `[REDACTED]`, not the secret.
#[test]
fn client_secret_is_redacted_in_debug() {
    let creds = ClientCreds {
        client_id: "id".to_string(),
        client_secret: busbar_api::Redacted::new("super-secret-value".to_string()),
        token_url: "https://t".to_string(),
        scope: "s".to_string(),
        http: super::super::minter_client().unwrap(),
    };
    let dbg = format!("{creds:?}");
    assert!(
        !dbg.contains("super-secret-value"),
        "client_secret must not appear in Debug: {dbg}"
    );
    assert!(
        dbg.contains("[REDACTED]"),
        "expected redaction marker: {dbg}"
    );
}

#[test]
fn build_rejects_a_credential_without_a_colon() {
    assert!(build("no-colon-here", "https://t", "s", &deny()).is_err());
    assert!(build(":secret-only", "https://t", "s", &deny()).is_err());
    assert!(build("id-only:", "https://t", "s", &deny()).is_err());
}

// `validate_credential` is the standalone `--validate` dry-run entry point (unlike `build`, it
// never constructs a provider or touches the network) - it must apply the SAME parse checks as
// `build`'s `split_credential` call, not just always succeed.
#[test]
fn validate_credential_rejects_malformed_and_accepts_well_formed() {
    assert!(validate_credential("no-colon-here").is_err());
    assert!(validate_credential(":secret-only").is_err());
    assert!(validate_credential("id-only:").is_err());
    assert!(validate_credential("id:secret").is_ok());
}

// build() re-validates token_url for SSRF/https as defense-in-depth
// (parity with jwt-bearer). A plaintext-http public token_url and a cloud-metadata/IMDS host are
// rejected even with a well-formed credential; loopback http is allowed (local dev IdP).
#[test]
fn build_rejects_unsafe_token_url() {
    assert!(build("id:secret", "http://login.example.com/token", "s", &deny()).is_err());
    assert!(build("id:secret", "https://169.254.169.254/token", "s", &deny()).is_err());
    assert!(build("id:secret", "http://127.0.0.1:8080/token", "s", &deny()).is_ok());
}

// The boot-time token_url check MUST honor the operator's
// metadata-host allow-overrides the SAME way config_validate does — else a config that
// allow-lists a metadata host as its token endpoint passes `--validate` but dies at boot
// (validate != apply). With the host allow-listed (or `allow_all`), build() must accept it.
#[test]
fn build_honors_metadata_allow_override_matching_validate() {
    // Denied by default...
    assert!(build("id:secret", "https://169.254.169.254/token", "s", &deny()).is_err());
    // ...permitted when the operator allow-lists that exact host (per-provider or global union).
    let allowed = ["169.254.169.254".to_string()];
    let overridden = super::super::MetadataSsrfPolicy {
        allow_overrides: &allowed,
        allow_all: false,
        blocked_hosts: &[],
    };
    assert!(build(
        "id:secret",
        "https://169.254.169.254/token",
        "s",
        &overridden
    )
    .is_ok());
    // ...and permitted under the nuclear allow_all_metadata.
    let nuclear = super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: true,
        blocked_hosts: &[],
    };
    assert!(build("id:secret", "https://169.254.169.254/token", "s", &nuclear).is_ok());
}

#[test]
fn build_accepts_a_secret_containing_a_colon() {
    // Only the FIRST colon splits id:secret, so a secret with colons is preserved. Constructed
    // outside a runtime, so no mint is spawned — this just checks the credential parse.
    assert!(build("client-abc:secret:with:colons", "https://t", "s", &deny()).is_ok());
}

// `expires_in` must tolerate a JSON number, a numeric string (ADFS /
// Azure AD v1), and absence (defaulting to 1 h) — a strict u64 breaks minting for those IdPs.
#[test]
fn token_response_tolerates_expires_in_as_number_string_or_absent() {
    let num: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":3600}"#).unwrap();
    assert_eq!(num.expires_in, 3600);
    let s: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":"7200"}"#).unwrap();
    assert_eq!(s.expires_in, 7200);
    let absent: TokenResponse = serde_json::from_str(r#"{"access_token":"a"}"#).unwrap();
    assert_eq!(absent.expires_in, super::super::default_expires_in());
    // Also tolerate a JSON float and a decimal string (truncated toward zero).
    let float: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":3600.0}"#).unwrap();
    assert_eq!(float.expires_in, 3600);
    let decimal_str: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":"3600.9"}"#).unwrap();
    assert_eq!(decimal_str.expires_in, 3600);
}

/// The token endpoint is an untrusted network peer (its `expires_in` is already treated as
/// attacker-influenced above), so `mint()` must read the response body under a size cap rather
/// than `resp.text()`'s unbounded read: a hijacked/misbehaving token endpoint returning a body
/// past the `upstream_error_body_max_bytes()` cap must surface a clear error, never silently
/// buffer the whole thing or attempt a partial JSON parse of a truncated fragment.
#[tokio::test]
async fn mint_rejects_a_response_body_over_the_cap() {
    let state = std::sync::Arc::new(crate::test_support::MockServerState::new());
    // A single oversized field pushes the serialized body past the 256 KiB default cap; the
    // fixture only needs to be a legal JSON document once truncated is irrelevant, since the
    // cap must trip and short-circuit BEFORE any JSON parsing happens.
    let oversized_token = "a".repeat(300 * 1024);
    state.push(crate::test_support::MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }),
    });
    let server = crate::test_support::MockServer::new(state).await;

    let creds = ClientCreds {
        client_id: "id".to_string(),
        client_secret: busbar_api::Redacted::new("secret".to_string()),
        token_url: server.base_url(),
        scope: "s".to_string(),
        http: super::super::minter_client().unwrap(),
    };
    let result = creds.mint().await;
    server.shutdown().await;

    let err = match result {
        Ok(_) => {
            panic!("an over-cap token response must be a clear error, not a buffered success")
        }
        Err(e) => e,
    };
    assert!(
        err.contains("cap") || err.contains("truncat"),
        "expected an error naming the size cap / truncation, got: {err}"
    );
}
