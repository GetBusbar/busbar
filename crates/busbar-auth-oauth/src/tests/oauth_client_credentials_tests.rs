// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `mint/oauth_client_credentials.rs`, ported from
//! the kernel's `egress_auth/tests/oauth_client_credentials_tests.rs`. The `token_url`
//! https/metadata tests stay with the kernel (ARCHITECT ruling Q2 (a)); the over-cap mint is proven
//! in `mint_tests` over the plugin's need.

use super::*;

/// The resolved `client_secret` NEVER appears in this struct's `Debug` (it is held `Redacted`).
#[test]
fn client_secret_is_redacted_in_debug() {
    let creds = build("id:super-secret-value", "https://t", "s").unwrap();
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

/// 1.5.5's two refusal texts, word for word (BOOT-030..035's credential clause).
#[test]
fn build_rejects_a_malformed_credential_in_1_5_5_words() {
    assert_eq!(
        build("no-colon-here", "https://t", "s").unwrap_err(),
        "oauth-client-credentials key must be `client_id:client_secret`"
    );
    for empty in [":secret-only", "id-only:"] {
        assert_eq!(
            build(empty, "https://t", "s").unwrap_err(),
            "oauth-client-credentials key has an empty client_id or client_secret"
        );
    }
}

#[test]
fn validate_credential_rejects_malformed_and_accepts_well_formed() {
    assert!(validate_credential("no-colon-here").is_err());
    assert!(validate_credential(":secret-only").is_err());
    assert!(validate_credential("id-only:").is_err());
    assert!(validate_credential("id:secret").is_ok());
}

#[test]
fn build_accepts_a_secret_containing_a_colon() {
    // Only the FIRST colon splits id:secret, so a secret with colons is preserved.
    let c = build("client-abc:secret:with:colons", "https://t", "s").unwrap();
    assert_eq!(
        c.request().unwrap().body.expose_secret(),
        "grant_type=client_credentials&client_id=client-abc&client_secret=secret%3Awith%3Acolons&scope=s"
    );
}

/// The token request: the four form pairs in 1.5.5's order, encoded by `serde_urlencoded` as
/// reqwest's `.form()` did, POSTed to `token_url` with the form content type.
#[test]
fn the_token_request_is_the_form_1_5_5_posted() {
    let c = build(
        "my id:s3cr&t=",
        "https://login.example.com/tenant/oauth2/v2.0/token",
        "https://cognitiveservices.azure.com/.default",
    )
    .unwrap();
    let req = c.request().unwrap();
    assert_eq!(
        req.target,
        "https://login.example.com/tenant/oauth2/v2.0/token"
    );
    assert_eq!(
        req.fields,
        vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "*/*"),
        ]
    );
    assert_eq!(
        req.body.expose_secret(),
        "grant_type=client_credentials&client_id=my+id&client_secret=s3cr%26t%3D&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
    );
}
