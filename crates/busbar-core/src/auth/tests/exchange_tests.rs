// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/auth/exchange.rs`.

use super::*;

/// The headless exchange response is SELF-CONTAINED: it carries `base_url` (= the configured
/// public_url, verbatim) alongside the key so a CI/BYOK caller has everything in one payload.
#[test]
fn exchange_ok_body_includes_base_url_equal_to_public_url() {
    let issued = IssuedKey {
        secret: busbar_api::Redacted::new("sk-busbar-abc".to_string()),
        key_id: "kid-1".into(),
        group: "eng".into(),
        exp: 1234567890,
    };
    let public_url = "https://busbar.example.com";
    let body = exchange_ok_body(&issued, public_url);
    assert_eq!(body["base_url"], public_url);
    assert_eq!(body["api_key"], "sk-busbar-abc");
    assert_eq!(body["key_id"], "kid-1");
    assert_eq!(body["group"], "eng");
    assert_eq!(body["exp"], 1234567890u64);
    // base_url is verbatim — no /v1 suffix (BYOK clients append their own).
    assert!(!body["base_url"].as_str().unwrap().ends_with("/v1"));
}

// ── the RFC 8707 `resource` (1.6.0 P2) ───────────────────────────────────────────────────────────
//
// RED AT THE BASE: against a binary without this face, `resolve_resource_audience` does not exist
// and `exchange()` never reads the body for anything — so a resource-bound exchange has no way to
// ask for a bound token at all, and these three assertions cannot be expressed.

/// No `resource` named: nothing to check, nothing minted bound — the untouched 1.5.5 shape.
#[test]
fn resolve_resource_audience_with_none_passes_through() {
    let app = crate::test_support::TestApp::new().build();
    assert_eq!(resolve_resource_audience(&app, None), Ok(None));
}

/// A `resource` no MOUNTED plane declares is REFUSED — the confused-deputy defence at the issuer,
/// not just the door: issuing it would hand back a credential whose only property is that nothing
/// accepts it.
#[test]
fn resolve_resource_audience_refuses_an_undeclared_resource() {
    let app = crate::test_support::TestApp::new().build();
    assert_eq!(
        resolve_resource_audience(&app, Some("https://busbar.example.com/mcp")),
        Err(ExchangeError::UndeclaredResource)
    );
}

/// A `resource` a mounted plane DOES declare is admitted — read off the plane's own admission
/// (`PlaneDispatch::mintable_audiences`), never a literal.
#[test]
fn resolve_resource_audience_admits_a_declared_resource() {
    const AUD: &str = "https://busbar.example.com/mcp";
    let mut builder = crate::test_support::TestApp::new();
    builder
        .mount_plane(
            "test-plane",
            "/mcp",
            busbar_substrate::plane::WIRE_HTTP_JSON,
        )
        .admit_plane(
            "test-plane",
            busbar_substrate::plane::PlaneAdmission {
                audience: AUD.to_string(),
                resource_metadata: format!("{AUD}/.well-known/oauth-protected-resource"),
            },
        );
    let app = builder.build();
    assert_eq!(resolve_resource_audience(&app, Some(AUD)), Ok(Some(AUD)));
}
