// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HTTPS token-minter tests, at LLM-egress parity: the REAL substrate egress client dials a loopback
//! `MockServer` (the exact bar the LLM plane's egress mock-tests hold), so the minter's request
//! preparation and response handling are exercised over the production request path, not a fake.
//!
//! Proven here: the requested secret lifetime is clamped to the accepted window (over the ceiling →
//! max, under the floor → min, unset → default); the `OpenAI-Safety-Identifier` caller binding is
//! stamped; the returned token is the provider's `ek_` value; a response value without the `ek_`
//! prefix is refused; and the real key never appears in the returned token.

use super::*;
use crate::ir::config::SessionConfig;
use crate::topology::webrtc::{MintError, TokenMinter};
use busbar_substrate::egress::engine::EngineSpec;
use busbar_substrate::proxy::build_egress_client;
use busbar_substrate::testkit::loopback_http::{MockResponse, MockServer, MockServerState};
use std::sync::Arc;

const REAL_KEY: &str = "sk-real-secret-key-never-leaves-the-server";
const SAFETY_ID: &str = "caller-identity-binding-abc123";

fn locked_config() -> SessionConfig {
    SessionConfig {
        instructions: Some("locked system instructions".to_string()),
        voice: Some("marin".to_string()),
        ..SessionConfig::default()
    }
}

async fn mock_returning(body: serde_json::Value) -> (MockServer, Arc<MockServerState>) {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body,
    });
    let server = MockServer::new(Arc::clone(&state)).await;
    (server, state)
}

fn minter(server: &MockServer, requested_ttl_secs: Option<u64>) -> HttpsTokenMinter {
    let client = build_egress_client(&EngineSpec::pooled_webpki(4, 300, false, false));
    HttpsTokenMinter::new(
        client,
        server.base_url(),
        REAL_KEY,
        SAFETY_ID,
        requested_ttl_secs,
    )
}

/// The seconds the mint request carried under `expires_after`, read off the mock's recorded body.
fn recorded_ttl_secs(state: &MockServerState) -> u64 {
    let raw = state.get_last_request_body().expect("mint sent a body");
    let sent: serde_json::Value = serde_json::from_slice(&raw).expect("mint body is json");
    sent["expires_after"]["seconds"]
        .as_u64()
        .expect("expires_after.seconds is a number")
}

#[tokio::test]
async fn ttl_over_ceiling_is_clamped_to_max() {
    let (server, state) = mock_returning(
        serde_json::json!({ "value": "ek_test123", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    let token = minter(&server, Some(99_999))
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert_eq!(
        recorded_ttl_secs(&state),
        7200,
        "over-ceiling clamps to 7200"
    );
    assert_eq!(token.value, "ek_test123");
    server.shutdown().await;
}

#[tokio::test]
async fn ttl_under_floor_is_clamped_to_min() {
    let (server, state) = mock_returning(
        serde_json::json!({ "value": "ek_test123", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    minter(&server, Some(1))
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert_eq!(recorded_ttl_secs(&state), 10, "under-floor clamps to 10");
    server.shutdown().await;
}

#[tokio::test]
async fn ttl_unset_defaults_to_600() {
    let (server, state) = mock_returning(
        serde_json::json!({ "value": "ek_test123", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    minter(&server, None)
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert_eq!(recorded_ttl_secs(&state), 600, "unset defaults to 600");
    server.shutdown().await;
}

#[tokio::test]
async fn safety_identifier_header_is_stamped() {
    let (server, state) = mock_returning(
        serde_json::json!({ "value": "ek_test123", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    minter(&server, None)
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert_eq!(
        state
            .get_last_request_header("OpenAI-Safety-Identifier")
            .as_deref(),
        Some(SAFETY_ID),
        "the caller-identity binding is stamped on the mint request"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn returns_the_ek_value_and_expiry() {
    let (server, _state) = mock_returning(
        serde_json::json!({ "value": "ek_livetoken789", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    let token = minter(&server, None)
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert_eq!(token.value, "ek_livetoken789");
    assert_eq!(token.expires_at_unix, 1_700_000_600);
    server.shutdown().await;
}

#[tokio::test]
async fn value_without_ek_prefix_is_refused() {
    let (server, _state) = mock_returning(
        serde_json::json!({ "value": "sk-not-an-ephemeral-secret", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    let err = minter(&server, None)
        .mint(&locked_config())
        .await
        .expect_err("a non-ek_ value is refused");

    match err {
        MintError::Provider(m) => assert!(
            m.contains("ek_"),
            "the refusal names the missing ek_ prefix, got: {m}"
        ),
    }
    server.shutdown().await;
}

#[tokio::test]
async fn the_real_key_never_appears_in_the_token() {
    let (server, _state) = mock_returning(
        serde_json::json!({ "value": "ek_test123", "expires_at": 1_700_000_600u64 }),
    )
    .await;
    let token = minter(&server, None)
        .mint(&locked_config())
        .await
        .expect("mint succeeds");

    assert!(
        !token.value.contains(REAL_KEY),
        "the real provider key is never in the browser-facing token value"
    );
    assert_eq!(token.value, "ek_test123");
    server.shutdown().await;
}
