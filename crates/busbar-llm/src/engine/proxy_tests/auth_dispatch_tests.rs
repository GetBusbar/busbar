// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH x DISPATCH INTEGRATION — relocated from core `auth/tests/tests.rs` (money-path Phase 3-4 C).
//! These drive the WHOLE stack (`build_router` + a live socket + `reqwest`) so a request crosses the
//! neutral `ArrivalCtx` seam into the LLM plane's universal ingress. Core's OWN test binary links two
//! `busbar-core` instances (crate-under-test + the plugin's dep copy), so an `ArrivalPayload` built by
//! one and downcast by the other cannot match — these must run in the plugin's single-`busbar-core`
//! binary. The pure-auth (401/verification) tests that never reach dispatch stay in core.

use axum::http::header::AUTHORIZATION;
use busbar_api::ScopeRef;
use busbar_core::auth::AuthMiddleware;
use busbar_substrate::sigv4::{sha256_hex, sign_v4, uri_encode_path, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};

/// Helper: a `RoleBindingCfg` from optional pool list / group / admin scope.
fn binding(
    allowed_pools: Option<&[&str]>,
    group: Option<&str>,
    admin_scope: Option<&str>,
) -> busbar_core::config::RoleBindingCfg {
    busbar_core::config::RoleBindingCfg {
        allowed_pools: allowed_pools.map(|ps| ps.iter().map(|p| p.to_string()).collect()),
        group: group.map(str::to_string),
        admin_scope: admin_scope.map(str::to_string),
    }
}

/// Helper: a `RoleBindings` table with one module's role->binding entries.
fn bindings_for(
    module: &str,
    roles: &[(&str, busbar_core::config::RoleBindingCfg)],
) -> busbar_core::config::RoleBindings {
    let mut table = std::collections::BTreeMap::new();
    for (role, b) in roles {
        table.insert(role.to_string(), b.clone());
    }
    let mut rb = busbar_core::config::RoleBindings::new();
    rb.insert(module.to_string(), table);
    rb
}

/// Helper: an `AuthCfg` whose data-plane chain names the given modules (bare entries).
fn chain_cfg(modules: &[&str]) -> busbar_core::config::AuthCfg {
    busbar_core::config::AuthCfg::with_chain(
        modules
            .iter()
            .map(|m| busbar_core::config::AuthChainEntry::bare(*m))
            .collect(),
    )
}

/// Helper: SigV4-sign a Bedrock request the way a real AWS client would, returning the
/// `Authorization` header value + the signed headers.
#[allow(clippy::type_complexity)]
fn sign_bedrock_request(
    secret: &str,
    access_key_id: &str,
    region: &str,
    service: &str,
    path: &str,
    body: &[u8],
    amzdate: &str,
) -> (String, Vec<(String, String)>) {
    let datestamp = &amzdate[0..8];
    let payload_hash = sha256_hex(body);
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let canonical_uri = uri_encode_path(path);
    let (sig, signed_headers) = sign_v4(
        secret,
        region,
        service,
        "POST",
        &canonical_uri,
        "",
        &headers,
        &payload_hash,
        amzdate,
        datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{datestamp}/{region}/{service}/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
    );
    (auth, headers)
}

/// Local helper: serve a router on an ephemeral port, returning (addr, join handle).
async fn dp_serve(
    app: std::sync::Arc<busbar_core::state::App>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// A governance engine (admin token set) with ONE enabled, pool-`pa` virtual key. Returns (gov, secret).
fn dp_gov_with_key() -> (std::sync::Arc<busbar_core::governance::GovState>, String) {
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov = std::sync::Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (_k, secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    (gov, secret.as_str().to_string())
}

fn dp_ok_state() -> std::sync::Arc<crate::test_support::MockServerState> {
    use crate::test_support::{MockResponse, MockServerState};
    let state = std::sync::Arc::new(MockServerState::new());
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: serde_json::json!({
                "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    state
}

/// End-to-end through the real router + `auth_middleware` with a CONFIGURED chain: the busbar
/// client credential authenticates via `x-goog-api-key` (Gemini SDK), via `x-api-key` (Anthropic
/// SDK), and via `Authorization: Bearer`. A missing/wrong credential is rejected 401 with the
/// native error envelope shaped for the inferred ingress protocol (`application/json`, not
/// `text/plain`). The chain is the test-groups-module (`grp:<role>` identifies).
#[tokio::test]
async fn test_chain_accepts_all_carriers_and_native_401() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let token = "grp:carrier";

    let state = Arc::new(MockServerState::new());
    // Three admitted requests reach the upstream; queue three OK bodies.
    for _ in 0..3 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Bearer still works.
    let r_bearer = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
        "valid token via Authorization: Bearer must pass (got {})",
        r_bearer.status()
    );

    // x-api-key (Anthropic SDK carrier) works.
    let r_xapi = client
        .post(&url)
        .header("x-api-key", token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
        "valid token via x-api-key must pass (got {})",
        r_xapi.status()
    );

    // x-goog-api-key (Gemini SDK carrier) works.
    let r_goog = client
        .post(&url)
        .header("x-goog-api-key", token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_goog.status().as_u16(),
        200,
        "valid token via x-goog-api-key must pass (got {})",
        r_goog.status()
    );

    // Wrong token via x-api-key → 401 with native (anthropic, inferred from /v1/messages) envelope.
    let r_wrong = client
        .post(&url)
        .header("x-api-key", "not-the-token")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r_wrong.status().as_u16(), 401, "wrong token must be 401");
    assert_eq!(
        r_wrong
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "401 must carry application/json native envelope, not text/plain"
    );
    let env: serde_json::Value = r_wrong.json().await.unwrap();
    // Anthropic native error envelope: {"type":"error","error":{...}}.
    assert!(
        env.get("error").is_some(),
        "native error envelope must contain an `error` object: {env}"
    );

    // Missing credential entirely → 401 (still JSON).
    let r_missing = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_missing.status().as_u16(),
        401,
        "missing token must be 401"
    );
    assert_eq!(
        r_missing
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware`: a virtual key with `enabled: false`
/// must be rejected with 401, while the same secret on an enabled key is admitted. Guards the
/// `Some(key) if key.enabled => ... else 401` authz path, which had no test (a regression that
/// dropped the `if key.enabled` guard would otherwise pass CI — an authz bypass).
#[tokio::test]
async fn test_disabled_virtual_key_is_rejected_401() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    // Mock upstream that returns a valid Anthropic-shaped body, so an ADMITTED request reaches
    // 200 rather than failing for an unrelated reason.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            }),
        });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let mk_spec = |name: &str| busbar_substrate::governance::NewKeySpec {
        name: name.to_string(),
        allowed_pools: Some(vec!["pa".to_string()]),
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (dis_key, disabled_secret) = gov
        .mint_signed(mk_spec("kdis"), 2_000_000_000, 1_000_000_000)
        .unwrap();
    let (_ena_key, enabled_secret) = gov
        .mint_signed(mk_spec("kena"), 2_000_000_000, 1_000_000_000)
        .unwrap();
    // Freeze the first key via the PATCH-shaped update (mint always starts `enabled: true`).
    gov.update_key(&dis_key.id, Some(false), None).unwrap();
    let disabled_secret = disabled_secret.as_str();
    let enabled_secret = enabled_secret.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let req =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Disabled key → 401.
    let r_dis = client
        .post(&url)
        .bearer_auth(disabled_secret)
        .body(req.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_dis.status().as_u16(),
        401,
        "a disabled virtual key must be rejected"
    );

    // Unknown secret → 401 (control: lookup miss is the same 401 path).
    let r_bogus = client
        .post(&url)
        .bearer_auth("sk-vk-nope")
        .body(req.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bogus.status().as_u16(),
        401,
        "unknown key must be rejected"
    );

    // Enabled key with the same shape → NOT 401 (admitted past auth).
    let r_ena = client
        .post(&url)
        .bearer_auth(enabled_secret)
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ena.status().as_u16(),
        200,
        "an enabled virtual key must pass auth (got {})",
        r_ena.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in GOVERNANCE mode, exercising the
/// non-`Authorization` carriers (`x-goog-api-key`, `x-api-key`) into the virtual-key lookup.
/// The existing governance test only uses `Authorization: Bearer`, and the multi-carrier test
/// runs under static-token mode (`governance=None`) — so the intersection (a virtual key
/// presented via a vendor-SDK carrier resolving the governance lookup) was untested. A
/// regression that stopped threading those carriers into `gov.lookup` would otherwise pass CI.
#[tokio::test]
async fn test_governance_accepts_vendor_carriers_and_native_401() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    // Two admitted requests (x-goog-api-key, x-api-key) reach the upstream; queue two bodies.
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (_key, token) = gov
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "kc".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Valid virtual key via x-goog-api-key (Gemini SDK carrier) → admitted past governance auth.
    let r_goog = client
        .post(&url)
        .header("x-goog-api-key", secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_goog.status().as_u16(),
        200,
        "valid virtual key via x-goog-api-key must pass governance (got {})",
        r_goog.status()
    );

    // Valid virtual key via x-api-key (Anthropic SDK carrier) → admitted past governance auth.
    let r_xapi = client
        .post(&url)
        .header("x-api-key", secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
        "valid virtual key via x-api-key must pass governance (got {})",
        r_xapi.status()
    );

    // Bad secret via x-goog-api-key → native JSON 401 (governance lookup miss).
    let r_bad = client
        .post(&url)
        .header("x-goog-api-key", "sk-vk-nope")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "an unknown virtual key via x-goog-api-key must be 401"
    );
    assert_eq!(
        r_bad
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "401 must carry the native application/json envelope, not text/plain"
    );

    handle.abort();
    server.shutdown().await;
}

/// A signed-token key must STOP authenticating after `revoke`, even though `revoke` denylists the
/// subject but DELIBERATELY leaves `enabled = true` (it preserves the binding for history) — so
/// the `enabled` check alone is not enough, `verify_token` must also consult the denylist.
/// (Formerly also covered the now-removed legacy hashed-secret `gov.lookup(secret)` fallback,
/// which had the same regression via a separate code path; that path no longer exists — see 1.5.0
/// migration notes, "1.4.x keys no longer authenticate" — so this test now exercises only the
/// signed-token path.)
#[tokio::test]
async fn test_governance_revoked_signed_token_key_rejected() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (key, token) = gov
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "revocable".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov.clone())
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Baseline: the freshly-minted signed token authenticates (200, proxied upstream).
    let ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok.status().as_u16(),
        200,
        "a live signed-token key must authenticate (got {})",
        ok.status()
    );

    // Revoke the subject (denylists it WITHOUT flipping `enabled`, exactly as `revoke_key` does).
    gov.revoke(&key.id, "audit regression").unwrap();
    assert!(gov.is_revoked(&key.id), "revoke must denylist the subject");

    // The same token must now be REJECTED 401 — a revoked key's signed token is dead.
    let denied = client
        .post(&url)
        .bearer_auth(secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status().as_u16(),
        401,
        "a REVOKED signed-token key's Bearer token must be rejected (got {})",
        denied.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (a) DEFAULT DEPLOY, NO admin token, a configured static auth chain: a request bearing a
/// credential that chain recognizes MUST be admitted by the static chain (governance is inert and
/// does NOT require a virtual key). Before the fix this 401'd because the always-present engine
/// forced a vkey lookup that no minted key could satisfy.
#[tokio::test]
async fn test_governance_inert_without_admin_token_static_token_admitted() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let token = "grp:static";
    let auth_cfg = chain_cfg(&["test-groups-module"]);
    // The default-deploy governance engine: RAM store, NO admin token, NO minted keys → INERT.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The static token MUST be honoured by the static chain — governance is inert, so no vkey needed.
    let r_ok = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the static [tokens] chain (got {})",
        r_ok.status()
    );

    // A WRONG token is still rejected by the static chain (the chain still gates, as before).
    let r_bad = client
        .post(&url)
        .bearer_auth("not-the-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "the static chain must still reject a non-allowlisted token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (b) NO admin token + EMPTY chain (open relay): a request presenting NO token MUST be admitted —
/// the open front door's accept-every-request semantics are honoured because governance is inert.
/// Before the fix the always-present engine rejected the tokenless request.
#[tokio::test]
async fn test_governance_inert_without_admin_token_open_relay_admits() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        // Empty chain = open relay (the old `mode: none`).
        .upstream_creds(busbar_core::auth::UpstreamCreds::Own)
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // NO token — the open relay must admit (governance is inert, not superseding the open door).
    let r_none = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the open relay (got {})",
        r_none.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (c) WITH admin token + a minted enabled key: governance is ACTIVE, so a valid virtual key is
/// admitted and an unknown token is rejected — the enforcement path is unchanged once active.
#[tokio::test]
async fn test_governance_active_with_admin_token_enforces_minted_key() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    // Admin token set → governance is ACTIVE (this is the real minted-keys deploy).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );
    let (_key, token) = gov
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "k".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The enabled virtual key is admitted.
    let r_ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an enabled virtual key must pass under active governance (got {})",
        r_ok.status()
    );

    // An unknown token is rejected — enforcement is live.
    let r_bad = client
        .post(&url)
        .bearer_auth("sk-vk-unknown")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "active governance must reject an unknown token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// BYPASS-EDGE (the durable-store-with-persisted-keys-but-admin-token-removed case): a store that
/// STILL holds a virtual key, but whose engine has NO admin token, is INERT. A request bearing that
/// persisted key's secret is therefore NOT governed by the key's per-key controls — it falls through
/// to the STATIC auth.chain. This pins the exact "bypass by mistake" behaviour the boot guard warns
/// about: the key's `allowed_pools` (here a pool the request does NOT target) is NOT enforced, and
/// the static chain (a token allowlist that does NOT list the key secret) is what decides admission.
///
/// The auth gate keys inertness on `admin_token_hash().is_some()`, independent of the store backend,
/// so a seeded `MemoryStore` + `None` admin token faithfully reproduces the durable-store edge for
/// the middleware's purposes (the store's DURABILITY only matters for the boot-time banner, covered
/// by the main-crate tests).
#[tokio::test]
async fn test_inert_governance_persisted_key_is_not_enforced_static_chain_wins() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore, Store, VirtualKey};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    // A key PERSISTED from a prior run, scoped to pool "restricted" ONLY (a pool the request below
    // does NOT target). If the key's controls were enforced, a request to pool "pa" bearing this
    // secret would be pool-ACL rejected. Under an INERT engine they are NOT consulted at all.
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kold".to_string(),
            generation_hash: busbar_substrate::sigv4::sha256_hex(persisted_secret.as_bytes()),
            name: "kold".to_string(),
            allowed_scopes: Some(vec![ScopeRef::pool("restricted")]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        })
        .unwrap();
    // NO admin token → INERT: the persisted key's controls are bypassed.
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );

    // The STATIC chain is what actually gates now - a chain that recognizes a DIFFERENT
    // credential shape (`grp:<role>`), NOT the persisted key secret.
    let static_token = "grp:static-chain";
    let auth_cfg = chain_cfg(&["test-groups-module"]);

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // (1) The persisted key secret is NOT in the static allowlist → the static chain REJECTS it.
    // This is the crux: the persisted key confers NOTHING now (its controls are inert); only the
    // static chain speaks. (If governance were still enforcing, this same secret would be ADMITTED
    // as a valid vkey — then pool-ACL/budget/RPM rejected. The 401-from-the-static-chain proves the
    // vkey path is not taken.)
    let r_key = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_key.status().as_u16(),
        401,
        "an inert engine's persisted key must confer nothing — the static chain (which does not \
         list it) rejects it (got {})",
        r_key.status()
    );

    // (2) The STATIC token is admitted — the static chain is fully in charge, and the key's zero
    // budget / zero RPM (which would block EVERY request if enforced) are NOT consulted. A 200 here
    // is the direct proof the persisted key's controls are bypassed.
    let r_static = client
        .post(&url)
        .bearer_auth(static_token)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_static.status().as_u16(),
        200,
        "the static chain governs an inert engine; the persisted key's 0-budget/0-RPM are NOT \
         enforced (got {})",
        r_static.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// CONTROL for the bypass-edge test: the SAME persisted key, but WITH an admin token set →
/// governance is ACTIVE and the key's per-key controls ARE enforced. The pool-ACL alone is enough
/// to prove enforcement: the key is scoped to "restricted" but the request targets "pa", so an
/// active engine rejects it (403 pool-ACL), whereas the inert twin above let the static chain decide.
#[tokio::test]
async fn test_active_governance_persisted_key_is_enforced() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore};
    use serde_json::json;
    use std::sync::Arc;

    busbar_core::metrics::init();

    // No upstream body queued — enforcement must reject before any upstream call.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    // Admin token SET → ACTIVE: the key resolves and its pool-ACL is enforced.
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );
    let (_key, persisted_secret) = gov
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "kold".to_string(),
                allowed_pools: Some(vec!["restricted".to_string()]), // NOT "pa"
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let persisted_secret = persisted_secret.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The key resolves (active engine) but its allowed_pools excludes "pa" → pool-ACL 403. The key
    // IS enforced — the opposite of the inert twin, where the static chain decided instead.
    let r = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "an active engine enforces the persisted key's pool-ACL (got {})",
        r.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// `chain:[]` + admin token + NO credential → 200 ANONYMOUS (the previously-impossible
/// "protected admin API, open relay" posture). Before 1.5.2 the admin token forced a vkey
/// on every data-plane request, so a no-credential request was 401.
#[tokio::test]
async fn test_1_5_2_open_chain_admin_token_no_credential_admits_anon() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    busbar_core::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    // Default auth = empty chain (open front door). Admin token present (governance active).
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "chain:[] + admin token + no credential must admit ANONYMOUS (open relay, protected admin)"
    );
    handle.abort();
    server.shutdown().await;
}

/// A `chain:[]` request carries a DEFAULT `GovCtx` (never a 500 MissingExtension). Same wire path
/// as the anonymous-admit case above: a 200 (rather than a 500) through the real router proves the
/// downstream `Extension<GovCtx>` extraction found the default GovCtx the Open arm inserts.
#[tokio::test]
async fn test_1_5_2_open_chain_inserts_default_govctx_no_500() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    busbar_core::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_ne!(
        r.status().as_u16(),
        500,
        "open chain must insert a default GovCtx (no MissingExtension 500)"
    );
    assert_eq!(r.status().as_u16(), 200);
    handle.abort();
    server.shutdown().await;
}

/// `chain:[]` + admin token + a VALID vkey voluntarily presented → 200, and the key is NOT
/// metered (pure anonymous: an empty chain resolves NOTHING). Before 1.5.2 the vkey path
/// resolved and metered it.
#[tokio::test]
async fn test_1_5_2_open_chain_valid_vkey_ignored_not_metered() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    busbar_core::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let key_id = gov.all_keys().unwrap()[0].id.clone();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .governance(gov.clone())
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .bearer_auth(&secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "open chain admits regardless of the presented vkey"
    );
    // PURE ANONYMOUS: the voluntarily-presented key was ignored → its ledger recorded no spend.
    let cost = busbar_core::cost::CostModel::flat(1);
    let spend = gov
        .usage_for(&cost, &key_id, busbar_core::store::now())
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(
        spend, 0,
        "an empty chain must NOT resolve/meter a presented vkey (pure anonymous)"
    );
    handle.abort();
    server.shutdown().await;
}

/// `chain:[keys]` + admin token + a VALID enabled vkey → 200 (admitted + governed, unchanged).
#[tokio::test]
async fn test_1_5_2_keys_chain_valid_vkey_admits() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    busbar_core::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .bearer_auth(&secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "chain:[keys] + valid enabled vkey must admit"
    );
    handle.abort();
    server.shutdown().await;
}

/// An IdP-style principal (the `test-groups-module` stand-in) whose role BINDS a group is
/// admitted with a SYNTHESIZED governance key: pool ACL applies (granted pool serves, ungranted 403).
#[tokio::test]
async fn test_1_5_2_role_bound_principal_synthesized() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    busbar_core::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    let rb = bindings_for(
        "test-groups-module",
        &[("eng", binding(Some(&["pa"]), None, None))],
    );
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .pool("pb", &[(0, 1)])
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .governance(gov)
        .role_bindings(rb)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let mk = |pool: &str| {
        reqwest::Client::new()
            .post(format!("http://{addr}/{pool}/v1/messages"))
            .bearer_auth("grp:eng")
            .body(serde_json::json!({"model": pool, "messages": [{"role":"user","content":"hi"}], "max_tokens": 8}).to_string())
            .send()
    };
    assert_eq!(
        mk("pa").await.unwrap().status().as_u16(),
        200,
        "granted pool serves (synth key)"
    );
    assert_eq!(
        mk("pb").await.unwrap().status().as_u16(),
        403,
        "ungranted pool is pool-ACL denied"
    );
    handle.abort();
    server.shutdown().await;
}

/// A correctly-signed Bedrock SigV4 ingress request under `chain:[keys]` is VERIFIED by the
/// pre-step and admitted (GovCtx attached, routes to upstream). The SigV4 pre-step now runs because
/// the chain names `keys`, NOT because an admin token is set.
#[tokio::test]
async fn test_1_5_2_sigv4_ingress_under_keys_chain_admitted() {
    crate::testkit::install_test_seams();
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    busbar_core::metrics::init();
    let state = std::sync::Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": "foo",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }),
    });
    let server = MockServer::new(state).await;

    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (_key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            busbar_core::store::now(),
        )
        .unwrap();

    let app = TestApp::new()
        .lane(
            LaneSpec::new("foo", crate::proto_codec::PROTO_OPENAI, &server.base_url())
                .provider("zai"),
        )
        .pool("foo", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;

    let path = "/model/foo/converse";
    let body = serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        .to_string();
    let amzdate = {
        let (a, _d) = busbar_substrate::sigv4::format_amz_time(busbar_core::store::now());
        a
    };
    let (auth, headers) = sign_bedrock_request(
        &secret,
        &akid,
        "us-east-1",
        "bedrock",
        path,
        body.as_bytes(),
        &amzdate,
    );
    let mut rb = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header(AUTHORIZATION, auth)
        .body(body);
    for (k, v) in &headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    let r = rb.send().await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "a correctly-signed Bedrock SigV4 request under chain:[keys] must verify and be admitted (got {})",
        r.status()
    );
    handle.abort();
    server.shutdown().await;
}
