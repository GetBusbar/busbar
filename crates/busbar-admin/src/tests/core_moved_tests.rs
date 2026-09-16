// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests MOVED here from busbar-core when the admin API service was extracted: they drive the
//! `/api/v1/admin/*` HTTP surface (mounted through the seam), which busbar-core's own test binary
//! no longer serves. Behavior is byte-identical; only the crate they live in changed.

use busbar_core::auth::X_ADMIN_TOKEN;
use axum::Router;

/// A present-but-blank `x-admin-token` must be rejected on
/// the admin surface. Driven end-to-end through the real router + `auth_middleware` so the
/// extraction + constant-time compare are exercised together. A correct token via the same header
/// authorizes, proving the 401 is the empty-filter and not a blanket reject.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_blank_header_token_rejected() {
    use busbar_core::governance::{GovState, MemoryStore};
    
    use std::sync::Arc;

    busbar_core::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Blank x-admin-token (and no Bearer) → 401: a blank header is treated as absent.
    let r_blank = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_blank.status().as_u16(),
        401,
        "a blank x-admin-token must be rejected (treated as absent), got {}",
        r_blank.status()
    );

    // Correct x-admin-token → authorized, proving the reject above is the empty-filter.
    let r_ok = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a correct x-admin-token must authorize, got {}",
        r_ok.status()
    );

    handle.abort();
}

/// Regression for the admin-token carrier-level timing oracle: the two admin
/// carriers (Authorization: Bearer and x-admin-token) are combined with a bitwise-OR fold, NOT a
/// short-circuiting `||`. Behaviorally this means EITHER carrier alone authorizes, AND a request
/// presenting BOTH carriers is authorized whenever EITHER matches — regardless of which one. We
/// drive it through the real router so the inline fold in `auth_middleware` is exercised:
///   - correct Bearer + wrong x-admin-token  → authorized (header compare ran, didn't veto)
///   - wrong Bearer  + correct x-admin-token  → authorized (Bearer miss didn't short-circuit away
///                                               the header compare)
///   - wrong + wrong                          → 401
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_both_carriers_or_fold_no_short_circuit() {
    use busbar_core::governance::{GovState, MemoryStore};
    
    use std::sync::Arc;

    busbar_core::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Correct Bearer + WRONG x-admin-token → authorized (the header compare must not veto a
    // matching Bearer; the fold is OR, not AND).
    let r = client
        .get(&url)
        .bearer_auth("admintok")
        .header(X_ADMIN_TOKEN, "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "correct Bearer + wrong x-admin-token must authorize (OR fold), got {}",
        r.status()
    );

    // WRONG Bearer + correct x-admin-token → authorized. This is the short-circuit regression: a
    // `||` would have stopped after the Bearer miss only if the header were checked next, but the
    // real risk is the inverse ordering — assert the header compare is reached and admits.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "wrong Bearer + correct x-admin-token must authorize (header compare must run), got {}",
        r.status()
    );

    // Both wrong → 401.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "also-wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "both carriers wrong must be rejected"
    );

    handle.abort();
}

/// Regression for the admin-surface carrier-separation invariant promised
/// by the comment at the top of the `is_admin` branch: the `/admin` operator surface is guarded
/// ONLY by `Authorization: Bearer` and `x-admin-token` — NOT by the vendor-SDK client-token
/// carriers (`x-api-key` / `x-goog-api-key`) that `extract_client_token` also reads. A future
/// DRY refactor unifying admin extraction onto `extract_client_token` would let the operator
/// admin token be presented via the carriers every native vendor SDK populates, turning any
/// leaked/observed client header into operator-surface (key create/delete) access. This pins the
/// boundary: the CORRECT admin secret presented via `x-api-key` or `x-goog-api-key` MUST 401,
/// while the two sanctioned admin carriers MUST authorize.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_not_acceptable_via_vendor_carriers() {
    use busbar_core::governance::{GovState, MemoryStore};
    
    use std::sync::Arc;

    busbar_core::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // The admin secret presented via the vendor-SDK carriers MUST be rejected: these carriers are
    // the client-token surface, NOT the operator surface. Exercise BOTH carriers, on BOTH the
    // GET (list) and POST (create) admin verbs, since the admin auth branch is verb-agnostic.
    for carrier in ["x-api-key", "x-goog-api-key"] {
        let r_get = client
            .get(&url)
            .header(carrier, "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_get.status().as_u16(),
            401,
            "admin secret via {carrier} (GET) must NOT reach the admin surface, got {}",
            r_get.status()
        );

        let r_post = client
            .post(&url)
            .header(carrier, "admintok")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_post.status().as_u16(),
            401,
            "admin secret via {carrier} (POST) must NOT reach the admin surface, got {}",
            r_post.status()
        );
    }

    // The two sanctioned admin carriers MUST authorize (proving the 401s above are carrier
    // separation, not a blanket reject).
    let r_bearer = client
        .get(&url)
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
        "Authorization: Bearer admintok must authorize the admin surface, got {}",
        r_bearer.status()
    );
    let r_hdr = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_hdr.status().as_u16(),
        200,
        "x-admin-token: admintok must authorize the admin surface, got {}",
        r_hdr.status()
    );

    handle.abort();
}

/// token authenticates `/api/v1/admin/*` and returns above the data-plane gate, unchanged.
/// (Gated on `auth-admin-tokens`: the operator admin-token module is compiled out under
/// `--no-default-features`, so there is no admin-token authenticator to exercise there.)
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_1_5_2_admin_path_bypasses_governance_and_mints() {
    
    busbar_core::metrics::init();
    let (gov, _secret) = dp_gov_with_key();
    let app = crate::new_test_app().governance(gov).build();
    let (addr, handle) = dp_serve(app).await;
    // Mint a key through the admin API using the operator admin token.
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(busbar_core::auth::X_ADMIN_TOKEN, "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "minted-via-admin"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "admin token must authenticate the admin API and mint (got {})",
        r.status()
    );
    // Wrong admin token → 401 (admin gate still enforced).
    let bad = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(busbar_core::auth::X_ADMIN_TOKEN, "nope")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "x"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong admin token must be rejected"
    );
    handle.abort();
}

/// SPLIT-LISTENER NO-DOUBLE-EXPOSURE: with a separate admin listener the admin surface must live
/// ONLY on the admin router. `build_split_routers_with_limits` must yield an admin router that
/// serves `/api/v1/admin/*` and a data router that does NOT — even for a request carrying a VALID
/// admin token (the route is ABSENT, not merely auth-guarded), so the public data bind can never
/// reach the management plane. Both planes keep an open, unauthenticated `/healthz`.
// Exercises the admin-token auth link, so it only applies when that feature is compiled in.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn split_admin_listener_no_double_exposure() {
    use busbar_core::governance::{GovState, MemoryStore};
    use busbar_core::test_support::LaneSpec;
    use std::sync::Arc;
    busbar_core::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    // One configured lane so `/healthz` reports ready (200) rather than "no usable lanes" (503) —
    // the probe URL is never actually dialed here; the test only exercises routing/auth.
    let app = crate::new_test_app()
        .lane(LaneSpec::new(
            "test-model",
            busbar_core::proto::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (data_router, admin_router, _handle) = crate::build_split_routers_with_limits(
        app,
        busbar_substrate::proxy::max_translate_body_bytes(),
        busbar_core::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_core::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );

    async fn get(router: Router, path: &str, token: Option<&str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut req = reqwest::Client::new().get(format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let code = req.send().await.unwrap().status().as_u16();
        server.abort();
        code
    }

    let admin_path = format!("{}/keys", busbar_core::admin::v1::contract::ADMIN_PREFIX);
    // Admin surface SERVED on the admin plane (valid token ⇒ 200).
    assert_eq!(
        get(admin_router.clone(), &admin_path, Some("admintok")).await,
        200,
        "admin router must serve the admin surface"
    );
    // Admin surface ABSENT on the data plane — even WITH a valid admin token it is a hard 404,
    // proving the route is not mounted here (no double-exposure), not merely auth-blocked.
    assert_eq!(
        get(data_router.clone(), &admin_path, Some("admintok")).await,
        404,
        "data router must NOT serve the admin surface even for an authenticated admin request"
    );
    // Both planes keep an open, unauthenticated liveness probe.
    assert_eq!(get(admin_router, "/healthz", None).await, 200);
    assert_eq!(get(data_router, "/healthz", None).await, 200);
}

// Local helpers copied from busbar-core's auth tests (shared there; a private copy here).
/// Local helper: serve a router on an ephemeral port, returning (addr, join handle).
async fn dp_serve(
    app: std::sync::Arc<busbar_core::state::App>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// A governance engine (admin token set) with ONE enabled, pool-`pa` virtual key. Returns (gov, secret).
fn dp_gov_with_key() -> (std::sync::Arc<busbar_core::governance::GovState>, String) {
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let signer = busbar_core::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_core::governance::signing::DEFAULT_KID,
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
