use super::*;
use crate::test_support::EnvVarGuard;
use crate::test_support::{build_once, cfg_with_provider_api_key};

// The monolith's root tests reached every crate-root item through `use super::*`. The split put
// those items in appbuild/preflight/router/boot; this block restores the same names to this file's
// scope. Allowed-unused as one block: which of these a given test build exercises varies by cfg.
#[allow(unused_imports)]
use crate::appbuild::{
    inert_durable_keys_banner, open_relay_banner, resolve_model_context_max,
    stateful_plane_ephemeral_store_warn,
};
use crate::config_validate::{registry_refusal, secret_module};
#[allow(unused_imports)]
use crate::preflight::{
    build_secret_resolver, is_real_auth_plugin_ref, is_real_identity_provider_plugin_ref,
    parse_signing_secret, resolve_admin_token, resolve_signing_key,
    valid_identity_provider_modules,
};
#[allow(unused_imports)]
use crate::router::{
    apply_common_layers, apply_inbound_concurrency_limit, base_data_router,
    build_router_with_limits, method_not_allowed_handler, project_auth_scope_caps,
    request_activity_tick, reshape_body_limit_413, reshape_oversized_413, server_timing,
    server_timing_dur_ms, AXUM_BODY_LIMIT_413_MARKER, HEADER_SERVER_TIMING, NO_UPSTREAM_RTT,
};
#[allow(unused_imports)]
use axum::Router;
#[allow(unused_imports)]
use std::collections::HashMap;

use crate::config::{PoolCfg, PoolMember};

/// The inbound-concurrency cap is added as a layer ONLY when `max_inbound_concurrent > 0`. This
/// drives `apply_inbound_concurrency_limit` over a minimal router whose handler PARKS on a barrier of
/// size 2 (released only once BOTH requests arrive). With cap = 1 the second request is SHED (Bug 4:
/// load-shed) rather than admitted, so it never reaches the barrier — the first handler waits out its
/// 300ms timeout ALONE and the run takes ≥ 300ms. With cap = 0 (NO layer) both requests reach the
/// barrier concurrently and release immediately (< 250ms). The dedicated shed semantics (the 503 the
/// second request receives) are asserted separately by
/// [`test_inbound_over_capacity_sheds_503_not_queued`]; this test only pins the add-layer-when-`>0`
/// rule via the timing difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_inbound_concurrency_layer_added_only_when_positive() {
    use std::sync::Arc;
    use tokio::sync::{Barrier, Notify};

    async fn run_router(router: Router) -> std::time::Duration {
        // Serve on an ephemeral port; fire two concurrent GETs to the parking handler.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let url = format!("http://{addr}/park");
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let (a, b) = tokio::join!(client.get(&url).send(), client.get(&url).send());
        a.unwrap();
        b.unwrap();
        let elapsed = start.elapsed();
        server.abort();
        elapsed
    }

    // Handler that signals arrival then waits on a barrier; the barrier of size 2 only releases
    // once BOTH requests have arrived — so if a layer serializes them to 1-at-a-time, the second
    // never arrives, the barrier never releases, and the handler instead falls back to a short
    // timeout. We detect the cap via that timeout path (capped run takes the timeout; uncapped run
    // releases immediately).
    fn make_router(barrier: Arc<Barrier>, _gate: Arc<Notify>) -> Router {
        Router::new().route(
            "/park",
            axum::routing::get(move || {
                let barrier = barrier.clone();
                async move {
                    // If both requests run concurrently the barrier releases at once. If a cap
                    // serializes them, this wait blocks until the per-request timeout fires.
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_millis(300), barrier.wait())
                            .await;
                    "ok"
                }
            }),
        )
    }

    // Uncapped (cap = 0): NO layer, both requests reach the barrier concurrently → fast release.
    let uncapped = apply_inbound_concurrency_limit(
        make_router(Arc::new(Barrier::new(2)), Arc::new(Notify::new())),
        0,
    );
    let uncapped_elapsed = run_router(uncapped).await;

    // Capped (cap = 1): the layer admits one and SHEDS the other, so the two requests can NOT both
    // reach the barrier at once → the first handler waits out its 300ms timeout alone.
    let capped = apply_inbound_concurrency_limit(
        make_router(Arc::new(Barrier::new(2)), Arc::new(Notify::new())),
        1,
    );
    let capped_elapsed = run_router(capped).await;

    assert!(
        uncapped_elapsed < std::time::Duration::from_millis(250),
        "cap=0 must add NO layer: both requests reach the barrier concurrently and release fast, \
             got {uncapped_elapsed:?}"
    );
    assert!(
        capped_elapsed >= std::time::Duration::from_millis(300),
        "cap=1 must serialize admission: the first request waits out its timeout before the \
             second is admitted, got {capped_elapsed:?}"
    );
}

/// THE ADMISSION CONTRACT. The original defect here was HEAD-OF-LINE BLOCKING: the old tower
/// concurrency layer queued in `poll_ready`, so a saturated cap wedged the whole CONNECTION and
/// every unrelated request sharing it. The fix keeps `poll_ready` always-ready and makes the
/// decision per REQUEST: an over-cap arrival is SHED IMMEDIATELY with the static 503 rather than
/// parked waiting for a slot. A queueing arm was tried in its place and had to be reverted — an
/// over-cap burst turned into an unbounded stall, which a client cannot tell apart from a hung
/// gateway, and it burns the caller's own deadline while holding the connection. This test pins
/// that shape: with cap = 1 held, a second request is answered AT ONCE with the 503, and the
/// admitted one still completes normally when it is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_inbound_over_capacity_sheds_immediately_and_admitted_request_completes() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let router = {
        let started = started.clone();
        let release = release.clone();
        Router::new().route(
            "/block",
            axum::routing::get(move || {
                let started = started.clone();
                let release = release.clone();
                async move {
                    // Signal that the (only) admission permit is now held, then hold it until released.
                    started.notify_one();
                    release.notified().await;
                    "ok"
                }
            }),
        )
    };
    let router = apply_inbound_concurrency_limit(router, 1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let url = format!("http://{addr}/block");

    // Request 1 acquires the single admission permit and parks in the handler.
    let url1 = url.clone();
    let req1 = tokio::spawn(async move { reqwest::Client::new().get(&url1).send().await });
    started.notified().await; // permit is now held

    // Request 2 arrives with the cap full: it must be SHED, and shed NOW — not parked until the
    // permit frees. (On a NEW connection, so this also witnesses the no-head-of-line property:
    // the second connection is serviced far enough to reach admission rather than wedging in the
    // accept path.) The timeout is the teeth: a parking layer never answers this call at all.
    let r2 = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::Client::new().get(&url).send(),
    )
    .await
    .expect("an over-capacity inbound request must be answered immediately, never parked")
    .expect("request 2 gets a response");
    assert_eq!(
        r2.status().as_u16(),
        503,
        "an over-capacity inbound request is shed with the at-capacity 503"
    );
    assert_eq!(
        r2.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "the shed names a concrete backoff"
    );
    assert_eq!(
        r2.text().await.unwrap(),
        r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#,
        "the static shed body is part of the observable contract"
    );

    // Shedding never disturbs the ADMITTED request: free the permit and request 1 completes 200.
    release.notify_one();
    let r1 = req1.await.unwrap().expect("request 1 completes");
    assert_eq!(r1.status().as_u16(), 200);
    server.abort();
}

fn pool(members: Vec<PoolMember>) -> PoolCfg {
    PoolCfg {
        upstream_credentials: None,
        members,
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy: crate::config::PoolPolicy::default(),
        gates: Vec::new(),
        base_named: false,
        ..Default::default()
    }
}

fn member(model: &str, context_max: Option<usize>) -> PoolMember {
    PoolMember {
        reasoning: None,
        model: model.to_string(),
        weight: 1,
        attempt_timeout_ms: None,
        context_max,
        tier: None,
        tags: Vec::new(),
    }
}

#[test]
fn test_resolve_model_context_max_explicit_wins_over_none() {
    // The same model in pool A with Some(128000) and pool B with None must resolve to the
    // explicit limit regardless of iteration order — None never clobbers a real value.
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", None)]));
    let resolved = resolve_model_context_max(&pools).expect("None must not override Some");
    assert_eq!(resolved.get("m"), Some(&Some(128_000)));
}

#[test]
fn test_resolve_model_context_max_identical_values_ok() {
    // The same explicit limit repeated across pools is consistent, not a conflict.
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(64_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", Some(64_000))]));
    let resolved = resolve_model_context_max(&pools).expect("identical values must not conflict");
    assert_eq!(resolved.get("m"), Some(&Some(64_000)));
}

#[test]
fn test_resolve_model_context_max_conflict_is_loud() {
    // Two DIFFERENT explicit limits for the same model is an operator contradiction: fail loud
    // (deterministic error) rather than silently pick whichever pool iterated last.
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", Some(32_000))]));
    let err =
        resolve_model_context_max(&pools).expect_err("conflicting context_max must be rejected");
    assert!(err.contains("conflicting context_max"), "got: {err}");
    assert!(err.contains('m'), "error must name the model; got: {err}");
    assert!(
        err.contains("128000") && err.contains("32000"),
        "error must show both values; got: {err}"
    );
}

#[test]
fn test_resolve_model_context_max_none_everywhere() {
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", None)]));
    pools.insert("b".to_string(), pool(vec![member("m", None)]));
    let resolved = resolve_model_context_max(&pools).expect("all-None resolves to None");
    assert_eq!(resolved.get("m"), Some(&None));
}

#[test]
fn test_open_relay_banner_distinguishes_absent_vs_explicit_none() {
    // Absent `auth:` block (empty chain): banner must flag the silent open-relay foot-gun.
    let absent = open_relay_banner(true, false).expect("empty chain must produce a banner");
    assert!(
        absent.contains("OPEN RELAY") && absent.contains("no `auth:` block"),
        "absent-auth banner must call out the missing block; got: {absent}"
    );
    // Explicit empty chain: still an open relay, but the operator opted in.
    let explicit = open_relay_banner(true, true).expect("explicit empty chain must banner");
    assert!(
        explicit.contains("OPEN RELAY") && explicit.contains("auth.chain is empty"),
        "explicit-empty banner must reference auth.chain is empty; got: {explicit}"
    );
}

#[test]
fn test_open_relay_banner_silent_when_auth_engaged() {
    // A non-empty chain emits nothing — the banner is exclusively for the open-relay state.
    assert!(open_relay_banner(false, true).is_none());
}

/// INERT-KEYS BOOT GUARD (bypass-edge): since 1.5.2 virtual-key enforcement is driven by the CHAIN
/// SHAPE, not the admin token. A DURABLE store carrying keys while `auth.chain` does NOT name the
/// `keys` verifier is the one state where a prior run's keys become silently unenforced (no
/// data-plane request resolves them). The banner fires EXACTLY there and nowhere else. The third
/// argument is now `keys_in_chain` (banner fires when it is FALSE).
#[test]
fn test_inert_durable_keys_banner_fires_only_for_durable_keyed_no_token() {
    // The dangerous edge: durable store, keys present, `keys` NOT in the chain → LOUD banner.
    let b = inert_durable_keys_banner(true, 3, false).expect("durable+keys+no-keys-chain banners");
    assert!(
        b.contains("INERT") && b.contains("3 key") && b.contains("keys"),
        "banner must name the count and the fix (add `keys` to auth.chain); got: {b}"
    );

    // `keys` IS in the chain → keys are enforced, no banner.
    assert!(
        inert_durable_keys_banner(true, 3, true).is_none(),
        "`keys` in the chain enforces persisted keys — no inert-keys banner"
    );

    // Durable store but EMPTY (fresh durable deploy, no keys yet) → nothing to bypass, no banner.
    assert!(
        inert_durable_keys_banner(true, 0, false).is_none(),
        "an empty durable store has no keys to leave unenforced"
    );

    // A RAM (non-durable) store never persists keys across restarts — even if it somehow reported
    // keys, the banner is scoped to durable stores.
    assert!(
        inert_durable_keys_banner(false, 5, false).is_none(),
        "the inert-keys banner is scoped to durable stores"
    );
}

/// STATEFUL-PLANE EPHEMERAL-STORE WARN: the sharper, conditional boot warn fires EXACTLY when the
/// RAM store is resolved AND a stateful plane (MCP tools / A2A agents, whether bare or pooled) is
/// configured — and names the CONSEQUENCE (in-flight task loss on restart), not just advice. An
/// LLM-only deploy (no stateful plane) and any durable store both stay silent: the sharper warn
/// would be noise there. This is a WARN, never a boot-block.
#[test]
fn test_stateful_plane_ephemeral_store_warn_fires_only_for_ram_plus_stateful() {
    // RAM store + an MCP plane configured (tool or tool-pool) → the specific warn fires.
    let w = stateful_plane_ephemeral_store_warn(true, true)
        .expect("RAM + the first stateful plane → sharper warn fires");
    assert!(
        w.contains("in-flight tasks will break")
            && w.contains(frozen_str("durable_store_advice").as_str())
            && w.contains("NOT survive a restart"),
        "the warn must name the CONSEQUENCE and the durable-store fix; got: {w}"
    );

    // RAM store + an A2A plane configured (agent or agent-pool) → fires (either stateful plane does).
    assert!(
        stateful_plane_ephemeral_store_warn(true, true).is_some(),
        "RAM + the second stateful plane → the sharper warn fires"
    );

    // RAM store but LLM-only (no stateful plane) → stateless, a restart costs nothing → NO warn.
    assert!(
        stateful_plane_ephemeral_store_warn(true, false).is_none(),
        "a stateless-only deploy must NOT get the sharper warn — noise trains people to \
         ignore warnings"
    );

    // A DURABLE store → task state survives a restart → no warn, even with stateful planes present.
    assert!(
        stateful_plane_ephemeral_store_warn(false, true).is_none(),
        "a durable store persists stateful-plane task state across restarts — no sharper warn"
    );
}

/// A MEMORY store can never REACH the inert-with-keys state in practice: keys are only minted
/// through the admin API, which is gated by the admin token — so a keyed engine implies an admin
/// token, and a RAM store starts empty every boot. This pins that invariant end-to-end: a fresh
/// `MemoryStore` reports zero keys, and its `admin_token_hash()` gate matches the token it was
/// constructed with. (The durable-store analogue is exercised by the router-level bypass test.)
#[test]
fn test_memory_store_cannot_reach_inert_with_keys() {
    use crate::governance::{GovState, MemoryStore};
    use std::sync::Arc;

    // No admin token → engine inert AND the store is empty (RAM starts fresh each boot). There is
    // no keyed-but-inert state to warn about: key_count is 0, so the banner is None regardless.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    assert!(gov.admin_token_hash().is_none(), "no admin token → inert");
    let key_count = gov.all_keys().map(|k| k.len()).unwrap_or(0);
    assert_eq!(key_count, 0, "a fresh RAM store holds no keys");
    // store_is_durable = false for memory → banner is None even if key_count were nonzero.
    assert!(inert_durable_keys_banner(false, key_count, false).is_none());

    // With an admin token the same engine is active — the state a real minted-keys deploy is in.
    let store2 = Arc::new(MemoryStore::new());
    let gov2 = GovState::new(store2, Some("admintok".to_string())).unwrap();
    assert!(gov2.admin_token_hash().is_some(), "admin token → active");
}

/// A deployment with NO plane mounted: every path resolves through the resolver's residual arm,
/// which is the arm these vendor-envelope assertions are about.
fn residual_planes() -> crate::plane_driver::dispatch::PlaneDispatch {
    crate::plane_driver::dispatch::PlaneDispatch::default()
}

// THE RESIDUAL-DIALECT TABLE (`test_residual_dialect_inference`: which shipped dialect each residual
// path shape is answered in) MOVED to the composition root's
// `crates/busbar/tests/residual_envelope_cross_plane.rs`, beside the other tests that assert
// real-plane behaviour. Its assertions are the real dialects' own residual
// claims, which that integration target reaches through the plane crate's testkit; this neutral
// source names no dialect.

// (The test that pinned `main.rs::proto_for_path` against the canonical `proto::proto_for_path`
// is GONE WITH ITS SUBJECT: there is no second classifier left for it to agree with. ONE resolver
// — `plane::PlaneDispatch::ingress_of` — answers for the fallback handlers, the 413 reshape and the
// auth-time 401 alike, so agreement is now a property of the code rather than of a test watching
// two copies. `plane_tests::the_mount_table_is_read_before_the_path_shape` pins what it answers.)

/// A 404 fallback on the OpenAI path is shaped as the OpenAI error envelope (no amzn headers).
#[tokio::test]
async fn test_fallback_chat_completions_404_is_json_no_amzn_headers() {
    let resp = fallback_error_response(
        &residual_planes(),
        "/v1/chat/completions",
        axum::http::StatusCode::NOT_FOUND,
        // REGRESSION: the fallback 404 emits the CANONICAL `not_found_error` kind, so
        // an OpenAI-inferred 404 carries `{"error":{"type":"not_found_error"}}`, not `not_found`.
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json") // golden wire-contract literal (kept bare on purpose)
    );
    // Guard the canonical kind reaches the body via the OpenAI writer's verbatim passthrough.
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["error"]["type"],
        "not_found_error", // golden wire-contract literal (kept bare on purpose)
        "a chat-completions-path 404 must carry the canonical not_found_error type, not not_found"
    );
    let resp = fallback_error_response(
        &residual_planes(),
        "/v1/chat/completions",
        axum::http::StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_none(),
        "a non-Converse-path fallback must NOT carry x-amzn-* headers"
    );
}

/// `Server-Timing` reports Busbar's OWN processing time = total − upstream RTT, with the
/// no-upstream sentinel reporting the full time and clock skew saturating to zero (never a
/// huge underflowed value).
#[test]
fn test_server_timing_dur_ms() {
    // total 1090µs − upstream 1000µs = 90µs internal = 0.090 ms.
    assert!((server_timing_dur_ms(1090, 1000) - 0.090).abs() < 1e-9);
    // No upstream hop (sentinel) → report the full time (e.g. /healthz at 57µs).
    assert!((server_timing_dur_ms(57, NO_UPSTREAM_RTT) - 0.057).abs() < 1e-9);
    // Clock skew (upstream measured ≥ total) saturates to 0, never underflows.
    assert_eq!(server_timing_dur_ms(500, 800), 0.0);
}

/// REGRESSION: axum's `DefaultBodyLimit` rejects an
/// oversized body with a bare `text/plain` 413 (`"length limit exceeded"`) — a router/proxy
/// tell. `reshape_oversized_413` must turn that into a protocol-native `application/json`
/// envelope. Against the OLD code (no reshaping layer) the response stayed `text/plain`, so this
/// assertion on `application/json` fails; after the fix it passes.
#[tokio::test]
async fn test_oversized_body_413_reshaped_to_json_not_plain_text() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    // Simulate exactly what axum's DefaultBodyLimit emits: a 413 with a bare text/plain body.
    let axum_native_413 = (
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "length limit exceeded",
    )
        .into_response();

    let reshaped =
        reshape_oversized_413(&residual_planes(), "/v1/chat/completions", axum_native_413).await;
    assert_eq!(reshaped.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    let ct = reshaped
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());
    assert_eq!(
        ct,
        Some("application/json"), // golden wire-contract literal (kept bare on purpose)
        "oversized-body 413 must be reshaped to application/json, not the bare text/plain tell"
    );
    let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
    // Must be valid JSON (not the plain-text "length limit exceeded" string).
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("reshaped 413 body must be valid JSON");
    assert!(
        v.get("error").is_some(),
        "a chat-completions-path 413 must carry an `error` envelope; got {v}"
    );
    assert_ne!(
        String::from_utf8_lossy(&bytes),
        "length limit exceeded",
        "the axum plain-text body must not survive reshaping"
    );
}

/// A non-413 response (or a 413 a handler already shaped as JSON) must pass through
/// `reshape_oversized_413` untouched — the layer only rewrites the bare-text body-limit reject.
#[tokio::test]
async fn test_reshape_oversized_413_passthrough() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    // Non-413: untouched.
    let ok = (axum::http::StatusCode::OK, "hello").into_response();
    let passed = reshape_oversized_413(&residual_planes(), "/v1/chat/completions", ok).await;
    assert_eq!(passed.status(), axum::http::StatusCode::OK);
    let bytes = passed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"hello",
        "non-413 body must pass through verbatim"
    );

    // 413 that is ALREADY application/json: untouched (re-wrapping would corrupt it).
    let already_json = (
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(busbar_contract::protocol::APPLICATION_JSON),
        )],
        r#"{"error":{"type":"request_too_large","message":"native"}}"#,
    )
        .into_response();
    let passed =
        reshape_oversized_413(&residual_planes(), "/v1/chat/completions", already_json).await;
    let bytes = passed.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["error"]["message"], "native",
        "an already-JSON 413 must be passed through, not re-wrapped"
    );
}

/// REGRESSION: a forward-path-relayed UPSTREAM 413 with a NON-JSON content-type (e.g.
/// an upstream that itself answers 413 with a `text/plain`/`text/html` body that is NOT axum's
/// own `length limit exceeded` marker) must pass through `reshape_oversized_413` UNTOUCHED —
/// reshaping it would clobber the upstream's relayed error with busbar's own envelope.
///
/// Against the OLD code (which reshaped ANY non-JSON 413) this body would be rewritten into
/// busbar's `request_too_large` JSON, so the `text/plain` content-type + verbatim-body
/// assertions below fail; after the sentinel gate they pass.
#[tokio::test]
async fn test_relayed_upstream_413_not_reshaped() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    // An upstream-relayed 413 whose body is NOT axum's body-limit sentinel.
    let upstream_413 = (
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "upstream says: prompt is too long",
    )
        .into_response();

    let passed =
        reshape_oversized_413(&residual_planes(), "/v1/chat/completions", upstream_413).await;
    assert_eq!(passed.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    // Content-type must remain the upstream's text/plain — NOT rewritten to application/json.
    assert_eq!(
        passed
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("text/plain; charset=utf-8"), // golden wire-contract literal (kept bare on purpose)
        "a relayed upstream 413 must keep its own content-type, not be reshaped to JSON"
    );
    let bytes = passed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"upstream says: prompt is too long",
        "a relayed upstream 413 body must pass through verbatim, not be clobbered"
    );
}

/// The sentinel gate must be exact: a non-JSON 413 whose body equals axum's
/// [`AXUM_BODY_LIMIT_413_MARKER`] IS reshaped (it is axum's own reject), confirming the
/// passthrough above is driven by the body content and not merely the content-type.
#[tokio::test]
async fn test_axum_marker_413_is_reshaped_even_as_plain_text() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    let axum_native_413 = (
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        std::str::from_utf8(AXUM_BODY_LIMIT_413_MARKER).unwrap(),
    )
        .into_response();

    let reshaped =
        reshape_oversized_413(&residual_planes(), "/v1/chat/completions", axum_native_413).await;
    assert_eq!(
        reshaped
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json"), // golden wire-contract literal (kept bare on purpose)
        "axum's own body-limit 413 (sentinel body) must be reshaped to JSON"
    );
    let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("reshaped 413 body must be valid JSON");
    assert!(v.get("error").is_some());
}

/// Helpers for the plugin pre-flight regression tests: a fresh temp plugins dir, and the rows a
/// plugins directory admits, stated through the registry double (`test_support::rows`): the kernel
/// names no loader, so no tarball is packed or scanned here. What the loader admits from a directory,
/// and in which words it refuses, is proven where the loader is composed
/// (`crates/busbar/tests/plugin_preflight_scan.rs`).
pub(crate) fn tmp_plugin_dir(tag: &str) -> std::path::PathBuf {
    // A monotonic counter, NOT a timestamp. Several helpers call this with the same `tag` from
    // different tests running concurrently, and a clock read is not guaranteed to differ between
    // two threads. Colliding on the path made two tests share one directory: one wrote its tarball
    // while the other scanned it, or removed the directory out from under it — surfacing as an
    // unrelated hooks test failing on "corrupt tar.gz archive" roughly one run in three.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // AND a once-per-process token, because the pid alone is not a process identity over time.
    // These dirs are deliberately never cleaned up, and under process churn (a full workspace
    // build spawning thousands of compiler processes while several copies of this binary run) the
    // OS reuses pids within a session — at which point a fresh run's `create_dir_all` happily
    // adopts a PREVIOUS run's leftover dir, stale manifests, stale cdylib copies and all. A stale
    // plugin dir reads exactly like an ABI or staleness defect, which is the worst possible way
    // for a fixture to fail. One clock read per PROCESS (not per call — see the counter note
    // above), so two calls in one process still can't collide and two processes with one pid
    // can't either.
    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-plugins-{}-{token:x}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A row dropped into a plugins directory, named `name`, aliased `alias`, of `kind`: unsigned and
/// admitted under the `allow_unsigned` opt-in, keyed (and printed) by its canonical name, as the
/// loader states a scanned row.
pub(crate) fn dropped(name: &str, alias: &str, kind: &str) -> busbar_contract::plugin_rows::Row {
    let mut row = crate::test_support::rows::row(name, alias, kind);
    row.key = name.to_string();
    row
}

/// A plugin present in `file` and SKIPPED by the trust policy for `reason`.
pub(crate) fn skipped_in(
    file: &str,
    name: &str,
    alias: &str,
    reason: &str,
) -> busbar_contract::plugin_rows::Skipped {
    let mut s = crate::test_support::rows::skipped(name, alias, reason);
    s.file = file.to_string();
    s
}

/// The loader's reason for skipping an unsigned plugin under the default trust (its words, as the
/// trust evaluator states them).
pub(crate) const UNSIGNED_SKIPPED: &str = "manifest carries no signature; refusing to load an \
     unsigned plugin. Set plugins.trust.allow_unsigned=true to permit unsigned plugins.";

fn plugins_cfg(dir: &std::path::Path, enabled: bool) -> crate::config::PluginsCfg {
    crate::config::PluginsCfg {
        enabled,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    }
}

fn gov_with_store(store: &str) -> crate::config::StoreCfg {
    crate::config::StoreCfg {
        module: store.to_string(),
        settings: serde_json::Map::new(),
    }
}

/// FAIL-CLOSED (hard requirement 1): `governance.store: <plugin>` with `plugins.enabled: false`
/// (or the block absent) is a BOOT ERROR that NAMES the flag — the drop-is-inert failsafe.
#[test]
fn store_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    let dir = tmp_plugin_dir("disabled-store");
    let err = crate::plugins_preflight(
        Some(&gov_with_store("durable-kv")),
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, false),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("durable-kv"), "names the store: {err}");
    // The ABSENT-block default behaves identically.
    let err = crate::plugins_preflight(
        Some(&gov_with_store("durable-kv")),
        None,
        &Default::default(),
        &Default::default(),
        &crate::config::PluginsCfg::default(),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "absent block: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE BOOT LOG OVER THE ROOT'S REGISTRY BUILD (ARCHITECT ruling Q8): the registry is built by
/// the composition root (`preflight::RegistryBuild`), and the preflight logs each step the build
/// notes — the same lines, the same fields, in the order it logged them when it scanned the
/// directory itself: `disabled`; or `enabled`, then every skipped row, then every loadable row.
/// The rows are the registry double's (`test_support::rows`): the directory holds the unsigned
/// `acme-lines` plugin, SKIPPED by the default trust and admitted under `allow_unsigned`.
#[test]
fn the_registry_build_keeps_the_preflights_boot_lines_in_order() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = tmp_plugin_dir("boot-lines");
    // The default trust skips the unsigned plugin.
    let skip = skipped_in("lines.tar.gz", "acme-lines", "lines", UNSIGNED_SKIPPED);
    crate::test_support::rows::drop_in(&dir, Vec::new(), vec![skip]);
    let lines = |cfg: &crate::config::PluginsCfg| {
        let cap = WarnCapture::capturing_debug();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        tracing::subscriber::with_default(subscriber, || {
            crate::plugins_preflight(
                None,
                None,
                &Default::default(),
                &Default::default(),
                cfg,
                &Default::default(),
            )
            .expect("the preflight passes");
        });
        let ours = |m: &String| m.starts_with("plugin");
        let messages = cap.messages().into_iter().filter(ours);
        messages
            .map(|m| m.trim_end().to_owned())
            .collect::<Vec<_>>()
    };
    let d = dir.to_string_lossy().into_owned();
    let off = lines(&plugins_cfg(&dir, false));
    assert_eq!(
        off,
        ["plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"]
    );
    let skipped = lines(&plugins_cfg(&dir, true));
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_eq!(
        skipped[0],
        format!("plugins: enabled dir={d} loadable=0 skipped=1")
    );
    assert!(
        skipped[1].starts_with("plugin present but NOT loaded (trust policy) ")
            && skipped[1].contains("plugin=acme-lines")
            && skipped[1].contains("lines.tar.gz"),
        "{skipped:?}"
    );
    // `allow_unsigned` admits it.
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-lines",
            "lines",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let allowed = lines(&cfg);
    assert_eq!(allowed.len(), 2, "{allowed:?}");
    assert_eq!(
        allowed[0],
        format!("plugins: enabled dir={d} loadable=1 skipped=0")
    );
    assert!(
        allowed[1].starts_with(
            "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in) "
        ) && allowed[1].contains("plugin=acme-lines"),
        "{allowed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// BOOT WARNS ABOUT A MALFORMED FLOOR where it resolved the trust policy: the preflight (boot,
/// reload, apply) warns before the root's registry build resolves the policy.
#[test]
fn the_preflight_warns_about_a_malformed_floor() {
    use crate::diagnostics::CONFIG_ANTIDOWNGRADE_FLOOR_INVALID;
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    let mut cfg = crate::config::PluginsCfg::default();
    cfg.min_versions.insert("p".into(), "v1".into());
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        crate::plugins_preflight(
            None,
            None,
            &Default::default(),
            &Default::default(),
            &cfg,
            &Default::default(),
        )
        .expect("the preflight passes");
    });
    assert!(
        cap.contains(&CONFIG_ANTIDOWNGRADE_FLOOR_INVALID.banner().to_string()),
        "{:?}",
        cap.messages()
    );
}

/// K5 (DECISIONS #2 rule (1)) — THE BUILT-IN STORE IS A ROW OF THE STORE AXIS. The linked store is
/// registered through the root's registry build (`preflight::RegistryBuild`), the admission a
/// dropped-in store's row takes, and the configured name resolves to it there — not a name the
/// kernel matches. With the plugins directory off the registry holds exactly that row, which states
/// itself ephemeral and opens through `open_store`, by its key and by its canonical name alike
/// (ARCHITECT C': one plugin, one identity). What the loader's build does with a dropped-in copy of
/// the SAME plugin and with a DIFFERENT plugin spelling the linked row's key (Q-P4-12) is proven
/// where the loader is composed: `crates/busbar/tests/plugin_preflight_scan.rs`,
/// `the_built_in_stores_dropped_in_copy_is_admitted_once_and_a_rival_is_refused`.
///
/// RED by planting the door bypass: `linked_rows()` registering nothing leaves the configured
/// `store.module` (the stand-in row) unresolved (the preflight then refuses it as a plugin with
/// plugins off).
#[test]
fn the_built_in_store_is_a_linked_row_of_the_store_axis() {
    let store = crate::test_support::stand_in_store();
    let name = store.module.as_str();
    let reg = crate::plugins_preflight(
        Some(&store),
        None,
        &Default::default(),
        &Default::default(),
        &crate::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("the configured store resolves on the axis");
    let row = reg.resolve(name).expect("the configured store is a row");
    assert_eq!(
        (row.kind.as_str(), row.ephemeral),
        (busbar_contract::abi::mechanism::kind::STORE, true)
    );
    let stores = reg
        .linked()
        .into_iter()
        .filter(|p| p.kind == busbar_contract::abi::mechanism::kind::STORE);
    assert_eq!((stores.count(), reg.loadable().len()), (1, 0));
    reg.store_door(name)
        .expect("the row states its door to boot");
    let canonical = row.name.clone();
    assert_ne!(canonical, name, "the row's canonical name is not its key");
    assert_eq!(row.key, name, "the row prints its key");
    reg.store_door(&canonical)
        .expect("the canonical name opens the same store");
    let by_canonical = crate::plugins_preflight(
        Some(&gov_with_store(&canonical)),
        None,
        &Default::default(),
        &Default::default(),
        &crate::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("`store.module: <canonical>` resolves as the key does");
    assert!(by_canonical.resolve(&canonical).expect("resolves").linked);
}

/// THE PRINTED NAME OF A LINKED ROW IS ITS KEY (ARCHITECT C'): every preflight refusal that names a
/// linked row prints the key it printed before the row answered to its canonical name too —
/// reached by its key or by its canonical name. Pinned per surface: `require_plugin` (a hook
/// referencing the store), the `identity-providers:` refusal, the `secrets:` key and a secret
/// reference.
#[test]
fn a_linked_rows_refusals_print_its_key() {
    let store = crate::test_support::stand_in_store();
    let key = store.module.clone();
    let dir = tmp_plugin_dir("printed-key");
    let plugins = plugins_cfg(&dir, true);
    let reg = crate::plugins_preflight(
        Some(&store),
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the store resolves");
    let canonical = reg.resolve(&key).expect("the row").name;
    for word in [key.as_str(), canonical.as_str()] {
        let hooks: std::collections::HashMap<String, crate::config::HookCfg> =
            serde_json::from_value(serde_json::json!({ "h": { "module": word, "kind": "tap" } }))
                .expect("hooks");
        let refused = crate::plugins_preflight(
            Some(&store),
            None,
            &Default::default(),
            &hooks,
            &plugins,
            &Default::default(),
        )
        .expect_err("a store is not a hook");
        assert!(
            refused.contains(&format!(
                "resolves to plugin '{key}' of kind 'store', not a `hook` plugin"
            )),
            "{word}: {refused}"
        );
        let providers: crate::config::IdentityProviders =
            serde_json::from_value(serde_json::json!({ "x": { "module": word } })).expect("idps");
        let refused = crate::plugins_preflight(
            Some(&store),
            None,
            &providers,
            &Default::default(),
            &plugins,
            &Default::default(),
        )
        .expect_err("a store is not an auth plugin");
        assert!(
            refused.contains(&format!(
                "identity-providers.x.module: '{word}' resolves to plugin '{key}' of kind 'store'"
            )),
            "{word}: {refused}"
        );
        assert_eq!(
            crate::config_validate::secret_module(reg.as_ref(), word).unwrap_err(),
            format!(
                "secrets.{word}: plugin '{key}' has kind 'store', not 'secret'; only a kind: \
                 secret plugin can back a `secrets:` block entry"
            )
        );
        let cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef {
            module: word.to_string(),
            ..crate::config::SecretRef::env("K")
        });
        let refused = crate::config_validate::registry_refusal(reg.as_ref(), &cfg).unwrap_err();
        assert!(
            refused.contains(&format!(
                "references secret module '{word}', but plugin '{key}' has kind 'store'"
            )),
            "{word}: {refused}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE LINKED SECRET SOURCES ARE PLUGINS ON THE SECRET KIND TABLE (THE DESIGN, "Plugins" and the
/// plugin ABI). `env` and `file` are secret plugins the kernel reaches through the root's
/// `SecretAxis`, not rows of the cold-kind registry and not a name the resolver matches: the
/// registry holds no secret row for either, and a resolution's failure text is the plugin's own,
/// unwrapped (1.5.5's). A dropped-in cold plugin spelling `env` does not take the name: the resolver
/// asks the linked plugins first, and the cold lane only for a module none of them answers.
///
/// RED by planting the shortcut back: a registry row answering `env` fails the first assert.
#[test]
fn the_linked_secret_sources_are_plugins_on_the_secret_table() {
    use crate::config::secret::{SecretRef, SecretResolver};
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &crate::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("the default boot registers its linked rows");
    for name in ["env", "file"] {
        assert!(reg.resolve(name).is_none(), "{name} is no cold-kind row");
        assert!(
            crate::config::secret::is_linked_secret(name),
            "{name} is a linked secret plugin"
        );
    }
    let var = "BUSBAR_K5B_LINKED_SECRET_ROW";
    std::env::set_var(var, "hunter2");
    let resolver = SecretResolver::builtins_only();
    assert_eq!(
        resolver.resolve(&SecretRef::env(var)).unwrap(),
        busbar_contract::redacted::Secret::new(b"hunter2".to_vec())
    );
    let missing = resolver
        .resolve(&SecretRef::env("BUSBAR_K5B_NO_SUCH_VARIABLE"))
        .expect_err("an unset variable refuses");
    assert_eq!(
        missing,
        "secret env:BUSBAR_K5B_NO_SUCH_VARIABLE cannot resolve: environment variable \
         'BUSBAR_K5B_NO_SUCH_VARIABLE' is unset"
    );

    let dir = tmp_plugin_dir("linked-secret");
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "env",
            "acme-env",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .expect("the directory scans");
    assert!(
        reg.resolve("env").is_some(),
        "the dropped-in row registered"
    );
    let cold = SecretResolver::with_plugin(Box::new(|_, _| {
        Ok(busbar_contract::redacted::Secret::new(
            b"from-the-cold-lane".to_vec(),
        ))
    }));
    assert_eq!(
        cold.resolve(&SecretRef::env(var)).unwrap(),
        busbar_contract::redacted::Secret::new(b"hunter2".to_vec())
    );
    std::env::remove_var(var);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ARCHITECT Q-P4-13: the pre-flight resolves a hook reference against the SAME claim table boot
/// opens hooks through — the LINKED hook rows (the hook axis: Statement name, aliases, former names,
/// hook words) beside the plugins directory's — not the registry alone, which holds no linked hook.
/// GREEN: a config naming this build's linked hook (the stand-in hook door) passes, with the plugin
/// subsystem off and on (RED before: "the hooks registry names plugin module(s) [<its name>],
/// which require the plugin subsystem" / "no plugin matching the hook reference"). RED ARM: an
/// unknown name is still refused in 1.5.5's BUSBAR-6009 words (golden BOOT-138c).
#[test]
fn a_linked_hook_named_in_config_passes_preflight_and_an_unknown_one_is_refused() {
    let hook = |module: &str| {
        let cfg: crate::config::HookCfg =
            serde_yaml::from_str(&format!("kind: gate\nmodule: {module}\n")).expect("a hook");
        std::collections::HashMap::from([("h".to_string(), cfg)])
    };
    let dir = tmp_plugin_dir("linked-hook");
    let run = |module: &str, enabled: bool| {
        crate::plugins_preflight(
            None,
            None,
            &Default::default(),
            &hook(module),
            &plugins_cfg(&dir, enabled),
            &Default::default(),
        )
    };
    let linked = linked_hook_name();
    for enabled in [false, true] {
        run(linked, enabled).unwrap_or_else(|e| {
            panic!("the linked hook '{linked}' passes (plugins.enabled: {enabled}): {e}")
        });
    }
    let err = run("oracle-hook", true).expect_err("an unknown hook is refused");
    assert!(
        err.starts_with(&format!(
            "no plugin matching the hook reference 'oracle-hook' is installed in '{}' (plugins ARE \
             enabled; loadable: []). Two things to check: is the plugin subsystem enabled? (it is) \
             — and is the signed `kind: hook` tarball actually IN the folder?",
            dir.display()
        )),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The linked hook's Statement name, as this test build links it (the ranking double).
fn linked_hook_name() -> &'static str {
    crate::test_support::ranking_double::NAME
}

/// K5b (3c) exit test, on the hook door: the built-in ranking strategies are the HOOK WORDS of ONE
/// linked `hooks-ranking` door on the hook axis — each strategy word names that row, and opens (with
/// `{"policy": "<word>"}`) as the strategy it spells. `weighted` stays the inline floor (no row).
/// The words are the door's Statement marks, never registry aliases: no registry row spells them.
/// RED by planting the door bypass: an axis with no linked ranking door leaves every strategy word
/// unknown.
#[test]
fn the_built_in_ranking_strategies_are_hook_words_of_one_linked_door_on_the_hook_axis() {
    for name in crate::config::RESERVED_HOOK_NAMES
        .iter()
        .filter(|n| crate::config::parse_strategy(n) != crate::config::PoolPolicy::Weighted)
    {
        assert!(
            crate::preflight::builtin_ranking_known(name),
            "a built-in ranking strategy is a hook word of the linked ranking door: {name}"
        );
        let (policy, _) = crate::preflight::builtin_ranking(name).expect("the strategy opens");
        assert_eq!(policy.name(), *name);
    }
    assert!(!crate::preflight::builtin_ranking_known(
        crate::config::ON_ERROR_WEIGHTED
    ));
    let reg = crate::preflight::linked().expect("the linked rows register");
    assert!(
        reg.resolve("cheapest").is_none(),
        "a strategy word is the door's mark, not a registry alias"
    );
}

/// RANKING PARITY THROUGH THE DOOR (ARCHITECT Q-SO9): each of the four strategy words, opened
/// through the hook axis and called through the hook seam, answers exactly the decision 1.5.5's
/// in-process native answered on the ranking parity cases (the 1.5.5 natives' own cases: the same
/// candidates, the same expected order or abstain). Every answer is `Ok`: the call never fails,
/// times out or reaches `on_error`. Its deadline is the dispatcher's Call class budget, never the
/// 1 ms gate default.
#[tokio::test]
async fn each_strategy_word_ranks_as_1_5_5_did_through_the_door_and_never_reaches_on_error() {
    use crate::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
    /// `(idx, cost, latency, concurrency, rate headroom)`.
    type Row = (usize, Option<f64>, Option<f64>, usize, Option<f64>);
    let cand = |&(idx, cost, lat, conc, rate): &Row| Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: cost,
        tags: &[],
        latency_ms: lat,
        available_concurrency: conc,
        budget_remaining: None,
        rate_headroom: rate,
        signals: Default::default(),
    };
    let req = RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "wire-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 10,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
        session: None,
    };
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let prefer = |o: &[usize]| RoutingDecision::Prefer(o.to_vec());
    // The 1.5.5 natives' cases (crates/hooks-ranking lib_tests before the door): word, candidates,
    // the decision 1.5.5 answered.
    let cases: Vec<(&str, Vec<Row>, RoutingDecision)> = vec![
        (
            "cheapest",
            vec![
                (0, Some(15.0), None, 1, None),
                (1, Some(3.0), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "cheapest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "cheapest",
            vec![(0, Some(5.0), None, 1, None)],
            prefer(&[0]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(120.0), 1, None),
                (1, None, Some(40.0), 1, None),
                (2, None, Some(80.0), 1, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "fastest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "fastest",
            vec![(0, None, Some(30.0), 1, None)],
            prefer(&[0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 2, None),
                (1, None, None, 9, None),
                (2, None, None, 5, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 0, None),
                (1, None, None, 0, None),
                (2, None, None, 0, None),
            ],
            prefer(&[0, 1, 2]),
        ),
        ("least_busy", vec![(0, None, None, 3, None)], prefer(&[0])),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.10)),
                (1, None, None, 1, Some(0.90)),
                (2, None, None, 1, None),
                (3, None, None, 1, Some(0.50)),
            ],
            prefer(&[1, 3, 0, 2]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, None),
                (1, None, None, 1, None),
                (2, None, None, 1, None),
            ],
            RoutingDecision::Abstain,
        ),
        (
            "usage",
            vec![(0, None, None, 1, Some(0.0)), (1, None, None, 1, Some(0.0))],
            prefer(&[0, 1]),
        ),
        ("cheapest", Vec::new(), RoutingDecision::Abstain),
        ("fastest", Vec::new(), RoutingDecision::Abstain),
        ("least_busy", Vec::new(), RoutingDecision::Abstain),
        ("usage", Vec::new(), RoutingDecision::Abstain),
        // An infinity is a key like any other, ordered as 1.5.5 ordered it (the v1.5.5 ranking
        // natives' `lib.rs:77-80`, `:99-102`): never dropped as absent.
        (
            "cheapest",
            vec![
                (0, Some(f64::INFINITY), None, 1, None),
                (1, Some(f64::INFINITY), None, 1, None),
            ],
            prefer(&[0, 1]),
        ),
        (
            "cheapest",
            vec![
                (0, Some(3.0), None, 1, None),
                (1, Some(f64::NEG_INFINITY), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(f64::INFINITY), 1, None),
                (1, None, Some(10.0), 1, None),
            ],
            prefer(&[1, 0]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.5)),
                (1, None, None, 1, None),
                (2, None, None, 1, Some(f64::INFINITY)),
            ],
            prefer(&[2, 0, 1]),
        ),
    ];
    let gate_default = std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS);
    for (word, rows, want) in cases {
        let (policy, budget) =
            crate::preflight::builtin_ranking(word).expect("the strategy opens through the door");
        assert!(
            budget > gate_default,
            "`{word}`'s deadline is the dispatcher's Call class budget, not the gate default"
        );
        let cands: Vec<Candidate<'_>> = rows.iter().map(cand).collect();
        let got = policy.decide(&req, &cands, &ctx, budget).await;
        match got {
            Ok(decision) => assert_eq!(decision, want, "`{word}` over {rows:?}"),
            Err(e) => panic!("`{word}` reached on_error ({e}); 1.5.5's ranking never did"),
        }
    }
}

/// An UNKNOWN `governance.store` name (no plugin matches by alias or name) is a clear boot error
/// listing what IS available.
#[test]
fn unknown_store_name_is_a_clear_boot_error() {
    let dir = tmp_plugin_dir("unknown-store");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-store-x",
            "x",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let err = crate::plugins_preflight(
        Some(&gov_with_store("dynamo")),
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("'dynamo'"), "names the missing store: {err}");
    assert!(
        err.contains("acme-store-x"),
        "lists what is available: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── secrets: block validation + alias/name canonicalization ──────────────────────────────────────

/// A registry over a plugins directory holding an unsigned `kind: secret` plugin (name
/// `acme-secret-vault`, alias `vault`) admitted under `allow_unsigned`, for exercising the
/// `secrets:` block resolution.
fn secret_registry(
    tag: &str,
) -> (
    std::path::PathBuf,
    std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
) {
    let dir = tmp_plugin_dir(tag);
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-secret-vault",
            "vault",
            busbar_contract::abi::mechanism::kind::SECRET,
        )],
        Vec::new(),
    );
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .expect("allow_unsigned permits the unsigned secret plugin");
    (dir, reg)
}

/// A `secrets:` entry naming a reserved BUILT-IN resolver (`env` / `file`) as a
/// module is rejected — the built-ins take no module-level open() config, so such an entry is an
/// operator error, not a silent no-op. The one validator refuses it in its semantic pass, before
/// any registry exists, on every path (boot, apply, `--validate`, the admin dry run): this is the
/// refusal the operator reads. (The registry-side check that once refused it a second time, in
/// other words, could never be reached and is gone — S-10.)
#[test]
fn secrets_block_rejects_builtin_resolver_names() {
    for reserved in ["env", "file"] {
        let mut cfg =
            crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::env("K"));
        cfg.secrets.insert(
            reserved.to_string(),
            crate::config::SecretModuleCfg::default(),
        );
        let errs = crate::config_validate::validate(&cfg).unwrap_err();
        let refusal = errs
            .iter()
            .find(|e| e.starts_with(&format!("secrets.{reserved}: ")))
            .unwrap_or_else(|| panic!("reserved '{reserved}' not refused: {errs:?}"));
        assert!(
            refusal.starts_with(&format!(
                "secrets.{reserved}: the built-in '{reserved}' secret module takes no \
                 module-level config; its settings ("
            )) && refusal.ends_with(
                ") belong on each individual secret reference, not in the top-level `secrets:` \
                 block"
            ),
            "reserved '{reserved}' refused in the semantic pass's words: {refusal}"
        );
        // The same config, through the one validator, stops at the semantic pass.
        let refused = crate::config_validate::check(
            &cfg,
            crate::config_validate::Check {
                plugins: &crate::config::PluginsCfg::default(),
                unset_env_vars: &[],
                root: &crate::config_validate::no_root_rules,
                fetch: None,
                resolve_builtins: false,
            },
        )
        .unwrap_err();
        assert!(
            matches!(&refused, crate::config_validate::Refusal::Config(e) if e.contains(refusal)),
            "the one validator refuses '{reserved}' in the semantic pass: {refused:?}"
        );
    }
}

/// THE ONE VALIDATOR'S ORDER (S-10). Boot, every apply, `--validate` and the admin dry run all
/// run `config_validate::check`, so one config gets one answer on every path:
/// - a semantic refusal stops it before the root's rules are asked;
/// - the root's refusal stops it before any plugin is scanned;
/// - a `secrets:` block entry no plugin backs is refused before a secret REFERENCE no plugin backs;
/// - the built-in secrets are resolved only when asked.
#[test]
fn one_validator_refuses_in_one_order() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    let plugins = crate::config::PluginsCfg::default();
    let check = |cfg: &crate::config::RootCfg,
                 root: &dyn Fn(&crate::config::RootCfg) -> Result<(), String>,
                 resolve_builtins: bool| {
        crate::config_validate::check(
            cfg,
            crate::config_validate::Check {
                plugins: &plugins,
                unset_env_vars: &[],
                root,
                fetch: None,
                resolve_builtins,
            },
        )
    };
    let refuse_root = |_: &crate::config::RootCfg| Err("the root refuses".to_string());

    // A reference to a secret module nothing backs, plus a `secrets:` entry nothing backs.
    let mut cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef {
        module: "typo-ref".to_string(),
        ..crate::config::SecretRef::env("K")
    });
    cfg.secrets.insert(
        "typo-vault".to_string(),
        crate::config::SecretModuleCfg::default(),
    );
    match check(&cfg, &crate::config_validate::no_root_rules, false) {
        Err(crate::config_validate::Refusal::Plugins(e)) => assert!(
            e.starts_with("secrets.typo-vault: no loadable `kind: secret` plugin"),
            "the `secrets:` block is judged before the references: {e}"
        ),
        other => panic!("refused by the registry half: {other:?}"),
    }
    // The root's rules come before any plugin is scanned.
    assert_eq!(
        check(&cfg, &refuse_root, false).unwrap_err(),
        crate::config_validate::Refusal::Root("the root refuses".to_string())
    );
    // With the `secrets:` entry gone, the reference is what is refused.
    cfg.secrets.clear();
    match check(&cfg, &crate::config_validate::no_root_rules, false) {
        Err(crate::config_validate::Refusal::Plugins(e)) => assert!(
            e.contains("references secret module 'typo-ref', which is not a built-in"),
            "the reference is refused: {e}"
        ),
        other => panic!("refused by the registry half: {other:?}"),
    }
    // A semantic refusal comes before the root's rules.
    cfg.limits.reasoning_effort_budgets.minimal = 0;
    assert!(
        matches!(
            check(&cfg, &refuse_root, false),
            Err(crate::config_validate::Refusal::Config(_))
        ),
        "the semantic pass answers first"
    );

    // Built-in secrets resolve only when asked: an unset env var passes until then.
    let var = "BUSBAR_S10_ONE_VALIDATOR_UNSET_VAR";
    assert!(std::env::var_os(var).is_none());
    let cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::env(var));
    assert!(check(&cfg, &crate::config_validate::no_root_rules, false).is_ok());
    match check(&cfg, &crate::config_validate::no_root_rules, true) {
        Err(crate::config_validate::Refusal::Unresolved(e)) => {
            assert!(e.contains(var), "the unresolved reference is named: {e}")
        }
        other => panic!("refused as unresolved: {other:?}"),
    }
}

/// A `secrets:` entry that resolves to NO loadable plugin is a hard error (not a silent `{}` open) —
/// this is the failure that pairs with the alias/name mismatch below.
#[test]
fn secrets_block_rejects_unknown_module() {
    let reg = crate::test_support::rows::empty();
    let err = secret_module(reg.as_ref(), "typo-vault").unwrap_err();
    assert!(
        err.contains("no loadable") && err.contains("typo-vault"),
        "unknown module named in the error: {err}"
    );
}

/// The `secrets:` block key canonicalizes through the SAME by_name/by_alias
/// resolution the registry uses — a block keyed on the ALIAS and a block keyed on the CANONICAL name
/// both resolve to the plugin's canonical name, so a later `SecretRef` written under either spelling
/// finds the configured open() config (no silent `{}`).
#[test]
fn secrets_block_canonicalizes_alias_and_name_to_the_same_key() {
    let (dir, reg) = secret_registry("secrets-canon");
    // Both the alias and the canonical name resolve to the SAME canonical name.
    assert_eq!(
        secret_module(reg.as_ref(), "vault").unwrap(),
        "acme-secret-vault"
    );
    assert_eq!(
        secret_module(reg.as_ref(), "acme-secret-vault").unwrap(),
        "acme-secret-vault"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `secrets:` entry naming a plugin whose kind is NOT `secret` is rejected (only a kind: secret
/// plugin can back a `secrets:` block entry).
#[test]
fn secrets_block_rejects_non_secret_kind() {
    let dir = tmp_plugin_dir("secrets-wrong-kind");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    // A STORE-kind plugin — wrong kind for a secrets: entry.
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-store-x",
            "x",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .unwrap();
    let err = secret_module(reg.as_ref(), "x").unwrap_err();
    assert!(
        err.contains("not 'secret'"),
        "wrong-kind rejection names the mismatch: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED PROVIDER CREDENTIAL: a provider `api_key` whose reference does not resolve STOPS
/// BOOT. It used to warn and start the lane with an empty credential — a lane that reported healthy,
/// was never probed (no key, no probe), and 401'd every request routed to it.
///
/// The refusal must name the provider and the REFERENCE, and must carry no credential material: a
/// SECOND provider whose key DOES resolve puts a sentinel value in the process environment, and the
/// refusal must not contain it. That is the real property — nothing dumps a resolved credential into
/// a boot diagnostic — and it is checkable, unlike asserting the absence of a value that was never
/// read.
#[test]
fn boot_refuses_a_provider_api_key_that_does_not_resolve() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    const SENTINEL: &str = "sk-sentinel-must-never-be-printed";
    let set_var = format!("BUSBAR_TEST_PROVIDER_KEY_SET_{}", std::process::id());
    let unset_var = format!("BUSBAR_TEST_PROVIDER_KEY_UNSET_{}", std::process::id());
    std::env::set_var(&set_var, SENTINEL);
    std::env::remove_var(&unset_var);

    let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(&unset_var));
    // A second, RESOLVING provider (the same fixture under another name), so the sentinel really is
    // resolvable during this boot and its absence from the error means something.
    let resolving = cfg_with_provider_api_key(crate::config::SecretRef::env(&set_var))
        .providers
        .remove("acme")
        .expect("fixture provider");
    cfg.providers.insert("resolves".to_string(), resolving);
    for (model, provider) in [("m-unset", "acme"), ("m-set", "resolves")] {
        cfg.models
            .insert(model.to_string(), model_cfg_for_provider(provider));
    }

    let err = build_once(cfg, None)
        .err()
        .expect("an api_key that does not resolve must refuse boot, not degrade to an empty key");
    assert!(
        err.contains("acme"),
        "the refusal names the provider: {err}"
    );
    assert!(
        err.contains(&format!("env:{unset_var}")),
        "the refusal names the reference: {err}"
    );
    assert!(
        err.contains("api_key: none"),
        "and points at the keyless declaration for an upstream that takes no credential: {err}"
    );
    assert!(
        !err.contains(SENTINEL),
        "a resolved credential value must never appear in a boot diagnostic"
    );

    std::env::remove_var(&set_var);
}

/// `api_key: none` — the EXPLICIT keyless declaration — BOOTS. It is the one form that starts a lane
/// with no credential now that a reference which fails to resolve refuses, so the whole migration
/// path for a keyless local upstream rests on this building an App at all.
///
/// What that lane then does on the wire — no auth header, and skipped by the prober — is asserted at
/// the seams that decide it, in the retired engine crate's `auth_style_tests` and `health` tests, rather than
/// re-derived here through a lane accessor that exists only for the test.
#[test]
fn boot_starts_a_keyless_lane_declared_none() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::none());
    cfg.models
        .insert("m0".to_string(), model_cfg_for_provider("acme"));
    build_once(cfg, None).expect("`api_key: none` starts the lane");
}

/// A `ModelCfg` naming `provider`, with every other field at its default — the two credential tests
/// above differ only in the provider's `api_key`, so the model they hang off it is boilerplate.
#[cfg(test)]
fn model_cfg_for_provider(provider: &str) -> crate::config::ModelCfg {
    crate::config::ModelCfg {
        provider: provider.into(),
        max_concurrent: Some(1),
        max_requests: -1,
        default_max_tokens: None,
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: None,
        prompt_caching: None,
        protocol: None,
    }
}

/// The marquee 1.5.0 "secrets are plugins" feature — a provider
/// `api_key: { module: acme-vault, … }` (TLS cert/key, `auth.signing_key`, and the admin token are
/// the same shape) — must PASS validation when the `kind: secret` plugin is loaded + trusted. The
/// module-existence check is DEFERRED past `config_validate::validate` (which runs before the plugin
/// registry exists) to `config_validate::registry_refusal`, which consults the SAME registry the resolver uses.
#[test]
fn secret_ref_plugin_backed_module_passes_when_plugin_present() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    let (dir, reg) = secret_registry("secretref-vault-ok");
    // The `vault` alias AND the canonical `acme-secret-vault` name both resolve → both pass.
    for module in ["vault", "acme-secret-vault"] {
        let cfg = cfg_with_provider_api_key(crate::config::SecretRef {
            module: module.to_string(),
            settings: serde_json::Map::new(),
        });
        // `config_validate::validate` (pre-registry) must NOT reject a plugin-backed module.
        assert!(
            crate::config_validate::validate(&cfg).is_ok(),
            "pre-registry validate must not reject plugin-backed module '{module}'"
        );
        // The registry-backed pre-flight check PASSES because the plugin is loaded + is kind:secret.
        assert!(
            registry_refusal(reg.as_ref(), &cfg).is_ok(),
            "a loaded kind:secret plugin '{module}' must pass the secret-ref pre-flight"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A GENUINE typo — a secret module that is neither a built-in
/// (`env`/`file`) nor a loaded plugin — must still FAIL, so the deferral does not weaken the check.
#[test]
fn secret_ref_typo_module_still_fails_at_preflight() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    let (dir, reg) = secret_registry("secretref-typo");
    let cfg = cfg_with_provider_api_key(crate::config::SecretRef {
        module: "vaultt".to_string(), // typo of the `vault` alias — no such plugin
        settings: serde_json::Map::new(),
    });
    // `validate` alone can't tell a typo from an installed plugin (no registry), so it must NOT be
    // the layer that catches this — the deferred registry check is.
    assert!(
        crate::config_validate::validate(&cfg).is_ok(),
        "pre-registry validate cannot (and must not) reject the unknown module by itself"
    );
    let err = registry_refusal(reg.as_ref(), &cfg)
        .expect_err("a typo'd secret module with no plugin must fail the pre-flight");
    assert!(
        err.contains("providers.acme.api_key")
            && err.contains("vaultt")
            && err.contains("no loadable"),
        "the error must name the ref and the unknown module: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The built-in `env`/`file` modules always pass the registry
/// pre-flight (they are resolved inline, never through a plugin), even with an EMPTY registry.
#[test]
fn secret_ref_builtin_modules_pass_with_empty_registry() {
    let reg = crate::test_support::rows::empty();
    let cfg = cfg_with_provider_api_key(crate::config::SecretRef::env("ACME_KEY"));
    assert!(
        registry_refusal(reg.as_ref(), &cfg).is_ok(),
        "a built-in env ref must pass the pre-flight with no plugins loaded"
    );
}

/// A secret ref naming a plugin of the WRONG kind (a store plugin,
/// not `kind: secret`) fails the pre-flight — the same wrong-kind guard the `secrets:` block gets.
#[test]
fn secret_ref_wrong_kind_plugin_fails_at_preflight() {
    let dir = tmp_plugin_dir("secretref-wrong-kind");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-store-x",
            "x",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .unwrap();
    let root = cfg_with_provider_api_key(crate::config::SecretRef {
        module: "x".to_string(),
        settings: serde_json::Map::new(),
    });
    let err = registry_refusal(reg.as_ref(), &root)
        .expect_err("a store-kind plugin cannot back a secret reference");
    assert!(
        err.contains("not 'secret'") && err.contains("providers.acme.api_key"),
        "wrong-kind rejection names the ref and mismatch: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── CREDENTIAL SecretRefs RE-RESOLVE ON APPLY/RELOAD ──────────────────────
//
// `GovState` is process-lifetime and REUSED across every config apply/reload (the key cache,
// ledgers and rate windows must survive one). Its admin-token digest and signing key were resolved
// ONCE at construction and then frozen, so an operator who rotated the underlying secret behind the
// operator credential's `token:` or `auth.signing_key` and reloaded got NO effect: the process kept
// accepting the boot-time credential for the rest of its life, while every signal it gave said the
// rotation had landed. The rotation tests drive the REAL `build_app_from_config` apply path with an
// operator token configured, so they need the auth row the composition root links for it: they live
// beside that row, in the root's `root/tests/linked_auth.rs`.

/// The neutral session substrate is PROCESS-LIFETIME: a config apply must carry the SAME
/// `SessionStore` `Arc` across the rebuild — otherwise every apply would forget every live session's
/// cleared-scan set (and any future tenant's state), exactly the failure the probe-schedule carry
/// guards against. Synchronous pointer identity, no clock. Also pins the operator default: with the
/// env flag unset the gate hot path stays OFF (`incremental_scan == false`), i.e. byte-identical to
/// 1.5.4.
#[test]
fn a_rebuild_carries_the_session_store_and_defaults_scan_off() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let cfg = || {
        cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_SESSION_STORE",
        ))
    };
    let prior = build_once(cfg(), None).expect("boot");
    assert!(
        !prior.incremental_scan,
        "with BUSBAR_INCREMENTAL_SCAN unset the gate incremental scan must default OFF"
    );
    let next = build_once(cfg(), Some(&prior)).expect("rebuild");
    assert!(
        std::sync::Arc::ptr_eq(&prior.session_store, &next.session_store),
        "an apply must carry the process-lifetime session substrate across the rebuild"
    );
}

/// #39: a `secrets:` block written under BOTH a plugin's ALIAS and its CANONICAL name resolves to
/// one module, and the second entry used to silently overwrite the first — one block's configured
/// address/token/CA just vanished while the module loaded happily on the survivor. Ambiguous by
/// construction (there is no defensible winner), so it is a loud boot error naming both spellings.
#[test]
fn secrets_block_rejects_alias_and_canonical_for_one_module() {
    let (dir, reg) = secret_registry("secrets-alias-collision");
    let mut secrets = std::collections::BTreeMap::new();
    for spelling in ["vault", "acme-secret-vault"] {
        secrets.insert(
            spelling.to_string(),
            crate::config::SecretModuleCfg {
                settings: serde_json::Map::new(),
            },
        );
    }
    let err = match crate::preflight::build_secret_resolver(reg.clone(), &secrets) {
        Err(e) => e,
        Ok(_) => panic!("two spellings of one secret module must be a loud error"),
    };
    assert!(
        err.contains("acme-secret-vault") && err.contains("vault") && err.contains("TWICE"),
        "the error names the module and both spellings: {err}"
    );

    // Either spelling ALONE is fine (the canonicalization itself is unchanged).
    for spelling in ["vault", "acme-secret-vault"] {
        let mut one = std::collections::BTreeMap::new();
        one.insert(
            spelling.to_string(),
            crate::config::SecretModuleCfg {
                settings: serde_json::Map::new(),
            },
        );
        assert!(
            crate::preflight::build_secret_resolver(reg.clone(), &one).is_ok(),
            "a single '{spelling}' block still configures the module"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A REJECTED CONFIG MUST NOT LEAVE ITS LIMITS INSTALLED.
///
/// `build_app_from_config` installs the candidate `limits` process-wide as its FIRST act — it has
/// to, because the build itself reads them through the deep-call-stack accessors. But every step
/// after that is fallible (semantic validation, the plugin pre-flight, secret-ref resolution, the
/// store open), and no error path used to put the previous values back. A `POST /config/apply` that
/// returned 400 therefore mutated live, process-wide caps under the old `App` that kept serving:
/// `busbar_kernel_egress::upstream::max_translate_body_bytes()` bounds both the SigV4 auth-middleware body buffer and the
/// cross-protocol translate buffer, so a rejected apply could silently start 401-ing larger Bedrock
/// requests and failing larger cross-protocol completions.
///
/// The sharpest case is the one asserted here, because it is self-contradictory: the values
/// `validate_limits` exists to REJECT are exactly the ones that got installed anyway, since the
/// range check runs after the install.
///
/// Asserted as "the rejected value is not what is installed" rather than "the prior value is" —
/// `INSTALLED` is process-global and other tests in this binary build apps concurrently, but none
/// of them uses this deliberately-illegal number.
#[test]
fn a_rejected_config_leaves_no_limits_behind() {
    crate::snapshot::init();
    // Below `REQUEST_BODY_MAX_BYTES_FLOOR` (64 KiB) — `validate_limits` refuses it, which is the
    // whole point: the refusal happens AFTER the install.
    const ILLEGAL: usize = 4096;
    // Precondition, checked at COMPILE time: raising the floor must not quietly make this test
    // assert nothing.
    const _: () = assert!(ILLEGAL < crate::config::REQUEST_BODY_MAX_BYTES_FLOOR);

    // `api_key: none` — this fixture's provider is never contacted, so it declares no credential
    // rather than naming a variable it knows is unset (which now refuses boot).
    let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::none());
    cfg.limits.request_body_max_bytes = ILLEGAL;

    let Err(err) = build_once(cfg, None) else {
        panic!("a below-floor body cap must fail validation")
    };
    assert!(
        err.contains("request_body_max_bytes"),
        "the build failed for the expected reason: {err}"
    );
    assert_ne!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        ILLEGAL,
        "the REJECTED config's limits are installed process-wide — an invalid apply changed the \
         live signed-ingress and cross-protocol translate body caps"
    );
}

/// THE 413 RESHAPE MUST FIRE ON A REAL OVERSIZED REQUEST.
///
/// Every existing test of this path hand-constructs the sentinel body and calls the pure
/// `reshape_oversized_413` directly, so all four passed while the layer was dead in production:
/// `AXUM_BODY_LIMIT_413_MARKER` was pinned to axum 0.7's wire shape and the crate is on axum 0.8,
/// whose `FailedToBufferBody::LengthLimitError` renders a DIFFERENT body. The byte-equality gate
/// therefore never matched, and every oversized request — admin and data plane alike — answered with
/// a bare `text/plain` body: the admin surface's frozen `{error:{code}}` envelope broken (tooling
/// that branches on `code` throws on parse), and official OpenAI/Anthropic/Bedrock SDKs handed a
/// router tell instead of the vendor-native JSON the reshape exists to produce.
///
/// This drives a REAL request through the REAL layer stack, so it cannot pass on a marker the
/// running axum does not emit — whatever axum emits next, this fails when it changes. One leg is
/// enough: `apply_common_layers` installs the body limit and this reshape on the admin and data
/// routers alike, so the layer is either live for both surfaces or dead for both. (The admin leg
/// cannot be driven here without a configured admin credential — auth answers 401 before the body
/// is ever buffered.)
#[tokio::test]
async fn oversized_request_413_is_reshaped_on_the_live_stack() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new().build();
    // A tiny body cap so an ordinary request trips `DefaultBodyLimit`.
    let (mut router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);

    // The request is handed to the router IN PROCESS: no socket is bound, so there is no port for
    // another process's listener to be mistaken for ours. The old shape bound `127.0.0.1:0` and
    // dialled it, and on a CI host running the whole workspace's test binaries side by side a
    // dial could land on a different process's listener (the integration tests reserve ports by
    // pick-then-bind) and read ITS 404 here. Every layer under test is still the production
    // stack: `DefaultBodyLimit`, the reshape, auth and the catch-all all run, and axum enforces
    // the cap on the body stream exactly as it does off a connection.
    let oversized = "x".repeat(4096);
    let payload = serde_json::json!({"pad": oversized}).to_string();
    let req = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("content-length", payload.len().to_string())
        .body(axum::body::Body::from(payload))
        .unwrap();
    type Req = axum::http::Request<axum::body::Body>;
    std::future::poll_fn(|cx| <axum::Router as tower::Service<Req>>::poll_ready(&mut router, cx))
        .await
        .unwrap();
    let r = <axum::Router as tower::Service<Req>>::call(&mut router, req)
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 413, "the body cap must reject");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = {
        use http_body_util::BodyExt as _;
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    assert!(
        ct.starts_with("application/json"),
        "an oversized-body 413 must speak JSON, not the bare `{body}` router tell (content-type \
         was `{ct}`) — the reshape layer's sentinel no longer matches what axum emits"
    );
    let v: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"));
    assert!(
        v.get("error").is_some(),
        "the 413 must carry the error envelope; got {v}"
    );
}

// ── THE MOUNT-AWARE RESOLVER, read off the wire ──────────────────────────────────────────────────
//
// One resolver answers "which plane, and in which dialect, is this path spoken", and an oversized
// POST is the cheapest place to READ its answer: the body cap fires OUTSIDE auth and OUTSIDE
// routing, so the 413 envelope is shaped by the resolver alone with nothing else in the way. If the
// mount table and the path-shape classifier ever disagree again, these three tests are where it
// shows.

// `an_unmounted_plane_claims_no_path_by_url_shape` MOVED to the composition root's
// `crates/busbar/tests/residual_envelope_cross_plane.rs`, beside its mounted twin in `crates/busbar/tests/plane_integration.rs`: the path it probes is a real plane's
// mount path, which that integration target names through the plane crate itself.

// ── response-header consolidation (default OFF, opt-in via `advanced.response_headers`) ──────────
//
// Drives a REAL request through the REAL layer stack (like the 413 test above), rather than calling
// `server_timing` or `maybe_attach_route_policy` directly, so the assertion is on what actually ships
// on the wire — a composition-gate bug (the layer silently staying installed, or never installed even
// when enabled) would not be caught by a unit test that calls the middleware function by hand.

/// RED (pre-task-#139 behavior, pinned here as the regression this test guards against): the
/// `server_timing` middleware layer used to be installed UNCONDITIONALLY — an `Arc<AtomicU64>`
/// allocation, an `Instant::now()`, and a task-local `.scope()` on every request regardless of the
/// flag, with only the response header itself suppressed when disabled. GREEN: with
/// `server_timing_enabled == false` the layer is not installed at all (see
/// `apply_common_layers`'s composition gate) and the `Server-Timing` response header is absent by
/// default; with `true` the layer IS installed and the header is present, carrying the
/// `busbar;dur=<ms>` shape.
#[tokio::test]
async fn server_timing_header_absent_by_default_present_when_enabled() {
    crate::snapshot::init();
    let client = reqwest::Client::new();

    // Default OFF.
    let app = crate::test_support::TestApp::new().build();
    let (router, _handle) = crate::build_router_with_limits(app, 1 << 20, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let r = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert!(
        r.headers().get("server-timing").is_none(),
        "Server-Timing must be ABSENT by default (advanced.response_headers.server_timing defaults \
         false): {:?}",
        r.headers().get("server-timing")
    );
    server.abort();

    // Explicitly enabled.
    let app = crate::test_support::TestApp::new().build();
    let (router, _handle) = crate::build_router_with_limits(app, 1 << 20, 1024, true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let r = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    let st = r
        .headers()
        .get("server-timing")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    server.abort();
    let st = st.expect("Server-Timing must be PRESENT when server_timing_enabled == true");
    assert!(
        st.starts_with("busbar;dur="),
        "unexpected Server-Timing shape: {st}"
    );
}

/// GREEN: `x-busbar-route-policy` / `x-busbar-route-target` are ABSENT by default on a real request
/// through the real stack — `advanced.response_headers.route_policy` defaults `false`, and nothing in
/// this test process ever calls `proxy::configure_route_policy_headers(true)`
/// (`route_policy_headers_enabled()` returns `false` when unconfigured — see its doc comment), so this
/// end-to-end check needs no global-state setup. The `enabled == true` direction (and the "still
/// absent for a default policy even when enabled" inner-gate direction) is covered deterministically
/// by `proxy::wire::tests` against the pure `maybe_attach_route_policy_gated` core instead of here:
/// `ROUTE_POLICY_HEADERS_ENABLED` is a process-wide `OnceLock` that can be set at most once for the
/// life of this test binary, so flipping it to `true` in an end-to-end test would permanently leak
/// into every other test that shares this process.
#[tokio::test]
async fn route_policy_headers_absent_by_default_on_the_live_stack() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new().build();
    let (router, _handle) = crate::build_router_with_limits(app, 1 << 20, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let r = reqwest::Client::new()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert!(
        r.headers().get("x-busbar-route-policy").is_none(),
        "x-busbar-route-policy must be ABSENT by default"
    );
    assert!(
        r.headers().get("x-busbar-route-target").is_none(),
        "x-busbar-route-target must be ABSENT by default"
    );
    server.abort();
}

// ── real boot-time legacy-config refusal / migration (end to end) ────────────────────────────────
//
// Every legacy/migration test in `config::migrate::tests` drives `detect_legacy_markers` /
// `migrate_config` directly against an in-memory `serde_yaml::Value` — none of them go through
// `load_config_from_disk`, the REAL disk-read -> env-interpolate -> legacy-marker-check ->
// typed-parse pipeline that boot, `POST .../config/reload`, and `--validate` all actually run. A
// bug in the stitching around the marker check (wrong path, marker check skipped, wired to the
// wrong error string) would pass every existing test and only show up at a real boot. These two
// tests close that gap by writing REAL files to disk and calling the REAL boot entry point.

/// A representative 1.4.x config (same shape as `config::migrate::tests::LEGACY_14X`) written to a
/// REAL file on disk for the boot-path tests below. `admin_token` carries a REAL `${PATH}`
/// interpolation token (rather than a plain literal) so these tests also exercise `EnvSubst::Strict`
/// interpolation ahead of the legacy-marker check — a bug where the marker check ran on the RAW
/// (pre-interpolation) text, or where interpolation itself introduced/hid a marker, would otherwise
/// slip past. `PATH` is used because it's guaranteed set in any process environment, so the fixture
/// needs no env mutation.
const BOOT_LEGACY_14X_CONFIG: &str = r#"
listen: "0.0.0.0:8080"
governance:
  enabled: true
  db_path: "/var/lib/busbar/governance.db"
  admin_token: '${PATH}'
providers:
  upstream-a:
    api_key_env: UPSTREAM_A_KEY
models:
  claude: { provider: upstream-a }
pools:
  fast:
    members:
      - { target: claude, weight: 1 }
"#;

/// A fresh temp dir holding `config.yaml` (given content) + an empty `providers.yaml`, so
/// `load_config_from_disk` has real files to read.
fn boot_config_dir(
    tag: &str,
    config_yaml: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-legacy-{}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&providers_path, "{}\n").unwrap();
    std::fs::write(&config_path, config_yaml).unwrap();
    (dir, config_path, providers_path)
}

/// THE BOOT PATH ITSELF must refuse a real 1.x config file on disk, loudly and by name — never a
/// silent load with 1.5.0 semantics, never a bare unknown-field parse error that doesn't say what's
/// actually wrong. This is the one path that actually proves the product's documented promise ("a
/// loud fail-closed boot on an outdated config, never a silent behavior change").
#[test]
fn load_config_from_disk_refuses_a_real_legacy_config_file_loudly() {
    let (dir, config_path, providers_path) = boot_config_dir("refuse", BOOT_LEGACY_14X_CONFIG);

    let result = load_config_from_disk(
        &config_path,
        Some(&providers_path),
        false,
        crate::config::EnvSubst::Strict,
    );

    let err = match result {
        Ok(_) => panic!(
            "a REAL 1.x config file on disk must be REFUSED at the real boot entry point \
             (load_config_from_disk), not silently loaded under 1.5.0 semantics"
        ),
        Err(e) => e,
    };
    assert!(
        err.contains("busbar --migrate-config"),
        "the boot-time refusal must name the migrator: {err}"
    );
    assert!(
        err.contains("1.x"),
        "the boot-time refusal must name the version family: {err}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The `--migrate-config` output, written to a REAL file and fed back through the REAL boot entry
/// point, must boot cleanly — the recovery half of the same promise: an operator who migrates ends
/// up with a config the actual boot path accepts, not one that still trips the legacy detector or
/// fails typed parsing for some other reason.
#[test]
fn migrate_config_then_load_config_from_disk_boots_the_real_migrated_file() {
    crate::test_support::register_neutral_test_plane();
    let (dir, legacy_config_path, providers_path) =
        boot_config_dir("migrate", BOOT_LEGACY_14X_CONFIG);

    // Mirrors `migrate_config_command`: read the real file from disk, run the real migrator.
    let raw = std::fs::read_to_string(&legacy_config_path).unwrap();
    let migrated = crate::config::migrate::migrate_config(&raw).expect("legacy config migrates");

    let migrated_path = dir.join("migrated-config.yaml");
    std::fs::write(&migrated_path, &migrated.yaml).unwrap();

    // THE REAL BOOT ENTRY POINT must accept the migrated file on disk without error.
    let loaded = load_config_from_disk(
        &migrated_path,
        Some(&providers_path),
        false,
        crate::config::EnvSubst::Strict,
    )
    .unwrap_or_else(|e| {
        panic!("the migrated config must boot cleanly through the real boot path: {e}")
    });

    // Prove it's a real typed parse of the real content, not a stub: the migrated `listen` value
    // and the store module the migrator selected both round-trip through the real boot path.
    assert_eq!(loaded.deploy.listen, "0.0.0.0:8080");
    assert_eq!(
        loaded.deploy.store.as_ref().map(|s| s.module.as_str()),
        Some(frozen_str("legacy_backend_1_4").as_str()),
        "the migrated store module must survive the real disk-load pipeline"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Proves the restore survives a PANIC between
/// `set_var` and the end of scope, not just the happy path. Before introducing the `Drop` guard, a
/// failed assertion in `worker_threads_from_config_reads_a_real_file` would unwind past its manual
/// `match prior { .. }` restore and leak the override to every later test in the binary. This test
/// deliberately panics inside `catch_unwind` while the guard is live and asserts the env var is back
/// to its pre-test value once the guard drops — i.e. the guard, not test-ordering luck, is what
/// makes the leak impossible.
#[test]
fn env_var_guard_restores_on_panic() {
    const KEY: &str = "BUSBAR_TEST_ENV_GUARD_PANIC_PROBE";
    // Establish a known ambient value so "restored" has something concrete to check against.
    std::env::set_var(KEY, "ambient-value");

    let result = std::panic::catch_unwind(|| {
        let _guard = EnvVarGuard::capture(KEY);
        std::env::set_var(KEY, "clobbered-by-test-body");
        panic!("simulated assertion failure mid-test");
    });
    assert!(result.is_err(), "the inner closure was expected to panic");

    assert_eq!(
        std::env::var(KEY).as_deref(),
        Ok("ambient-value"),
        "EnvVarGuard must restore the prior value even when the guarded scope unwinds via panic"
    );
    std::env::remove_var(KEY);
}

/// `is_real_auth_plugin_ref`: `keys` is always exempt (engine-handled, never a plugin). A module
/// the build's auth axis answers in process is exempt ONLY when the install record says so — with
/// no such answer (every shipped build) it is a real (unresolvable) plugin ref, so `--validate` fails
/// it the same way real boot does, rather than silently agreeing a config naming it is fine. Every
/// other name is always a real ref.
#[test]
fn is_real_auth_plugin_ref_exempts_keys_always_and_in_process_modules_only_where_answered() {
    let none: fn(&str) -> bool = |_| false;
    let test_modules: fn(&str) -> bool = crate::test_support::auth_modules::answers;
    assert!(!is_real_auth_plugin_ref(config::KEYS_MODULE, test_modules));
    assert!(!is_real_auth_plugin_ref(config::KEYS_MODULE, none));
    assert!(
        !is_real_auth_plugin_ref("test-groups-module", test_modules),
        "exempt where the build's auth axis answers it in process"
    );
    assert!(
        is_real_auth_plugin_ref("test-groups-module", none),
        "must NOT be exempt where nothing answers it in process - a release config naming it must \
         be treated as a real (and therefore unresolvable) plugin ref, not silently waved through"
    );
    assert!(is_real_auth_plugin_ref("test-idp-double", test_modules));
    assert!(is_real_auth_plugin_ref("test-idp-double", none));
}

/// A minimal but structurally VALID 1.5.x config (parses into `DeployCfg`; `load_config_from_disk`
/// does not resolve, so empty maps are fine).
const BOOT_MINIMAL_CONFIG: &str = "providers: {}\nmodels: {}\n";

/// 1.5.3 durable-by-default at the BOOT path: with NO `config:` section the default overlay lands next
/// to config.yaml and the config is reported mutable. The deprecated `BUSBAR_CONFIG_OVERLAY` env var
/// (still honored when set) is cleared for the run so the DEFAULT path is what is under test; its
/// precedence is pinned separately in the overlay consolidation tests.
#[test]
fn boot_default_config_resolves_a_durable_overlay_next_to_config() {
    let (dir, config_path, _providers_path) = boot_config_dir("durable", BOOT_MINIMAL_CONFIG);
    // Guarded so any ambient value is restored on drop (incl. panic).
    let _guard = EnvVarGuard::capture("BUSBAR_CONFIG_OVERLAY");
    std::env::remove_var("BUSBAR_CONFIG_OVERLAY");
    let loaded = load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
        .expect("a mutable default config must boot");
    assert!(!loaded.config_locked, "default config is mutable");
    assert_eq!(
        loaded.overlay_path.as_deref(),
        Some(dir.join("busbar-overlay.json").as_path()),
        "durable-by-default: overlay next to config.yaml"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.3 BOOT INVARIANT: a mutable config that explicitly disables the overlay REFUSES TO BOOT, with an
/// actionable message (writable overlay OR `config.locked: true`). Pre-1.5.3 nothing
/// enforced "mutable XOR writable overlay".
#[test]
fn boot_mutable_with_overlay_disabled_refuses_to_boot() {
    let cfg = "providers: {}\nmodels: {}\nconfig:\n  locked: false\n  overlay: false\n";
    let (dir, config_path, _p) = boot_config_dir("no-backend", cfg);
    let Err(err) =
        load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
    else {
        panic!("mutable + overlay disabled must refuse to boot");
    };
    // Pin the SPECIFIC resolve_backend Err arm for `overlay: false` on a mutable config — not an OR of
    // two substrings that a coincidentally-worded unrelated error could satisfy. This is the
    // "mutable-but-overlay-disabled" arm, distinct from the read-only-dir "not writable" arm and the
    // `overlay: true` "names no backend" arm.
    assert!(
        err.contains("has no writable overlay backend")
            && err.contains("`config.overlay` is disabled"),
        "the boot refusal must be the specific mutable-without-backend message: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.3: a LOCKED config boots with NO overlay backend (mutations are refused at runtime).
#[test]
fn boot_locked_config_has_no_overlay() {
    let cfg = "providers: {}\nmodels: {}\nconfig:\n  locked: true\n";
    let (dir, config_path, _p) = boot_config_dir("locked", cfg);
    let loaded = load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
        .expect("a locked config boots");
    assert!(loaded.config_locked);
    assert!(loaded.overlay_path.is_none(), "locked ⇒ no overlay backend");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Providers catalog resolution: the top-level `providers_file:` pointer names the catalog (resolved
/// relative to config.yaml), honored with NO env var; and an explicit override (the `--providers`
/// flag, or a reload's live path) still wins. Pre-1.5.3 the catalog path came only from a hardcoded
/// default; a config-file pointer had no code path.
#[test]
fn boot_providers_file_pointer_is_honored_and_override_wins() {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-providers-file-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    // The catalog lives at a NON-default name, reachable only via the pointer.
    let catalog = dir.join("catalog.yaml");
    std::fs::write(&catalog, "{}\n").unwrap();
    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nproviders_file: catalog.yaml\n",
    )
    .unwrap();

    // No override → the `providers_file:` pointer is used.
    let loaded = load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
        .expect("providers_file pointer resolves");
    assert_eq!(
        loaded.providers_path, catalog,
        "the providers_file pointer must be honored"
    );

    // An explicit override (the `--providers` flag, or a reload's live path) wins.
    let other = dir.join("other-catalog.yaml");
    std::fs::write(&other, "{}\n").unwrap();
    let loaded2 = load_config_from_disk(
        &config_path,
        Some(&other),
        false,
        crate::config::EnvSubst::Strict,
    )
    .expect("override resolves");
    assert_eq!(
        loaded2.providers_path, other,
        "the override wins over providers_file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `App.auth_scope_caps` is keyed by PROVIDER NAME, not by the backing plugin MODULE.
///
/// Two named providers sharing one plugin module must get INDEPENDENT ceilings (the invariant
/// `ChainVerdict::Identified` documents), and the read side (`auth::module_admin_scope_cap`) looks
/// the ceiling up by the provider NAME a chain verdict carries. This test is the one shape the whole
/// suite lacked: a config where name != module, plus the escalation shape where one provider's NAME
/// collides with a DIFFERENT provider's MODULE.
#[test]
fn auth_scope_caps_are_keyed_by_provider_name_not_module() {
    use crate::config::{AuthCfg, AuthChainEntry};
    let entry = |name: &str, module: &str, cap: Option<&str>| AuthChainEntry {
        name: name.to_string(),
        module: module.to_string(),
        max_admin_scope: cap.map(str::to_string),
        token: None,
        settings: serde_json::Map::new(),
    };
    let mut auth = AuthCfg::default_none();
    // Two NAMED providers on ONE plugin module, with DIFFERENT ceilings — plus a third provider
    // whose NAME is literally the module name the other two ride, the collision that escalated.
    auth.admin_auth = vec![
        entry("corp-sso", "test-idp-double", Some("full")),
        entry("vendor-sso", "test-idp-double", Some("read-only")),
        entry("test-idp-double", "some-other-module", Some("none")),
    ];
    let caps = project_auth_scope_caps(&auth);

    assert_eq!(
        caps.get("corp-sso").map(String::as_str),
        Some("full"),
        "the operator's explicit ceiling must be found under the PROVIDER NAME (module-keying \
         silently floored this to read-only)"
    );
    assert_eq!(
        caps.get("vendor-sso").map(String::as_str),
        Some("read-only"),
        "the sibling provider on the same module keeps its OWN, independent ceiling"
    );
    assert_eq!(
        caps.get("test-idp-double").map(String::as_str),
        Some("none"),
        "the provider actually NAMED `test-idp-double` owns that key — not whichever provider happens to run \
         the `test-idp-double` module (module-keying made a last-writer-wins collision here, handing one \
         provider's ceiling to another)"
    );
    assert_eq!(caps.len(), 3, "one entry per NAMED provider: {caps:?}");
}

/// THE ROOT'S RULES JUDGE EVERY BUILD (`appbuild::RootRules`, passed to the build and run by the one
/// validator right after the semantic pass): a configuration the rules refuse is refused by the
/// build itself, with the rules' words, before anything of it is built or installed, so an apply carrying it never reaches a swap; one they pass builds as before,
/// and the built `App` keeps the rules it was built under, for every build after it to pass on.
/// RED before the fix: the build had no root rules, so a configuration only the root could judge
/// went live through an apply.
#[test]
fn a_configuration_the_root_rules_refuse_is_refused_by_the_build() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    const REFUSED: &str = "https://refused.root-rules.test";
    struct Refusing;
    impl crate::appbuild::RootRules for Refusing {
        fn check(&self, cfg: &crate::config::RootCfg) -> Result<(), String> {
            if cfg.public_url.as_deref() == Some(REFUSED) {
                Err("`agent_push.ca` is not a usable trust anchor".to_string())
            } else {
                Ok(())
            }
        }
    }
    crate::snapshot::init();
    let rules: std::sync::Arc<dyn crate::appbuild::RootRules> = std::sync::Arc::new(Refusing);
    let build = |public_url: Option<&str>| {
        let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_ROOT_RULES",
        ));
        cfg.public_url = public_url.map(str::to_string);
        crate::build_app_from_config(
            cfg,
            crate::config::PluginsCfg::default(),
            None,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            (None, None),
            None,
            &rules,
        )
    };
    assert_eq!(
        build(Some(REFUSED)).map(|_| ()),
        Err("`agent_push.ca` is not a usable trust anchor".to_string()),
        "the rules' words, before anything is built"
    );
    let (app, _, _) = build(None).expect("a configuration they pass builds as before");
    assert!(
        std::sync::Arc::ptr_eq(&app.root_rules, &rules),
        "the built App keeps the rules it was built under"
    );
}

/// RESTART-TO-APPLY FOR A PLANE THE BOOT DID NOT OPEN (u67 BLOCK 2 item 2; BUSBAR-1.6.0.md Law 7
/// l.547, and §6 item 8 l.980-982): a configuration that writes the section of a plane the root's
/// rules name as not opened at boot builds, but gives that plane NO slot (it claims, admits and
/// lists nothing this generation) and carries its section in `App::planes_awaiting_restart` for
/// the apply's answer; the same configuration under rules that opened it builds the slot as
/// before. RED before the fix: the build gave the unopened plane a slot (half-served) and nothing
/// reported it.
#[test]
fn a_plane_the_boot_did_not_open_builds_no_slot_and_is_reported_awaiting_restart() {
    const SECTION: &str = "pending-red";
    static PENDING: crate::plane_driver::registry::PlaneDecl =
        crate::plane_driver::registry::PlaneDecl {
            declaration: crate::plane_driver::registry::PlaneDeclaration {
                key: "pending-red-plane",
                fallback: false,
                config_section: SECTION,
                ..crate::test_support::NEUTRAL_FALLBACK.declaration
            },
            build: |_, _| {
                Some(std::sync::Arc::new(()) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
            },
            ..crate::test_support::NEUTRAL_FALLBACK
        };
    struct Unopened;
    impl crate::appbuild::RootRules for Unopened {
        fn check(&self, _cfg: &crate::config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn planes_awaiting_restart(&self, cfg: &crate::config::RootCfg) -> Vec<&'static str> {
            if cfg.plane_sections.contains(SECTION) {
                vec![SECTION]
            } else {
                Vec::new()
            }
        }
    }
    let _registry = crate::test_support::planes::TestRegistryIsolation::seeded(&[
        crate::test_support::neutral_fallback_plane(),
        &PENDING,
    ]);
    crate::snapshot::init();
    let build = |rules: std::sync::Arc<dyn crate::appbuild::RootRules>, writes: bool| {
        let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_PENDING_PLANE",
        ));
        if writes {
            cfg.plane_sections.insert(SECTION);
        }
        crate::build_app_from_config(
            cfg,
            crate::config::PluginsCfg::default(),
            None,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            (None, None),
            None,
            &rules,
        )
        .expect("the configuration builds")
        .0
    };
    let opened = build(std::sync::Arc::new(crate::appbuild::AcceptAll), true);
    assert!(
        opened.plane_slot(PENDING.key).is_some(),
        "a plane the boot opened builds its slot, as before"
    );
    assert!(opened.planes_awaiting_restart.is_empty());
    let pending = build(std::sync::Arc::new(Unopened), true);
    assert!(
        pending.plane_slot(PENDING.key).is_none(),
        "a plane the boot did not open is given no slot: nothing of it is half-served"
    );
    assert_eq!(pending.planes_awaiting_restart, vec![SECTION.to_string()]);
    let unwritten = build(std::sync::Arc::new(Unopened), false);
    assert!(unwritten.plane_slot(PENDING.key).is_none());
    assert!(
        unwritten.planes_awaiting_restart.is_empty(),
        "a configuration that does not write the plane reports nothing"
    );
    assert_eq!(
        crate::state::planes_awaiting_restart_added(&pending, &unwritten),
        vec![SECTION.to_string()],
        "the mutation that first writes the section is the one flagged"
    );
    assert!(
        crate::state::planes_awaiting_restart_added(&pending, &pending).is_empty(),
        "a later edit does not re-flag it"
    );
}

// ── STEP 2.3: THE TYPE-ERASED PLANE SLOT MAP (`App::plane_slot`) ─────────────────────────────
//
// Additive: `App::mcp` / `App::a2a` still exist and every existing reader is untouched. These
// tests pin the two things Step 2.3 actually promises — the slot mirrors the typed field's SAME
// `Arc` when a plane is configured, and is absent exactly when the typed field is `None`.

// ── PLANELESS CONFIGS GET AN INERT `PlaneBreakers` (idle-RSS doctrine) ───────────────────────
//
// "What is not configured must not be loaded": a config with no mounted plane, no `tools:`/
// `agents:` registration and no plane pools must not pay for the 8 placeholder breaker cells
// (a preallocated 1024-slot outcome window each, plus per-worker padded counter stripes —
// ~130 KiB of idle RSS). These pin the four arms of the apply-time decision in
// `build_app_from_config` and the inert handle's fail-closed guards.

/// Boot with a planeless config yields the INERT handle; a second planeless apply REUSES it
/// (same `Arc`); the first apply that carries plane content upgrades to a PROVISIONED handle at
/// apply time; and a provisioned prior is reused even when the plane content disappears again
/// (learned reliability survives every apply).
#[test]
fn planeless_config_gets_inert_plane_breakers_and_apply_upgrades() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let planeless = || {
        cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_PLANES",
        ))
    };
    let build = |cfg, prior: Option<&crate::state::App>| {
        crate::build_app_from_config(
            cfg,
            crate::config::PluginsCfg::default(),
            None,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            (None, None),
            prior,
            &(std::sync::Arc::new(crate::appbuild::AcceptAll)
                as std::sync::Arc<dyn crate::appbuild::RootRules>),
        )
        .expect("boot must succeed")
        .0
    };

    // Arm 1: no plane content, no prior → inert.
    let app = build(planeless(), None);
    assert!(
        !app.plane_breakers.is_provisioned(),
        "a planeless config must get the inert handle"
    );
    // The inert guards fail CLOSED (refuse / no-op), never index the empty lane table.
    assert!(
        matches!(
            app.plane_breakers.try_admit("tool:x", 0),
            Err(busbar_kernel::store::Unavailable::Shedding)
        ),
        "inert admit must refuse, not panic"
    );
    app.plane_breakers.record_success("tool:x", 0);
    app.plane_breakers.release("tool:x", 0, Some(7));
    assert_eq!(app.plane_breakers.retry_after_secs("tool:x", 0), 1);

    // Arm 2: still planeless with an inert prior → the SAME handle (no re-allocation per apply).
    let app2 = build(planeless(), Some(&app));
    assert!(
        std::sync::Arc::ptr_eq(&app.plane_breakers, &app2.plane_breakers),
        "an inert prior must be reused across a planeless apply"
    );

    // Arm 3: plane content appears (a plane pool here — any of the plane signals works) →
    // upgraded to a provisioned handle AT APPLY, not on a request path.
    let mut with_pool = planeless();
    with_pool
        .plane_pools
        .entry("search-section")
        .or_default()
        .insert(
            "search".to_string(),
            crate::config::pools::CandidatePoolCfg {
                members: vec!["search-eu".to_string(), "search-us".to_string()],
                ..Default::default()
            },
        );
    let app3 = build(with_pool, Some(&app2));
    assert!(
        app3.plane_breakers.is_provisioned(),
        "the first apply carrying plane content must provision the breakers"
    );
    assert!(
        !std::sync::Arc::ptr_eq(&app2.plane_breakers, &app3.plane_breakers),
        "the provisioned handle is a fresh build, not the inert prior"
    );

    // Arm 4: plane content removed again → the PROVISIONED prior is kept (learned reliability
    // survives every apply; an apply never downgrades).
    let app4 = build(planeless(), Some(&app3));
    assert!(
        std::sync::Arc::ptr_eq(&app3.plane_breakers, &app4.plane_breakers),
        "a provisioned prior must survive an apply that removes the plane content"
    );
}

// ── A GENERATION'S LIMITS GO LIVE WITH IT, AND REACH EVERY PLANE (Q128 p1#6, p12#4, p6#1) ──────

/// Puts the process-wide limits back exactly as a test found them, failure path included.
struct RestorePublished(Option<crate::config::LimitsResolved>);

impl Drop for RestorePublished {
    fn drop(&mut self) {
        crate::config::limits::swap_installed(self.0.take());
    }
}

/// The live readers' view, read on ANOTHER thread — the running generation's traffic, which no
/// build is on: the WHOLE published `LimitsResolved` (its `Debug` rendering, every field) and the
/// derived caps mirrored out of it (the translate-body cap and the hook content ceiling).
fn live_limits() -> (Option<String>, usize, usize) {
    std::thread::spawn(|| {
        (
            crate::config::limits::installed().map(|l| format!("{l:?}")),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            crate::hooks::hook_content_max_bytes(),
        )
    })
    .join()
    .expect("reader thread must not panic")
}

/// A `LimitsResolved` whose live-read fields all differ from the defaults and from each other's
/// tag, so a reader that saw any one of them is caught. Every value is within validation's bounds.
fn tagged_limits(tag: u64) -> crate::config::LimitsResolved {
    let n = usize::try_from(tag).expect("small tag");
    crate::config::LimitsResolved {
        key_gauge_limit: 1_000 + n,
        request_body_max_bytes: (1 + n) * 1024 * 1024,
        hook_content_max_bytes: 1_024 * (1 + n),
        upstream_error_body_max_bytes: 8_192 + n,
        default_probe_interval_secs: 20 + tag,
        default_probe_timeout_secs: 3 + tag,
        default_policy_timeout_ms: 500 + tag,
        hard_down_cooldown_secs: 600 + tag,
        max_honored_retry_after_secs: 3_600 + tag,
        tls_handshake_timeout_secs: 5 + tag,
        request_body_read_timeout_secs: 15 + tag,
        rate_sweep_interval: 100 + u32::try_from(tag).expect("small tag"),
        ..crate::config::LimitsResolved::default()
    }
}

fn build_with(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<(crate::state::App, crate::appbuild::InstalledLimits), String> {
    crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
        &(std::sync::Arc::new(crate::appbuild::AcceptAll)
            as std::sync::Arc<dyn crate::appbuild::RootRules>),
    )
    .map(|(app, _, limits)| (app, limits))
}

/// A BUILT GENERATION'S LIMITS ARE IN FORCE ONLY ONCE IT IS LIVE (BUSBAR-1.6.0.md THE DESIGN §6
/// item 8, l.980-982: a reload "swaps them in atomically ... and is refused, leaving the running
/// generation serving, if any check fails"; §3: "A validation refusal keeps the running
/// generation"). Judged on the WHOLE published `LimitsResolved` and the caps derived from it, read
/// on another thread: unchanged after a refused apply; unchanged while an apply is built but not
/// live — the window an admin apply's persist runs in; the candidate's, field for field, from the
/// swap that installs it. Register entry GEN-LIMITS (testing/shadow-oracle/accepted-differences.json):
/// v1.5.5 installed the candidate before validating it (main.rs:2704/2711).
///
/// RED before the fix: the build installed its candidate's limits process-wide FIRST, before
/// validation, and they stayed in force until the handle was dropped — the live view read the
/// candidate's limits while the generation was built but not live.
#[test]
fn a_built_generations_limits_are_in_force_only_once_it_is_live() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D):
    // without it the fixture's provider is refused before any limit is read.
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let _lock = crate::config::limits::LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestorePublished(crate::config::limits::installed());
    let running = tagged_limits(1);
    crate::config::limits::install(&running);
    let before = live_limits();
    assert_eq!(
        before,
        (
            Some(format!("{running:?}")),
            running.request_body_max_bytes,
            running.hook_content_max_bytes
        ),
        "the live view reads the running generation's limits"
    );
    let cfg = |limits: crate::config::LimitsResolved| {
        let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_LIMITS_LIVE",
        ));
        cfg.limits = limits;
        cfg
    };

    // A REFUSED apply (validation: a zero sticky cooldown) changes no live limit.
    let mut refused = tagged_limits(2);
    refused.hard_down_cooldown_secs = 0;
    let Err(refusal) = build_with(cfg(refused), None) else {
        panic!("validation refuses it");
    };
    assert!(
        refusal.contains("limits.hard_down_cooldown_secs must be >= 1"),
        "refused for its zero sticky cooldown, not another reason: {refusal}"
    );
    assert_eq!(
        live_limits(),
        before,
        "a refused apply changed a live limit"
    );

    // BUILT BUT NOT LIVE: the running generation's limits stand, every field, on every thread.
    let candidate = tagged_limits(3);
    let (next, unkept) = build_with(cfg(candidate.clone()), None).expect("builds");
    assert_eq!(
        live_limits(),
        before,
        "a built-but-not-live generation's limits are in force under the running generation"
    );
    assert_eq!(
        crate::config::limits::installed().map(|l| format!("{l:?}")),
        Some(format!("{running:?}")),
        "the build's own view of its candidate ends with the build"
    );

    // LIVE: the swap that installs it publishes its limits, every field.
    let handle = crate::state::AppHandle::new(crate::test_support::TestApp::new().build());
    handle.swap(std::sync::Arc::new(next));
    let after = (
        Some(format!("{candidate:?}")),
        candidate.request_body_max_bytes,
        candidate.hook_content_max_bytes,
    );
    assert_eq!(live_limits(), after, "the swapped-in generation's limits");
    // The commit after the swap republishes the same values.
    unkept.keep();
    assert_eq!(live_limits(), after);
}

/// THE OPERATOR'S BREAKER LIMITS REACH EVERY PLANE'S CELLS (BUSBAR-1.6.0.md THE DESIGN §1: "Any
/// plugin gets all functionality ... A capability one plane has and a sibling plane lacks is a gap
/// to close"). The first plane's store has always been built under `limits.hard_down_cooldown_secs`
/// / `limits.max_honored_retry_after_secs`; the store every other plane's cells live in now is too,
/// and — being process-lifetime — takes a subsequent generation's values at the swap that puts that
/// generation live, not during its build. Under the default config nothing changes: the defaults
/// the config layer resolves are the values the store was hard-wired to.
///
/// RED before the fix: the plane store was built with the hard-wired 1800s sticky cooldown and
/// never refreshed, so the first hard-down below read ~1800, not <= 60.
#[test]
fn the_operator_breaker_limits_reach_every_planes_cells() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D):
    // without it the fixture's provider is refused before any limit is read.
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let _lock = crate::config::limits::LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestorePublished(crate::config::limits::installed());
    let hard_down = busbar_contract::upstream::CanonicalSignal {
        class: busbar_contract::upstream::StatusClass::Auth,
        provider_signal: None,
        retry_after: None,
    };
    let cfg = |hard_down_cooldown_secs: u64| {
        let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_PLANE_LIMITS",
        ));
        // Any plane content provisions the plane store; a pool of opaque members is the smallest.
        cfg.plane_pools.entry("p-section").or_default().insert(
            "p".to_string(),
            crate::config::pools::CandidatePoolCfg {
                members: vec!["m1".to_string(), "m2".to_string()],
                ..Default::default()
            },
        );
        cfg.limits.hard_down_cooldown_secs = hard_down_cooldown_secs;
        cfg
    };

    let (first, _) = build_with(cfg(60), None).expect("builds");
    assert!(first.plane_breakers.is_provisioned());
    first.plane_breakers.record_signal("k:a", 0, &hard_down);
    let ra = first.plane_breakers.retry_after_secs("k:a", 0);
    assert!(
        (1..=60).contains(&ra),
        "the operator's 60s sticky cooldown on a plane cell, got {ra}"
    );

    // A subsequent generation REUSES the process-lifetime store; its build does not touch the live cells.
    let (second, _) = build_with(cfg(120), Some(&first)).expect("builds");
    assert!(std::sync::Arc::ptr_eq(
        &first.plane_breakers,
        &second.plane_breakers
    ));
    second.plane_breakers.record_signal("k:b", 0, &hard_down);
    let ra = second.plane_breakers.retry_after_secs("k:b", 0);
    assert!(
        (1..=60).contains(&ra),
        "a generation not yet live must not change the live cells' limits, got {ra}"
    );

    // Swapped in: the next hard-down arms the new generation's value.
    let handle = crate::state::AppHandle::new(std::sync::Arc::new(first));
    handle.swap(std::sync::Arc::new(second));
    let live = handle.load();
    live.plane_breakers.record_signal("k:c", 0, &hard_down);
    let ra = live.plane_breakers.retry_after_secs("k:c", 0);
    assert!(
        (61..=120).contains(&ra),
        "the swapped-in generation's 120s sticky cooldown, got {ra}"
    );
}

// ── THE REQUEST-PANIC BOUNDARY (1.6.0 item 148) ──────────────────────────────────────────────────

/// A PANIC FAILS ITS OWN REQUEST, NOT THE CONNECTION. Drives the REAL common layer stack over a
/// real socket: a route that panics must answer `500` in the kernel's standard JSON error body, and
/// the SAME client (its pooled keep-alive connection) must go on being served. Without the boundary
/// the unwind tears down hyper's connection task and the client sees a reset instead of a response.
#[tokio::test]
async fn a_panicking_handler_fails_only_its_own_request() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new().build();
    let handle = std::sync::Arc::new(crate::state::AppHandle::new(app));
    async fn boom() -> &'static str {
        panic!("deliberate handler panic (request-panic boundary test)")
    }
    async fn fine() -> &'static str {
        "fine"
    }
    let (router, table) = crate::core_routes::CoreRouter::new()
        .route(
            "/v1/chat/completions",
            RouteMethod::Post,
            RouteAuth::None,
            boom,
        )
        .route("/still-serving", RouteMethod::Get, RouteAuth::None, fine)
        .into_parts();
    let router = apply_common_layers(router, table, &handle, 1 << 20, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let r = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("a panicking handler must still produce a RESPONSE, not a torn-down connection");
    assert_eq!(r.status().as_u16(), 500, "the one request fails with 500");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "content-type was `{ct}`"
    );
    let v: serde_json::Value = r.json().await.expect("the 500 body is JSON");
    assert_eq!(
        v["error"]["type"], "api_error",
        "the kernel's standard dialect-native error body, got {v}"
    );

    // The sibling: the same client, the same pool, served normally after the panic.
    for _ in 0..3 {
        let ok = client
            .get(format!("http://{addr}/still-serving"))
            .send()
            .await
            .expect("the listener keeps serving after a request panicked");
        assert_eq!(ok.status().as_u16(), 200);
        assert_eq!(ok.text().await.unwrap(), "fine");
    }
    server.abort();
}

/// An admin module that panics on the credential `boom` and passes every other one.
struct PanickingAdminModule;
impl crate::auth::AuthModule for PanickingAdminModule {
    fn name(&self) -> &'static str {
        "panicking-admin"
    }
    fn authenticate(&self, candidate: Option<&str>) -> crate::auth::AuthVerdict {
        assert_ne!(
            candidate,
            Some("boom"),
            "deliberate admin-chain panic (request-panic boundary test)"
        );
        crate::auth::AuthVerdict::Pass
    }
}

/// BOTH SERVED ROUTERS CARRY THE REQUEST-PANIC BOUNDARY. The data and admin routers come from
/// `build_split_routers_serving`, the builder the node serves: a panic inside a data route's
/// handler, and one inside the admin auth chain, each answer `500` in busbar's standard JSON error
/// body, the same client is served on its next requests, and each panic is logged once at `error`
/// with the request's path.
#[tokio::test(flavor = "current_thread")]
async fn both_served_routers_answer_a_panic_500_log_it_and_keep_serving() {
    use crate::plane_routes::{PlaneReqCtx, PlaneRouteSpec};
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    use tracing_subscriber::layer::SubscriberExt as _;
    crate::snapshot::init();
    let cap = crate::test_support::warn_capture::WarnCapture::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));

    const BOOM: &str = "/panic-boundary-test/boom";
    const FINE: &str = "/panic-boundary-test/fine";
    let door = |path: &str, panics: bool| PlaneRouteSpec {
        path: path.to_string(),
        method: RouteMethod::Post,
        auth: RouteAuth::None,
        handler: std::sync::Arc::new(move |_: PlaneReqCtx| {
            Box::pin(async move {
                assert!(
                    !panics,
                    "deliberate data-route panic (request-panic boundary test)"
                );
                axum::response::Response::new(axum::body::Body::from("fine"))
            })
        }),
    };
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["panicking-admin".to_string()])
        .admin_module("panicking-admin", Box::new(PanickingAdminModule))
        .build();
    let (data, admin, _handle) = crate::build_split_routers_serving(
        app,
        vec![door(BOOM, true), door(FINE, false)],
        1 << 20,
        0,
        false,
    );
    let serve = |router: Router| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, server)
    };
    let (data_addr, data_server) = serve(data).await;
    let (admin_addr, admin_server) = serve(admin).await;
    let client = reqwest::Client::new();

    async fn json_500(r: reqwest::Response) -> serde_json::Value {
        assert_eq!(r.status().as_u16(), 500, "the one request fails with 500");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "content-type was `{ct}`"
        );
        let v: serde_json::Value = r.json().await.expect("the 500 body is JSON");
        assert!(
            v["error"].is_object(),
            "busbar's standard error body, got {v}"
        );
        v
    }

    // THE DATA ROUTER: a handler panic.
    let r = client
        .post(format!("http://{data_addr}{BOOM}"))
        .body("x")
        .send()
        .await
        .expect("a panicking data route still produces a response");
    json_500(r).await;
    for _ in 0..3 {
        let ok = client
            .post(format!("http://{data_addr}{FINE}"))
            .body("x")
            .send()
            .await
            .expect("the data listener keeps serving after a request panicked");
        assert_eq!(ok.status().as_u16(), 200);
        assert_eq!(ok.text().await.unwrap(), "fine");
    }

    // THE ADMIN ROUTER: a panic in its auth chain.
    let r = client
        .get(format!("http://{admin_addr}/api/v1/admin/keys"))
        .bearer_auth("boom")
        .send()
        .await
        .expect("a panicking admin chain still produces a response");
    let v = json_500(r).await;
    assert_eq!(
        v["error"]["code"], "internal",
        "the admin envelope's own code, got {v}"
    );
    let next = client
        .get(format!("http://{admin_addr}/api/v1/admin/keys"))
        .bearer_auth("not-boom")
        .send()
        .await
        .expect("the admin listener keeps serving after a request panicked");
    assert_ne!(
        next.status().as_u16(),
        500,
        "the next admin request is judged, not failed"
    );
    let health = client
        .get(format!("http://{admin_addr}/healthz"))
        .send()
        .await
        .expect("the admin listener keeps serving");
    // Its readiness answer (this fixture links no plane, so `/healthz` says unready), never the
    // boundary's 500.
    assert_ne!(
        health.status().as_u16(),
        500,
        "`/healthz` is answered, not failed"
    );

    // EACH PANIC IS LOGGED, ONCE, WITH ITS PATH.
    let logged = cap.messages();
    for path in [BOOM, "/api/v1/admin/keys"] {
        let lines: Vec<_> = logged
            .iter()
            .filter(|m| m.contains("a request handler panicked") && m.contains(path))
            .collect();
        assert_eq!(lines.len(), 1, "{path}: {logged:?}");
    }
    data_server.abort();
    admin_server.abort();
}

/// On the native-API root the boundary's 500 is the frozen admin envelope's own `internal` code —
/// never the `not_found` the root's 404/405 branch would otherwise hand a 500.
#[tokio::test]
async fn a_500_on_the_native_api_root_is_the_frozen_internal_envelope() {
    let resp = fallback_error_response(
        &residual_planes(),
        "/api/v1/admin/info",
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        busbar_contract::protocol::KIND_API_ERROR,
        "internal error",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], "internal", "got {v}");
}

/// FROZEN CUSTOMER TEXT the kernel's tests pin (ARCHITECT RULING 2026-09-25, F-T): one value of
/// `tests/fixtures/frozen_customer_text.yaml`, the golden input DATA that holds the store spellings and
/// credential kind operators see, byte-for-byte as 1.5.5 shipped them — so no test source spells them.
pub(crate) fn frozen_text(key: &str) -> serde_yaml::Value {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../tests/fixtures/frozen_customer_text.yaml"
    ))
    .expect("the frozen-text fixture parses");
    doc.get(key)
        .cloned()
        .unwrap_or_else(|| panic!("the frozen-text fixture has no `{key}`"))
}

/// [`frozen_text`] as a string.
pub(crate) fn frozen_str(key: &str) -> String {
    let v = frozen_text(key);
    v.as_str()
        .unwrap_or_else(|| panic!("frozen `{key}` is not a string"))
        .to_string()
}

/// F25 row 634: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs::unknown_ingress_error_envelope_is_core_s_own_and_names_no_dialect.
/// Pins: an ingress name that resolves to no protocol is answered in the kernel's OWN envelope —
/// the status as given (503), `application/json`, the agnostic `kind` stated VERBATIM
/// (`overloaded`, never rewritten onto a dialect's vocabulary), the message verbatim — and with no
/// dialect's error headers (the content type is the only header).
#[tokio::test]
async fn unknown_ingress_error_envelope_is_core_s_own_and_names_no_dialect() {
    let resp = crate::ingress::ingress_error(
        "no-such-protocol",
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        "everything is on fire",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        resp.headers().get("x-amzn-requestid").is_none(),
        "an unresolved ingress must not carry a dialect's error headers"
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        resp.headers().len(),
        1,
        "no dialect attached a header of its own: {:?}",
        resp.headers()
    );
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON envelope");
    assert_eq!(
        v["error"]["type"],
        busbar_contract::protocol::KIND_OVERLOADED,
        "the kernel's envelope states the agnostic kind verbatim"
    );
    assert_eq!(v["error"]["message"], "everything is on fire");
}

/// A KERNEL-SHAPED REFUSAL IS RENDERED BY THE DOOR THAT OWNS ITS PATH (ARCHITECT ruling 2026-10-16,
/// 3b B): the kernel decides the reason, status and words and hands them, with the path and target,
/// to the bound door renderer; its answer is served as rendered. A path no door owns, or a render
/// that failed (`None`), gets the kernel's own answer, and the native-API root, the kernel's own
/// surface, never asks a door. RED arms: the unbound handle, the failed render and the root.
#[tokio::test]
async fn a_kernel_refusal_is_rendered_by_the_door_that_owns_its_path() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_routes::{KernelRefusal, PlaneRefuseByPathFn};
    use http_body_util::BodyExt as _;
    use std::sync::{Arc, Mutex};
    // (reason, status, words, path, target), as the door renderer was handed them.
    type Seen = Vec<(ReasonCode, u16, String, String, String)>;
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let refuser: PlaneRefuseByPathFn = {
        let seen = Arc::clone(&seen);
        Arc::new(move |r: &KernelRefusal<'_>| {
            seen.lock().unwrap().push((
                r.reason,
                r.status,
                r.text.to_string(),
                r.path.to_string(),
                r.target.to_string(),
            ));
            (r.path != "/door/failed").then(|| {
                axum::http::Response::builder()
                    .status(r.status)
                    .body(axum::body::Body::from("door"))
                    .unwrap()
            })
        })
    };
    let answer = |handle: &crate::state::AppHandle, path: &str| {
        crate::router::kernel_refusal_response(
            handle,
            &residual_planes(),
            ReasonCode::MethodNotAllowed,
            path,
            &format!("{path}?q=1"),
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        )
    };
    let body = |r: axum::response::Response| async move {
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    };
    let unbound = crate::state::AppHandle::new(crate::test_support::TestApp::new().build());
    let r = answer(&unbound, "/door/x");
    assert_eq!(r.status(), axum::http::StatusCode::METHOD_NOT_ALLOWED);
    assert_ne!(body(r).await, b"door", "no door bound: the kernel answers");
    let bound = crate::state::AppHandle::new(crate::test_support::TestApp::new().build());
    bound.bind_door_refuser(refuser);
    let r = answer(&bound, "/door/x");
    assert_eq!(r.status(), axum::http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body(r).await, b"door");
    assert_eq!(
        seen.lock().unwrap().last().cloned(),
        Some((
            ReasonCode::MethodNotAllowed,
            405,
            "method not allowed for this resource".to_string(),
            "/door/x".to_string(),
            "/door/x?q=1".to_string(),
        ))
    );
    let r = answer(&bound, "/door/failed");
    assert_ne!(
        body(r).await,
        b"door",
        "a failed render: the kernel answers"
    );
    let asked = seen.lock().unwrap().len();
    let root = format!("{}/info", crate::admin::gate::API_ROOT);
    let r = answer(&bound, &root);
    assert_ne!(body(r).await, b"door");
    assert_eq!(
        seen.lock().unwrap().len(),
        asked,
        "the native-API root asks no door"
    );
}
