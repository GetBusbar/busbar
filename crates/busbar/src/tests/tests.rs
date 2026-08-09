use super::*;
use crate::config::{PoolCfg, PoolMember};

/// Panic-safe process-env restore for a test that must temporarily override a `std::env` var (e.g.
/// `BUSBAR_CONFIG`). A bare "set, assert, manually restore" sequence leaks the override to every
/// later test in the same binary the instant an `assert!`/`assert_eq!` in between fails: the panic
/// unwinds straight past the manual restore. `Drop` runs during unwind too, so holding the prior
/// value in a guard and restoring it there is safe regardless of whether the body between
/// construction and drop panics.
struct EnvVarGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    /// Snapshot `key`'s current value (restored on drop). Does not itself set anything — callers
    /// `std::env::set_var` afterward.
    fn capture(key: &'static str) -> Self {
        Self {
            key,
            prior: std::env::var_os(key),
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

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

/// Bug 4 — `limits.max_inbound_concurrent` must SHED excess inbound requests with a 503, not queue
/// them behind the cap. With cap = 1 and one request in-flight holding the only admission permit, a
/// second concurrent request must return 503 + Retry-After IMMEDIATELY — not block until the first
/// completes. On the unfixed code (`GlobalConcurrencyLimitLayer` alone) the second request QUEUES for
/// a permit, so the `timeout` wrapper fires (RED); after the load-shed fix it sheds fast (GREEN).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_inbound_over_capacity_sheds_503_not_queued() {
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

    // Request 2 arrives with the cap full. It MUST be shed (503) immediately, not queued. The
    // `timeout` is the shed-not-queued assertion: on the unfixed (queueing) code this hangs until
    // request 1 releases, so the timeout fires and `.expect` panics (RED).
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reqwest::Client::new().get(&url).send(),
    )
    .await
    .expect("excess inbound request must be shed immediately, not queued behind the cap (Bug 4)")
    .expect("send completes");

    assert_eq!(
        resp.status().as_u16(),
        503,
        "an over-capacity inbound request must be shed with 503, not queued"
    );
    assert!(
        resp.headers().get(reqwest::header::RETRY_AFTER).is_some(),
        "the inbound-shed 503 must carry a Retry-After header"
    );

    // Let request 1 finish so the server task drains cleanly.
    release.notify_one();
    let r1 = req1.await.unwrap().expect("request 1 completes");
    assert_eq!(
        r1.status().as_u16(),
        200,
        "the admitted request still succeeds"
    );
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

/// The fallback handlers infer the ingress protocol from the
/// request path so a 404/405 is shaped in the client's own protocol, not a bare axum body.
#[test]
fn test_proto_for_path_inference() {
    assert_eq!(proto_for_path("/v1/chat/completions"), "openai");
    assert_eq!(proto_for_path("/v1/responses"), "responses");
    assert_eq!(proto_for_path("/v2/chat"), "cohere");
    // Both the stable v1 and v1beta Gemini surfaces infer gemini.
    assert_eq!(
        proto_for_path("/v1/models/gemini-pro:generateContent"),
        "gemini"
    );
    assert_eq!(
        proto_for_path("/v1beta/models/gemini-pro:streamGenerateContent"),
        "gemini"
    );
    // REGRESSION: an OpenAI-SDK `model.retrieve` hits
    // `GET /v1/models/{model_id}` — NO `:<action>` colon. That must infer OpenAI (so the 405/404
    // error is OpenAI-decodable), not Gemini, even though it shares the `/v1/models/` prefix.
    assert_eq!(proto_for_path("/v1/models/gpt-4o"), "openai");
    assert_eq!(proto_for_path("/v1/models"), "openai"); // list-models (no trailing id)
                                                        // A `/v1/models/` path WITH a colon action is still the Gemini surface.
    assert_eq!(
        proto_for_path("/v1/models/gemini-1.5-pro:generateContent"),
        "gemini"
    );
    // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
    assert_eq!(proto_for_path("/v1beta/models/gemini-pro"), "gemini");
    assert_eq!(
        proto_for_path("/model/anthropic.claude/converse"),
        "bedrock"
    );
    assert_eq!(
        proto_for_path("/model/anthropic.claude/converse-stream"),
        "bedrock"
    );
    assert_eq!(proto_for_path("/my-model/v1/messages"), "anthropic");
    // REGRESSION: a NON-Converse `/model/...` path must NOT be classified as bedrock
    // (it lacks the `/converse`/`/converse-stream` suffix). The previous unconditional
    // `starts_with("/model/")` shaped it as bedrock here while auth shaped it as openai —
    // contradictory error envelopes for one path. The canonical classifier now requires the
    // suffix, so a bare `/model/foo/bar` falls through to the OpenAI default, matching auth.rs.
    assert_eq!(
        proto_for_path("/model/foo/bar"),
        "openai",
        "non-Converse /model/ path must align with auth.rs (openai), not bedrock"
    );
    assert_eq!(proto_for_path("/model/foo/predict"), "openai");
    // Unknown path defaults to the widely-understood OpenAI envelope.
    assert_eq!(proto_for_path("/totally/unknown"), "openai");
}

/// REGRESSION: the two `proto_for_path` classifiers (main.rs fallback/405 handlers
/// and `auth.rs` 401 shaping) must agree for EVERY path — they now share one canonical
/// implementation in `proto`, so this guards that main.rs's delegate matches the canonical source
/// across the full table including the previously-divergent non-Converse `/model/` paths.
#[test]
fn test_proto_for_path_matches_canonical() {
    for path in [
        "/v1/chat/completions",
        "/v1/responses",
        "/v2/chat",
        "/v1/models/gemini-pro:generateContent",
        "/v1beta/models/gemini-pro:streamGenerateContent",
        "/v1/models/gpt-4o",
        "/v1/models",
        "/model/anthropic.claude/converse",
        "/model/anthropic.claude/converse-stream",
        "/model/foo/bar",
        "/model/foo/predict",
        "/my-model/v1/messages",
        "/v1/messages",
        "/totally/unknown",
    ] {
        assert_eq!(
            proto_for_path(path),
            proto::proto_for_path(path),
            "main.rs proto_for_path must equal the canonical proto::proto_for_path for {path}"
        );
    }
}

/// A 404 fallback on a Bedrock path must carry the native `__type` envelope AND the `x-amzn-*`
/// headers a real AWS endpoint always emits — never axum's empty body (a proxy tell).
#[test]
fn test_fallback_bedrock_404_is_native_envelope_with_amzn_headers() {
    let resp = fallback_error_response(
        "/model/some.model/converse",
        axum::http::StatusCode::NOT_FOUND,
        crate::admin::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json"), // golden wire-contract literal (kept bare on purpose)
        "fallback must be application/json, not bare text"
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_some(),
        "bedrock fallback must carry x-amzn-RequestId"
    );
    assert!(
        resp.headers().get("x-amzn-errortype").is_some(),
        "bedrock fallback must carry x-amzn-errortype"
    );
}

/// A 404 fallback on the OpenAI path is shaped as the OpenAI error envelope (no amzn headers).
#[tokio::test]
async fn test_fallback_openai_404_is_json_no_amzn_headers() {
    let resp = fallback_error_response(
        "/v1/chat/completions",
        axum::http::StatusCode::NOT_FOUND,
        // REGRESSION: the fallback 404 emits the CANONICAL `not_found_error` kind, so
        // an OpenAI-inferred 404 carries `{"error":{"type":"not_found_error"}}`, not `not_found`.
        crate::admin::ERR_TYPE_NOT_FOUND,
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
        "OpenAI-inferred 404 must carry the canonical not_found_error type, not not_found"
    );
    let resp = fallback_error_response(
        "/v1/chat/completions",
        axum::http::StatusCode::NOT_FOUND,
        crate::admin::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_none(),
        "non-bedrock fallback must NOT carry x-amzn-* headers"
    );
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
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, TestApp};
    use std::sync::Arc;
    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    // One configured lane so `/healthz` reports ready (200) rather than "no usable lanes" (503) —
    // the probe URL is never actually dialed here; the test only exercises routing/auth.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (data_router, admin_router, _handle) = build_split_routers_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
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

    let admin_path = format!("{}/keys", crate::admin::v1::contract::ADMIN_PREFIX);
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

    let reshaped = reshape_oversized_413("/v1/chat/completions", axum_native_413).await;
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
        "OpenAI-inferred 413 must carry an `error` envelope; got {v}"
    );
    assert_ne!(
        String::from_utf8_lossy(&bytes),
        "length limit exceeded",
        "the axum plain-text body must not survive reshaping"
    );
}

/// REGRESSION: a Bedrock-inferred oversized-body 413 must carry the native AWS
/// `__type` envelope AND the `x-amzn-*` headers, indistinguishable from a real Bedrock reject.
#[tokio::test]
async fn test_oversized_body_413_bedrock_native_envelope_with_amzn_headers() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    let axum_native_413 = (
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "length limit exceeded",
    )
        .into_response();

    let reshaped = reshape_oversized_413("/model/some.model/converse", axum_native_413).await;
    assert_eq!(reshaped.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        reshaped
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json") // golden wire-contract literal (kept bare on purpose)
    );
    assert!(
        reshaped.headers().get("x-amzn-requestid").is_some(),
        "bedrock 413 must carry x-amzn-RequestId"
    );
    assert!(
        reshaped.headers().get("x-amzn-errortype").is_some(),
        "bedrock 413 must carry x-amzn-errortype"
    );
    let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("reshaped bedrock 413 body must be valid JSON");
    assert!(
        v.get("__type").is_some(),
        "bedrock 413 must carry the native __type envelope; got {v}"
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
    let passed = reshape_oversized_413("/v1/chat/completions", ok).await;
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
            axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
        )],
        r#"{"error":{"type":"request_too_large","message":"native"}}"#,
    )
        .into_response();
    let passed = reshape_oversized_413("/v1/chat/completions", already_json).await;
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

    let passed = reshape_oversized_413("/v1/chat/completions", upstream_413).await;
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

    let reshaped = reshape_oversized_413("/v1/chat/completions", axum_native_413).await;
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

/// Helpers for the plugin pre-flight regression tests: a fresh temp plugins dir and an in-memory
/// signed/unsigned tarball builder.
pub(crate) fn tmp_plugin_dir(tag: &str) -> std::path::PathBuf {
    // A monotonic counter, NOT a timestamp. Several helpers call this with the same `tag` from
    // different tests running concurrently, and a clock read is not guaranteed to differ between
    // two threads. Colliding on the path made two tests share one directory: one wrote its tarball
    // while the other scanned it, or removed the directory out from under it — surfacing as an
    // unrelated hooks test failing on "corrupt tar.gz archive" roughly one run in three.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-plugins-{}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub(crate) fn plugin_manifest(
    name: &str,
    alias: &str,
    publisher: &str,
) -> busbar_plugin_sign::Manifest {
    busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: publisher.into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    }
}

/// An UNSIGNED (but structurally valid) tarball: sha256 set, signature empty.
pub(crate) fn unsigned_tarball(mut m: busbar_plugin_sign::Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

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
        ..Default::default()
    }
}

/// FAIL-CLOSED (hard requirement 1): `governance.store: <plugin>` with `plugins.enabled: false`
/// (or the block absent) is a BOOT ERROR that NAMES the flag — the drop-is-inert failsafe.
#[test]
fn store_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    let dir = tmp_plugin_dir("disabled-store");
    let err = crate::plugins_preflight(
        Some(&gov_with_store("valkey")),
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, false),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("valkey"), "names the store: {err}");
    // The ABSENT-block default behaves identically.
    let err = crate::plugins_preflight(
        Some(&gov_with_store("valkey")),
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

/// DROP-IS-INERT: plugins present in the directory but `plugins.enabled: false` (store: memory) —
/// boot succeeds with an EMPTY registry; nothing in the dir is even considered.
#[test]
fn disabled_plugins_are_inert_even_when_present() {
    let dir = tmp_plugin_dir("inert");
    let tarball = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), tarball).unwrap();
    // Even an INVALID tarball must not matter while disabled.
    std::fs::write(dir.join("junk.tar.gz"), b"not a tarball").unwrap();
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, false),
        &Default::default(),
    )
    .expect("inert");
    assert!(reg.loadable().is_empty() && reg.skipped().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// SECURITY: if the CONFIGURED governance store resolves to a plugin that is UNTRUSTED and NOT
/// opted-in, boot must FAIL with a clear error that NAMES the plugin and carries the exact trust
/// reason - never silently skip the store the operator asked for. With `allow_unsigned` set, the
/// same tarball passes preflight and resolves by alias AND canonical name.
#[test]
fn configured_store_with_untrusted_plugin_fails_boot_with_naming_error() {
    let dir = tmp_plugin_dir("untrusted-store");
    let tarball = unsigned_tarball(
        plugin_manifest("busbar-store-sqlite", "sqlite", "busbar"),
        b"unsigned lib bytes",
    );
    std::fs::write(dir.join("sqlite.tar.gz"), tarball).unwrap();

    // STRICT default trust: the referenced store plugin is skipped -> preflight fails, naming it.
    let err = crate::plugins_preflight(
        Some(&gov_with_store("sqlite")),
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, true),
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("busbar-store-sqlite") || err.contains("'sqlite'"),
        "names the plugin: {err}"
    );
    assert!(
        err.contains("allow_unsigned"),
        "carries the exact opt-in flag to set: {err}"
    );

    // Opt in to unsigned: preflight passes and the store resolves by alias AND canonical name.
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let reg = crate::plugins_preflight(
        Some(&gov_with_store("sqlite")),
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .expect("allow_unsigned permits the unsigned store plugin at boot");
    assert!(reg.resolve("sqlite").is_some(), "alias resolves");
    assert!(
        reg.resolve("busbar-store-sqlite").is_some(),
        "canonical name resolves"
    );
    let reg2 = crate::plugins_preflight(
        Some(&gov_with_store("busbar-store-sqlite")),
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .expect("the canonical name is equally valid as governance.store");
    assert!(reg2.resolve("busbar-store-sqlite").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An UNKNOWN `governance.store` name (no plugin matches by alias or name) is a clear boot error
/// listing what IS available.
#[test]
fn unknown_store_name_is_a_clear_boot_error() {
    let dir = tmp_plugin_dir("unknown-store");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let tarball = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), tarball).unwrap();
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

/// FAIL-CLOSED (hard requirement 1): ANY invalid tarball/manifest in an ENABLED plugins dir aborts
/// preflight (and therefore boot) with the file + reason named — never a partial boot, even when
/// the invalid plugin is not the configured store.
#[test]
fn invalid_manifest_in_enabled_dir_fails_boot() {
    let dir = tmp_plugin_dir("invalid-any");
    std::fs::write(dir.join("junk.tar.gz"), b"not a tarball at all").unwrap();
    let err = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, true),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("junk.tar.gz"), "names the file: {err}");
    assert!(err.contains("plugin validation failed"), "got {err}");

    // A structurally-broken manifest (bad sha256 binding) equally aborts.
    std::fs::remove_file(dir.join("junk.tar.gz")).unwrap();
    let mut m = plugin_manifest("acme-store-x", "x", "acme");
    m.sha256 = busbar_plugin_sign::sha256_hex(b"OTHER bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
    std::fs::write(dir.join("sha.tar.gz"), tarball).unwrap();
    let err = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, true),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("integrity"), "names the sha mismatch: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// CONFLICT (hard requirement 3): two loadable plugins claiming the same alias abort boot naming
/// BOTH — "you can't use valkey and a third-party valkey".
#[test]
fn alias_conflict_fails_boot_naming_both() {
    let dir = tmp_plugin_dir("conflict");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let a = unsigned_tarball(
        plugin_manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"a",
    );
    let b = unsigned_tarball(plugin_manifest("acme-store-valkey", "valkey", "acme"), b"b");
    std::fs::write(dir.join("a.tar.gz"), a).unwrap();
    std::fs::write(dir.join("b.tar.gz"), b).unwrap();
    let err = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("busbar-store-valkey-plugin") && err.contains("acme-store-valkey"),
        "names both plugins: {err}"
    );
    assert!(err.contains("alias conflict"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── secrets: block validation + alias/name canonicalization ──────────────────────────────────────

/// A `kind: secret` manifest with the correct secret ABI (the store default from `plugin_manifest`
/// carries the store ABI, which the secret kind would reject).
fn secret_manifest(name: &str, alias: &str) -> busbar_plugin_sign::Manifest {
    let mut m = plugin_manifest(name, alias, "acme");
    m.kind = "secret".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("secret")
        .iter()
        .max()
        .expect("secret abi");
    m
}

/// A registry loaded from an unsigned `kind: secret` tarball (name `acme-secret-vault`, alias
/// `vault`), for exercising the `secrets:` block resolution.
fn secret_registry(tag: &str) -> (std::path::PathBuf, busbar_plugin_loader::PluginRegistry) {
    let dir = tmp_plugin_dir(tag);
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let tarball = unsigned_tarball(secret_manifest("acme-secret-vault", "vault"), b"lib");
    std::fs::write(dir.join("vault.tar.gz"), tarball).unwrap();
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
/// operator error, not a silent no-op.
#[test]
fn secrets_block_rejects_builtin_resolver_names() {
    let reg = busbar_plugin_loader::PluginRegistry::empty();
    for reserved in ["env", "file"] {
        let err = validate_secret_module(&reg, reserved).unwrap_err();
        assert!(
            err.contains("built-in secret resolver"),
            "reserved '{reserved}' rejected as a module: {err}"
        );
    }
}

/// A `secrets:` entry that resolves to NO loadable plugin is a hard error (not a silent `{}` open) —
/// this is the failure that pairs with the alias/name mismatch below.
#[test]
fn secrets_block_rejects_unknown_module() {
    let reg = busbar_plugin_loader::PluginRegistry::empty();
    let err = validate_secret_module(&reg, "typo-vault").unwrap_err();
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
        validate_secret_module(&reg, "vault").unwrap(),
        "acme-secret-vault"
    );
    assert_eq!(
        validate_secret_module(&reg, "acme-secret-vault").unwrap(),
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
    // A STORE-kind plugin (default from plugin_manifest) — wrong kind for a secrets: entry.
    let tarball = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), tarball).unwrap();
    let reg = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &cfg,
        &Default::default(),
    )
    .unwrap();
    let err = validate_secret_module(&reg, "x").unwrap_err();
    assert!(
        err.contains("not 'secret'"),
        "wrong-kind rejection names the mismatch: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A minimal `RootCfg` whose SOLE provider's `api_key` is the given secret reference — the smallest
/// config that exercises `config_validate::secret_refs` (and thus `validate_secret_refs`).
fn cfg_with_provider_api_key(api_key: crate::config::SecretRef) -> crate::config::RootCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());
    let provider = crate::config::ProviderCfg {
        protocol: "openai".into(),
        base_url: "https://api.example.com".into(),
        api_key,
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
    };
    let mut providers = std::collections::HashMap::new();
    providers.insert("acme".to_string(), provider);
    crate::config::RootCfg {
        tool_defs: Default::default(),
        // Not an MCP server.
        mcp: None,
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models: std::collections::HashMap::new(),
        pools: std::collections::HashMap::new(),
        hooks: std::collections::HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        store: None,
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        limits: crate::config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

/// The marquee 1.5.0 "secrets are plugins" feature — a provider
/// `api_key: { module: acme-vault, … }` (TLS cert/key, `auth.signing_key`, and the admin token are
/// the same shape) — must PASS validation when the `kind: secret` plugin is loaded + trusted. The
/// module-existence check is DEFERRED past `config_validate::validate` (which runs before the plugin
/// registry exists) to `validate_secret_refs`, which consults the SAME registry the resolver uses.
#[test]
fn secret_ref_plugin_backed_module_passes_when_plugin_present() {
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
            validate_secret_refs(&reg, &cfg).is_ok(),
            "a loaded kind:secret plugin '{module}' must pass the secret-ref pre-flight"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A GENUINE typo — a secret module that is neither a built-in
/// (`env`/`file`) nor a loaded plugin — must still FAIL, so the deferral does not weaken the check.
#[test]
fn secret_ref_typo_module_still_fails_at_preflight() {
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
    let err = validate_secret_refs(&reg, &cfg)
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
    let reg = busbar_plugin_loader::PluginRegistry::empty();
    let cfg = cfg_with_provider_api_key(crate::config::SecretRef::env("ACME_KEY"));
    assert!(
        validate_secret_refs(&reg, &cfg).is_ok(),
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
    let tarball = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), tarball).unwrap();
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
    let err = validate_secret_refs(&reg, &root)
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
// ONCE at construction and then frozen, so an operator who rotated the underlying secret behind
// `auth.admin_auth[admin-tokens].token` or `auth.signing_key` and reloaded got NO effect: the
// process kept accepting the boot-time credential for the rest of its life, while every signal it
// gave said the rotation had landed. These drive the REAL `build_app_from_config` apply path.

/// Build a minimal, valid RootCfg whose admin token and signing key are `file:` secret refs, so a
/// rotation is "write different bytes to the same path". Only used by the 3 `auth-admin-tokens`
/// -gated tests below.
#[cfg(feature = "auth-admin-tokens")]
fn cfg_with_credentials(
    token_path: &std::path::Path,
    key_path: &std::path::Path,
) -> crate::config::RootCfg {
    let mut cfg =
        cfg_with_provider_api_key(crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY"));
    let mut admin_entry = crate::config::AuthChainEntry::bare(crate::config::ADMIN_TOKENS_MODULE);
    admin_entry.token = Some(crate::config::SecretRef::file(
        token_path.to_string_lossy().to_string(),
    ));
    cfg.auth = Some(crate::config::AuthCfg {
        signing_key: Some(crate::config::SecretRef::file(
            key_path.to_string_lossy().to_string(),
        )),
        chain: vec![],
        admin_auth: vec![admin_entry],
        role_bindings: crate::config::RoleBindings::new(),
        methods: Default::default(),
        key_ttl: None,
    });
    cfg
}

fn build_once(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<crate::state::App, String> {
    // Test-only direct call: there is no outer admin transaction / persist step here, so firing any
    // resolved governance-credential rotation immediately is correct
    // and keeps this helper's callers (which assert on rotation taking effect) unchanged.
    let (app, gov_rotate) = crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
    )?;
    if let Some(rotate) = gov_rotate {
        rotate();
    }
    Ok(app)
}

/// An unchanged lane set must CARRY the probe schedule (same `Arc`) across a rebuild —
/// otherwise a mutation cadence faster than the probe interval (`/config/settings` metered at
/// 10/min vs a 30s default interval) resets every generation before its first tick and probing goes
/// dark while still logging that it is enabled. A lane-set CHANGE must mint a fresh one, because
/// deadlines are index-keyed.
///
/// No clock in this assertion — synchronous pointer identity — so the "21 spawns in the same
/// millisecond" false-green mode cannot apply here.
#[test]
fn a_rebuild_carries_the_probe_schedule() {
    crate::metrics::init();
    let no_lane_cfg = || {
        cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_PROBE_SCHEDULE",
        ))
    };
    let one_lane_cfg = || {
        let mut cfg = no_lane_cfg();
        cfg.models.insert(
            "m0".to_string(),
            crate::config::ModelCfg {
                reasoning: None,
                prompt_caching: None,
                max_requests: -1,
                provider: "acme".into(),
                max_concurrent: Some(1),
                default_max_tokens: None,
                upstream_model: None,
                attempt_timeout_ms: None,
            },
        );
        cfg
    };

    // Positive half: zero lanes both times (the zip is vacuously true), but the buggy code still
    // mints a fresh `Arc` unconditionally, so this alone discriminates.
    let prior = build_once(no_lane_cfg(), None).expect("boot");
    let next = build_once(no_lane_cfg(), Some(&prior)).expect("rebuild, unchanged config");
    assert!(
        std::sync::Arc::ptr_eq(&prior.probe_schedule, &next.probe_schedule),
        "an unchanged lane set must carry the probe schedule across a rebuild"
    );

    // Negative half: a lane REMOVED must NOT carry — the old indices would mean something else.
    let prior2 = build_once(one_lane_cfg(), None).expect("boot with one lane");
    let next2 = build_once(no_lane_cfg(), Some(&prior2)).expect("rebuild with the lane removed");
    assert!(
        !std::sync::Arc::ptr_eq(&prior2.probe_schedule, &next2.probe_schedule),
        "a lane-set change must NOT carry the probe schedule"
    );
}

/// Rotating the admin-token secret on disk and RE-APPLYING changes the credential the process
/// accepts. RED without the re-resolution: the digest stays on `tok-v1` forever.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn admin_token_secret_ref_re_resolves_on_apply() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok-v1").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior = build_once(cfg_with_credentials(&token_path, &key_path), None).expect("boot");
    let gov = prior.governance.clone().expect("governance");
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(crate::sigv4::sha256_hex(b"tok-v1").as_str()),
        "boot accepts the resolved token"
    );

    // THE ROTATION: the operator replaces the secret behind the ref, then reloads.
    std::fs::write(&token_path, "tok-v2").unwrap();
    let next =
        build_once(cfg_with_credentials(&token_path, &key_path), Some(&prior)).expect("apply");

    assert!(
        std::sync::Arc::ptr_eq(next.governance.as_ref().unwrap(), &gov),
        "the apply REUSES the same GovState (keys/ledgers survive) — the credential is swapped in place"
    );
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(crate::sigv4::sha256_hex(b"tok-v2").as_str()),
        "the rotated admin token is the one now accepted"
    );
    assert_ne!(
        gov.admin_token_hash().as_deref(),
        Some(crate::sigv4::sha256_hex(b"tok-v1").as_str()),
        "the pre-rotation admin token is no longer accepted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same for `auth.signing_key`: after rotating the key material and re-applying, a token minted
/// under the OLD key no longer verifies and a freshly-minted one does. A resolution FAILURE on
/// apply is fail-closed — the apply is refused rather than silently keeping the old key.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn signing_key_secret_ref_re_resolves_on_apply_and_fails_closed() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-signing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior = build_once(cfg_with_credentials(&token_path, &key_path), None).expect("boot");
    let gov = prior.governance.clone().expect("governance");
    let spec = crate::governance::NewKeySpec {
        name: "k".into(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
    };
    let now = crate::store::now();
    let (_binding, old_token) = gov.mint_signed(spec, now + 10_000, now).expect("mint");
    assert!(
        gov.verify_token(&old_token, now, None).is_some(),
        "valid pre-rotation"
    );

    // THE ROTATION: new key material behind the same ref, then reload.
    std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();
    build_once(cfg_with_credentials(&token_path, &key_path), Some(&prior)).expect("apply");

    assert!(
        gov.verify_token(&old_token, now, None).is_none(),
        "a token minted under the PRE-rotation signing key must stop verifying after the reload"
    );
    let spec2 = crate::governance::NewKeySpec {
        name: "k2".into(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
    };
    let (_b2, fresh) = gov
        .mint_signed(spec2, now + 10_000, now)
        .expect("mint under the new key");
    assert!(
        gov.verify_token(&fresh, now, None).is_some(),
        "the engine mints AND verifies under the rotated key (signer and verifier swap as one unit)"
    );

    // FAIL-CLOSED: an unresolvable ref refuses the apply outright.
    std::fs::remove_file(&key_path).unwrap();
    let err = match build_once(cfg_with_credentials(&token_path, &key_path), Some(&prior)) {
        Err(e) => e,
        Ok(_) => panic!("an unresolvable signing-key ref must refuse the apply"),
    };
    assert!(
        err.contains("signing_key"),
        "the refusal names the ref: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// #37: a `token:` secret ref that resolves to EMPTY or WHITESPACE must refuse to start. The
/// documented boot guard for this was lost when the admin token became a SecretRef, and the
/// consequence is worse than "the admin API is silently locked": the digest is taken over the blank
/// string, so `admin_token_hash` becomes `Some(sha256(""))` — a real credential that an empty
/// presented token satisfies. An env var expanding to nothing would hand over the admin surface.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn blank_admin_token_refuses_to_start() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-blank-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    for blank in ["", "   ", "\n\t "] {
        let token_path = dir.join("admin.token");
        std::fs::write(&token_path, blank).unwrap();
        let err = match build_once(cfg_with_credentials(&token_path, &key_path), None) {
            Err(e) => e,
            Ok(_) => panic!("a blank admin token ({blank:?}) must refuse to start"),
        };
        assert!(
            err.contains("admin-tokens"),
            "the refusal names the admin credential: {err}"
        );
        if !blank.is_empty() {
            // A WHITESPACE-only value passes the resolver's own non-empty check (the bytes are
            // there) — this is exactly the case only the trim guard catches.
            assert!(
                err.contains("EMPTY/whitespace-only"),
                "a whitespace-only token must hit the trim guard: {err}"
            );
        }
    }

    // A real token still boots, and the digest is of the real value (not of the blank string).
    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "real-token").unwrap();
    let app = build_once(cfg_with_credentials(&token_path, &key_path), None).expect("boot");
    let gov = app.governance.clone().expect("governance");
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(crate::sigv4::sha256_hex(b"real-token").as_str())
    );
    assert_ne!(
        gov.admin_token_hash().as_deref(),
        Some(crate::sigv4::sha256_hex(b"").as_str()),
        "the blank-string digest must never be a live admin credential"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// #39: a `secrets:` block written under BOTH a plugin's ALIAS and its CANONICAL name resolves to
/// one module, and the second entry used to silently overwrite the first — one block's configured
/// address/token/CA just vanished while the module loaded happily on the survivor. Ambiguous by
/// construction (there is no defensible winner), so it is a loud boot error naming both spellings.
#[test]
fn secrets_block_rejects_alias_and_canonical_for_one_module() {
    let (dir, reg) = secret_registry("secrets-alias-collision");
    let reg = std::sync::Arc::new(reg);
    let mut secrets = std::collections::BTreeMap::new();
    for spelling in ["vault", "acme-secret-vault"] {
        secrets.insert(
            spelling.to_string(),
            crate::config::SecretModuleCfg {
                settings: serde_json::Map::new(),
            },
        );
    }
    let err = match crate::build_secret_resolver(reg.clone(), &secrets) {
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
            crate::build_secret_resolver(reg.clone(), &one).is_ok(),
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
/// `limits::translate_body_max_bytes()` bounds both the SigV4 auth-middleware body buffer and the
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
    crate::metrics::init();
    // Below `REQUEST_BODY_MAX_BYTES_FLOOR` (64 KiB) — `validate_limits` refuses it, which is the
    // whole point: the refusal happens AFTER the install.
    const ILLEGAL: usize = 4096;
    // Precondition, checked at COMPILE time: raising the floor must not quietly make this test
    // assert nothing.
    const _: () = assert!(ILLEGAL < crate::config::REQUEST_BODY_MAX_BYTES_FLOOR);

    let mut cfg =
        cfg_with_provider_api_key(crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY"));
    cfg.limits.request_body_max_bytes = ILLEGAL;

    let Err(err) = build_once(cfg, None) else {
        panic!("a below-floor body cap must fail validation")
    };
    assert!(
        err.contains("request_body_max_bytes"),
        "the build failed for the expected reason: {err}"
    );
    assert_ne!(
        crate::limits::translate_body_max_bytes(),
        ILLEGAL,
        "the REJECTED config's limits are installed process-wide — an invalid apply changed the \
         live SigV4 and cross-protocol translate body caps"
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
    crate::metrics::init();
    let app = crate::test_support::TestApp::new().build();
    // A tiny body cap so an ordinary request trips `DefaultBodyLimit`.
    let (router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let client = reqwest::Client::new();
    let oversized = "x".repeat(4096);
    let r = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::json!({"pad": oversized}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 413, "the body cap must reject");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = r.text().await.unwrap();
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

    server.abort();
}

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
    crate::metrics::init();
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
    crate::metrics::init();
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
  store: sqlite
  db_path: "/var/lib/busbar/governance.db"
  admin_token: '${PATH}'
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude: { provider: anthropic }
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
        Some("sqlite"),
        "the migrated store module must survive the real disk-load pipeline"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `worker_threads_from_env`: an unset var returns None (the normal default path, no warning); a
/// valid positive integer returns Some(n); zero/negative/non-numeric returns None WITH a warning
/// printed (not silently ignored, see the function's own doc comment). Uses a
/// test-unique env var name so this can never collide with a concurrently-running test.
#[test]
fn worker_threads_from_env_parses_valid_rejects_invalid() {
    let unset_name = "BUSBAR_TEST_WORKER_THREADS_UNSET_MARKER_1";
    std::env::remove_var(unset_name);
    assert_eq!(
        worker_threads_from_env(unset_name),
        None,
        "an unset var must return None"
    );

    let valid_name = "BUSBAR_TEST_WORKER_THREADS_VALID_MARKER_1";
    std::env::set_var(valid_name, "7");
    assert_eq!(
        worker_threads_from_env(valid_name),
        Some(7),
        "a valid positive integer must round-trip exactly"
    );
    std::env::remove_var(valid_name);

    for bad in ["0", "-1", "not-a-number", ""] {
        let bad_name = "BUSBAR_TEST_WORKER_THREADS_BAD_MARKER_1";
        std::env::set_var(bad_name, bad);
        assert_eq!(
            worker_threads_from_env(bad_name),
            None,
            "a non-positive-integer value ({bad:?}) must return None, not panic or parse partially"
        );
        std::env::remove_var(bad_name);
    }
}

/// `validate_worker_threads_config`: a config-supplied `advanced.worker_threads: 0` is DIAGNOSED
/// (`Err`, so the caller warns) rather than silently dropped — matching `worker_threads_from_env`'s
/// treatment of an invalid env value. A positive count or an unset value passes through as `Ok`.
/// Pre-fix the config path used `.filter(|n| *n >= 1)`, which returned `None` for
/// `Some(0)` with NO diagnostic — reverting to that (removing this validation) fails the `Err` case.
#[test]
fn validate_worker_threads_config_diagnoses_zero() {
    assert!(
        validate_worker_threads_config(Some(0)).is_err(),
        "worker_threads: 0 must be diagnosed, not silently dropped"
    );
    assert_eq!(validate_worker_threads_config(Some(4)), Ok(Some(4)));
    assert_eq!(validate_worker_threads_config(None), Ok(None));
}

/// `upstream_bool_env_override`: the env→config migration precedence for the boot-time upstream
/// booleans. When the deprecated env var is UNSET, the config value stands; when SET, it wins (`"0"`
/// or empty = off, anything else = on). Dropping the `None => config_val` arm (so the
/// config key stops being honored) fails the "env absent → config value" cases.
#[test]
fn upstream_bool_env_override_precedence() {
    use std::ffi::OsString;
    // Env unset → the config value stands (both directions).
    assert!(
        upstream_bool_env_override(None, true),
        "unset → config true"
    );
    assert!(
        !upstream_bool_env_override(None, false),
        "unset → config false"
    );
    // Env set → it wins over the config value.
    assert!(
        upstream_bool_env_override(Some(OsString::from("1")), false),
        "env `1` overrides config false → on"
    );
    assert!(
        !upstream_bool_env_override(Some(OsString::from("0")), true),
        "env `0` overrides config true → off"
    );
    assert!(
        !upstream_bool_env_override(Some(OsString::from("")), true),
        "env empty → off (overrides config true)"
    );
}

/// `worker_threads_from_config`: END-TO-END from a real config.yaml (not just a parse). A positive
/// `advanced.worker_threads` is read back from the file the `BUSBAR_CONFIG` env var names; a `0` is
/// diagnosed away to `None`. Deleting `worker_threads_from_config`'s parse (or its
/// call in `main()`) means `advanced.worker_threads` stops being read from config.yaml — the positive
/// assertion fails.
#[test]
fn worker_threads_from_config_reads_a_real_file() {
    // `BUSBAR_CONFIG` is read ONLY by `worker_threads_from_config` outside of `main()`, so setting it
    // here does not perturb other unit tests (they pass explicit config paths to `load_config_from_disk`).
    //
    // The restore MUST be panic-safe: a bare `assert_eq!` between the `set_var` and a manual restore
    // at the bottom of the function would, on failure, unwind straight past the restore and leak a
    // `BUSBAR_CONFIG` pointing at THIS test's (about-to-be-deleted) temp dir to every later test in
    // the same binary — a process-global env var is not per-test state, so that leak is silent and
    // order-dependent. `EnvVarGuard`'s `Drop` runs during unwind too, so the restore happens
    // regardless of whether the assertions below pass. See
    // `env_var_guard_restores_on_panic` for a direct proof of that unwind behavior.
    let _guard = EnvVarGuard::capture(ENV_CONFIG);
    let dir = std::env::temp_dir().join(format!(
        "busbar-wtcfg-{}-{}",
        std::process::id(),
        crate::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nadvanced:\n  worker_threads: 5\n",
    )
    .unwrap();
    std::env::set_var(ENV_CONFIG, &config_path);
    assert_eq!(
        worker_threads_from_config(),
        Some(5),
        "a positive advanced.worker_threads must be read from config.yaml"
    );

    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nadvanced:\n  worker_threads: 0\n",
    )
    .unwrap();
    assert_eq!(
        worker_threads_from_config(),
        None,
        "advanced.worker_threads: 0 is invalid → None (diagnosed, not honored)"
    );

    // `_guard`'s `Drop` restores `BUSBAR_CONFIG` here (or on unwind above) — no manual restore needed.
    let _ = std::fs::remove_dir_all(&dir);
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

/// `is_real_auth_plugin_ref`: `keys` is always exempt (engine-handled, never a plugin).
/// `test-groups-module` is exempt ONLY when `is_test_build` is true — in a release build it must
/// be treated as a real (unresolvable) plugin ref, so `--validate` fails it the same way real boot
/// does, rather than silently agreeing a config naming it is fine. Every other name is always a
/// real ref regardless of build flavor.
#[test]
fn is_real_auth_plugin_ref_exempts_keys_always_and_test_groups_module_only_in_test_builds() {
    assert!(!is_real_auth_plugin_ref(config::KEYS_MODULE, true));
    assert!(!is_real_auth_plugin_ref(config::KEYS_MODULE, false));
    assert!(
        !is_real_auth_plugin_ref("test-groups-module", true),
        "exempt in a test build, matching AuthMiddleware::new's #[cfg(test)] arm"
    );
    assert!(
        is_real_auth_plugin_ref("test-groups-module", false),
        "must NOT be exempt in a release build - it isn't a real registered module there, so a \
         release config naming it must be treated as a real (and therefore unresolvable) plugin \
         ref, not silently waved through"
    );
    assert!(is_real_auth_plugin_ref("oidc", true));
    assert!(is_real_auth_plugin_ref("oidc", false));
}

/// `safe_mode_requested`: true iff `--safe-mode` is literally present among the args; absent, a
/// near-miss, or an empty arg list must all return false.
#[test]
fn safe_mode_requested_matches_the_exact_flag_only() {
    assert!(safe_mode_requested(
        vec!["busbar".to_string(), "--safe-mode".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(
        vec!["busbar".to_string(), "--validate".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(
        vec!["busbar".to_string(), "--safe-mode=true".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(std::iter::empty()));
}

/// `is_audit_restore_read_hiccup`: exactly the "audit restore read failed" prefix routes to the
/// hiccup (warn) path; a chain-verification failure message (or anything else) does not, even if
/// it shares a substring or near-miss prefix — the distinction is load-bearing (tamper evidence
/// must never be logged at the same severity as a transient read hiccup).
#[test]
fn audit_restore_read_hiccup_matches_only_its_own_prefix() {
    assert!(is_audit_restore_read_hiccup(
        "audit restore read failed: disk error"
    ));
    assert!(is_audit_restore_read_hiccup("audit restore read failed"));
    assert!(!is_audit_restore_read_hiccup(
        "audit chain verification failed: hash mismatch at seq 42"
    ));
    assert!(!is_audit_restore_read_hiccup(""));
    assert!(!is_audit_restore_read_hiccup(
        "something else entirely audit restore read failed"
    ));
}

/// `recv_shutdown`: a `-> ()` mutant would resolve immediately regardless of the channel — the
/// real function must genuinely BLOCK until something is sent (or the sender is dropped), then
/// resolve promptly once it is.
#[tokio::test(start_paused = true)]
async fn recv_shutdown_blocks_until_a_send_then_resolves() {
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    let handle = tokio::spawn(recv_shutdown(rx));

    // Give the spawned task every chance to (wrongly) resolve on its own if it were a no-op.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "recv_shutdown must still be waiting with nothing sent on the channel"
    );

    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), handle)
        .await
        .expect("recv_shutdown must resolve promptly once the channel fires")
        .unwrap();
}

/// `shutdown_signal`: a `-> ()` mutant would resolve immediately — the real function must genuinely
/// block (nothing sends SIGINT/SIGTERM in this test), never completing within a bounded wait.
#[tokio::test]
async fn shutdown_signal_blocks_when_no_signal_is_delivered() {
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(200), shutdown_signal()).await;
    assert!(
        result.is_err(),
        "shutdown_signal must still be pending with no real signal delivered, not resolve as a no-op"
    );
}

/// `serve_listener`: a `-> ()` mutant would never actually accept connections. Bind a real
/// listener, serve a trivial router through `serve_listener`, and confirm a real HTTP request
/// against it succeeds before the shutdown future fires.
#[tokio::test]
async fn serve_listener_actually_serves_real_http_traffic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route("/probe", axum::routing::get(|| async { "ok" }));
    let secret_resolver = Arc::new(crate::config::secret::SecretResolver::builtins_only());
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    let serve_handle = tokio::spawn(serve_listener(
        listener,
        router,
        None,
        secret_resolver,
        "test",
        recv_shutdown(shutdown_rx),
    ));

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/probe"))
        .send()
        .await
        .expect("serve_listener must actually accept and answer a real HTTP request");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), serve_handle)
        .await
        .expect("serve_listener must actually stop once shutdown fires")
        .unwrap();
}

/// `plugins.fetch` (resource/DoS finding): a mistyped or compromised fetch URL serving an
/// oversized body must be rejected under a size cap, never buffered whole into memory via
/// `resp.bytes()`. Drives the REAL downloader (`plugin_fetch_downloader_with_cap`, which
/// `plugin_fetch_downloader` pins to `config::DEFAULT_PLUGIN_FETCH_MAX_BYTES` in production)
/// against a local server that serves a body larger than a small test cap, from BOTH an honest
/// `Content-Length` (the fast pre-check) and a chunked/no-Content-Length transfer (the streamed
/// cap, which must catch a body a lying/absent header would otherwise let through).
#[tokio::test]
async fn plugin_fetch_downloader_rejects_an_oversized_body() {
    const CAP: usize = 64;
    let oversized = vec![b'x'; CAP * 4];

    // (a) Content-Length present and honest: rejected before any streamed read.
    {
        let body = oversized.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/big",
            axum::routing::get(move || async move { axum::body::Bytes::from(body) }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let downloader = plugin_fetch_downloader_with_cap(&[], CAP);
        let url = format!("http://{addr}/big");
        let result = tokio::task::spawn_blocking(move || downloader(&url))
            .await
            .unwrap();
        server.abort();

        let err = result.expect_err("an over-cap plugins.fetch download must be a clear error");
        assert!(
            err.contains("cap"),
            "expected an error naming the size cap, got: {err}"
        );
    }

    // (b) No Content-Length (axum's `Body::from_stream`, so the header is omitted): the streamed
    // cap in `read_capped` must still catch it — the Content-Length pre-check is a fast path, not
    // the only defense.
    {
        let body = oversized.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/big-streamed",
            axum::routing::get(move || async move {
                let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
                    body.chunks(8).map(|c| Ok(c.to_vec())).collect();
                let stream = futures::stream::iter(chunks);
                axum::body::Body::from_stream(stream)
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let downloader = plugin_fetch_downloader_with_cap(&[], CAP);
        let url = format!("http://{addr}/big-streamed");
        let result = tokio::task::spawn_blocking(move || downloader(&url))
            .await
            .unwrap();
        server.abort();

        let err = result.expect_err(
            "an over-cap plugins.fetch download with no Content-Length must still be rejected",
        );
        assert!(
            err.contains("cap"),
            "expected an error naming the size cap, got: {err}"
        );
    }

    // Sanity: a within-cap body still downloads successfully (the cap does not false-positive on
    // legitimate small artifacts).
    {
        let small = vec![b'y'; CAP / 2];
        let expected = small.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/small",
            axum::routing::get(move || async move { axum::body::Bytes::from(small) }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let downloader = plugin_fetch_downloader_with_cap(&[], CAP);
        let url = format!("http://{addr}/small");
        let result = tokio::task::spawn_blocking(move || downloader(&url))
            .await
            .unwrap();
        server.abort();

        assert_eq!(
            result.expect("a within-cap download must succeed"),
            expected,
            "the downloaded bytes must match the served body exactly"
        );
    }
}

/// SECURITY (signing-key stdout-only contract): `--generate-signing-key` prints the secret ONLY on
/// stdout; the stderr guidance must be secret-free so a stderr capture (systemd journal, CI/build log,
/// terminal scrollback) can never leak the master signing key. Enforced here, not merely commented.
/// RED before the fix: the stderr guidance embedded `export BUSBAR_SIGNING_KEY={hex}`.
#[test]
fn signing_key_guidance_omits_secret() {
    use governance::signing::{TokenSigner, DEFAULT_KID};
    // A real generated key (64 hex chars), so the assertion is against actual secret material.
    let signer = TokenSigner::generate(DEFAULT_KID).expect("generate a signing key");
    let hex = hex::encode(signer.secret_bytes());
    assert_eq!(hex.len(), 64, "sanity: an ed25519 secret is 64 hex chars");

    let (stdout, stderr) = signing_key_command_output(&hex);

    // STDOUT carries the secret verbatim (and ONLY the secret).
    assert_eq!(
        stdout, hex,
        "the secret must be printed verbatim on stdout for `> /run/secrets/...` capture"
    );
    // STDERR guidance must NOT contain the secret anywhere.
    assert!(
        !stderr.contains(&hex),
        "the stderr guidance must be secret-free — it must never embed the generated key"
    );
    // And it must point the operator at the stdout value with a non-secret placeholder.
    assert!(
        stderr.contains("export BUSBAR_SIGNING_KEY=<paste-the-64-hex-key-printed-above>"),
        "the guidance must use a non-secret placeholder pointing at the stdout key"
    );
}

/// Boot RUNS `plugins.fetch` before preflight, and a PIN-CACHED entry skips the
/// network (the URL is unreachable — if boot tried to fetch it, this would fail). Proves the fetch
/// step is wired into `build_app_from_config`'s boot path and that cache-by-pin means no-network.
#[test]
fn fetch_cached_pin_boots_without_network() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-fetch-boot-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    // A file already present, hashing to the pin. Named `*.dat` (not `*.tar.gz`) so the plugin
    // preflight scanner ignores it — this test asserts the FETCH wiring + cache-by-pin no-network
    // path, not tarball validity (that is preflight's job, covered elsewhere).
    let body = b"cached-blob-bytes";
    std::fs::write(dir.join("cached-blob.dat"), body).unwrap();
    let pin = busbar_plugin_sign::sha256_hex(body);

    let cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(
        "BUSBAR_TEST_NO_SUCH_KEY_FETCH",
    ));
    let plugins_cfg = crate::config::PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        fetch: vec![crate::config::PluginFetch::Url(crate::config::UrlFetch {
            // Unreachable on purpose — cache-by-pin must skip it.
            url: "https://plugin.invalid/cached-blob.dat".into(),
            sha256: Some(pin),
        })],
        ..Default::default()
    };
    let res = crate::build_app_from_config(
        cfg,
        plugins_cfg,
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
    );
    // Ok carries a non-Debug App; collapse to the Err string for the assert message.
    let err = res.err();
    assert!(
        err.is_none(),
        "cached-pin boot must succeed without network: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Source review of the boot-logging matrix: the enabled/disabled boot lines and
/// the two-part referenced-but-missing diagnosis are present in `plugins_preflight`. Guards the
/// observability wording against silent removal.
#[test]
fn plugins_boot_logging_wording_present() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(
        src.contains("plugins: disabled (plugins.enabled is false"),
        "disabled boot line missing"
    );
    assert!(
        src.contains("\"plugins: enabled\""),
        "enabled boot line missing"
    );
    // Two-part diagnosis + fetch/drop remediation on the referenced-but-missing arms.
    assert!(
        src.contains("no plugin matching store.module")
            && src.contains("no plugin matching auth.chain module")
            && src.contains("no plugin matching the hook reference"),
        "referenced-but-missing arms not enriched"
    );
    assert!(
        src.contains("Add it to plugins.fetch or drop the signed tarball"),
        "two-part remediation wording missing"
    );
}

/// A minimal but structurally VALID 1.5.x config (parses into `DeployCfg`; `load_config_from_disk`
/// does not resolve, so empty maps are fine).
const BOOT_MINIMAL_CONFIG: &str = "providers: {}\nmodels: {}\n";

/// 1.5.3 durable-by-default at the BOOT path: with NO `config:` section and NO `BUSBAR_CONFIG_OVERLAY`,
/// `load_config_from_disk` resolves a writable overlay next to config.yaml and reports the config
/// mutable. Pre-1.5.3 an unset env var meant `overlay_path: None` (RAM-only).
#[test]
fn boot_default_config_resolves_a_durable_overlay_next_to_config() {
    let (dir, config_path, _providers_path) = boot_config_dir("durable", BOOT_MINIMAL_CONFIG);
    // Note: this test does not set BUSBAR_CONFIG_OVERLAY; the default must still be durable.
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

/// 1.5.3 providers migration (`BUSBAR_PROVIDERS` → `providers_file:`): the top-level `providers_file:`
/// pointer names the catalog (resolved relative to config.yaml), honored with NO env var; and an
/// explicit override (the deprecated env var, or a reload's live path) still wins. Pre-1.5.3 the
/// catalog path came ONLY from `BUSBAR_PROVIDERS` / the hardcoded default; a config-file pointer had
/// no code path.
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

    // An explicit override (deprecated BUSBAR_PROVIDERS, or a reload's live path) wins.
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
        entry("corp-sso", "oidc", Some("full")),
        entry("vendor-sso", "oidc", Some("read-only")),
        entry("oidc", "some-other-module", Some("none")),
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
        caps.get("oidc").map(String::as_str),
        Some("none"),
        "the provider actually NAMED `oidc` owns that key — not whichever provider happens to run \
         the `oidc` module (module-keying made a last-writer-wins collision here, handing one \
         provider's ceiling to another)"
    );
    assert_eq!(caps.len(), 3, "one entry per NAMED provider: {caps:?}");
}
