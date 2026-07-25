use super::*;
use crate::config::{PoolCfg, PoolMember};

/// The inbound-concurrency cap is added as a layer ONLY when `max_inbound_concurrent > 0`. This
/// drives `apply_inbound_concurrency_limit` over a minimal router whose handler PARKS on a barrier
/// (held until we release it), so two requests are genuinely concurrent. With cap = 1 the second
/// request cannot complete until the first releases its permit (the layer is present); with cap =
/// 0 both complete immediately (NO layer — today's behavior).
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

    // Capped (cap = 1): the layer serializes admission, so the two requests can NOT both reach the
    // barrier at once → the first handler waits out its 300ms timeout before the second is admitted.
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

fn pool(members: Vec<PoolMember>) -> PoolCfg {
    PoolCfg {
        members,
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        module_hooks: Vec::new(),
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

/// INERT-KEYS BOOT GUARD (bypass-edge): a DURABLE store carrying keys with NO admin token is the
/// one state where a prior run's keys become silently unenforced (governance goes inert). The
/// banner fires EXACTLY there and nowhere else.
#[test]
fn test_inert_durable_keys_banner_fires_only_for_durable_keyed_no_token() {
    // The dangerous edge: durable store, keys present, no admin token → LOUD banner.
    let b = inert_durable_keys_banner(true, 3, false).expect("durable+keys+no-token must banner");
    assert!(
        b.contains("INERT") && b.contains("3 key") && b.contains("admin_token"),
        "banner must name the count and the fix; got: {b}"
    );

    // An admin token IS set → keys are enforced, no banner.
    assert!(
        inert_durable_keys_banner(true, 3, true).is_none(),
        "an admin token makes governance active — no inert-keys banner"
    );

    // Durable store but EMPTY (fresh durable deploy, no keys yet) → nothing to bypass, no banner.
    assert!(
        inert_durable_keys_banner(true, 0, false).is_none(),
        "an empty durable store has no keys to leave unenforced"
    );

    // A RAM (non-durable) store never persists keys across the admin-token removal that creates
    // this edge — even if it somehow reported keys, the banner is scoped to durable stores.
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
        crate::config::DEFAULT_EMIT_SERVER_TIMING,
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
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-plugins-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
        Some(&gov_with_store("redis")),
        None,
        &Default::default(),
        &plugins_cfg(&dir, false),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("redis"), "names the store: {err}");
    // The ABSENT-block default behaves identically.
    let err = crate::plugins_preflight(
        Some(&gov_with_store("redis")),
        None,
        &Default::default(),
        &crate::config::PluginsCfg::default(),
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
    let reg = crate::plugins_preflight(None, None, &Default::default(), &plugins_cfg(&dir, false))
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
        &plugins_cfg(&dir, true),
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
        &cfg,
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
        &cfg,
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
        &cfg,
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
    let err = crate::plugins_preflight(None, None, &Default::default(), &plugins_cfg(&dir, true))
        .unwrap_err();
    assert!(err.contains("junk.tar.gz"), "names the file: {err}");
    assert!(err.contains("plugin validation failed"), "got {err}");

    // A structurally-broken manifest (bad sha256 binding) equally aborts.
    std::fs::remove_file(dir.join("junk.tar.gz")).unwrap();
    let mut m = plugin_manifest("acme-store-x", "x", "acme");
    m.sha256 = busbar_plugin_sign::sha256_hex(b"OTHER bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
    std::fs::write(dir.join("sha.tar.gz"), tarball).unwrap();
    let err = crate::plugins_preflight(None, None, &Default::default(), &plugins_cfg(&dir, true))
        .unwrap_err();
    assert!(err.contains("integrity"), "names the sha mismatch: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// CONFLICT (hard requirement 3): two loadable plugins claiming the same alias abort boot naming
/// BOTH — "you can't use redis and a third-party redis".
#[test]
fn alias_conflict_fails_boot_naming_both() {
    let dir = tmp_plugin_dir("conflict");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let a = unsigned_tarball(
        plugin_manifest("busbar-store-redis", "redis", "busbar"),
        b"a",
    );
    let b = unsigned_tarball(plugin_manifest("acme-store-redis", "redis", "acme"), b"b");
    std::fs::write(dir.join("a.tar.gz"), a).unwrap();
    std::fs::write(dir.join("b.tar.gz"), b).unwrap();
    let err = crate::plugins_preflight(None, None, &Default::default(), &cfg).unwrap_err();
    assert!(
        err.contains("busbar-store-redis") && err.contains("acme-store-redis"),
        "names both plugins: {err}"
    );
    assert!(err.contains("alias conflict"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── secrets: block validation + alias/name canonicalization (audit MEDIUM) ─────────────────────

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
    let reg = crate::plugins_preflight(None, None, &Default::default(), &cfg)
        .expect("allow_unsigned permits the unsigned secret plugin");
    (dir, reg)
}

/// AUDIT (NIT #17): a `secrets:` entry naming a reserved BUILT-IN resolver (`env` / `file`) as a
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

/// AUDIT (MEDIUM #8): the `secrets:` block key canonicalizes through the SAME by_name/by_alias
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
    let reg = crate::plugins_preflight(None, None, &Default::default(), &cfg).unwrap();
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
        auth: None,
        allow_metadata_hosts: Vec::new(),
    };
    let mut providers = std::collections::HashMap::new();
    providers.insert("acme".to_string(), provider);
    crate::config::RootCfg {
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
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
    let reg = crate::plugins_preflight(None, None, &Default::default(), &cfg).unwrap();
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
/// rotation is "write different bytes to the same path".
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
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        chain: vec![],
        admin_auth: vec![admin_entry],
        role_bindings: crate::config::RoleBindings::new(),
    });
    cfg
}

fn build_once(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<crate::state::App, String> {
    crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
    )
}

/// Rotating the admin-token secret on disk and RE-APPLYING changes the credential the process
/// accepts. RED without the re-resolution: the digest stays on `tok-v1` forever.
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
        gov.verify_token(&old_token, now).is_some(),
        "valid pre-rotation"
    );

    // THE ROTATION: new key material behind the same ref, then reload.
    std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();
    build_once(cfg_with_credentials(&token_path, &key_path), Some(&prior)).expect("apply");

    assert!(
        gov.verify_token(&old_token, now).is_none(),
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
        gov.verify_token(&fresh, now).is_some(),
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
