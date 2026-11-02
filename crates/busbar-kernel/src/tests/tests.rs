use super::*;
use crate::test_support::EnvVarGuard;
use crate::test_support::{build_once, cfg_with_provider_api_key};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_inbound_concurrency_layer_added_only_when_positive() {
    use std::sync::Arc;
    use tokio::sync::{Barrier, Notify};

    async fn run_router(router: Router) -> std::time::Duration {
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

    fn make_router(barrier: Arc<Barrier>, _gate: Arc<Notify>) -> Router {
        Router::new().route(
            "/park",
            axum::routing::get(move || {
                let barrier = barrier.clone();
                async move {
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_millis(300), barrier.wait())
                            .await;
                    "ok"
                }
            }),
        )
    }

    let uncapped = apply_inbound_concurrency_limit(
        make_router(Arc::new(Barrier::new(2)), Arc::new(Notify::new())),
        0,
    );
    let uncapped_elapsed = run_router(uncapped).await;

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

    let url1 = url.clone();
    let req1 = tokio::spawn(async move { reqwest::Client::new().get(&url1).send().await });
    started.notified().await;

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
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", None)]));
    let resolved = resolve_model_context_max(&pools).expect("None must not override Some");
    assert_eq!(resolved.get("m"), Some(&Some(128_000)));
}

#[test]
fn test_resolve_model_context_max_identical_values_ok() {
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(64_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", Some(64_000))]));
    let resolved = resolve_model_context_max(&pools).expect("identical values must not conflict");
    assert_eq!(resolved.get("m"), Some(&Some(64_000)));
}

#[test]
fn test_resolve_model_context_max_conflict_is_loud() {
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
    let absent = open_relay_banner(true, false).expect("empty chain must produce a banner");
    assert!(
        absent.contains("OPEN RELAY") && absent.contains("no `auth:` block"),
        "absent-auth banner must call out the missing block; got: {absent}"
    );

    let explicit = open_relay_banner(true, true).expect("explicit empty chain must banner");
    assert!(
        explicit.contains("OPEN RELAY") && explicit.contains("auth.chain is empty"),
        "explicit-empty banner must reference auth.chain is empty; got: {explicit}"
    );
}

#[test]
fn test_open_relay_banner_silent_when_auth_engaged() {
    assert!(open_relay_banner(false, true).is_none());
}

#[test]
fn test_inert_durable_keys_banner_fires_only_for_durable_keyed_no_token() {
    let b = inert_durable_keys_banner(true, 3, false).expect("durable+keys+no-keys-chain banners");
    assert!(
        b.contains("INERT") && b.contains("3 key") && b.contains("keys"),
        "banner must name the count and the fix (add `keys` to auth.chain); got: {b}"
    );

    assert!(
        inert_durable_keys_banner(true, 3, true).is_none(),
        "`keys` in the chain enforces persisted keys — no inert-keys banner"
    );

    assert!(
        inert_durable_keys_banner(true, 0, false).is_none(),
        "an empty durable store has no keys to leave unenforced"
    );

    assert!(
        inert_durable_keys_banner(false, 5, false).is_none(),
        "the inert-keys banner is scoped to durable stores"
    );
}

#[test]
fn test_stateful_plane_ephemeral_store_warn_fires_only_for_ram_plus_stateful() {
    let w = stateful_plane_ephemeral_store_warn(true, true)
        .expect("RAM + the first stateful plane → sharper warn fires");
    assert!(
        w.contains("in-flight tasks will break")
            && w.contains(frozen_str("durable_store_advice").as_str())
            && w.contains("NOT survive a restart"),
        "the warn must name the CONSEQUENCE and the durable-store fix; got: {w}"
    );

    assert!(
        stateful_plane_ephemeral_store_warn(true, true).is_some(),
        "RAM + the second stateful plane → the sharper warn fires"
    );

    assert!(
        stateful_plane_ephemeral_store_warn(true, false).is_none(),
        "a stateless-only deploy must NOT get the sharper warn — noise trains people to \
         ignore warnings"
    );

    assert!(
        stateful_plane_ephemeral_store_warn(false, true).is_none(),
        "a durable store persists stateful-plane task state across restarts — no sharper warn"
    );
}

#[test]
fn test_memory_store_cannot_reach_inert_with_keys() {
    use crate::governance::GovState;
    use std::sync::Arc;

    let store = crate::real_store::store();
    let gov = GovState::new(store, None).unwrap();
    assert!(gov.admin_token_hash().is_none(), "no admin token → inert");
    let key_count = gov.all_keys().map(|k| k.len()).unwrap_or(0);
    assert_eq!(key_count, 0, "a fresh RAM store holds no keys");

    assert!(inert_durable_keys_banner(false, key_count, false).is_none());

    let store2 = crate::real_store::store();
    let gov2 = GovState::new(store2, Some("admintok".to_string())).unwrap();
    assert!(gov2.admin_token_hash().is_some(), "admin token → active");
}

fn residual_planes() -> crate::plane_driver::dispatch::PlaneDispatch {
    crate::plane_driver::dispatch::PlaneDispatch::default()
}

#[tokio::test]
async fn test_fallback_chat_completions_404_is_json_no_amzn_headers() {
    let resp = fallback_error_response(
        &residual_planes(),
        "/v1/chat/completions",
        axum::http::StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json") // golden wire-contract literal (kept bare on purpose)
    );

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

#[test]
fn test_server_timing_dur_ms() {
    assert!((server_timing_dur_ms(1090, 1000) - 0.090).abs() < 1e-9);

    assert!((server_timing_dur_ms(57, NO_UPSTREAM_RTT) - 0.057).abs() < 1e-9);

    assert_eq!(server_timing_dur_ms(500, 800), 0.0);
}

#[tokio::test]
async fn test_oversized_body_413_reshaped_to_json_not_plain_text() {
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

#[tokio::test]
async fn native_api_oversized_body_keeps_413_and_the_code_envelope() {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    let handle = std::sync::Arc::new(crate::state::AppHandle::new(
        crate::test_support::TestApp::new().build(),
    ));
    let router = axum::Router::new()
        .route(
            "/api/body-cap-probe",
            axum::routing::post(|_body: axum::body::Bytes| async { "buffered" }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(64))
        .layer(axum::middleware::from_fn_with_state(
            handle,
            reshape_body_limit_413,
        ));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/body-cap-probe")
                .body(axum::body::Body::from(vec![b'x'; 65]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/json"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["error"]["code"],
        busbar_contract::protocol::KIND_REQUEST_TOO_LARGE
    );
    assert_eq!(
        value["error"]["message"],
        "request body exceeds the maximum allowed size"
    );
    assert!(value["error"].get("type").is_none());
}

#[tokio::test]
async fn test_reshape_oversized_413_passthrough() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

    let ok = (axum::http::StatusCode::OK, "hello").into_response();
    let passed = reshape_oversized_413(&residual_planes(), "/v1/chat/completions", ok).await;
    assert_eq!(passed.status(), axum::http::StatusCode::OK);
    let bytes = passed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"hello",
        "non-413 body must pass through verbatim"
    );

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

#[tokio::test]
async fn test_relayed_upstream_413_not_reshaped() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt as _;

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

pub(crate) fn tmp_plugin_dir(tag: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

pub(crate) fn dropped(name: &str, alias: &str, kind: &str) -> busbar_contract::plugin_rows::Row {
    let mut row = crate::test_support::rows::row(name, alias, kind);
    row.key = name.to_string();
    row
}

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

#[test]
fn the_registry_build_keeps_the_preflights_boot_lines_in_order() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = tmp_plugin_dir("boot-lines");

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

fn linked_hook_name() -> &'static str {
    crate::test_support::ranking_double::NAME
}

#[test]
fn the_built_in_ranking_strategies_are_hook_words_of_one_linked_door_on_the_hook_axis() {
    for name in crate::config::RESERVED_HOOK_NAMES
        .iter()
        .filter(|n| crate::config::is_strategy_name(n) && **n != crate::config::ON_ERROR_WEIGHTED)
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

#[tokio::test]
async fn each_strategy_word_ranks_as_1_5_5_did_through_the_door_and_never_reaches_on_error() {
    use crate::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};

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

#[test]
fn one_validator_refuses_in_one_order() {
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

    assert_eq!(
        check(&cfg, &refuse_root, false).unwrap_err(),
        crate::config_validate::Refusal::Root("the root refuses".to_string())
    );

    cfg.secrets.clear();
    match check(&cfg, &crate::config_validate::no_root_rules, false) {
        Err(crate::config_validate::Refusal::Plugins(e)) => assert!(
            e.contains("references secret module 'typo-ref', which is not a built-in"),
            "the reference is refused: {e}"
        ),
        other => panic!("refused by the registry half: {other:?}"),
    }

    cfg.limits.reasoning_effort_budgets.minimal = 0;
    assert!(
        matches!(
            check(&cfg, &refuse_root, false),
            Err(crate::config_validate::Refusal::Config(_))
        ),
        "the semantic pass answers first"
    );

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

#[test]
fn secrets_block_rejects_unknown_module() {
    let reg = crate::test_support::rows::empty();
    let err = secret_module(reg.as_ref(), "typo-vault").unwrap_err();
    assert!(
        err.contains("no loadable") && err.contains("typo-vault"),
        "unknown module named in the error: {err}"
    );
}

#[test]
fn secrets_block_canonicalizes_alias_and_name_to_the_same_key() {
    let (dir, reg) = secret_registry("secrets-canon");

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

#[test]
fn secrets_block_rejects_non_secret_kind() {
    let dir = tmp_plugin_dir("secrets-wrong-kind");
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
    let err = secret_module(reg.as_ref(), "x").unwrap_err();
    assert!(
        err.contains("not 'secret'"),
        "wrong-kind rejection names the mismatch: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn boot_refuses_a_provider_api_key_that_does_not_resolve() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const SENTINEL: &str = "sk-sentinel-must-never-be-printed";
    let set_var = format!("BUSBAR_TEST_PROVIDER_KEY_SET_{}", std::process::id());
    let unset_var = format!("BUSBAR_TEST_PROVIDER_KEY_UNSET_{}", std::process::id());
    std::env::set_var(&set_var, SENTINEL);
    std::env::remove_var(&unset_var);

    let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::env(&unset_var));

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

#[test]
fn boot_starts_a_keyless_lane_declared_none() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let mut cfg = cfg_with_provider_api_key(crate::config::SecretRef::none());
    cfg.models
        .insert("m0".to_string(), model_cfg_for_provider("acme"));
    build_once(cfg, None).expect("`api_key: none` starts the lane");
}

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

#[test]
fn secret_ref_plugin_backed_module_passes_when_plugin_present() {
    crate::test_support::register_neutral_test_plane();
    let (dir, reg) = secret_registry("secretref-vault-ok");

    for module in ["vault", "acme-secret-vault"] {
        let cfg = cfg_with_provider_api_key(crate::config::SecretRef {
            module: module.to_string(),
            settings: serde_json::Map::new(),
        });

        assert!(
            crate::config_validate::validate(&cfg).is_ok(),
            "pre-registry validate must not reject plugin-backed module '{module}'"
        );

        assert!(
            registry_refusal(reg.as_ref(), &cfg).is_ok(),
            "a loaded kind:secret plugin '{module}' must pass the secret-ref pre-flight"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secret_ref_typo_module_still_fails_at_preflight() {
    crate::test_support::register_neutral_test_plane();
    let (dir, reg) = secret_registry("secretref-typo");
    let cfg = cfg_with_provider_api_key(crate::config::SecretRef {
        module: "vaultt".to_string(),
        settings: serde_json::Map::new(),
    });

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

#[test]
fn secret_ref_builtin_modules_pass_with_empty_registry() {
    let reg = crate::test_support::rows::empty();
    let cfg = cfg_with_provider_api_key(crate::config::SecretRef::env("ACME_KEY"));
    assert!(
        registry_refusal(reg.as_ref(), &cfg).is_ok(),
        "a built-in env ref must pass the pre-flight with no plugins loaded"
    );
}

struct CheckingAxis;

impl busbar_contract::secret::SecretAxis for CheckingAxis {
    fn sugars(&self) -> busbar_contract::secret_ref::Sugars {
        Default::default()
    }
    fn answers(&self, module: &str) -> bool {
        module == "vault"
    }
    fn linked(&self, _: &str) -> bool {
        false
    }
    fn shared(
        &self,
        module: &str,
    ) -> Result<std::sync::Arc<dyn busbar_contract::secret::SecretCalls>, String> {
        Err(format!("{module} is not linked"))
    }
    fn open(
        &self,
        module: &str,
        _: &serde_json::Value,
        _: &dyn Fn(
            &crate::config::SecretRef,
        ) -> Result<busbar_contract::secret::SecretBytes, String>,
    ) -> Result<std::sync::Arc<dyn busbar_contract::secret::SecretCalls>, String> {
        Err(format!("{module} is never opened to be checked"))
    }
    fn check(&self, _: &str, settings: &serde_json::Value) -> Result<(), Vec<String>> {
        match settings.get("path") {
            Some(_) => Ok(()),
            None => Err(vec![
                "settings.path: missing".to_string(),
                "settings: names no secret".to_string(),
            ]),
        }
    }
}

#[test]
fn a_reference_its_plugins_check_refuses_fails_the_preflight() {
    use crate::config_validate::secret_refs::registry_refusal_with;
    crate::test_support::register_neutral_test_plane();
    let (dir, reg) = secret_registry("secretref-checked");
    let mut settings = serde_json::Map::new();
    let refused = cfg_with_provider_api_key(crate::config::SecretRef {
        module: "vault".to_string(),
        settings: settings.clone(),
    });
    assert_eq!(
        registry_refusal_with(reg.as_ref(), &refused, Some(&CheckingAxis)),
        Err("providers.acme.api_key: settings.path: missing\n\
             providers.acme.api_key: settings: names no secret"
            .to_string())
    );
    settings.insert("path".to_string(), serde_json::json!("kv/acme"));
    let accepted = cfg_with_provider_api_key(crate::config::SecretRef {
        module: "vault".to_string(),
        settings,
    });
    assert_eq!(
        registry_refusal_with(reg.as_ref(), &accepted, Some(&CheckingAxis)),
        Ok(())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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

#[test]
fn a_rebuild_carries_the_session_store_and_defaults_scan_off() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[test]
fn an_apply_carries_the_node_amendment_journal_its_governance_owns() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let cfg = || {
        cfg_with_provider_api_key(crate::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_AMENDMENT_JOURNAL",
        ))
    };
    let prior = build_once(cfg(), None).expect("boot");
    let gov = prior
        .governance
        .clone()
        .expect("the boot builds governance");
    assert!(
        std::sync::Arc::ptr_eq(&prior.amendments, gov.amendments()),
        "the boot generation carries the journal its governance owns"
    );
    let next = build_once(cfg(), Some(&prior)).expect("apply");
    assert!(
        std::sync::Arc::ptr_eq(&next.amendments, &prior.amendments),
        "an apply carries the prior generation's journal, never a new one"
    );
    let next_gov = next.governance.clone().expect("the apply keeps governance");
    assert!(
        std::sync::Arc::ptr_eq(&next.amendments, next_gov.amendments()),
        "and it is still the journal governance owns"
    );
}

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

#[test]
fn a_rejected_config_leaves_no_limits_behind() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    const ILLEGAL: usize = 4096;

    const _: () = assert!(ILLEGAL < crate::config::REQUEST_BODY_MAX_BYTES_FLOOR);

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

#[tokio::test]
async fn oversized_request_413_is_reshaped_on_the_live_stack() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = crate::test_support::TestApp::new().build();

    let (mut router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);

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

#[tokio::test]
async fn server_timing_header_absent_by_default_present_when_enabled() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let client = reqwest::Client::new();

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

#[tokio::test]
async fn route_policy_headers_absent_by_default_on_the_live_stack() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[test]
fn migrate_config_then_load_config_from_disk_boots_the_real_migrated_file() {
    crate::test_support::register_neutral_test_plane();
    let (dir, legacy_config_path, providers_path) =
        boot_config_dir("migrate", BOOT_LEGACY_14X_CONFIG);

    let raw = std::fs::read_to_string(&legacy_config_path).unwrap();
    let migrated = crate::config::migrate::migrate_config(&raw).expect("legacy config migrates");

    let migrated_path = dir.join("migrated-config.yaml");
    std::fs::write(&migrated_path, &migrated.yaml).unwrap();

    let loaded = load_config_from_disk(
        &migrated_path,
        Some(&providers_path),
        false,
        crate::config::EnvSubst::Strict,
    )
    .unwrap_or_else(|e| {
        panic!("the migrated config must boot cleanly through the real boot path: {e}")
    });

    assert_eq!(loaded.deploy.listen, "0.0.0.0:8080");
    assert_eq!(
        loaded.deploy.store.as_ref().map(|s| s.module.as_str()),
        Some(frozen_str("legacy_backend_1_4").as_str()),
        "the migrated store module must survive the real disk-load pipeline"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_var_guard_restores_on_panic() {
    const KEY: &str = "BUSBAR_TEST_ENV_GUARD_PANIC_PROBE";

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

const BOOT_MINIMAL_CONFIG: &str = "providers: {}\nmodels: {}\n";

#[test]
fn boot_default_config_defers_store_overlay_recovery_until_the_anchor_opens() {
    let (dir, config_path, _providers_path) = boot_config_dir("durable", BOOT_MINIMAL_CONFIG);

    let _guard = EnvVarGuard::capture("BUSBAR_CONFIG_OVERLAY");
    std::env::remove_var("BUSBAR_CONFIG_OVERLAY");
    let loaded = load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
        .expect("a mutable default config must boot");
    assert!(!loaded.config_locked, "default config is mutable");
    assert!(loaded.overlay_path.is_none());
    assert!(loaded.overlay_doc.is_none());
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        2,
        "only operator input files exist"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn boot_mutable_with_overlay_disabled_refuses_to_boot() {
    let cfg = "providers: {}\nmodels: {}\nconfig:\n  locked: false\n  overlay: false\n";
    let (dir, config_path, _p) = boot_config_dir("no-backend", cfg);
    let Err(err) =
        load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
    else {
        panic!("mutable + overlay disabled must refuse to boot");
    };

    assert!(
        err.contains("mutable config requires") && err.contains("Store-backed overlay"),
        "the boot refusal must be the specific mutable-without-backend message: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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

    let catalog = dir.join("catalog.yaml");
    std::fs::write(&catalog, "{}\n").unwrap();
    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nproviders_file: catalog.yaml\n",
    )
    .unwrap();

    let loaded = load_config_from_disk(&config_path, None, false, crate::config::EnvSubst::Strict)
        .expect("providers_file pointer resolves");
    assert_eq!(
        loaded.providers_path, catalog,
        "the providers_file pointer must be honored"
    );

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

#[test]
fn a_configuration_the_root_rules_refuse_is_refused_by_the_build() {
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
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

struct RestorePublished(Option<crate::config::LimitsResolved>);

impl Drop for RestorePublished {
    fn drop(&mut self) {
        crate::config::limits::swap_installed(self.0.take());
    }
}

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

#[test]
fn a_built_generations_limits_are_in_force_only_once_it_is_live() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

    let handle = crate::state::AppHandle::new(crate::test_support::TestApp::new().build());
    handle.swap(std::sync::Arc::new(next));
    let after = (
        Some(format!("{candidate:?}")),
        candidate.request_body_max_bytes,
        candidate.hook_content_max_bytes,
    );
    assert_eq!(live_limits(), after, "the swapped-in generation's limits");

    unkept
        .keep()
        .expect("the test generation confirms its rates");
    assert_eq!(live_limits(), after);
}

#[tokio::test]
async fn a_panicking_handler_fails_only_its_own_request() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[tokio::test(flavor = "current_thread")]
async fn both_served_routers_answer_a_panic_500_log_it_and_keep_serving() {
    use crate::plane_routes::{PlaneReqCtx, PlaneRouteSpec};
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    use tracing_subscriber::layer::SubscriberExt as _;
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

    assert_ne!(
        health.status().as_u16(),
        500,
        "`/healthz` is answered, not failed"
    );

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

pub(crate) fn frozen_text(key: &str) -> serde_yaml::Value {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "fixtures/frozen_customer_text.yaml"
    ))
    .expect("the frozen-text fixture parses");
    doc.get(key)
        .cloned()
        .unwrap_or_else(|| panic!("the frozen-text fixture has no `{key}`"))
}

pub(crate) fn frozen_str(key: &str) -> String {
    let v = frozen_text(key);
    v.as_str()
        .unwrap_or_else(|| panic!("frozen `{key}` is not a string"))
        .to_string()
}

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

#[tokio::test]
async fn a_kernel_refusal_is_rendered_by_the_door_that_owns_its_path() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_routes::{KernelRefusal, PlaneRefuseByPathFn};
    use http_body_util::BodyExt as _;
    use std::sync::{Arc, Mutex};

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
