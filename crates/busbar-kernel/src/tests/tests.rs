use super::*;

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

    let router = axum::Router::new()
        .route(
            "/api/body-cap-probe",
            axum::routing::post(|_body: axum::body::Bytes| async { "buffered" }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(64));
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
    let response = reshape_oversized_413(&residual_planes(), "/api/body-cap-probe", response).await;
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
    use busbar_contract::plugin_rows::{NeedLevel, Row, Trust};
    // Inert metadata only: no plugin, door, registry, or registration is created.
    Row {
        file: format!("{name}.tar.gz"),
        key: name.into(),
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: "1.0.0".into(),
        abi_version: 1,
        trust: Trust::Allowed {
            reason: "unsigned metadata".into(),
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}

pub(crate) fn skipped_in(
    file: &str,
    name: &str,
    alias: &str,
    reason: &str,
) -> busbar_contract::plugin_rows::Skipped {
    busbar_contract::plugin_rows::Skipped {
        file: file.into(),
        name: name.into(),
        alias: alias.into(),
        reason: reason.into(),
        code: "unsigned",
    }
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
fn the_preflight_warns_about_a_malformed_floor() {
    use crate::diagnostics::CONFIG_ANTIDOWNGRADE_FLOOR_INVALID;
    use tracing_subscriber::layer::SubscriberExt as _;
    let mut cfg = crate::config::PluginsCfg::default();
    cfg.min_versions.insert("p".into(), "v1".into());
    let directory = tmp_plugin_dir("malformed-floor-warning");
    let path = directory.join("warnings.log");
    let file = std::fs::File::create(&path).expect("warning capture file");
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_ansi(false)
            .with_writer(move || file.try_clone().expect("warning capture writer")),
    );
    // The actual CLI/bootstrap caller invokes this production policy owner directly.
    tracing::subscriber::with_default(subscriber, || cfg.warn_invalid_floors());
    let captured = std::fs::read_to_string(&path).expect("actual diagnostic output");
    assert!(
        captured.contains(&CONFIG_ANTIDOWNGRADE_FLOOR_INVALID.banner().to_string()),
        "{captured}"
    );
    let _ = std::fs::remove_dir_all(directory);
}

// ROOT pure-framework disposition: env_var_guard_restores_on_panic tested only
// the deleted test kit's EnvVarGuard destructor, not product interpolation or policy.
// Its two fake-helper bookkeeping assertions retire with that helper.

#[test]
fn is_real_auth_plugin_ref_exempts_keys_always_and_in_process_modules_only_where_answered() {
    let none: fn(&str) -> bool = |_| false;
    // A pure classifier input, not an AuthModule/axis or a registration backend.
    let test_modules: fn(&str) -> bool = |module| module == "test-groups-module";
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
fn a_plane_the_boot_did_not_open_builds_no_slot_and_is_reported_awaiting_restart() {
    use crate::appbuild::plane_is_open_for_build;
    use crate::state::awaiting_restart_added;
    const SECTION: &str = "pending-red";
    let written = std::collections::BTreeSet::from([SECTION]);
    let unwritten = std::collections::BTreeSet::new();
    let pending = [SECTION];
    assert!(plane_is_open_for_build(false, SECTION, &written, &[]));
    assert!(!plane_is_open_for_build(false, SECTION, &written, &pending));
    assert!(!plane_is_open_for_build(
        false, SECTION, &unwritten, &pending
    ));
    assert!(plane_is_open_for_build(true, SECTION, &unwritten, &pending));
    let pending = vec![SECTION.to_string()];
    assert_eq!(awaiting_restart_added(&pending, &[]), pending);
    assert!(awaiting_restart_added(&pending, &pending).is_empty());
}

// Panic status/envelopes, both listener survival and exactly-once logs are exercised
// against actual application routers in central2_handler_panic. The old synthetic
// auth producer and fake TestApp were solely fault injection machinery.

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
    let doc: serde_yaml::Value =
        serde_yaml::from_str(include_str!("fixtures/frozen_customer_text.yaml"))
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

// Door refusal custody, exact fields/target, failed-render fallback and native API
// exclusion now run over actual served routers in central2_handler_panic.
