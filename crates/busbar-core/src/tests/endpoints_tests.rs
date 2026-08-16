// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/endpoints.rs`.

use super::*;
use crate::governance::{ScopeRef, VirtualKey};
use crate::test_support::{LaneSpec, TestApp};

/// A virtual key restricted to `allowed_pools`. Mapping for the test helper: an EMPTY
/// slice models the OMITTED grant (all pools, None); a non-empty slice is the explicit list.
fn vkey(allowed_pools: &[&str]) -> std::sync::Arc<VirtualKey> {
    std::sync::Arc::new(VirtualKey {
        id: "k-test".to_string(),
        generation_hash: "deadbeef".to_string(),
        name: "test".to_string(),
        allowed_scopes: (!allowed_pools.is_empty())
            .then(|| allowed_pools.iter().map(|s| ScopeRef::pool(*s)).collect()),
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    })
}

/// Two pools, three lanes: `pool-a` -> lanes {0,1}, `pool-b` -> lane {2}. Lane 2's model is
/// private to `pool-b` so a `pool-a`-only key must never see it.
fn topology_app() -> Arc<App> {
    TestApp::new()
        .lane(LaneSpec::new(
            "model-a0",
            crate::proto::Protocol::openai(),
            "http://a0",
        ))
        .lane(LaneSpec::new(
            "model-a1",
            crate::proto::Protocol::openai(),
            "http://a1",
        ))
        .lane(LaneSpec::new(
            "model-b",
            crate::proto::Protocol::openai(),
            "http://b",
        ))
        .pool("pool-a", &[(0, 1), (1, 1)])
        .pool("pool-b", &[(2, 1)])
        .build()
}

async fn stats_json(app: Arc<App>, gov: GovCtx) -> Value {
    let resp = stats(crate::state::CurrentApp(app), Extension(gov)).await;
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect /stats body");
    serde_json::from_slice(&bytes).expect("/stats body is JSON")
}

/// A vkey restricted to `pool-a` must see ONLY
/// `pool-a` in the reported topology and ONLY the lanes that pool routes to — never `pool-b`
/// or its private lane `model-b`.
#[tokio::test]
async fn test_stats_restricted_key_sees_only_its_pools_and_lanes() {
    let app = topology_app();
    let gov = GovCtx {
        key: Some(vkey(&["pool-a"])),
    };
    let body = stats_json(app, gov).await;

    let pools = body["pools"].as_object().expect("pools object");
    assert!(pools.contains_key("pool-a"), "allowed pool must be visible");
    assert!(
        !pools.contains_key("pool-b"),
        "a pool the key cannot target must be hidden; got {pools:?}"
    );

    let lane_models: Vec<&str> = body["lanes"]
        .as_array()
        .expect("lanes array")
        .iter()
        .map(|l| l["model"].as_str().expect("lane model"))
        .collect();
    assert!(
        lane_models.contains(&"model-a0") && lane_models.contains(&"model-a1"),
        "lanes reachable via the visible pool must be reported; got {lane_models:?}"
    );
    assert!(
        !lane_models.contains(&"model-b"),
        "a lane private to a hidden pool must NOT leak in the lane list; got {lane_models:?}"
    );
}

/// An OMITTED `allowed_pools` grant (operator/admin default; None) preserves the behavior: the FULL
/// topology — every pool and every lane — is reported.
#[tokio::test]
async fn test_stats_empty_allowed_pools_sees_full_topology() {
    let app = topology_app();
    let gov = GovCtx {
        key: Some(vkey(&[])),
    };
    let body = stats_json(app, gov).await;

    let pools = body["pools"].as_object().expect("pools object");
    assert!(pools.contains_key("pool-a") && pools.contains_key("pool-b"));

    let lanes = body["lanes"].as_array().expect("lanes array");
    assert_eq!(lanes.len(), 3, "an unrestricted key sees every lane");
}

/// No key at all (governance disabled) is equivalent to unrestricted: full topology.
#[tokio::test]
async fn test_stats_no_key_sees_full_topology() {
    let app = topology_app();
    let body = stats_json(app, GovCtx::default()).await;

    let pools = body["pools"].as_object().expect("pools object");
    assert!(pools.contains_key("pool-a") && pools.contains_key("pool-b"));
    assert_eq!(body["lanes"].as_array().expect("lanes array").len(), 3);
}

/// Bug 1 capacity signal: `/stats` must externally distinguish a saturated (at-capacity) lane
/// from an idle one. A bounded lane's `available`/`at_capacity` flip when its last permit is
/// held; an unbounded lane reports `available: "unbounded"` and is never at capacity.
#[tokio::test]
async fn test_stats_reports_at_capacity_when_lane_saturated() {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("bounded", crate::proto::Protocol::openai(), "http://b")
                .max(1)
                .sem(sem.clone()),
        )
        .lane(
            LaneSpec::new("unbounded", crate::proto::Protocol::openai(), "http://u")
                .max(tokio::sync::Semaphore::MAX_PERMITS),
        )
        .pool("p", &[(0, 1), (1, 1)])
        .build();

    // Idle: the bounded lane has its one permit free; the unbounded lane reports "unbounded".
    let body = stats_json(app.clone(), GovCtx::default()).await;
    let lane = |b: &Value, model: &str| -> Value {
        b["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["model"] == model)
            .cloned()
            .unwrap_or_else(|| panic!("lane {model} missing from /stats"))
    };
    let bounded = lane(&body, "bounded");
    assert_eq!(
        bounded["available"],
        json!(1),
        "idle bounded lane: 1 permit free"
    );
    assert_eq!(bounded["at_capacity"], json!(false));
    // The unified availability signal is rendered from `classify` — an idle, healthy
    // bounded lane reads "available" with a null recovery hint and a closed breaker.
    assert_eq!(bounded["availability"], json!("available"));
    assert_eq!(bounded["recovery_hint_ms"], Value::Null);
    assert_eq!(bounded["breaker_state"], json!("closed"));
    let unbounded = lane(&body, "unbounded");
    assert_eq!(unbounded["available"], json!("unbounded"));
    assert_eq!(unbounded["at_capacity"], json!(false));
    assert_eq!(unbounded["availability"], json!("available"));

    // Saturate the bounded lane by holding its only permit; the signal must flip.
    let _held = sem
        .clone()
        .try_acquire_owned()
        .expect("hold the bounded lane's only permit");
    let body = stats_json(app, GovCtx::default()).await;
    let bounded = lane(&body, "bounded");
    assert_eq!(
        bounded["available"],
        json!(0),
        "a saturated bounded lane reports 0 available permits"
    );
    assert_eq!(
        bounded["at_capacity"],
        json!(true),
        "a saturated bounded lane must be flagged at_capacity in /stats"
    );
    // The same saturation the `at_capacity` flag reports ALSO flows through the
    // unified `availability` signal (breaker healthy, so the reason is at-capacity), with the
    // honest at-capacity recovery floor (2s) instead of a deceptive Retry-After=1. The breaker
    // axis stays independently "closed" — the two are orthogonal.
    assert_eq!(
        bounded["availability"],
        json!("at_capacity"),
        "a saturated lane's availability must classify at_capacity"
    );
    assert_eq!(
        bounded["recovery_hint_ms"],
        json!(2000),
        "at-capacity recovery hint floors at the shipped 2s, never a deceptive 1"
    );
    assert_eq!(bounded["breaker_state"], json!("closed"));
}

/// A lane that is BOTH breaker-Open AND at capacity can never close its breaker (its recovery
/// probe needs a dispatch it cannot win). `/stats` must make that combination legible — the
/// breaker axis and the capacity axis are exposed INDEPENDENTLY, never collapsed into one string.
#[tokio::test]
async fn test_stats_surfaces_open_and_at_capacity_independently() {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("wedged", crate::proto::Protocol::openai(), "http://w")
                .max(1)
                .sem(sem.clone()),
        )
        .pool("p", &[(0, 1)])
        .build();

    // Trip the pool cell Open (cooldown far in the future) AND hold the only permit.
    let t = now();
    app.store.force_open_in("p", 0, t + 60);
    let _held = sem
        .clone()
        .try_acquire_owned()
        .expect("hold the only permit");

    let body = stats_json(app, GovCtx::default()).await;
    let lane = body["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["model"] == "wedged")
        .cloned()
        .expect("wedged lane present");

    // Breaker axis: Open. Capacity axis: at capacity, 0 permits. BOTH visible independently.
    assert_eq!(
        lane["breaker_state"],
        json!("open"),
        "the Open breaker must be visible so operators see why recovery never fires; got {lane}"
    );
    assert_eq!(lane["at_capacity"], json!(true), "capacity axis: saturated");
    assert_eq!(lane["available"], json!(0), "0 free permits");
    // Breaker-first collapse: `availability` classifies BreakerOpen (checked before capacity),
    // but the operator still learns about the saturation from the independent `at_capacity` flag.
    assert_eq!(
        lane["availability"],
        json!("breaker_open"),
        "availability classifies breaker-open (breaker-first); got {lane}"
    );
}

async fn models_ids(app: Arc<App>, gov: GovCtx) -> Vec<String> {
    let resp = list_models(
        crate::state::CurrentApp(app),
        Extension(gov),
        axum::http::HeaderMap::new(),
    )
    .await;
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect /v1/models body");
    let body: Value = serde_json::from_slice(&bytes).expect("/v1/models body is JSON");
    assert_eq!(body["object"], "list", "OpenAI list envelope");
    body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|m| {
            assert_eq!(m["object"], "model", "OpenAI model object");
            m["id"].as_str().expect("model id").to_string()
        })
        .collect()
}

/// `models.list()` is the first call an OpenAI SDK or a self-hosted UI makes. An
/// unrestricted caller sees every routable name: pools first, then direct models,
/// each sorted (a deterministic order UIs can render directly).
#[tokio::test]
async fn test_v1_models_lists_pools_and_models() {
    let app = topology_app();
    let ids = models_ids(app, GovCtx::default()).await;
    assert_eq!(
        ids,
        ["pool-a", "pool-b", "model-a0", "model-a1", "model-b"],
        "pools then models, each sorted"
    );
}

/// Info-disclosure regression: a key restricted to `pool-a` must not enumerate
/// `pool-b` or its private model through the model list — same rule as /stats.
#[tokio::test]
async fn test_v1_models_restricted_key_sees_only_reachable_names() {
    let app = topology_app();
    let gov = GovCtx {
        key: Some(vkey(&["pool-a"])),
    };
    let ids = models_ids(app, gov).await;
    assert_eq!(
        ids,
        ["pool-a", "model-a0", "model-a1"],
        "hidden pool and its private lane must not leak; got {ids:?}"
    );
}

/// An omitted-`allowed_pools` key (operator default; None) sees the full list, like /stats.
#[tokio::test]
async fn test_v1_models_empty_allowed_pools_sees_all() {
    let app = topology_app();
    let gov = GovCtx {
        key: Some(vkey(&[])),
    };
    let ids = models_ids(app, gov).await;
    assert_eq!(ids.len(), 5);
}

async fn models_body(app: Arc<App>, headers: axum::http::HeaderMap, beta: bool) -> Value {
    let resp = if beta {
        list_models_v1beta(
            crate::state::CurrentApp(app),
            Extension(GovCtx::default()),
            headers,
        )
        .await
    } else {
        list_models(
            crate::state::CurrentApp(app),
            Extension(GovCtx::default()),
            headers,
        )
        .await
    };
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

/// The Anthropic SDK always sends `anthropic-version` (their API requires it) — the
/// same path answers in the Anthropic list envelope for those callers.
#[tokio::test]
async fn test_v1_models_anthropic_fingerprint_gets_anthropic_envelope() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("anthropic-version", "2023-06-01".parse().unwrap());
    let body = models_body(topology_app(), headers, false).await;
    assert_eq!(body["has_more"], false, "Anthropic list envelope");
    let first = &body["data"][0];
    assert_eq!(first["type"], "model");
    assert_eq!(first["id"], "pool-a");
    assert!(body.get("object").is_none(), "no OpenAI envelope fields");
}

/// Gemini callers (x-goog-api-key header, or the /v1beta path their SDK uses) get the
/// Gemini models envelope with `models/<id>` resource names.
#[tokio::test]
async fn test_v1_models_gemini_fingerprint_gets_gemini_envelope() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-goog-api-key", "k".parse().unwrap());
    let body = models_body(topology_app(), headers, false).await;
    assert_eq!(body["models"][0]["name"], "models/pool-a");

    let beta = models_body(topology_app(), axum::http::HeaderMap::new(), true).await;
    assert_eq!(
        beta["models"][0]["name"], "models/pool-a",
        "/v1beta path implies Gemini"
    );
}
