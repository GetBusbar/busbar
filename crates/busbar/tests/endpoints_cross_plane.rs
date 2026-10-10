// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `/stats` and `/v1/models` TESTS, relocated here from `src/tests/endpoints_tests.rs`
//! (the "fix the 85" pass after the A6/HostCtx dev-dependency-cycle cleanup): every test in this file
//! builds a `TestApp` with real lanes/pools and reads the topology back through `App::engine_tables_view`,
//! which projects the FALLBACK plane's own runtime slot through that plane decl's `viewer` fn-pointer
//! (`state.rs::App::engine_tables_view`'s doc). Only the REAL `busbar_llm` plane sets `viewer`/
//! `build_runtime` to something that actually returns lane/pool tables — a neutral fake plane (all
//! hooks `None`/no-op) would leave every one of these reading the empty `EMPTY_VIEW` projection, which
//! is a different, false-negative failure than what these tests exist to pin. That only type-checks
//! with ONE `busbar_kernel` in the graph, which is exactly what an integration-test target gives. See
//! `crates/busbar/tests/plane_integration.rs`'s header for the same rationale, first written there.
//!
//! `endpoints::{stats, list_models, list_models_v1beta}` were widened from `pub(crate)` to `pub` for
//! exactly this move — nothing about the tests themselves changed; they still drive the real handler
//! functions directly, not a shim or a real HTTP round trip.
//!
//! MOVED HERE from `crates/busbar-kernel/tests/`, assertions unchanged (kind-isolation, ARCHITECT:
//! core names zero plane types, its tests included; Q128 audit HIGH on the kernel's test-linked
//! build.rs): every cell reads lane/pool topology through the fallback plane's runtime view, which
//! only a real plane builds, and the composition root is where a plane may be linked.

mod linked;

use axum::{extract::Extension, http::HeaderMap};
use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_kernel::endpoints::{list_models, list_models_v1beta, stats};
use busbar_kernel::governance::GovCtx;
use busbar_kernel::state::{App, CurrentApp};
use busbar_kernel::store::now;
use busbar_kernel::test_support::{LaneSpec, TestApp};
use serde_json::{json, Value};
use std::sync::Arc;

fn register_planes() {
    linked::install();
}

/// A virtual key restricted to `allowed_pools`. Mapping for the test helper: an EMPTY
/// slice models the OMITTED grant (all pools, None); a non-empty slice is the explicit list.
fn vkey(allowed_pools: &[&str]) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
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
        ..Default::default()
    })
}

/// Two pools, three lanes: `pool-a` -> lanes {0,1}, `pool-b` -> lane {2}. Lane 2's model is
/// private to `pool-b` so a `pool-a`-only key must never see it.
fn topology_app() -> Arc<App> {
    topology().build()
}

/// The builder [`topology_app`] builds.
fn topology() -> TestApp {
    register_planes();
    TestApp::new()
        .lane(LaneSpec::new(
            "model-a0",
            busbar_kernel::proto::PROTO_OPENAI,
            "http://a0",
        ))
        .lane(LaneSpec::new(
            "model-a1",
            busbar_kernel::proto::PROTO_OPENAI,
            "http://a1",
        ))
        .lane(LaneSpec::new(
            "model-b",
            busbar_kernel::proto::PROTO_OPENAI,
            "http://b",
        ))
        .pool("pool-a", &[(0, 1), (1, 1)])
        .pool("pool-b", &[(2, 1)])
}

async fn stats_json(app: Arc<App>, gov: GovCtx) -> Value {
    let resp = stats(CurrentApp(app), Extension(gov)).await;
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
    register_planes();
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("bounded", busbar_kernel::proto::PROTO_OPENAI, "http://b")
                .max(1)
                .sem(sem.clone()),
        )
        .lane(
            LaneSpec::new("unbounded", busbar_kernel::proto::PROTO_OPENAI, "http://u")
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

/// Every lane in `/stats` carries a numeric `limit` field that aliases `max_concurrent`: the
/// configured cap for a bounded lane, and the semaphore's max permit count (never null) for an
/// unbounded one. Older scrapers key on `limit`, so it must stay present and numeric.
#[tokio::test]
async fn test_stats_limit_is_numeric_alias_of_max_concurrent() {
    register_planes();
    let app = TestApp::new()
        .lane(LaneSpec::new("bounded", busbar_kernel::proto::PROTO_OPENAI, "http://b").max(3))
        .lane(
            LaneSpec::new("unbounded", busbar_kernel::proto::PROTO_OPENAI, "http://u")
                .max(tokio::sync::Semaphore::MAX_PERMITS),
        )
        .pool("p", &[(0, 1), (1, 1)])
        .build();
    let body = stats_json(app, GovCtx::default()).await;
    let lane = |model: &str| -> Value {
        body["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["model"] == model)
            .cloned()
            .unwrap_or_else(|| panic!("lane {model} missing from /stats"))
    };

    let bounded = lane("bounded");
    assert_eq!(bounded["limit"], json!(3), "bounded lane: configured cap");
    assert_eq!(bounded["limit"], bounded["max_concurrent"]);

    let unbounded = lane("unbounded");
    assert!(
        unbounded["limit"].is_u64(),
        "unbounded lane: limit must be numeric, never null; got {}",
        unbounded["limit"]
    );
    assert_eq!(
        unbounded["limit"],
        json!(tokio::sync::Semaphore::MAX_PERMITS),
        "unbounded lane: limit is the semaphore's max permit count"
    );
    assert_eq!(unbounded["limit"], unbounded["max_concurrent"]);
}

/// A lane that is BOTH breaker-Open AND at capacity can never close its breaker (its recovery
/// probe needs a dispatch it cannot win). `/stats` must make that combination legible — the
/// breaker axis and the capacity axis are exposed INDEPENDENTLY, never collapsed into one string.
#[tokio::test]
async fn test_stats_surfaces_open_and_at_capacity_independently() {
    register_planes();
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("wedged", busbar_kernel::proto::PROTO_OPENAI, "http://w")
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
    let resp = list_models(CurrentApp(app), Extension(gov), HeaderMap::new()).await;
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

async fn models_body(app: Arc<App>, headers: HeaderMap, beta: bool) -> Value {
    let resp = if beta {
        list_models_v1beta(CurrentApp(app), Extension(GovCtx::default()), headers).await
    } else {
        list_models(CurrentApp(app), Extension(GovCtx::default()), headers).await
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
    let mut headers = HeaderMap::new();
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
    let mut headers = HeaderMap::new();
    headers.insert("x-goog-api-key", "k".parse().unwrap());
    let body = models_body(topology_app(), headers, false).await;
    assert_eq!(body["models"][0]["name"], "models/pool-a");

    let beta = models_body(topology_app(), HeaderMap::new(), true).await;
    assert_eq!(
        beta["models"][0]["name"], "models/pool-a",
        "/v1beta path implies Gemini"
    );
}

// ── each plane generation's listed names (THE DESIGN section 2) ──────────────────────────────────

/// The scope kind the listing door states: a grant of it names a listed name.
const LISTING_KIND: &str = "listing_door_entry";

/// A door plane folded under `key`/`section` whose generation lists `names`, and the topology app
/// with that generation's slot installed.
fn with_listing_door(
    key: &'static str,
    section: &'static str,
    names: &'static [&'static str],
) -> Arc<App> {
    use busbar_contract::plane_calls::{DoorFacing, PlaneRegistration};
    use busbar_kernel::plane::door::{fold, DoorSection, DoorSlot};
    let reg = PlaneRegistration {
        key,
        section,
        owns: Vec::new(),
        consumes: Vec::new(),
        secret_refs: Vec::new(),
        admin_routes: Vec::new(),
        admin_openapi: None,
        label: "Listing",
        subject_noun: "entry",
        admin_noun: "entry",
        audit_kind: "listing_entry",
        signing: None,
        dialects: Vec::new(),
        scope_kinds: vec![LISTING_KIND],
        billable_classes: Vec::new(),
        fee_units: Vec::new(),
        record_kinds: Vec::new(),
        trust_keys: Vec::new(),
        caller_credential_refusal: None,
        validate: Arc::new(|_: &[u8]| Ok(())),
        facing: Arc::new(move |_: &[u8], _: &[u8], _: Option<&str>| {
            Ok(DoorFacing {
                listed: names.iter().map(|n| (*n).to_string()).collect(),
                ..DoorFacing::default()
            })
        }),
    };
    let facing = (reg.facing)(b"", b"", None).expect("faces");
    let decl = fold(reg).expect("the listing door folds");
    let mut t = topology();
    t.install_plane_runtime(
        decl.key,
        Arc::new(DoorSlot {
            section: DoorSection::new(section, serde_yaml::Value::Null),
            facing,
        }),
    );
    t.build()
}

/// RED: `/v1/models` APPENDS EACH PLANE GENERATION'S LISTED NAMES after the routing tables' own, in
/// the plane's order, a name already listed not listed twice, scope-filtered as the plane admits a
/// direct route: a key whose grants name only pools sees none of them, a key granting the plane's
/// scope kind sees the names it grants.
#[tokio::test]
async fn test_v1_models_appends_each_plane_generations_listed_names() {
    let app = with_listing_door(
        "v1-models-listing",
        "v1_models_listing",
        &["listed-b", "pool-a", "listed-a"],
    );
    assert_eq!(
        models_ids(Arc::clone(&app), GovCtx::default()).await,
        ["pool-a", "pool-b", "model-a0", "model-a1", "model-b", "listed-b", "listed-a"],
        "the plane's listed names follow the tables' own, once each"
    );
    let pools_only = GovCtx {
        key: Some(vkey(&["pool-a"])),
    };
    assert_eq!(
        models_ids(Arc::clone(&app), pools_only).await,
        ["pool-a", "model-a0", "model-a1"],
        "a key granting only pools sees no listed name"
    );
    let mut granted = (*vkey(&["pool-a"])).clone();
    granted
        .allowed_scopes
        .as_mut()
        .expect("a restricted key")
        .push(ScopeRef {
            kind: LISTING_KIND.to_string(),
            value: "listed-a".to_string(),
        });
    let granted = GovCtx {
        key: Some(Arc::new(granted)),
    };
    assert_eq!(
        models_ids(app, granted).await,
        ["pool-a", "model-a0", "model-a1", "listed-a"],
        "a grant of the plane's scope kind names what it sees"
    );
}

/// PIN: A PLANE GENERATION THAT LISTS NOTHING LEAVES `/v1/models` BYTE-IDENTICAL (the 1.5.5 bytes):
/// every envelope, governed or not, is the same bytes as the app with no plane slot at all.
#[tokio::test]
async fn test_v1_models_bytes_unchanged_when_no_plane_lists_a_name() {
    async fn bytes(app: Arc<App>, gov: GovCtx, headers: HeaderMap) -> Vec<u8> {
        let resp = list_models(CurrentApp(app), Extension(gov), headers).await;
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body")
            .to_vec()
    }
    let quiet = with_listing_door("v1-models-quiet", "v1_models_quiet", &[]);
    let mut fingerprints = vec![HeaderMap::new()];
    let mut h = HeaderMap::new();
    h.insert("anthropic-version", "2023-06-01".parse().unwrap());
    fingerprints.push(h);
    let mut h = HeaderMap::new();
    h.insert("x-goog-api-key", "k".parse().unwrap());
    fingerprints.push(h);
    for headers in fingerprints {
        for gov in [
            GovCtx::default(),
            GovCtx {
                key: Some(vkey(&["pool-a"])),
            },
        ] {
            assert_eq!(
                bytes(Arc::clone(&quiet), gov.clone(), headers.clone()).await,
                bytes(topology_app(), gov, headers.clone()).await,
                "a plane listing nothing moves no byte"
            );
        }
    }
}
