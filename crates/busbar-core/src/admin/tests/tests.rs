use crate::governance::{GovState, MemoryStore, NewKeySpec};
use crate::test_support::warn_capture::WarnCapture;
use crate::test_support::TestApp;
use std::sync::Arc;

/// Build a `GovState` that CAN mint 1.5.0 signed-token keys: it carries a deterministic
/// `TokenSigner` (fixed key bytes + the default kid) so `POST /keys` issues a `bbk_` token instead
/// of a 409 "signed-token minting is unavailable". Every admin test that mints (directly or over
/// HTTP) builds its gov through this so the signer is always present; a read-only test could stay on
/// `GovState::new`, but giving them all a signer keeps the fixtures uniform and future-proof.
fn gov_with_signer(
    store: Arc<dyn crate::governance::Store>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[9u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .unwrap(),
    )
}

/// Build a router whose App has governance enabled with a known admin token, returning the
/// listen address + the live server handle.
async fn serve_with_gov(gov: Arc<GovState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// `GET /api/v1/admin/info` flows end-to-end through the ports-and-adapters stack (JSON-REST
/// transport → service → contract view): admin-token guarded, returns the version, the
/// compiled-in plugin proof (with the default build's `tokens`/`ranking` present + the always-on
/// `weighted_floor`), and the topology counts. Proves the transport is mounted and the frozen
/// v1 surface answers.
#[tokio::test]
async fn test_admin_v1_info_reports_version_features_and_topology() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // Wrong token → 401 (the v1 surface is admin-guarded like the rest of /admin).
    let unauth = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "v1/info must be admin-guarded"
    );

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "info must report the build version"
    );
    // The `weighted_floor` is ALWAYS true (non-removable). `keys` is engine-handled and always
    // present; `admin-tokens`/`ranking` are present iff their feature is compiled in - so the
    // compliance-by-compilation proof holds under `--no-default-features` too.
    assert_eq!(body["build"]["weighted_floor"], serde_json::json!(true));
    let auth_modules = body["build"]["auth_modules"].as_array().unwrap();
    assert!(
        auth_modules.iter().any(|m| m == "keys"),
        "auth_modules must contain the built-in `keys` verifier: {auth_modules:?}"
    );
    assert_eq!(
        auth_modules.iter().any(|m| m == "admin-tokens"),
        cfg!(feature = "auth-admin-tokens"),
        "auth_modules must contain `admin-tokens` iff its feature is compiled in: {auth_modules:?}"
    );
    let hook_plugins = body["build"]["hook_plugins"].as_array().unwrap();
    assert_eq!(
            hook_plugins.iter().any(|m| m == "ranking"),
            cfg!(feature = "hooks-ranking"),
            "hook_plugins must contain `ranking` iff the hooks-ranking feature is compiled in: {hook_plugins:?}"
        );
    // Topology keys are present and numeric (exact counts depend on the TestApp fixture).
    assert!(body["topology"]["pools"].is_number());
    assert!(body["topology"]["models"].is_number());
    assert!(body["topology"]["providers"].is_number());
    // 1.5.3 durable-by-default: a plain TestApp is MUTABLE with a writable overlay → persistence on.
    assert_eq!(body["config_persistence"], true);

    handle.abort();
}

/// The topology read surface (`/api/v1/admin/pools`, `/models`, `/providers`) flows through the
/// service and projects the pool/model/provider views. Built on a two-lane, two-provider fixture
/// so the provider aggregation + pool membership are observable.
#[tokio::test]
async fn test_admin_v1_topology_reads_pools_models_providers() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "model-a",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov-x"),
        )
        .lane(
            LaneSpec::new(
                "model-b",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov-y"),
        )
        .pool("mypool", &[(0, 3), (1, 1)])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let get = |path: String| {
        let url = format!("http://{addr}{path}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    let pools = get("/api/v1/admin/pools".into()).await;
    let items = pools["items"].as_array().unwrap();
    let mypool = items
        .iter()
        .find(|p| p["name"] == "mypool")
        .expect("mypool present");
    let members = mypool["members"].as_array().unwrap();
    assert_eq!(members.len(), 2, "pool has two members");
    let weight_a = members.iter().find(|m| m["model"] == "model-a").unwrap()["weight"].as_u64();
    assert_eq!(weight_a, Some(3), "model-a weight projected");

    let models = get("/api/v1/admin/models".into()).await;
    let m_items = models["items"].as_array().unwrap();
    assert!(m_items
        .iter()
        .any(|m| m["model"] == "model-a" && m["provider"] == "prov-x"));
    assert!(m_items
        .iter()
        .any(|m| m["model"] == "model-b" && m["provider"] == "prov-y"));

    let providers = get("/api/v1/admin/providers".into()).await;
    let p_items = providers["items"].as_array().unwrap();
    let px = p_items.iter().find(|p| p["provider"] == "prov-x").unwrap();
    assert_eq!(px["model_count"].as_u64(), Some(1));
    assert!(p_items.iter().any(|p| p["provider"] == "prov-y"));

    handle.abort();
}

/// `GET /api/v1/admin/pools/{name}` projects each member's LIVE status (usable/cooldown/concurrency/
/// inflight/tallies) from the store; 404s an unknown pool.
/// EVERY response under the native-API root speaks the frozen envelope —
/// including unmatched paths (404 `not_found`) and wrong methods (405 `method_not_allowed`),
/// which previously fell through to the data plane's vendor-native shaping (`error.type`).
#[tokio::test]
async fn test_api_root_unmatched_paths_speak_the_admin_envelope() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Unmatched path INSIDE the admin nest + an /api path outside any surface: both 404 in the
    // admin envelope (`code`, never a vendor `type`).
    for path in ["/api/v1/admin/nonexistent", "/api/junk"] {
        let r = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
        assert!(
            body["error"]["type"].is_null(),
            "{path}: never the vendor envelope: {body}"
        );
    }

    // Wrong method on a real endpoint: 405 in the envelope with the frozen code.
    let r = client
        .delete(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 405);
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "method_not_allowed"
    );
    handle.abort();
}

/// Governance-off semantics are UNAMBIGUOUS — collection reads answer the
/// truthful empty page, single reads a truthful 404, and writes a 409 `conflict` with an
/// actionable message (previously everything was 404, making `not_found` mean two things).
#[tokio::test]
async fn test_keys_surface_governance_disabled_semantics() {
    crate::metrics::init();
    let mut app = TestApp::new().build(); // NO governance
    {
        // Open admin posture (explicit empty chain) — this test probes HANDLER semantics, not
        // auth; with governance off there is no admin token for the default chain to accept.
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = Vec::new();
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Collection read: 200 empty page in the standard envelope.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "collection GET is 200-empty");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());

    // Single-resource read: truthful 404.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // Write: 409 conflict with the actionable message.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "writes conflict with server state"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("governance"),
        "actionable message: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_pool_detail_live_status() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "m1",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("p"),
        )
        .pool("mypool", &[(0, 5)])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let ok: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools/mypool"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ok["name"], "mypool");
    let members = ok["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    let m = &members[0];
    assert_eq!(m["model"], "m1");
    assert_eq!(m["weight"], 5);
    // Live-status fields present + typed. A fresh lane is usable with no cooldown.
    assert_eq!(m["usable"], true);
    assert_eq!(m["cooldown_remaining_seconds"], 0);
    assert!(m["available_concurrency"].is_number());
    assert!(m["inflight"].is_number());
    assert!(m["ok"].is_number());
    assert!(m["dead"].is_boolean());
    // Trip observability: a MONOTONIC trip counter + last-trip epoch, so a poller
    // detects transient breaker episodes it can never catch live. Fresh lane: 0 / null.
    assert_eq!(m["trip_count"], 0);
    assert!(m["last_trip_at"].is_null());

    // ?detail=true on the COLLECTION returns the same row shape for every pool in ONE call
    // (no more M+1 dashboard fan-out).
    let detailed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools?detail=true"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = detailed["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "mypool");
    assert_eq!(
        items[0]["members"][0]["usable"], true,
        "detail rows carry the live status inline: {detailed}"
    );
    assert_eq!(items[0]["members"][0]["trip_count"], 0);

    // ?detail=false is the explicit non-detailed request, not a rejected value: it must fall
    // through to the plain (non-detailed) listing, same shape as omitting `detail` entirely, NOT
    // the `pools_bad_detail`-style 400 an unrecognized value gets.
    let plain_via_false = client
        .get(format!("http://{addr}/api/v1/admin/pools?detail=false"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(plain_via_false.status(), 200);
    let plain_via_false: serde_json::Value = plain_via_false.json().await.unwrap();
    let plain_items = plain_via_false["items"].as_array().unwrap();
    assert_eq!(plain_items.len(), 1);
    assert_eq!(plain_items[0]["name"], "mypool");
    assert!(
        plain_items[0]["members"][0].get("usable").is_none(),
        "detail=false must NOT carry the live-status row shape: {plain_via_false}"
    );

    // Unknown pool → 404 not_found.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/pools/nope"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    handle.abort();
}

/// `pool_detail` must report the PER-POOL breaker cell, not the lane-global any-cell/max-cell
/// aggregate: one lane in two pools, only ONE pool's cell tripped. Before the fix `usable`/
/// `cooldown_remaining_seconds` came from `store.snapshot` (`lane_usable_any_cell` /
/// `lane_max_cooldown_remaining`), so BOTH pools reported the tripped pool's numbers — a
/// dashboard for the untouched pool would show a phantom cooldown, and the tripped pool would show
/// `usable: true` (any-cell) even though routing in that exact pool will skip the member.
#[tokio::test]
async fn test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "m1",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("p"),
        )
        .pool("fast", &[(0, 1)])
        .pool("cheap", &[(0, 1)])
        .build();
    let now = crate::store::now();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .store
        .force_open_in("fast", 0, now + 300);

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let fast: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools/fast"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fm = &fast["members"][0];
    assert_eq!(
        fm["usable"], false,
        "the tripped pool's OWN cell must report unusable: {fast}"
    );
    // A RANGE, not an equality, and the reason is a real failure: this asserted exactly 300 and
    // went red in CI. The test seeds the cell with `now + 300` from one `now()`, and the handler
    // computes the remainder from a SECOND `now()` taken when the request arrives. Between them sit
    // a router build, a TCP bind, a task spawn and a real HTTP round trip — so on a loaded runner
    // the wall clock ticks and the answer is 299, which is correct behaviour reported as a failure.
    //
    // The property worth asserting is that the cell reports ITS OWN cooldown rather than a
    // neighbour's or a default, and a couple of seconds of slack proves that just as well while
    // being independent of how busy the machine is. Kept tight enough that a genuinely wrong value
    // (0, or the other pool's) still fails.
    let remaining = fm["cooldown_remaining_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("cooldown_remaining_seconds must be a number: {fast}"));
    assert!(
        (295..=300).contains(&remaining),
        "the tripped pool must report its own cell's cooldown (~300s, allowing for the wall clock \
         advancing between seeding the cell and serving the request); got {remaining}: {fast}"
    );

    let cheap: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools/cheap"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cm = &cheap["members"][0];
    assert_eq!(
        cm["usable"], true,
        "an untouched pool's own cell must still be usable, not the any-cell aggregate: {cheap}"
    );
    assert_eq!(
        cm["cooldown_remaining_seconds"], 0,
        "an untouched pool must not inherit another pool's max-cell cooldown: {cheap}"
    );

    handle.abort();
}

/// `GET /api/v1/admin/admin-auth` reports the admin-plane guard: with governance + an admin token it
/// is `configured: true` with the `admin-token` module. Never a secret.
#[tokio::test]
async fn test_admin_v1_admin_auth_read() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["configured"], true);
    // modules reports the live admin_auth chain verbatim (the SAME resource PUT admin-auth writes)
    assert!(body["modules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == "admin-tokens"));

    handle.abort();
}

/// `GET /api/v1/admin/keys/{id}` returns one key's metadata (never the secret/hash); 404 for an
/// unknown id. Fills the single-key read gap on the legacy key surface.
#[tokio::test]
async fn test_admin_v1_get_single_key() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (minted, minted_secret) = gov
        .create_key(
            NewKeySpec {
                name: "svc".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Found → 200 with metadata, no secret/hash.
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", minted.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["id"], minted.id);
    assert_eq!(body["name"], "svc");
    assert!(
        body.get("generation_hash").is_none(),
        "never expose the hash"
    );
    assert!(
        !text.contains(&minted_secret),
        "never expose the secret on a read"
    );

    // Unknown id → 404.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_doesnotexist"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

/// `GET /api/v1/admin/usage` is the METERING read: the current UTC-day bucket aggregated per
/// (model, provider) and per key, each row carrying the raw token SPLIT plus busbar's DERIVED
/// `spend_micros` (from the configured CostModel rate card + flat fee), under a `window`/`as_of`
/// header. Never leaks the secret (id/name only).
#[tokio::test]
async fn test_admin_v1_usage_meters_by_model_and_key() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    // Prices: 1 cent/request + a rate card of 500 micro-units/token on every tier (the same
    // blended 50 cents/1k tokens the pre-rate-card assertions were derived from). Spend is now
    // DERIVED at read time from ledger x rate card, so the CostModel is the derivation input.
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let rate = crate::config::RateEntryCfg {
        input_utok: 500.0,
        output_utok: 500.0,
        cache_read_utok: 500.0,
        cache_write_utok: 500.0,
    };
    let rate_card: std::collections::BTreeMap<String, crate::config::RateEntryCfg> =
        [("gpt-x".to_string(), rate), ("claude-z".to_string(), rate)]
            .into_iter()
            .collect();
    let cost = crate::cost::CostModel::resolve_parts(
        Some(&rate_card),
        1,
        &std::collections::BTreeMap::new(),
    );
    let now = crate::store::now();
    let (minted, minted_secret) = gov
        .create_key(
            NewKeySpec {
                name: "team-a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            now,
        )
        .unwrap();
    // Two responses metered against one model (split preserved), one against another model.
    let usage = crate::billing::TokenUsage {
        input: 700,
        output: 200,
        cache_read: Some(100),
        cache_creation: None,
        ..Default::default()
    };
    // `record_metering` only accumulates into `pending_metering` (write-behind); an explicit
    // `flush_metering()` is required so the GET below deterministically sees them in the store.
    gov.record_metering(&minted.id, "gpt-x", "openai", Some(&usage), now);
    gov.record_metering(&minted.id, "gpt-x", "openai", Some(&usage), now);
    gov.record_metering(&minted.id, "claude-z", "anthropic", None, now);
    gov.flush_metering();
    let app = TestApp::new().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Window/freshness header. The usage response carries a `currency` field sourced from
    // the single USAGE_CURRENCY const (emitted only on this endpoint).
    assert_eq!(
        body.get("currency").and_then(|c| c.as_str()),
        Some("USD"),
        "usage response carries currency:USD"
    );
    assert!(body["as_of"].as_u64().unwrap() >= now);
    let (start, end) = (
        body["window"]["start"].as_u64().unwrap(),
        body["window"]["end"].as_u64().unwrap(),
    );
    assert_eq!(end - start, 86_400, "one UTC-day metering bucket");
    assert!((start..end).contains(&now));

    // Totals: raw split + derived spend. 3 requests; billable = 2x(700+200+100) = 2000 tokens.
    // spend = 3 req x 10_000 micro + 2000 tokens x 500 utok = 30_000 + 1_000_000 = 1_030_000 micro-units.
    assert_eq!(body["total"]["requests"], 3);
    assert_eq!(body["total"]["tokens_input"], 1400);
    assert_eq!(body["total"]["tokens_output"], 400);
    assert_eq!(body["total"]["tokens_cache_read"], 200);
    assert_eq!(body["total"]["tokens_cache_creation"], 0);
    assert_eq!(body["total"]["spend_micros"], 1_030_000);

    // Per-model attribution (the FinOps unit): each row carries the same split shape.
    let by_model = body["by_model"].as_array().unwrap();
    assert_eq!(by_model.len(), 2, "{by_model:?}");
    let x = by_model.iter().find(|m| m["model"] == "gpt-x").unwrap();
    assert_eq!(x["provider"], "openai");
    assert_eq!(x["requests"], 2);
    assert_eq!(x["tokens_input"], 1400);
    // 2 req x 10_000 micro + 2000 tokens x 500 utok = 1_020_000 micro-units
    assert_eq!(x["spend_micros"], 1_020_000);
    let z = by_model.iter().find(|m| m["model"] == "claude-z").unwrap();
    assert_eq!(
        z["requests"], 1,
        "a flat (zero-token) response still counts"
    );
    assert_eq!(
        z["spend_micros"], 10_000,
        "1 req x 1 cent = 10_000 micro-units"
    );

    // Per-key attribution names the key; the secret never appears anywhere in the body.
    let by_key = body["by_key"].as_array().unwrap();
    assert_eq!(by_key.len(), 1);
    assert_eq!(by_key[0]["id"], minted.id);
    assert_eq!(by_key[0]["name"], "team-a");
    assert_eq!(by_key[0]["requests"], 3);
    let text = body.to_string();
    assert!(
        !text.contains(&minted_secret),
        "usage must not leak the key secret"
    );

    handle.abort();
}

/// END-TO-END config apply: `POST /api/v1/admin/hooks` registers a hook at runtime (201), and a
/// subsequent `GET /api/v1/admin/hooks` SEES it — proving the AppHandle swap took effect AND the
/// per-request service reads the CURRENT snapshot. Invalid definitions reject with invalid_request.
/// E2e (unix): PATCH settings pushes `configure` to the running hook and commits ON ACK
/// (the registry shows the new settings); a NACKing hook commits nothing; GET schema proxies
/// the hook's describe reply.
#[cfg(unix)]
/// Control plane over the DLOPEN hook seam: registering a hook loads its `kind: hook` plugin; a
/// settings PATCH pushes `configure` and COMMITS on the plugin's exact-version ack (the test-hook
/// plugin acks by default); `GET .../schema` proxies the plugin's `describe` self-description
/// envelope, extracting the `schema` member (single nest). The retired socket/webhook mock is gone —
/// the plugin IS the transport now. (A NACK/wrong-version ack rejecting the commit is covered at the
/// DlopenPolicy configure unit level.)
#[tokio::test]
async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
    crate::metrics::init();
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // Kept for the readiness wait below — `HookEnv` clones share one `Arc<PluginRegistry>`, which is
    // what the resolution is keyed on, so this really is the env the handler will resolve against.
    let env_for_warm = env.clone();
    let app = TestApp::new().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Register the hook (overlay), then PATCH its settings — the plugin acks: commits.
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "cfg-hook",
                "config": {"kind": "gate", "plugin": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    // The PATCH below is a CONTROL-PLANE request under a real 5 s deadline, and what this test is
    // about is the ack, not whether a `dlopen` finished in time on a busy CI box. Wait on the
    // loader's readiness signal for exactly the resolution the handler will perform — same registry,
    // same hook name, same post-PATCH settings — so the assertion stops racing the dynamic linker.
    // See `hooks::resolution` for why that race was real (a 5.9 s median load under a full test run)
    // and why widening the deadline was the wrong answer.
    let warm: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "plugin": "test-hook", "settings": {"ratio": 0.4}
    }))
    .expect("hook cfg");
    assert!(
        crate::hooks::await_transport_published("cfg-hook", &warm, &env_for_warm).await,
        "the loader must publish a transport for the hook the PATCH is about to configure"
    );
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"ratio": 0.4}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);
    let got: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    // The COMMIT is visible as the settings KEY NAMES — never the values. A hook's settings bag is a
    // `SecretRef` carrier (and `GET /hooks/{name}` is READ-ONLY scope), so it is projected exactly
    // like every other admin settings bag; see `HookView::settings_keys`.
    assert_eq!(
        got["settings_keys"],
        serde_json::json!(["ratio"]),
        "committed settings visible as KEY NAMES: {got}"
    );
    assert!(
        got.get("settings").is_none(),
        "the raw settings bag must never be on this wire: {got}"
    );

    // Schema proxy: the plugin's `describe` reply is the {schema, dashboard?} envelope; the engine
    // EXTRACTS the schema member, so the endpoint serves a SINGLE nest.
    let schema: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook/schema")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        schema["schema"]["properties"]["order"]["type"], "array",
        "describe schema extracted, single nest: {schema}"
    );

    serve.abort();
}

/// `GET /plugins/{name}/schema`'s describe→manifest fallback: a loaded hook whose live `describe`
/// answers `schema: null` is NOT evidence the plugin has no real settings shape — the handler must
/// fall back to the manifest baseline SERVER-SIDE and return it with `source: "manifest"`, not just
/// report `source: "describe"` with a bare null. Uses the real dlopen'd `busbar-hook-test-plugin`
/// (its `empty_management: true` setting makes `describe()` return `{}`, the real "unsupported"
/// reply) with a manifest stamped with a real `settings_schema`, over the live admin router.
#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_plugin_schema_falls_back_to_manifest_when_describe_answers_null() {
    crate::metrics::init();
    let manifest_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"order": {"type": "array"}},
    });
    let Some(env) = crate::test_support::test_hook_env_with_schema(
        &["test-hook-fallback"],
        Default::default(),
        Some(&manifest_schema.to_string()),
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // See the sibling test: kept so the readiness wait below resolves against the SAME registry.
    let env_for_warm = env.clone();
    let app = TestApp::new().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Register + configure the hook so `describe()` returns `{}` (empty_management: true) — a
    // LOADED plugin that genuinely answers nothing, not merely "never loaded."
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "fallback-hook",
                "config": {"kind": "gate", "plugin": "test-hook-fallback"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);
    // Readiness signal, not a wider deadline — see the sibling test above. The same published
    // resolution serves both the PATCH's `configure` and the `/schema` read that follows it, since
    // the committed settings are the ones warmed here.
    let warm: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "plugin": "test-hook-fallback", "settings": {"empty_management": true}
    }))
    .expect("hook cfg");
    assert!(
        crate::hooks::await_transport_published("fallback-hook", &warm, &env_for_warm).await,
        "the loader must publish a transport for the hook the PATCH is about to configure"
    );
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/fallback-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"empty_management": true}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);

    // The GENERALIZED admin-plugins endpoint, not the hook-only `/hooks/{name}/schema` proxy —
    // proves the fallback lives in `plugin_schema`, the code path this test targets.
    let got: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/plugins/fallback-hook/schema"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        got["source"], "manifest",
        "describe answered null -> falls back to the manifest baseline: {got}"
    );
    assert_eq!(
        got["schema"], manifest_schema,
        "the ACTUAL manifest schema comes back, not just a source label: {got}"
    );
    assert_eq!(got["schema_error"], serde_json::Value::Null);

    serve.abort();
}

/// `POST /api/v1/admin/config/apply`: a body-carried full config swaps in atomically — the new
/// topology is live, the surviving identity keeps its tripped health, and a stale
/// If-Match is a 409 that changes nothing.
#[tokio::test]
async fn test_admin_v1_config_apply_body_swaps_and_carries_health() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .store
        .record_hard_down(0, "tripped before apply");
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let body = serde_json::json!({
        "providers": {
            "test-provider": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1/", "api_key_env": "BUSBAR_TEST_APPLY_NO_KEY"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "providers": {"test-provider": {"api_key": {"env": "BUSBAR_TEST_APPLY_NO_KEY"}}},
            "models": {
                "m0": {"provider": "test-provider", "max_concurrent": 4},
                "m-applied": {"provider": "test-provider", "max_concurrent": 4}
            },
            "pools": {"apply-pool": {"members": [{"model": "m0"}, {"model": "m-applied"}]}}
        }
    });
    let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);

    let pool: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/pools/apply-pool")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let members = pool["members"].as_array().unwrap();
    let m0 = members.iter().find(|m| m["model"] == "m0").unwrap();
    let ma = members.iter().find(|m| m["model"] == "m-applied").unwrap();
    assert_eq!(m0["usable"], false, "carried trip: {m0}");
    assert_eq!(ma["usable"], true, "fresh lane: {ma}");

    // Stale If-Match: 409, nothing applied (concurrency rides the header, never the body).
    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    // A malformed If-Match is a 400 invalid_request, never a silent unguarded write.
    let malformed = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"not-a-version\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status().as_u16(), 400);

    handle.abort();
}

/// `POST /api/v1/admin/config/reload`: re-reads disk truth and swaps it in atomically — the new
/// topology is live, surviving lanes keep their learned health BY IDENTITY (a breaker tripped
/// before the reload is still tripped after it), and an invalid disk config rejects with 400
/// changing nothing.
#[tokio::test]
async fn test_admin_v1_config_reload_swaps_disk_truth_and_carries_health() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY
",
    )
    .unwrap();
    // Disk truth: the SAME identity as the running lane (m0 @ test-provider) plus a NEW model.
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
providers:
  test-provider:
    api_key: { env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY }
models:
  m0:
    provider: test-provider
    max_concurrent: 4
  m-new:
    provider: test-provider
    max_concurrent: 4
pools:
  reload-pool:
    members:
      - model: m0
      - model: m-new
",
    )
    .unwrap();

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
        // Trip m0's default-cell breaker hard so the carried state is unmistakable.
        inner.store.record_hard_down(0, "tripped before reload");
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    // Reload: disk truth replaces the synthetic topology.
    let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);
    let models: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/models")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = models["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["model"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"m-new"),
        "the reloaded topology is live: {names:?}"
    );

    // The surviving identity (m0 @ test-provider) carried its tripped health state.
    let pool: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/pools/reload-pool")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let members = pool["members"].as_array().unwrap();
    let m0 = members
        .iter()
        .find(|m| m["model"] == "m0")
        .expect("m0 present");
    let m_new = members
        .iter()
        .find(|m| m["model"] == "m-new")
        .expect("m-new present");
    assert_eq!(
        m0["usable"], false,
        "m0's pre-reload trip must survive by identity: {m0}"
    );
    assert_eq!(
        m_new["usable"], true,
        "the new lane starts healthy: {m_new}"
    );

    // Invalid disk config: 400, nothing changes.
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
models:
  broken:
    provider: nope
    max_concurrent: 1
providers: {}
",
    )
    .unwrap();
    let before: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bad = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "invalid disk config rejects");
    let after: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        before["config_version"], after["config_version"],
        "a rejected reload changes nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Per-principal mutation rate limits: the config class (apply/rollback) caps at 10/min per
/// principal — the 11th attempt in the window is a 429 in the frozen envelope, and FAILED
/// attempts count (these are all 404s — anti-enumeration).
#[tokio::test]
async fn test_admin_v1_mutation_rate_limit_config_class() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // 10 rollback attempts to a bogus version (all 404 — still spend budget), then the 11th
    // is limited. Tolerate landing exactly on a minute boundary (window refill mid-loop) by
    // accepting the 429 anywhere from attempt 11 to 22, but REQUIRE it eventually.
    let mut limited_at = None;
    for i in 1..=22 {
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/config/rollback"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"version": 424242}).to_string())
            .send()
            .await
            .unwrap();
        match resp.status().as_u16() {
            404 => continue,
            429 => {
                assert!(i >= 11, "the budget is 10/min; limited too early at {i}");
                let body: serde_json::Value = resp.json().await.unwrap();
                assert_eq!(body["error"]["code"], "rate_limited");
                limited_at = Some(i);
                break;
            }
            other => panic!("unexpected status {other} at attempt {i}"),
        }
    }
    assert!(
        limited_at.is_some(),
        "the limiter never fired in 22 attempts"
    );

    handle.abort();
}

/// The scope CHAIN end-to-end (1.5.2 two-rung collapse) with group-mapped principals (via the
/// test-only external module): a `read-only` role reads but cannot mutate (403, audited); a `full`
/// role mutates; an unmapped group gets nothing at all (403 even on reads); a role bound only under
/// a DIFFERENT module earns nothing here; the operator token stays full.
#[tokio::test]
async fn test_admin_v1_scope_ladder_e2e_with_group_mapped_principals() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        // A role BOUND full — with the module ceiling lifted to full it mutates.
        table.insert(
            "admins".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
        // Trust boundary: `sneaky` is bound full ONLY under a DIFFERENT module - a role
        // asserted by test-scope-module never rides another module's binding table.
        let mut other = std::collections::BTreeMap::new();
        other.insert(
            "sneaky".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("other-module".to_string(), other);
        // Lift the external module's default read-only ceiling to `full` so the `admins` binding
        // resolves un-capped.
        inner
            .auth_scope_caps
            .insert("test-scope-module".to_string(), "full".to_string());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let with = |tok: &'static str, req: reqwest::RequestBuilder| {
        req.header("x-admin-token", tok)
            .header("content-type", "application/json")
    };
    let hook_body = serde_json::json!({
        "name": "scoped-hook",
        "config": {"kind": "tap", "plugin": "test-hook"}
    })
    .to_string();
    let key_body = serde_json::json!({"name": "k"}).to_string();

    // read-only: GET 200, mutations 403 with the frozen envelope.
    let r = with(
        "grp:viewers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "read-only can read");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "read-only cannot mint (Full)");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "read-only cannot register hooks (Full)"
    );

    // full: mutations succeed.
    let r = with(
        "grp:admins",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "full registers hooks");
    let r = with(
        "grp:admins",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "full mints keys");

    // Unmapped group: authenticated but zero grants — 403 even on reads.
    let r = with(
        "grp:strangers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "unmapped groups grant nothing");

    // NESTED-BY-MODULE: `sneaky` is bound full under `other-module` only - asserted through
    // test-scope-module it earns nothing (a role never rides another module's binding table).
    let r = with(
        "grp:sneaky",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "a role bound under another module grants nothing through this one"
    );

    // The operator token is still full (admin-tokens is exempt from module ceilings).
    let r = with(
        "admintok",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "operator token stays full");

    handle.abort();
}

/// The idempotency cache is SCOPED TO THE PRINCIPAL: a second admin presenting the same
/// Idempotency-Key value must mint its OWN key, never replay the first principal's response
/// (which carries a once-shown secret). Two full principals, same key value, distinct results.
#[tokio::test]
async fn test_admin_v1_idempotency_key_is_principal_scoped() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        // A role bound FULL so the second principal can also mint keys.
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "admins".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
        inner
            .auth_scope_caps
            .insert("test-scope-module".to_string(), "full".to_string());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let mint = |tok: &'static str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .header("idempotency-key", "shared-value")
            .body(serde_json::json!({"name": "k"}).to_string())
            .send()
    };

    // Principal A (operator) mints under the shared key.
    let a: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
    // Principal B (a different full principal) mints under the SAME key value.
    let b: serde_json::Value = mint("grp:admins").await.unwrap().json().await.unwrap();

    assert!(a["id"].is_string() && b["id"].is_string());
    assert_ne!(
        a["id"], b["id"],
        "a second principal's identical Idempotency-Key must mint a NEW key, not replay A's"
    );
    assert_ne!(
        a["token"], b["token"],
        "B must never receive A's once-shown token via a cross-principal replay"
    );
    // And A replaying its OWN key still returns A's response (per-principal idempotency intact).
    let a2: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
    assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

    handle.abort();
}

/// The credential cache end-to-end: an external-module identify is CACHED (the second
/// request is served from the cache — observable via the flush count), `POST
/// /api/v1/admin/auth/cache/flush` drops it (full scope; read-only principals get 403), and the
/// built-in operator token is NEVER cached (flush finds nothing after operator calls).
#[tokio::test]
async fn test_admin_v1_credential_cache_and_flush_endpoint() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Two reads as a group-mapped principal: the module's Identify lands in the cache.
    for _ in 0..2 {
        let r = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "grp:viewers")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
    }

    // A read-only principal cannot flush (full-scope mutation).
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "grp:viewers")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");

    // Operator flushes the module partition: exactly ONE entry (the cached viewers identify;
    // operator-token authentications are never cached).
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"module": "test-scope-module"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    // TWO entries in the module's partition: the viewers Identify, plus the PASS the module
    // returned for the operator token (Pass IS cached, short-TTL —; only the built-in
    // admin-tokens module's own verdicts are exempt). The flushing request's own Pass was
    // inserted by its chain run before the handler flushed.
    assert_eq!(
        body["flushed"], 2,
        "the viewers Identify + the operator credential's cached Pass"
    );

    // Flush-all with an empty body: nothing left.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    // Exactly ONE: this very request's chain run re-cached a Pass for the operator credential
    // under the external module before the handler flushed. Nothing else survived.
    assert_eq!(
        body["flushed"], 1,
        "only this request's own cached Pass remained"
    );

    // Malformed body: invalid_request.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"module\": 7}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    handle.abort();
}

/// `PUT /api/v1/admin/admin-auth` end-to-end with the dry-run guard: a chain that would lock the
/// CALLER out is a 409 and nothing changes; a chain the caller survives applies atomically
/// (the old credential stops working on the very next request, the surviving one carries on);
/// unknown modules and a stale If-Match reject.
#[tokio::test]
async fn test_admin_v1_put_auth_dry_run_guard() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        // Chain starts as BOTH modules (so both credentials work); a role binding + an explicit
        // full ceiling make `grp:admins` a full principal through the external stand-in.
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "admins".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
        inner
            .auth_scope_caps
            .insert("test-scope-module".to_string(), "full".to_string());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let put = |tok: &'static str, body: serde_json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    // Unknown module: 400, nothing changes.
    let r = put("admintok", serde_json::json!({"admin_auth": ["saml"]}))
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "unknown module is invalid_request"
    );

    // Stale If-Match: 409 (concurrency rides the header; a body-level twin no longer parses
    // — deny_unknown_fields makes a leftover `expected_version` field a loud 400, not a no-op).
    let r = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("if-match", "\"999\"")
        .body(serde_json::json!({"admin_auth": ["admin-tokens"]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "stale If-Match conflicts");

    // THE GUARD: the operator token would NOT survive a chain of only the external module
    // (its credential has no grp: shape — all-Pass denies). 409, and the operator still works.
    let r = put(
        "admintok",
        serde_json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "a chain that locks the caller out is refused"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "nothing changed on the refusal");

    // The SAME change made by a caller who survives it (a full group-mapped principal through
    // the external module) applies…
    let r = put(
        "grp:admins",
        serde_json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the surviving caller's change applies"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["applied"], true);

    // …after which the operator token no longer authenticates (it is not in the chain)…
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "the dropped module's credential stops working immediately"
    );

    // …and the surviving credential carries on.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "grp:admins")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // READ-AFTER-WRITE: GET /api/v1/admin/admin-auth reflects exactly what the PUT installed —
    // the write and read now name the SAME resource (previously PUT lived on /auth and GET
    // admin-auth reported a hard-coded module, so they could never agree).
    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "grp:admins")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["configured"], true);
    assert_eq!(
        body["modules"],
        serde_json::json!(["test-scope-module"]),
        "GET admin-auth mirrors the PUT'd chain verbatim"
    );

    handle.abort();
}

/// 1.5.3 LOCKED invariant for `PUT /api/v1/admin/admin-auth`: a locked (no-overlay) config REFUSES the
/// admin_auth chain mutation with `400`, matching the documented guarantee that "every config-mutating
/// admin call is refused" on a locked deployment. Without the guard this endpoint went straight to a
/// live swap, silently diverging the live auth posture from config.yaml until restart.
///
/// Without the `overlay_path.is_none()` refusal in `put_auth`, a valid chain applies (`200`) on a
/// locked config; the guard makes it a `400`.
#[tokio::test]
async fn test_admin_v1_put_auth_refused_on_locked_config() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // `.no_overlay()` = a LOCKED config (the only supported way to reach `overlay_path: None`).
    let app = TestApp::new().governance(gov).no_overlay().build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    // A chain the caller would survive — so ONLY the locked refusal can make this a 400.
    let resp = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"admin_auth": ["admin-tokens"]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a locked config must refuse PUT /admin-auth"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no writable config overlay"),
        "the refusal names the locked/no-overlay reason: {body}"
    );
    handle.abort();
}

/// 1.5.3 LOCKED invariant for `POST /api/v1/admin/config/apply`: a locked (no-overlay) config REFUSES a
/// full-config apply with `400`. This is the widest config-plane mutation, so a locked/GitOps
/// deployment must refuse it rather than swap an alternate config live until restart.
///
/// Without the `overlay_path.is_none()` refusal in `apply_config`, a valid body swaps live (`200`)
/// on a locked config; the guard makes it a `400`.
#[tokio::test]
async fn test_admin_v1_config_apply_refused_on_locked_config() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .no_overlay()
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "providers": {
            "test-provider": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1/", "api_key_env": "BUSBAR_TEST_LOCKED_APPLY_NO_KEY"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "providers": {"test-provider": {"api_key": {"env": "BUSBAR_TEST_LOCKED_APPLY_NO_KEY"}}},
            "models": {"m0": {"provider": "test-provider", "max_concurrent": 4}},
            "pools": {"p": {"members": [{"model": "m0"}]}}
        }
    });
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a locked config must refuse POST /config/apply"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no writable config overlay"),
        "the refusal names the locked/no-overlay reason: {body}"
    );
    handle.abort();
}

/// Idempotent mint + optimistic concurrency: a retried POST with the same Idempotency-Key
/// returns the FIRST response (same id + secret, no double-create); a PATCH with a stale
/// If-Match is a 409 that changes nothing; a fresh If-Match succeeds.
#[tokio::test]
async fn test_admin_v1_key_idempotent_mint_and_if_match() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Same Idempotency-Key twice → identical response, ONE key.
    let mint = |k: &'static str| {
        admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
            .header("idempotency-key", k)
            .body(serde_json::json!({"name": "idem"}).to_string())
            .send()
    };
    let a: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
    let b: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
    assert_eq!(a["id"], b["id"], "replay returns the same key");
    assert_eq!(
        a["token"], b["token"],
        "replay returns the FIRST response verbatim"
    );
    let listed: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/keys?prefix={}",
        a["id"].as_str().unwrap()
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        1,
        "no double-create: {listed}"
    );

    // If-Match: stale = 409 untouched; current etag = applied.
    let id = a["id"].as_str().unwrap();
    let got = admin(client.get(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .send()
        .await
        .unwrap();
    // ETag is header-only now — strip the surrounding quotes to feed back as If-Match.
    let etag = got
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .trim_matches('"')
        .to_string();
    let stale = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .header("if-match", "\"deadbeefdeadbeef\"")
        .body(serde_json::json!({"enabled": false}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");
    let fresh = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .header("if-match", format!("\"{etag}\""))
        .body(serde_json::json!({"enabled": false}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");

    handle.abort();
}

/// The idempotency RESERVATION frees itself on a FAILED mint: a POST that reserves an
/// Idempotency-Key then fails validation must NOT leave a stuck in-flight sentinel — a
/// subsequent valid retry under the SAME key mints normally (not a spurious 409/replay).
#[tokio::test]
async fn test_admin_v1_idempotency_reservation_frees_on_failure() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let post = |body: &'static str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "reuse-key")
            .body(body)
            .send()
    };

    // Reserve the key, then fail validation (unknown budget_period).
    let bad = post(r#"{"name": "x", "budget_period": "fortnightly"}"#)
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "invalid body is a 400");

    // The SAME key now mints normally — the reservation was cleared, not stuck in-flight.
    let good = post(r#"{"name": "x"}"#).await.unwrap();
    assert_eq!(
        good.status().as_u16(),
        201,
        "a valid retry under the same key mints (reservation freed on the prior failure)"
    );

    handle.abort();
}

/// A `Store` wrapper that PARKS the FIRST `put_key` on a rendezvous until the test explicitly
/// releases it, then runs at full speed. It stands in for a slow durable store's write round-trip,
/// but unlike a `sleep` it does not race a clock: it makes the window between "the mint has been
/// handed to the uncancellable blocking task" and "the mint actually lands" as wide as the test
/// needs and not one microsecond wider, and it tells the test EXACTLY when each edge is crossed.
///
/// WHY NOT A SLEEP. The predecessor slept 500ms here and the test raced a 100ms client timeout
/// against it. Both the client's timer and the server's whole request path live on the SAME
/// single-threaded `#[tokio::test]` runtime, so one OS-level deschedule of that single worker
/// thread longer than the client's budget makes tokio observe the timeout as expired BEFORE it ever
/// polls the server far enough to reach `put_key`. The client errors, `first.is_err()` is satisfied
/// for entirely the wrong reason, and NOTHING is ever minted -- so no amount of polling afterwards
/// can observe a write that never started. That is what failed on a contended Windows runner during
/// the 1.5.3 release while the identical SHA passed on the same job minutes earlier. Reproduced
/// locally by shrinking the client budget under heavy CPU oversubscription; it fails with precisely
/// the old "never landed" message. The repair is not a longer timeout, which only makes the same
/// race rarer and slower. It is to stop having a race at all.
///
/// THREE SIGNALS, no clocks in the happy path:
///   `entered` (store -> test)  the mint is INSIDE `put_key` and has not written yet.
///   `release` (test -> store)  the test is done arranging the disconnect; finish the write.
///   `landed`  (store -> test)  the write has committed.
///
/// `release` blocks a BLOCKING-POOL thread, never a runtime worker: `put_key` is only ever reached
/// from inside the mint's `spawn_blocking` closure. If that ever stopped being true this would
/// block a runtime worker instead, which is itself the invariant this test exists to defend.
///
/// The `recv_timeout` on `release` is a DEADLOCK BACKSTOP, not synchronisation. The mint holds the
/// process-wide `EXISTENCE_GATE` across this park, so a test that panicked between `entered` and
/// `release` would otherwise wedge every other key-mutating test in the binary forever. The backstop
/// turns that into a bounded, legible failure instead of a hung suite. Nothing in a passing run ever
/// waits on it.
struct GatedKeyStore {
    inner: Arc<dyn crate::governance::Store>,
    entered: tokio::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    landed: tokio::sync::mpsc::Sender<()>,
    fired: std::sync::atomic::AtomicBool,
}
impl crate::governance::Store for GatedKeyStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> crate::governance::StoreResult<()> {
        if self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return self.inner.put_key(key);
        }
        // FIRST `put_key` only: this is the mint the test wants to catch in flight.
        let _ = self.entered.try_send(());
        if let Some(rx) = self
            .release
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
        }
        let out = self.inner.put_key(key);
        let _ = self.landed.try_send(());
        out
    }
    fn get_key(&self, id: &str) -> crate::governance::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// A `Store` wrapper that sleeps on exactly the `slow_on_call`-th `put_key` invocation (0-indexed
/// across the wrapper's whole lifetime), full speed otherwise — used to slow a SPECIFIC write (e.g.
/// a rotate's, but not the mint's that precedes it) so a concurrent request can be landed
/// deterministically inside the slowed call's window.
struct SlowNthPutKeyStore {
    inner: Arc<dyn crate::governance::Store>,
    delay: std::time::Duration,
    calls: std::sync::atomic::AtomicUsize,
    slow_on_call: usize,
}
impl crate::governance::Store for SlowNthPutKeyStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> crate::governance::StoreResult<()> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == self.slow_on_call {
            std::thread::sleep(self.delay);
        }
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> crate::governance::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// The double-mint reachable when a client goes away mid-mint: the handler future is DROPPED
/// mid-`config_transaction` (a client disconnect, whether from a timeout, a ^C or a closed laptop),
/// but the mint keeps running to completion on the uncancellable blocking task and DOES write the
/// key. A retry with the same `Idempotency-Key` must see the reservation still held (not an empty
/// slot it can double-mint into).
///
/// FULLY DETERMINISTIC. Every ordering this test depends on is established by a rendezvous with
/// `GatedKeyStore` (see its doc comment for the wall-clock race this replaced), never by racing one
/// duration against another:
///   1. the mint is provably INSIDE `put_key` before the client is taken away,
///   2. the client is provably gone before the write is allowed to proceed,
///   3. the write has provably committed before the retry is issued.
/// Step 2 also lets the test ASSERT the write had not landed yet, which the timeout-racing version
/// could not do: it had no way to tell a disconnect mid-mint from a disconnect after one.
#[tokio::test]
async fn an_idempotency_key_survives_a_client_disconnect_mid_mint() {
    crate::metrics::init();
    let inner = Arc::new(MemoryStore::new());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (landed_tx, mut landed_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let gated_store: Arc<dyn crate::governance::Store> = Arc::new(GatedKeyStore {
        inner,
        entered: entered_tx,
        release: std::sync::Mutex::new(Some(release_rx)),
        landed: landed_tx,
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let gov = gov_with_signer(gated_store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let keys_url = format!("http://{addr}/api/v1/admin/keys");
    let post = |client: &reqwest::Client, url: &str| {
        client
            .post(url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "dc-1")
            .body(r#"{"name": "disconnector"}"#)
            .send()
    };
    let count_disconnector = |v: &serde_json::Value| -> usize {
        v["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|k| k["name"].as_str() == Some("disconnector"))
                    .count()
            })
            .unwrap_or(0)
    };

    // The request that will be abandoned. NO client timeout: the disconnect below is caused
    // deliberately, so nothing here depends on a clock.
    let doomed_url = keys_url.clone();
    let doomed = tokio::spawn(async move {
        let client = reqwest::Client::new();
        post(&client, &doomed_url).await
    });

    // RENDEZVOUS 1: the mint is inside the store's `put_key` and has not written yet.
    //
    // THE `timeout` IS A LIVENESS BACKSTOP, NOT THE SYNCHRONISATION. The ordering this test needs is
    // established by the rendezvous itself; the timeout only bounds how long a BROKEN harness may
    // hang. It has to be here: if the mint never reaches `put_key`, the sender is still alive (the
    // store outlives the test body), so `recv()` would block forever and the run would burn the CI
    // job's whole timeout while saying nothing at all. The bound is deliberately enormous relative
    // to the microseconds the happy path takes, so no amount of runner contention can reach it --
    // that asymmetry is exactly what the 500ms-sleep-versus-100ms-timeout version did not have.
    // Every backstop below states what it was waiting for and what it saw instead.
    const RENDEZVOUS_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::time::timeout(RENDEZVOUS_BACKSTOP, entered_rx.recv())
        .await
        .expect(
            "waited 60s for the mint to enter the store's put_key and it never did. The request \
             did not get as far as the blocking mint, so there is no mid-mint window to disconnect \
             inside and this test would be asserting nothing.",
        )
        .expect("the gated store was dropped before the mint entered put_key");

    // THE DISCONNECT. Dropping the in-flight request closes the connection, which is precisely what
    // a client-side timeout does to the server, minus the race. The handler future is dropped; the
    // already-scheduled `spawn_blocking` mint is not.
    doomed.abort();
    let joined = doomed.await;
    assert!(
        joined.as_ref().is_err_and(|e| e.is_cancelled()),
        "the doomed request must have been cancelled mid-flight; it instead completed, which means \
         the store gate did not hold the mint open and there was no mid-mint disconnect: {:?}",
        joined.map(|r| r.map(|resp| resp.status()))
    );

    // A full probe round trip: it forces the runtime to poll the server task (reaping the closed
    // connection) AND proves the write really has not landed yet, i.e. the disconnect above was
    // genuinely mid-mint rather than after it. Note this read does not take `EXISTENCE_GATE`, which
    // the parked mint is holding, so it cannot deadlock against it.
    let probe = reqwest::Client::new();
    let mid: serde_json::Value = probe
        .get(&keys_url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        count_disconnector(&mid),
        0,
        "the mint must still be parked in put_key at this point, so no key should exist yet; \
         found one already committed, so the disconnect was not mid-mint: {mid:?}"
    );

    // RENDEZVOUS 2 and 3: let the abandoned mint finish, and wait for it to actually commit.
    release_tx
        .send(())
        .expect("the parked mint hung up on its release channel");
    tokio::time::timeout(RENDEZVOUS_BACKSTOP, landed_rx.recv())
        .await
        .expect(
            "waited 60s after releasing the parked mint and its write never committed. A mint \
             whose client disconnected must still run to completion on the uncancellable blocking \
             task; observed instead: released, then silence.",
        )
        .expect("the gated store was dropped before the released mint could commit");

    // Retry with the SAME Idempotency-Key.
    let normal_client = reqwest::Client::new();
    let retry = post(&normal_client, &keys_url).await.unwrap();
    // Either outcome is correct under the fix: a 409 "already in flight" (if `dc-1`'s TTL window is
    // still open and the reservation was never cleared) or — since the mint already landed and the
    // cache slot may have been replaced by the real committed body before this retry runs — a replay
    // of that same committed response. What must NOT happen is a fresh 201 that mints a SECOND key.
    assert_ne!(
        retry.status().as_u16(),
        201,
        "a disconnect mid-mint must never let a retry mint a SECOND key"
    );

    let keys: serde_json::Value = normal_client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = keys["items"].as_array().unwrap();
    let disconnector_count = items
        .iter()
        .filter(|k| k["name"].as_str() == Some("disconnector"))
        .count();
    assert_eq!(
        disconnector_count, 1,
        "exactly one key must exist after a client disconnect mid-mint + retry, got: {items:?}"
    );

    handle.abort();
}

/// Key ROTATION: the new secret works, the old stops resolving, the id + settings are
/// unchanged; unknown ids 404. And keys pagination: limit/offset over the id-sorted set with a
/// stable total.
#[tokio::test]
async fn test_admin_v1_key_rotate_and_pagination() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov.clone()).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Mint three signed-token keys. The mint returns a `bbk_` token (not a bearer secret); we keep
    // only the id - pagination is over the id-sorted set, and rotation below mints its own secret.
    let mut ids = Vec::new();
    for n in ["ka", "kb", "kc"] {
        let created: serde_json::Value =
            admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
                .body(serde_json::json!({"name": n}).to_string())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert!(
            created["token"]
                .as_str()
                .is_some_and(|t| t.starts_with("bbk_")),
            "mint returns a signed token: {created}"
        );
        ids.push(created["id"].as_str().unwrap().to_string());
    }

    // Pagination (cursor envelope): page 1 with ?limit=2 yields 2 items + a next_cursor; feeding
    // that opaque cursor back yields the final item with next_cursor=null. Covers all three once.
    let p1: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/keys?limit=2")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(p1["items"].as_array().unwrap().len(), 2);
    let cursor = p1["next_cursor"]
        .as_str()
        .expect("more rows remain -> a next_cursor is present");
    let p2: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/keys?limit=2&cursor={cursor}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert!(
        p2["next_cursor"].is_null(),
        "last page has no next_cursor: {p2}"
    );
    let mut seen: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(p2["items"].as_array().unwrap())
        .map(|k| k["id"].as_str().unwrap().to_string())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "pages cover every key exactly once");

    // A malformed/foreign cursor is a 400 invalid_request (never a silent skip).
    let bad = admin(client.get(format!("http://{addr}/api/v1/admin/keys?cursor=notacursor")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        400,
        "foreign cursor is invalid_request"
    );
    assert_eq!(
        bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );

    // Rotate the first key: these are SIGNED-TOKEN bindings, so rotation re-mints the TOKEN at a
    // fresh binding generation (every prior token for the subject is now rejected) and keeps the id
    // stable. It must NOT hand back a legacy bearer secret — arming the hashed-secret path on a key
    // minted without one would add a second, weaker, non-expiring credential.
    let id = ids[0].clone();
    let rotated: serde_json::Value =
        admin(client.post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(rotated["id"], id.as_str(), "id is stable across rotation");
    let new_token = rotated["token"].as_str().unwrap().to_string();
    assert!(new_token.starts_with("bbk_"), "a re-minted signed token");
    assert!(
        rotated["secret"].is_null(),
        "rotation must not arm a legacy bearer secret on a signed-token key"
    );
    assert!(
        gov.verify_token(&new_token, crate::store::now(), None)
            .is_some(),
        "the re-minted token authenticates"
    );

    // Unknown id → 404.
    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/keys/vk_nope/rotate")))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

/// `rotate_key`'s idempotency cache sweeps stale entries by AGE (`now - t < IDEMPOTENCY_TTL_SECS`)
/// before consulting it. A same-key replay taken immediately after the first call has age ~0, so it
/// must survive the sweep and see the FIRST rotation's token again — not a fresh SECOND rotation. A
/// mutated `<` → `==` would evict every entry whose age isn't exactly the TTL, i.e. essentially all
/// of them, breaking replay entirely.
#[tokio::test]
async fn test_admin_v1_rotate_idempotent_replay_survives_the_ttl_sweep() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "r"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let rotate = |k: &'static str| {
        let (c, u, id) = (client.clone(), keys_url.clone(), id.clone());
        async move {
            c.post(format!("{u}/{id}/rotate"))
                .header("x-admin-token", "admintok")
                .header("idempotency-key", k)
                .send()
                .await
                .unwrap()
        }
    };

    let first: serde_json::Value = rotate("rot-replay").await.json().await.unwrap();
    let second: serde_json::Value = rotate("rot-replay").await.json().await.unwrap();
    // Assert a real, non-empty token BEFORE comparing the two — otherwise `first["token"] ==
    // second["token"]` passes vacuously if `token` were absent from both bodies (both index to
    // `Value::Null`), proving nothing about a real rotation having happened at all.
    assert!(
        first["token"].as_str().is_some_and(|t| !t.is_empty()),
        "rotate response must carry a real, non-empty token: {first}"
    );
    assert_eq!(
        first["token"], second["token"],
        "an immediate same-key replay must return the FIRST rotation's token verbatim, not \
         re-rotate a second time"
    );

    handle.abort();
}

/// `rotate_key`'s idempotency match guard (`if !cached.is_null()`) distinguishes a COMPLETED cached
/// response from an IN-FLIGHT reservation (the `Null` sentinel). A concurrent request under the SAME
/// Idempotency-Key while the first rotation is still landing must be refused as "already in flight"
/// (409) — never treated as a completed replay, which a mutated guard (`true`) would do, handing
/// back a bogus `200` whose body is the raw `null` sentinel instead of a real rotated key.
#[tokio::test]
async fn test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete() {
    crate::metrics::init();
    let inner = Arc::new(MemoryStore::new());
    // Slow the SECOND `put_key` call (the rotate's write) so a concurrent second request lands
    // while the first rotation is still in flight; the mint's own `put_key` (the first call) stays
    // fast so key creation itself isn't delayed.
    let slow_store: Arc<dyn crate::governance::Store> = Arc::new(SlowNthPutKeyStore {
        inner,
        delay: std::time::Duration::from_millis(500),
        calls: std::sync::atomic::AtomicUsize::new(0),
        slow_on_call: 1,
    });
    let gov = gov_with_signer(slow_store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "r"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let rotate_url = format!("{keys_url}/{id}/rotate");

    // Fire the reserving rotation on a background task — its `put_key` sleeps 500ms.
    let first_client = client.clone();
    let first_url = rotate_url.clone();
    let first = tokio::spawn(async move {
        first_client
            .post(&first_url)
            .header("x-admin-token", "admintok")
            .header("idempotency-key", "rot-inflight")
            .send()
            .await
            .unwrap()
    });
    // Give the handler time to insert the reservation and reach the slow blocking write (well
    // before its 500ms sleep completes).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // A concurrent request under the SAME key must see the in-flight sentinel, not a replay.
    let second = client
        .post(&rotate_url)
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "rot-inflight")
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status().as_u16(),
        409,
        "a concurrent same-key rotate while the first is still landing must be refused as \
         already-in-flight, not replayed as a completed response: {}",
        second.text().await.unwrap_or_default()
    );

    let first = first.await.unwrap();
    assert_eq!(
        first.status().as_u16(),
        200,
        "the reserving (first) rotation itself must still succeed"
    );

    handle.abort();
}

/// `PUT /api/v1/admin/hooks/{name}`: replaces an overlay hook live; 404 for an unknown name;
/// 409 for a grant change (immutability) and for a stale If-Match.
#[tokio::test]
async fn test_admin_v1_put_hook_replaces_live_with_guards() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // PUT on an unknown name is 404 (PUT replaces; POST creates).
    let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
        .body(serde_json::json!({"config": {"kind": "tap", "plugin": "test-hook"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    // Create, then replace with a new transport target (same grants) — 200, live.
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "rep",
                "config": {"kind": "tap", "plugin": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(serde_json::json!({"config": {"kind": "tap", "plugin": "test-hook-v2"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status().as_u16(), 200);
    let got: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("test-hook-v2"),
        "the replacement is live: {got}"
    );

    // Grant change via PUT is a 409 (immutability holds on the replace path too).
    let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(
            serde_json::json!({"config": {"kind": "gate", "plugin": "test-hook", "prompt": "rw"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

    // Stale If-Match is a 409 conflict (concurrency rides the header).
    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "plugin": "test-hook"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

    // The current ETag (from the GET above / the PUT response) applies cleanly: read it live.
    let live = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap();
    let etag = live
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("config-plane reads emit the ETag")
        .to_string();
    let fresh = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", etag)
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "plugin": "test-hook"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");
    assert!(
        fresh.headers().get(reqwest::header::ETAG).is_some(),
        "the mutation response carries the NEW ETag for chaining"
    );

    handle.abort();
}

/// The config version-history cycle: mutations record attributed versions; diff explains a
/// change; rollback restores a prior hook surface LIVE as a NEW version; unknown targets 404
/// and a stale If-Match conflicts.
#[tokio::test]
async fn test_admin_v1_config_versions_rollback_and_diff() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    // v1: register a hook. v2: delete it. (Boot floor is v0.)
    let body = serde_json::json!({
        "name": "rbk",
        "config": {"kind": "tap", "plugin": "test-hook"}
    });
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // The history lists boot + register + delete, newest first, attributed.
    let versions: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let list = versions["items"].as_array().unwrap();
    assert_eq!(list.len(), 3, "boot + register + delete: {versions}");
    assert_eq!(list[0]["version"], 2);
    assert!(list[0]["summary"]
        .as_str()
        .unwrap()
        .contains("hook.delete hook:rbk"));
    assert_eq!(list[0]["principal"], "admin");

    // Diff v1 -> v2: the hook was removed.
    let diff: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/config/diff?from=1&to=2"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(diff["hooks"]["removed"][0], "rbk", "{diff}");

    // Rollback to v1 restores the hook, LIVE, as a NEW version (append-only history).
    let rb = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(rb.status().as_u16(), 200);
    let rb_body: serde_json::Value = rb.json().await.unwrap();
    assert_eq!(rb_body["restored_version"], 1);
    assert_eq!(rb_body["config_version"], 3); // the post-rollback version, under the uniform name
    let restored = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        restored.status().as_u16(),
        200,
        "the rolled-back hook is live again"
    );

    // Guard rails: unknown target = 404; stale If-Match = 409.
    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 999}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .header("if-match", "\"0\"")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_register_hook_takes_effect_live() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Before: no hooks.
    let before: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 0);

    // Register a global gate at runtime.
    let body = serde_json::json!({
        "name": "compress",
        "config": {
            "kind": "gate",
            "plugin": "test-hook",
            "prompt": "rw",
            "global": true
        }
    });
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "hook registered");
    let created_body: serde_json::Value = created.json().await.unwrap();
    assert_eq!(created_body["name"], "compress");
    assert_eq!(created_body["kind"], "gate");
    assert_eq!(created_body["global"], true);

    // After: the hook is LIVE — a fresh read sees it (swap took effect + reads-current).
    let after: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = after["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "the registered hook is now in the live config"
    );
    assert_eq!(items[0]["name"], "compress");

    // The config version bumped from 0 → 1 on the apply (drift-detection primitive).
    let info: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        info["config_version"], 1,
        "one apply bumped the config version"
    );

    // GET one by name also sees it.
    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    // A RESERVED name (an on_error terminal / built-in) rejects on the register path too —
    // previously only boot validation checked this, so a runtime hook named `reject` could
    // shadow the terminal and make every consumer's on_error parse ambiguous.
    for reserved in ["reject", "weighted", "nothing", "cheapest", "admin-tokens"] {
        let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": reserved,
                    "config": {"kind": "gate", "plugin": "test-hook"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            shadow.status().as_u16(),
            400,
            "hook name `{reserved}` is reserved and must reject"
        );
        assert_eq!(
            shadow.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );
    }

    // Invalid definition (prompt:rw on a tap) → 400 invalid_request, no mutation.
    let bad = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "bad",
                "config": {"kind": "tap", "plugin": "test-hook", "prompt": "rw"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    assert_eq!(
        bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );

    // Grant immutability over the wire: re-registering "compress" (a prompt:rw gate) with a
    // DIFFERENT grant (prompt:ro) → 409 conflict, no mutation. Same grants would be idempotent.
    let escalate = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "compress",
                "config": {"kind": "gate", "plugin": "test-hook", "prompt": "ro"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        escalate.status().as_u16(),
        409,
        "grant change must conflict"
    );
    assert_eq!(
        escalate.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "conflict"
    );

    handle.abort();
}

/// `GET /api/v1/admin/audit` records admin mutations: registering a hook appears in the audit log as
/// `hook.register` / `applied`, with the resource named. (The audit ring is process-global, so
/// other concurrent tests may add entries — assert the specific action appears, not an exact count.)
#[tokio::test]
async fn test_admin_v1_audit_records_mutations() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // A uniquely-named hook so the audit assertion can't collide with a concurrent test.
    let name = "audit_probe_hook_x7";
    client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": name,
                "config": {"kind": "tap", "plugin": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = audit["items"].as_array().unwrap();
    let mine = entries
        .iter()
        .find(|e| e["resource"] == format!("hook:{name}"))
        .expect("the registration is recorded in the audit log");
    assert_eq!(mine["action"], "hook.register");
    assert_eq!(mine["outcome"], "applied");
    assert!(mine["seq"].is_number() && mine["ts"].is_number());

    // Filter by resource: only this hook's entries come back.
    let filtered: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let f = filtered["items"].as_array().unwrap();
    assert!(!f.is_empty());
    assert!(
        f.iter().all(|e| e["resource"] == format!("hook:{name}")),
        "the resource filter returns only matching entries"
    );

    // Filter by a non-matching action → empty.
    let none: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}&action=key.create"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    handle.abort();
}

/// The UNKNOWN-NAME 404 on `PUT /hooks/{name}` and
/// `PATCH /hooks/{name}/settings` must be AUDITED (like DELETE's 404) — an unaudited 404 lets a
/// principal probe which hook names exist by response code alone, with no trail.
#[tokio::test]
async fn test_admin_v1_hook_mutation_404_is_audited() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Two uniquely-named, NEVER-registered hooks so the audit assertions can't collide.
    let put_name = "ghost_put_hook_q3";
    let patch_name = "ghost_patch_hook_q3";

    let put_resp = client
        .put(format!("http://{addr}/api/v1/admin/hooks/{put_name}"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"config": {"kind": "tap", "plugin": "test-hook"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 404, "PUT on an unknown hook is a 404");

    let patch_resp = client
        .patch(format!(
            "http://{addr}/api/v1/admin/hooks/{patch_name}/settings"
        ))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"settings": {"k": "v"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        patch_resp.status(),
        404,
        "PATCH on an unknown hook is a 404"
    );

    // Both 404s must appear in the audit log as REJECTED, resource-named.
    for (name, action) in [(put_name, "hook.replace"), (patch_name, "hook.settings")] {
        let filtered: serde_json::Value = client
            .get(format!(
                "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let entry = filtered["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["resource"] == format!("hook:{name}"))
            .unwrap_or_else(|| panic!("the {action} 404 must be recorded in the audit log"));
        assert_eq!(entry["action"], action);
        assert_eq!(
            entry["outcome"], "rejected",
            "the unknown-name 404 is a rejected mutation, audited"
        );
    }

    handle.abort();
}

/// `GET /api/v1/admin/keys` supports `?prefix=` and `?enabled=` filters: a full-id prefix
/// returns just that key; a non-matching prefix returns none; `?enabled=true` includes a fresh key.
#[tokio::test]
async fn test_admin_v1_list_keys_filters() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (minted, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "filter-probe".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |query: String| {
        let url = format!("http://{addr}/api/v1/admin/keys{query}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    // Prefix = the full id → exactly this key.
    let by_prefix = get(format!("?prefix={}", minted.id)).await;
    let keys = by_prefix["items"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], minted.id);

    // Non-matching prefix → none.
    let none = get("?prefix=vk_does_not_exist".into()).await;
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    // enabled=true includes the fresh (enabled) key.
    let enabled = get("?enabled=true".into()).await;
    assert!(enabled["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["id"] == minted.id));

    handle.abort();
}

/// `GET /api/v1/admin/keys?group=<name>`: exact bound-group filter — returns the keys BOUND
/// to that group and nothing else (not another group's, not a groupless key). A name no group
/// registry carries is a valid EMPTY 200, never a 400/404 — deliberately no existence check, so a
/// key whose group another node's config dropped stays findable (that dangling state is exactly
/// what an operator hunts). Composes with `?enabled=`.
#[tokio::test]
async fn test_admin_v1_list_keys_group_filter() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mint = |name: &str, group: Option<&str>| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                allowed_pools: None,
                group: group.map(String::from),
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap()
        .0
    };
    // No registry existence check applies at the store seam either: these groups exist nowhere.
    let alpha = mint("alpha-key", Some("alpha"));
    let _beta = mint("beta-key", Some("beta"));
    let _loose = mint("groupless-key", None);
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let get = |query: String| {
        let url = format!("http://{addr}/api/v1/admin/keys{query}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    // ?group=alpha → exactly the alpha-bound key.
    let by_group = get("?group=alpha".into()).await;
    let items = by_group["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the alpha-bound key: {by_group}");
    assert_eq!(items[0]["id"], alpha.id);
    assert_eq!(items[0]["group"], "alpha");

    // A group NO key is bound to (and no registry carries) → 200 with an empty page.
    let ghost = client
        .get(format!("http://{addr}/api/v1/admin/keys?group=ghost"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        ghost.status().as_u16(),
        200,
        "a nonexistent group filter is a valid empty read, not an error"
    );
    let ghost: serde_json::Value = ghost.json().await.unwrap();
    assert_eq!(ghost["items"].as_array().unwrap().len(), 0);

    // Composes with ?enabled=: disable the alpha key, then split it out by state.
    let patched = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", alpha.id))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "disable the alpha key");
    let on = get("?group=alpha&enabled=true".into()).await;
    assert_eq!(
        on["items"].as_array().unwrap().len(),
        0,
        "the (disabled) alpha key drops out of enabled=true: {on}"
    );
    let off = get("?group=alpha&enabled=false".into()).await;
    let off_items = off["items"].as_array().unwrap();
    assert_eq!(off_items.len(), 1, "and shows under enabled=false: {off}");
    assert_eq!(off_items[0]["id"], alpha.id);

    handle.abort();
}

/// GOLDEN PATH: the whole config plane working together in one flow — register → live + version
/// bump + audit + persist → delete → gone + version bump + audit. A coherent-flow regression anchor
/// for the marquee feature (catches integration breaks the per-feature tests miss).
#[tokio::test]
async fn test_admin_v1_config_plane_golden_path() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("t".to_string()));
    let overlay = std::env::temp_dir().join(format!(
        "busbar-golden-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let c = reqwest::Client::new();
    let base = format!("http://{addr}");
    let get = |p: String| {
        let (c, url) = (c.clone(), format!("{base}{p}"));
        async move {
            c.get(url)
                .header("x-admin-token", "t")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };
    let name = "golden_gate";

    // Baseline: no hooks, version 0, persistence on.
    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let info0 = get("/api/v1/admin/info".into()).await;
    assert_eq!(info0["config_version"], 0);
    assert_eq!(info0["config_persistence"], true);

    // Register.
    let created = c
        .post(format!("{base}/api/v1/admin/hooks"))
        .header("x-admin-token", "t")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": name, "config":
                    {"kind": "gate", "plugin": "test-hook", "global": true}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // Live (read sees it), version bumped, persisted to disk.
    assert!(get("/api/v1/admin/hooks".into()).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == name));
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 1);
    assert_eq!(get("/api/v1/admin/config".into()).await["version"], 1);
    assert!(crate::config::overlay::read(&overlay)
        .unwrap()
        .hooks
        .contains_key(name));
    // Audit records it.
    assert!(
        get(format!("/api/v1/admin/audit?resource=hook:{name}")).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "hook.register" && e["outcome"] == "applied")
    );

    // Delete.
    let deleted = c
        .delete(format!("{base}/api/v1/admin/hooks/{name}"))
        .header("x-admin-token", "t")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // Gone, version bumped again, persisted removal.
    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 2);
    assert!(!crate::config::overlay::read(&overlay)
        .unwrap()
        .hooks
        .contains_key(name));

    let _ = std::fs::remove_file(&overlay);
    handle.abort();
}

/// Config-overlay PERSISTENCE: with an overlay path set, registering a hook over the API writes it
/// to the overlay file, and merging that overlay onto a fresh base config (a "restart") restores
/// the hook — so a runtime-registered hook survives a restart.
#[tokio::test]
async fn test_admin_v1_hook_register_persists_to_overlay() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = std::env::temp_dir().join(format!(
        "busbar-persist-test-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Register a global gate — the handler persists it to the overlay file.
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "persisted_gate",
                "config": {"kind": "gate", "plugin": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // The overlay file now holds the hook.
    let doc = crate::config::overlay::read(&overlay).expect("overlay written");
    assert!(doc.hooks.contains_key("persisted_gate"));
    assert!(doc.global_hooks.iter().any(|g| g == "persisted_gate"));

    // "Restart": merge the overlay onto a fresh RESOLVED base config → the hook is restored.
    let fresh_deploy: crate::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    let mut fresh = crate::config::resolve(&fresh_deploy, &std::collections::HashMap::new())
        .expect("minimal config resolves");
    crate::config::overlay::merge_into(&mut fresh, doc);
    assert!(
        fresh.hooks.contains_key("persisted_gate"),
        "the runtime-registered hook survives a restart via the overlay"
    );

    let _ = std::fs::remove_file(&overlay);
    handle.abort();
}

/// `POST /config/apply` layers the applied body UNDER the persisted overlay, as every other
/// rebuild path does. Apply was the sole exception while still carrying `overlay_path` forward, so
/// it kept writing an overlay it refused to read: an API-created group vanished from the live
/// registry immediately — every key bound to it fails closed at admission from that instant — and
/// the next unrelated group mutation then persisted the truncated registry over the file.
#[tokio::test]
async fn test_admin_v1_config_apply_preserves_the_persisted_overlay() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = std::env::temp_dir().join(format!(
        "busbar-apply-overlay-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let create_group = |name: &'static str| {
        let c = client.clone();
        async move {
            c.post(format!("http://{addr}/api/v1/admin/groups"))
                .header("x-admin-token", "admintok")
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "name": name,
                        "config": {"limits": [{"requests": 10, "per": "minute"}]}
                    })
                    .to_string(),
                )
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(create_group("api_team").await, 201);

    // Apply a config that does not mention `api_team`. A DeployCfg body has no way to express an
    // API-created group, so omitting one is not an instruction to delete it.
    let applied = client
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"config": {"providers": {}, "models": {}}}).to_string())
        .send()
        .await
        .unwrap();
    let st = applied.status().as_u16();
    let body = applied.text().await.unwrap_or_default();
    assert_eq!(st, 200, "the apply itself succeeds: {body}");

    // LIVE: still there, so a key bound to it still admits.
    let got = client
        .get(format!("http://{addr}/api/v1/admin/groups/api_team"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.status().as_u16(),
        200,
        "an API-created group survives an apply that does not name it"
    );

    // ON DISK: a later, unrelated mutation must not clobber it out of the overlay.
    assert_eq!(create_group("second_team").await, 201);
    let doc = crate::config::overlay::read(&overlay).expect("overlay still readable");
    assert!(
        doc.groups.contains_key("api_team"),
        "the next group write must not erase the earlier one from the overlay"
    );
    assert!(
        doc.groups.contains_key("second_team"),
        "and records the new one"
    );

    let _ = std::fs::remove_file(&overlay);
    handle.abort();
}

/// Key mutations are audited too: minting a key records
/// `key.create` / `applied` with the new key's id.
#[tokio::test]
async fn test_admin_v1_audit_records_key_mutations() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Mint a uniquely-named key.
    let minted: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "audit_key_probe_z3"}).to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = minted["id"].as_str().unwrap().to_string();

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mine = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["resource"] == format!("key:{id}"))
        .expect("the key creation is recorded in the audit log");
    assert_eq!(mine["action"], "key.create");
    assert_eq!(mine["outcome"], "applied");

    handle.abort();
}

/// Base-config hooks are READ-ONLY across every mutation verb — not even a `full` admin may
/// shadow/redirect (POST) or remove (DELETE) an operator's file-defined hook (e.g. a `pii-guard`
/// gate); edit config.yaml. PUT/PATCH already guarded; this pins POST + DELETE to the same 409,
/// matching the guard other verbs enforce.
#[tokio::test]
async fn test_admin_v1_base_hook_is_read_only_via_api() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "plugin": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = TestApp::new()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // POST a same-shape definition over the base hook's name → 409 (no silent transport redirect).
    let shadow = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "pii-guard",
                "config": {"kind": "gate", "plugin": "test-hook", "prompt": "no", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        shadow.status().as_u16(),
        409,
        "POST cannot shadow a base hook"
    );

    // DELETE the base hook → 409 (cannot remove an operator's base security gate via the API).
    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        409,
        "DELETE cannot remove a base hook"
    );

    // It is still present and unchanged.
    let got: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("test-hook"),
        "base hook untouched: {got}"
    );
}

/// `DELETE` on a base-config hook must return the TERMINAL `conflict` code even when the caller's
/// `If-Match` is also stale — the base-hook guard must outrank the retryable staleness check
/// (matching `put_hook`/`delete_group`'s precedence), not the other way around. Both errors are
/// HTTP 409, so the assertion MUST be on the frozen `code` field — a status-only check false-passes
/// both before and after this fix.
#[tokio::test]
async fn base_hook_delete_conflict_outranks_a_stale_if_match() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "plugin": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = TestApp::new()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .header("if-match", "\"999\"")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 409);
    let body: serde_json::Value = del.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], "conflict",
        "the terminal base-hook conflict must win over the retryable version_conflict: {body}"
    );
}

/// `DELETE /api/v1/admin/hooks/{name}` removes a hook at runtime (live): register → delete (204) →
/// GET /hooks/{name} 404. Deleting an unregistered hook is 404.
#[tokio::test]
async fn test_admin_v1_delete_hook_takes_effect_live() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let tok = ("x-admin-token", "admintok");

    // Register a global tap.
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header(tok.0, tok.1)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "logger",
                "config": {"kind": "tap", "plugin": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // Delete an absent hook → 404.
    let absent = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status().as_u16(), 404);

    // Delete the registered hook → 204, and it's gone live.
    let deleted = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let after = client
        .get(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the hook is gone from the live config"
    );

    handle.abort();
}

/// The hooks read surface (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`) projects the
/// registry definitions (kind/transport/grants/global), 404s an unknown name, and never leaks a
/// secret. Built on a fixture with one global gate.
#[tokio::test]
async fn test_admin_v1_hooks_read_surface() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 25,
        on_error: "reject".to_string(),
        prompt: crate::config::PromptAccess::Rw,
        user: crate::config::UserAccess::Ro,
        priority: 7,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = TestApp::new()
        .governance(gov)
        .hook("compress", gate)
        .global_hook("compress")
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // List: the one hook, projected.
    let list = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let h = &items[0];
    assert_eq!(h["name"], "compress");
    assert_eq!(h["kind"], "gate");
    assert_eq!(h["prompt"], "rw");
    assert_eq!(h["user"], "ro");
    assert_eq!(h["priority"], 7);
    assert_eq!(h["on_error"], "reject");
    assert_eq!(h["transport"]["kind"], "plugin");
    assert_eq!(h["transport"]["target"], "test-hook");
    assert_eq!(
        h["global"], true,
        "named in global_hooks → reported as globally wired"
    );

    // Get one by name.
    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    // Unknown name → 404 with the stable v1 `not_found` code.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let body: serde_json::Value = missing.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");

    handle.abort();
}

/// `GET /api/v1/admin/hooks/{name}/health` best-effort probes a hook's transport: 404 for an unknown
/// name; a webhook hook reports `reachable: null` (probed on demand); a socket hook pointing at a
/// nonexistent path reports `reachable: false`. Never fires the hook.
#[tokio::test]
async fn test_admin_v1_hook_health_best_effort() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mk = |plugin: &str| crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = TestApp::new()
        .governance(gov)
        .hook("web", mk("web-hook-plugin"))
        .hook("sock", mk("sock-hook-plugin"))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |name: &str| {
        let url = format!("http://{addr}/api/v1/admin/hooks/{name}/health");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
        }
    };

    // Unknown → 404 not_found.
    let missing = get("nope").await;
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    // A hook whose `kind: hook` plugin is not installed in the (empty test) registry → reachable
    // false with a "not installed" detail. Both hooks reference plugins now (the retired
    // socket/webhook transports are gone).
    let web: serde_json::Value = get("web").await.json().await.unwrap();
    assert_eq!(web["name"], "web");
    assert_eq!(web["transport"]["kind"], "plugin");
    assert_eq!(
        web["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );

    let sock: serde_json::Value = get("sock").await.json().await.unwrap();
    assert_eq!(sock["transport"]["kind"], "plugin");
    assert_eq!(
        sock["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );

    handle.abort();
}

/// The plugin catalog (`GET /api/v1/admin/plugins?type=`) lists compiled-in plugins per type (the
/// same feature-gated source as `info`) plus external hooks from the registry, and rejects an
/// unknown/absent type with the stable `invalid_request` code.
#[tokio::test]
async fn test_admin_v1_plugins_catalog_by_type() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = TestApp::new().governance(gov).hook("myhook", gate).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let get = |q: &str| {
        let url = format!("http://{addr}/api/v1/admin/plugins?type={q}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
        }
    };

    // auth: `keys` (engine-handled) is always listed; `admin-tokens` iff its feature is on.
    let auth: serde_json::Value = get("auth").await.json().await.unwrap();
    let a_items = auth["items"].as_array().unwrap();
    let keys = a_items
        .iter()
        .find(|p| p["name"] == "keys")
        .expect("the built-in keys verifier is always listed");
    assert_eq!(keys["loader"], "compiled-in");
    assert_eq!(keys["type"], "auth");
    let admin_tokens = a_items.iter().find(|p| p["name"] == "admin-tokens");
    assert_eq!(
        admin_tokens.is_some(),
        cfg!(feature = "auth-admin-tokens"),
        "admin-tokens listed iff compiled in"
    );
    if let Some(admin_tokens) = admin_tokens {
        assert_eq!(admin_tokens["loader"], "compiled-in");
        assert_eq!(admin_tokens["type"], "auth");
    }

    // hooks: the weighted floor is ALWAYS compiled-in; ranking iff the feature is on; plus the
    // external myhook.
    let hooks: serde_json::Value = get("hooks").await.json().await.unwrap();
    let h_items = hooks["items"].as_array().unwrap();
    assert!(h_items
        .iter()
        .any(|p| p["name"] == "weighted" && p["loader"] == "compiled-in"));
    assert_eq!(
        h_items.iter().any(|p| p["name"] == "ranking"),
        cfg!(feature = "hooks-ranking"),
        "ranking listed iff compiled in"
    );
    let ext = h_items
        .iter()
        .find(|p| p["name"] == "myhook")
        .expect("external hook listed");
    assert_eq!(ext["loader"], "external");
    assert_eq!(ext["active"], true);
    assert_eq!(ext["target"], "test-hook");

    // Unknown type → 400 invalid_request.
    let bad = get("nope").await;
    assert_eq!(bad.status().as_u16(), 400);
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    handle.abort();
}

/// `GET /api/v1/admin/auth` reports the ingress chain + upstream-credential mode, never a secret. A
/// governance-only fixture (no explicit auth chain) is the open front door.
#[tokio::test]
async fn test_admin_v1_auth_read() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body["chain"].is_array());
    assert_eq!(body["open"], true, "no explicit chain → open front door");
    assert_eq!(body["upstream_credentials"], "own");
    // Sanity: no secret-looking field leaked.
    assert!(body.get("client_tokens").is_none());

    handle.abort();
}

/// `POST /api/v1/admin/config/validate` dry-runs a proposed config: a malformed body is a 400
/// `invalid_request`; a well-formed body describing an INVALID config (here a provider reference
/// absent from the defs) returns 200 with `ok:false` and the resolution errors — never mutating.
#[tokio::test]
async fn test_admin_v1_config_validate_dry_run() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/config/validate");

    // Malformed body → 400 invalid_request (the REQUEST is broken, not the config).
    let bad = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"config\": \"not-an-object\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    // Well-formed body, invalid config: deploy references provider "openai" but the defs are empty
    // → resolve fails with a dangling-provider error → 200 ok:false.
    let proposed = serde_json::json!({
        "config": {
            "providers": { "openai": { "api_key": { "env": "OPENAI_KEY" } } },
            "models": {}
        },
        "providers": {}
    });
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(proposed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["ok"], false, "config with a dangling provider is invalid");
    let errors = v["errors"].as_array().unwrap();
    assert!(!errors.is_empty(), "invalid config must report errors");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap_or("").contains("openai")),
        "the dangling provider is named in an error: {errors:?}"
    );

    // THE CLI-PARITY CASE. A config the `--validate` CLI REJECTS must not come back `ok: true`
    // here. This one resolves and passes `config_validate` cleanly -- the defect is only reachable
    // in the post-resolve pre-flight: a `secrets:` entry naming a module that resolves to no
    // installed `kind: secret` plugin. The endpoint used to stop after
    // `config_validate` and answer `ok: true`, so an operator could dry-run a config green and then
    // watch boot fail on exactly this.
    let proposed = serde_json::json!({
        "config": {
            "secrets": { "acme-vault": { "settings": {} } },
            "providers": {},
            "models": {}
        },
        "providers": {}
    });
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(proposed.to_string())
        .send()
        .await
        .unwrap();
    let st = resp.status().as_u16();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        v["ok"], false,
        "a secret module the CLI cannot resolve must not validate green here: {v}"
    );
    assert!(
        v["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e.as_str().unwrap_or("").contains("acme-vault")),
        "the unresolvable secret module is named: {v}"
    );

    handle.abort();
}

/// `GET /api/v1/admin/config` composes the effective-config snapshot (auth + pools/models/providers +
/// hooks + global_hooks) from the redacted reads. Asserts the shape and that no secret-bearing
/// field (client tokens, provider keys) appears anywhere in the serialized body.
#[tokio::test]
async fn test_admin_v1_config_effective_snapshot_no_secrets() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "m",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov"),
        )
        .pool("p", &[(0, 1)])
        .hook("g", gate)
        .global_hook("g")
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/config"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    // Composed sections present.
    assert_eq!(body["version"], 0, "fresh config is version 0");
    assert!(body["auth"]["chain"].is_array());
    assert!(body["pools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "p"));
    assert!(body["models"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["model"] == "m"));
    assert!(body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["provider"] == "prov"));
    assert!(body["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == "g"));
    assert!(body["global_hooks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "g"));
    // No secret-bearing key names anywhere in the snapshot.
    for needle in ["admintok", "client_tokens", "api_key", "secret"] {
        assert!(
            !text.contains(needle),
            "effective config must not leak `{needle}`: {text}"
        );
    }

    handle.abort();
}

/// `GET /api/v1/admin/openapi.json` returns a valid OpenAPI 3.1 doc, and — the DRIFT GUARD — every GET
/// path it documents (from V1_GET_PATHS) actually resolves on the live router (never a phantom
/// endpoint in the discovery contract). Also asserts the stable error `code` enum is present.
#[tokio::test]
async fn test_admin_v1_openapi_paths_all_resolve() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let doc: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/openapi.json"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Busbar Admin API");
    // The stable error code enum is documented.
    let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]
        ["enum"]
        .as_array()
        .unwrap();
    assert!(codes.iter().any(|c| c == "not_found"));

    // The runtime hook mutation methods are documented in the discovery contract.
    assert!(
        doc["paths"]["/api/v1/admin/hooks"]["post"].is_object(),
        "POST /api/v1/admin/hooks (register) must be in the openapi doc"
    );
    assert!(
        doc["paths"]["/api/v1/admin/hooks/{name}"]["delete"].is_object(),
        "DELETE /api/v1/admin/hooks/{{name}} (remove) must be in the openapi doc"
    );

    // DRIFT GUARD: every documented GET path is both listed in the doc AND actually mounted.
    // V1_GET_PATHS entries are RELATIVE; the wire path derives from the contract prefix (whose
    // literal value is pinned by its own golden test in contract.rs).
    for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
        let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
        assert!(
            doc["paths"][&path]["get"].is_object(),
            "documented path {path} missing from openapi doc"
        );
        let status = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status();
        assert_ne!(
            status.as_u16(),
            404,
            "openapi documents {path} but the router does not mount it (phantom endpoint)"
        );
    }

    handle.abort();
}

/// SECURITY CONTRACT: every documented `/api/v1/admin` GET endpoint rejects a MISSING token and a
/// WRONG token with 401 — the whole surface is admin-guarded, no read leaks without the credential.
/// Iterates the same V1_GET_PATHS the openapi doc + drift guard use, so a newly-added endpoint is
/// automatically covered.
#[tokio::test]
async fn test_admin_v1_all_reads_require_admin_token() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
        let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
        // No token → 401, in the FROZEN v1 envelope (code `unauthorized`) — the most frequent
        // error a tooling consumer hits must branch on the same code seam as every other
        // (previously a protocol-shaped body).
        let none = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            none.status().as_u16(),
            401,
            "{path} must reject a request with NO admin token"
        );
        let body: serde_json::Value = none.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "unauthorized",
            "{path}: the admin 401 speaks the v1 envelope: {body}"
        );
        // Wrong token → 401.
        let wrong = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "not-the-token")
            .send()
            .await
            .unwrap();
        assert_eq!(
            wrong.status().as_u16(),
            401,
            "{path} must reject a request with the WRONG admin token"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_key_with_aws_credential_returns_secret_once_and_hides_on_reads() {
    // Minting with `issue_aws_credential: true` returns the AccessKeyId AND the secret access key
    // ONCE at creation; neither the AWS secret nor the generation_hash is ever returned by a later read.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "bedrock-key", "issue_aws_credential": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let body: serde_json::Value = created.json().await.unwrap();
    let akid = body["aws_access_key_id"].as_str().unwrap().to_string();
    let aws_secret = body["aws_secret_access_key"].as_str().unwrap().to_string();
    assert!(akid.starts_with("AKIA"), "akid shape: {akid}");
    assert_eq!(aws_secret.len(), 40, "aws secret is 40 chars");
    assert!(
        body["token"]
            .as_str()
            .is_some_and(|t| t.starts_with("bbk_")),
        "the signed token is returned once too"
    );

    // A plain mint (no flag) carries NO AWS fields.
    let plain: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "plain"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        plain["aws_secret_access_key"].is_null() && plain["aws_access_key_id"].is_null(),
        "a bearer-only key must not carry AWS fields: {plain}"
    );

    // The list endpoint must NEVER expose the AWS secret (nor generation_hash).
    let listed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed_str = listed.to_string();
    assert!(
        !listed_str.contains(&aws_secret),
        "the AWS secret access key must NEVER appear in a read response: {listed_str}"
    );
    for k in listed["items"].as_array().unwrap() {
        assert!(
            k["aws_secret_access_key"].is_null(),
            "list must not leak the AWS secret"
        );
        assert!(
            k["generation_hash"].is_null(),
            "list must not leak generation_hash"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_list_usage_roundtrip_through_spawn_blocking() {
    // Exercises the create_key / list_keys / key_usage handlers end-to-end after they were moved
    // onto spawn_blocking: a slow store call must not block a Tokio worker, and the offloaded
    // handlers must still return the same responses (no secret/hash leak; usage resolves).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // create
    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let body: serde_json::Value = created.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();
    assert!(
        body["token"]
            .as_str()
            .is_some_and(|t| t.starts_with("bbk_")),
        "signed token returned once on create"
    );
    assert!(
        body["generation_hash"].is_null(),
        "generation_hash must never be exposed"
    );

    // list
    let listed = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status().as_u16(), 200);
    let lb: serde_json::Value = listed.json().await.unwrap();
    assert_eq!(lb["items"].as_array().unwrap().len(), 1);
    assert!(
        lb["items"][0]["secret"].is_null(),
        "list must not leak secrets"
    );

    // usage - a 1.5.0 signed-token key carries NO inline rate caps (all enforcement flows through
    // the bound group), so `rate_headroom` is always null on the key-usage read. (The capped-key
    // headroom path can no longer be reached via mint; it is covered directly in the governance
    // unit tests over `rate_headroom`.)
    let usage = client
        .get(format!("http://{addr}/api/v1/admin/keys/{id}/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(usage.status().as_u16(), 200);
    let ub: serde_json::Value = usage.json().await.unwrap();
    assert_eq!(ub["id"], id);
    assert!(
        ub["rate_headroom"].is_null(),
        "an inline-cap-free key has no headroom signal: {ub}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_removed_budget_period_field() {
    // 1.5.0: keys are PURE AUTH - `budget_period` is GONE from the mint body, and the mint
    // struct is `#[serde(deny_unknown_fields)]`, so a body carrying the removed field is a loud 400
    // (invalid_request), never silently accepted. The premise of the old test (a typo'd period
    // degrading to `total`) no longer exists: there is no period on a key at all.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // A body naming the removed `budget_period` field is rejected by deny_unknown_fields - EVEN a
    // once-valid value like "total" (there is no such mint field to accept it).
    for removed in ["total", "daily", "weekly", ""] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "budget_period": removed}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the removed budget_period field must 400 via deny_unknown_fields (value '{removed}')"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum
            "400 error code must be invalid_request: {body}"
        );
    }

    // A body WITHOUT the removed field still mints, and the response carries no `budget_period`.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("budget_period").is_none() || body["budget_period"].is_null(),
        "the key surface no longer carries budget_period: {body}"
    );

    handle.abort();
}

/// SCRAPE BREAK: mint-time labels are echoed VERBATIM as Prometheus label names on this
/// key's metric series. A RESERVED label name (key/bucket/model/tier), a non-conforming label name,
/// an oversized map (> 16), or an over-long name/value must be rejected with 400 (never minted) so
/// the whole /metrics exposition can't be broken by one key. A well-formed label set still mints.
#[tokio::test]
async fn test_create_key_rejects_unsafe_labels() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let post = |labels: serde_json::Value| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", "labels": labels}))
                .send()
                .await
                .unwrap()
        }
    };

    // A `key` label (reserved) => 400.
    let resp = post(serde_json::json!({"key": "oops"})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a reserved 'key' label must be rejected"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("reserved"),
        "400 body must name the reserved-label reason: {body}"
    );

    // Each other reserved name is equally rejected.
    for reserved in ["bucket", "model", "tier"] {
        let resp = post(serde_json::json!({ reserved: "x" })).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "reserved label '{reserved}' must be rejected"
        );
    }

    // 100 labels => over the cap => 400.
    let mut many = serde_json::Map::new();
    for i in 0..100 {
        many.insert(format!("l{i}"), serde_json::json!("v"));
    }
    let resp = post(serde_json::Value::Object(many)).await;
    assert_eq!(resp.status().as_u16(), 400, "100 labels must be rejected");
    assert!(
        resp.json::<serde_json::Value>().await.unwrap()["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("too many labels"),
    );

    // A label name that is not a valid Prometheus label name => 400.
    let resp = post(serde_json::json!({"team-name": "growth"})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an invalid label name (hyphen) must be rejected"
    );
    // A name that leads with a digit is also invalid.
    let resp = post(serde_json::json!({"1team": "growth"})).await;
    assert_eq!(resp.status().as_u16(), 400, "leading-digit name rejected");

    // An over-long label value => 400.
    let resp = post(serde_json::json!({"team": "x".repeat(257)})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an over-long label value must be rejected"
    );

    // A well-formed label set still mints (201) and round-trips.
    let resp = post(serde_json::json!({"team": "growth", "env": "prod"})).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "a valid label set must still mint"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["labels"]["team"], "growth");
    assert_eq!(body["labels"]["env"], "prod");

    handle.abort();
}

/// The mint's `name` length bound is exact: a name of exactly `MAX_KEY_NAME_LEN` (256) chars mints
/// fine; one char past it is rejected. A mutated `>` → `==`/`>=` would either reject the boundary
/// length itself or admit names arbitrarily longer than the documented cap.
#[tokio::test]
async fn test_create_key_name_length_boundary_is_exact() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let post = |name: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name}))
                .send()
                .await
                .unwrap()
        }
    };

    let at_max = "n".repeat(256);
    let resp = post(at_max).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "a name of exactly 256 chars must mint"
    );

    let over_max = "n".repeat(257);
    let resp = post(over_max).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a name of 257 chars must be rejected"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("256 characters"),
        "the 400 body must name the length reason: {body}"
    );

    handle.abort();
}

/// No raw parse errors, no secret leak: a malformed admin create/update body must produce a
/// GENERIC 400 whose body contains NEITHER serde error prose NOR any fragment of the offending
/// input. The create-key body carries SECRETS (an AWS secret_access_key, the bearer being minted),
/// so axum's stock `Json<T>` rejection — which echoes the raw serde `Display` — must NOT be used.
#[tokio::test]
async fn test_admin_malformed_body_returns_generic_400_no_input_fragment() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // A SECRET-bearing fragment that must NEVER be echoed back in the error body.
    let secret_fragment = "SUPER_SECRET_AWS_KEY_abc123";
    let malformed = format!(r#"{{"name": "k", "secret_access_key": "{secret_fragment}" "#);

    for path in ["/api/v1/admin/keys", "/api/v1/admin/keys/some-id"] {
        let req = if path == "/api/v1/admin/keys" {
            client.post(format!("http://{addr}{path}"))
        } else {
            client.patch(format!("http://{addr}{path}"))
        };
        let resp = req
            .header("x-admin-token", "admintok")
            .header("content-type", crate::proxy::APPLICATION_JSON)
            .body(malformed.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "malformed body on {path} must be 400"
        );
        let text = resp.text().await.unwrap();
        assert!(
            !text.contains(secret_fragment),
            "the 400 body on {path} must NOT echo any input fragment; got {text}"
        );
        // The generic envelope only — no serde prose (e.g. "expected", "column", "EOF").
        assert!(
            !text.contains("expected")
                && !text.contains("column")
                && !text.contains("EOF")
                && !text.contains("line"),
            "the 400 body on {path} must NOT contain serde error text; got {text}"
        );
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            body["error"]["message"], "invalid JSON",
            "the 400 body on {path} must be the generic envelope; got {text}"
        );
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum
            "the 400 error code must be invalid_request; got {text}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_removed_max_budget_cents_field() {
    // 1.5.0: keys carry NO inline caps - `max_budget_cents` is REMOVED from the mint body, and
    // the mint struct is `#[serde(deny_unknown_fields)]`. The old test's premise (a negative cap
    // slipping past serde into a silent over-budget DoS) is gone: the field no longer exists on the
    // key surface, so ANY body carrying it - negative, zero, or positive - is a loud 400.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for value in [-1_i64, 0, 100_000] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "max_budget_cents": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the removed max_budget_cents field must 400 via deny_unknown_fields (value {value})"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "invalid_request",
            "400 error code must be invalid_request: {body}"
        );
    }

    // A pure-auth body (no removed field) still mints, and the response carries no max_budget_cents.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("max_budget_cents").is_none() || body["max_budget_cents"].is_null(),
        "the key surface no longer carries max_budget_cents: {body}"
    );

    handle.abort();
}

#[tokio::test]
async fn test_patch_key_enables_disables_and_validates_at_create_parity() {
    // PATCH /admin/keys/:id can disable a key (without DELETE destroying its history) and
    // adjust caps; it is admin-gated and rejects the same invalid values create() does.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin/keys");

    // Create a key to operate on.
    let created: serde_json::Value = client
        .post(&base)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let key_url = format!("{base}/{id}");

    // Admin gate: PATCH without the admin token is rejected by the middleware (not 200).
    let no_tok = client
        .patch(&key_url)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_ne!(no_tok.status().as_u16(), 200, "PATCH must be admin-gated");

    // Disable the key → 200, enabled=false.
    let disabled = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status().as_u16(), 200);
    let body: serde_json::Value = disabled.json().await.unwrap();
    assert_eq!(body["enabled"], false, "key is disabled: {body}");

    // Create-parity validation: negative budget and zero rate caps are 400 via PATCH too.
    for bad in [
        serde_json::json!({"max_budget_cents": -1}),
        serde_json::json!({"rpm_limit": 0}),
        serde_json::json!({"tpm_limit": 0}),
    ] {
        let r = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "PATCH must reject {bad} with 400");
    }

    // PATCH a non-existent key → 404.
    let missing = client
        .patch(format!("{base}/vk_nope"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_removed_rate_limit_fields() {
    // 1.5.0: `rpm_limit`/`tpm_limit` are REMOVED from the mint body (keys carry no inline caps;
    // enforcement flows through the bound group), and the mint struct is
    // `#[serde(deny_unknown_fields)]`. The old test's premise (a `0` limit slipping past serde into
    // a permanently-dead key) is gone: ANY body naming these fields is a loud 400.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for field in ["rpm_limit", "tpm_limit"] {
        for value in [0, 5] {
            let resp = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "k", field: value}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "the removed {field} field must 400 via deny_unknown_fields (value {value})"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body["error"]["code"], "invalid_request",
                "400 error code must be invalid_request: {body}"
            );
        }
    }

    // A pure-auth body (no removed fields) still mints, carrying no rate caps on the surface.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("rpm_limit").is_none() || body["rpm_limit"].is_null(),
        "the key surface no longer carries rpm_limit: {body}"
    );
    assert!(
        body.get("tpm_limit").is_none() || body["tpm_limit"].is_null(),
        "the key surface no longer carries tpm_limit: {body}"
    );

    handle.abort();
}

#[tokio::test]
async fn test_patch_key_three_state_group_and_enabled() {
    // PATCH /keys/{id} is AUTH-SHAPED in 1.5.0: `{enabled?, group??}`. `group` is three-state
    // (absent = unchanged, `null` = unbind to unlimited, a value = rebind with mint-parity
    // existence validation). The removed 1.4.x cap fields (rpm_limit/tpm_limit/max_budget_cents)
    // are UNKNOWN fields now and must 400 - PATCH cannot be a back door to a limit surface that
    // no longer exists (limits live on groups).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // The rebind target must EXIST: give the App a cost model carrying group "eng".
    let groups = std::collections::BTreeMap::from([(
        "eng".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Requests,
                amount: 100,
                per: Some(crate::config::groups::LimitWindow::Minute),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    // Seed BOTH the cost model and the groups_registry from one tree (the production invariant): the
    // rebind existence check now reads `groups_registry` — the authoritative registry the group
    // DELETE guard also uses — so cost and registry must AGREE, exactly as every real config apply
    // keeps them (`groups_tree` does this; a bare `.cost(...)` left the registry empty).
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .groups_tree(groups)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin/keys");

    // Mint a pure-auth key (no group).
    let created: serde_json::Value = client
        .post(&base)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["enabled"], true, "a fresh key is enabled");
    assert!(created["group"].is_null(), "minted without a group");
    let key_url = format!("{base}/{id}");

    // SET (a present value): rebind to an existing group; the response surfaces the binding.
    let set: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"group": "eng"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        set["group"], "eng",
        "rebind surfaces the new binding: {set}"
    );

    // A rebind to a MISSING group is a 400 (mint parity: no dangling binding via PATCH).
    let dangling = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"group": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        dangling.status().as_u16(),
        400,
        "a rebind target must exist (mint parity)"
    );

    // CLEAR (present null): unbind back to authed + unlimited. Absent leaves it unchanged.
    let cleared: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"group": null}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(cleared["group"].is_null(), "null unbinds: {cleared}");
    let toggled: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(toggled["enabled"], false, "enabled toggles");
    assert!(
        toggled["group"].is_null(),
        "an absent group field leaves the (unbound) binding unchanged"
    );

    // The removed 1.4.x cap fields are UNKNOWN and 400 loudly (no silent no-op back door).
    for gone in [
        serde_json::json!({"rpm_limit": 5}),
        serde_json::json!({"tpm_limit": 99}),
        serde_json::json!({"max_budget_cents": 123}),
    ] {
        let r = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&gone)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            400,
            "a removed cap field must fail loudly: {gone}"
        );
    }

    handle.abort();
}
#[test]
fn test_create_key_warns_on_unconfigured_allowed_pool() {
    // Create_key accepted `allowed_pools` with NO ingress
    // diagnostic, unlike its sibling validations. An entry naming no configured pool must NOT be
    // a 400 (minting a key before its pool exists is a supported forward-reference workflow), but
    // it MUST surface a NON-FATAL `tracing::warn!` so a typo (`"smrt"` for `"smart"`) is visible.
    // Against the old code (no warn) the unknown-pool assertion FAILS; it passes once the
    // diagnostic is emitted. We also assert the key is still created (201) and that a configured
    // pool produces NO warning (no false positive on the legitimate path).
    //
    // The diagnostic fires synchronously in the handler BEFORE the `spawn_blocking().await`, so a
    // thread-local subscriber (`with_default`) on a current-thread runtime captures it — we call
    // the handler directly rather than through the HTTP server (whose task would run on a
    // different thread, out of the subscriber's reach).
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // App has exactly one configured pool, "smart" (lane 0). "smrt" is the typo'd sibling.
    let app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:0",
        ))
        .pool("smart", &[(0, 1)])
        .governance(gov)
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let (unknown_status, known_status) = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            // Request 1: references "smart" (configured, OK) AND "smrt" (typo, no such pool).
            let body1 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-typo",
                    "allowed_pools": ["smart", "smrt"]
                })
                .to_string(),
            );
            let handle = std::sync::Arc::new(crate::state::AppHandle::new(app.clone()));
            let r1 = super::create_key(
                axum::extract::State(handle.clone()),
                axum::Extension(crate::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body1,
            )
            .await;
            let s1 = r1.status().as_u16();

            // Request 2: references ONLY the configured pool — no warning expected.
            let body2 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-ok",
                    "allowed_pools": ["smart"]
                })
                .to_string(),
            );
            let r2 = super::create_key(
                axum::extract::State(handle),
                axum::Extension(crate::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body2,
            )
            .await;
            let s2 = r2.status().as_u16();
            (s1, s2)
        })
    });

    // Both keys are still created — the diagnostic is non-fatal (forward-reference preserved).
    assert_eq!(
        unknown_status, 201,
        "an unconfigured allowed_pool must NOT 400 — the key is still minted"
    );
    assert_eq!(
        known_status, 201,
        "a configured allowed_pool creates the key"
    );

    let msgs = cap.messages();
    // Exactly one warning, naming the typo'd pool — "smart" (configured) must NOT warn.
    let pool_warns: Vec<&String> = msgs
        .iter()
        .filter(|m| m.contains("allowed_pools entry names no configured pool"))
        .collect();
    assert_eq!(
        pool_warns.len(),
        1,
        "exactly one allowed_pools diagnostic expected (only the typo'd entry): {msgs:?}"
    );
    assert!(
        pool_warns[0].contains("smrt"),
        "the warning must name the typo'd pool 'smrt': {:?}",
        pool_warns[0]
    );
    assert!(
        !pool_warns[0].contains("smart\""),
        "the configured pool 'smart' must NOT be reported as unconfigured: {:?}",
        pool_warns[0]
    );
}

#[tokio::test]
async fn test_delete_existing_key_returns_200() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();

    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        204,
        "existing key deletes with 204 No Content"
    );
    handle.abort();
}

#[tokio::test]
async fn test_delete_missing_key_returns_404() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/vk_does_not_exist"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a non-existent key must 404, not a spurious 200"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["message"], "key not found");
    assert_eq!(body["error"]["code"], "not_found"); // frozen v1 envelope: keys speak the SAME code enum
    handle.abort();
}

/// A `Store` wrapper that counts calls to `list_keys` (the O(n) full table scan) and `get_key`
/// (the O(1) single-row lookup) separately, delegating everything else to an inner `MemoryStore`.
/// Used to prove the single-key admin read/write paths resolve one key via `get_key`, not by
/// scanning the whole table and filtering by id.
struct CountingStore {
    inner: MemoryStore,
    list_keys_calls: std::sync::atomic::AtomicUsize,
    get_key_calls: std::sync::atomic::AtomicUsize,
}
impl CountingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            list_keys_calls: std::sync::atomic::AtomicUsize::new(0),
            get_key_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn reset(&self) {
        self.list_keys_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.get_key_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }
}
impl crate::governance::Store for CountingStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> crate::governance::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> crate::governance::StoreResult<Option<busbar_api::VirtualKey>> {
        self.get_key_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.list_keys_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> crate::governance::StoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> crate::governance::StoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

/// GET /keys/{id}, GET /keys/{id}/usage and POST /keys/{id}/revoke are pure single-key reads (no
/// cache refresh follows them), so a fixed handler must resolve the key via exactly one
/// `Store::get_key` call and never fall back to `Store::list_keys` (a full table scan) to find it.
/// Before the O(1) fix each of these called `gov.all_keys()` (→ `list_keys`) and filtered for the
/// id by hand.
#[tokio::test]
async fn test_single_key_reads_use_get_key_not_list_keys() {
    crate::metrics::init();
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (key_b, _) = gov
        .create_key(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (key_c, _) = gov
        .create_key(
            NewKeySpec {
                name: "c".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    store.reset();
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}} must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}} must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/admin/keys/{}/usage",
            key_b.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}}/usage must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}}/usage must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .post(format!(
            "http://{addr}/api/v1/admin/keys/{}/revoke",
            key_c.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "POST /keys/{{id}}/revoke must not scan the whole table to check existence"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "POST /keys/{{id}}/revoke must resolve the key via Store::get_key"
    );
    handle.abort();
}

/// PATCH /keys/{id} and DELETE /keys/{id} both refresh the in-memory cache (one legitimate
/// `list_keys` call) after a successful mutation, so they cannot be zero — but the pre-fix code
/// called `list_keys` a SECOND time (via `gov.all_keys().find(...)`) just to locate the row before
/// mutating it. A fixed handler resolves that existence/If-Match read via `Store::get_key`, so only
/// the one unavoidable refresh-driven `list_keys` call remains.
#[tokio::test]
async fn test_single_key_writes_use_get_key_for_their_existence_check() {
    crate::metrics::init();
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (key_b, _) = gov
        .create_key(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    store.reset();
    let resp = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "PATCH /keys/{{id}} must call list_keys only once, for the post-write cache refresh — \
         not a second time to locate the row"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "PATCH /keys/{{id}} must resolve the pre-image via Store::get_key"
    );

    store.reset();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key_b.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "DELETE /keys/{{id}} must call list_keys only once, for the post-write cache refresh — \
         not a second time to locate the row"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "DELETE /keys/{{id}} must resolve the pre-image via Store::get_key"
    );
    handle.abort();
}

#[tokio::test]
async fn test_delete_key_is_not_idempotent_204() {
    // After a successful delete, a second delete of the same id must 404 (proves the 204 was a
    // real revocation, not a no-op masquerading as success).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let first = client
        .delete(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 204);
    let second = client
        .delete(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 404, "second delete must 404");
    handle.abort();
}

#[tokio::test]
async fn test_concurrent_delete_returns_exactly_one_204() {
    // Two concurrent DELETEs of the SAME id must not
    // both observe the key and both return 204 (which would imply two revocations of one row in
    // an audit trail). The delete handler serializes its lookup→delete critical section, so the
    // winner returns 204 and every loser returns 404. Fire a burst and assert exactly one 204.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Launch several DELETEs concurrently against the single freshly-created key.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            client
                .delete(&url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut ok = 0;
    let mut not_found = 0;
    for t in tasks {
        match t.await.unwrap() {
            204 => ok += 1,
            404 => not_found += 1,
            other => panic!("unexpected status {other} from concurrent delete"),
        }
    }
    assert_eq!(
        ok, 1,
        "exactly one concurrent delete must report a 204 revocation"
    );
    assert_eq!(
        not_found, 7,
        "every losing concurrent delete must report 404"
    );
    handle.abort();
}

#[tokio::test]
async fn test_patch_after_delete_404s_and_does_not_recreate_key() {
    // A PATCH must never RESURRECT a key a DELETE removed. The
    // store's `update_key` is a check-then-act (`get_key` → `put_key`, where `put_key` UPSERTs and
    // so re-INSERTs a missing row). Serializing `update_key`'s lookup→put behind the same gate as
    // DELETE closes the window. This sequential case (DELETE fully precedes PATCH) proves the base
    // contract: PATCH on a deleted key 404s and leaves it deleted (a later GET/usage stays 404).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Revoke the key.
    let del = client
        .delete(&key_url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "the key is revoked");

    // PATCH the now-deleted key → 404, and it must NOT recreate the row.
    let patched = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        patched.status().as_u16(),
        404,
        "PATCH on a deleted key must 404, not resurrect it"
    );

    // The key must still be gone: usage 404s and the list is empty.
    let usage = client
        .get(format!("{key_url}/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        usage.status().as_u16(),
        404,
        "the revoked key must remain absent after the PATCH"
    );
    let listed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "PATCH must not have re-inserted the deleted key: {listed}"
    );
    handle.abort();
}

/// A `Store` decorator that can pause inside `put_key` to force the exact PATCH/DELETE
/// interleaving the resurrection race needs — something a black-box HTTP burst cannot do
/// deterministically (the window between `update_key`'s `get_key` and `put_key` is microscopic).
/// All methods delegate to an inner `MemoryStore`; only `put_key` is instrumented, and only once
/// armed (so the create-time `put_key` during setup is unaffected).
///
/// When armed, the FIRST subsequent `put_key` (the PATCH's) signals `entered` and then BLOCKS on
/// `release` until the test lets it proceed. This pins the PATCH between its existence check and
/// its write, so the test can run a DELETE in that gap and observe whether the gate prevents the
/// PATCH from re-inserting (resurrecting) the just-revoked row.
struct BarrierStore {
    inner: MemoryStore,
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl crate::governance::Store for BarrierStore {
    fn put_key(&self, key: &crate::governance::VirtualKey) -> crate::governance::StoreResult<()> {
        // Disarm atomically so only the first put after arming pauses (and never the setup put).
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.entered.send(());
            // Block this blocking-pool thread until the test releases us, AFTER it has run a DELETE.
            let _ = self.release.lock().unwrap().recv();
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<crate::governance::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    // Forward the denylist (1.5.0): DELETE revokes-then-deletes, so a store double that did not
    // forward add_denylist would make revoke error and abort the delete (the default trait no-op
    // errors) - breaking the resurrection-race tests. Forward to the inner MemoryStore.
    fn add_denylist(&self, sub: &str, reason: &str) -> crate::governance::StoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> crate::governance::StoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_patch_interleaved_with_delete_never_resurrects_key() {
    // A PATCH
    // that has already read an extant key, then is overtaken by a DELETE that revokes it, must NOT
    // have its `put_key` re-INSERT (resurrect) the row. `BarrierStore` forces the interleaving
    // deterministically: the PATCH's `put_key` pauses between the existence check and the write
    // while the DELETE runs. Holding `EXISTENCE_GATE` across lookup→put is what makes the DELETE
    // run strictly after the PATCH's put, so the row is removed last and ends up ABSENT.
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    // PATCH in the background — it will read the key, then block inside put_key.
    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Wait until the PATCH is parked inside put_key (between its check and its write).
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    // DELETE in the background. Old code: it completes now. Fixed code: it blocks on EXISTENCE_GATE.
    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Give the DELETE a moment to either complete (old) or wedge on the gate (fixed), then release
    // the paused PATCH so both can finish.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = patch_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    // DECISIVE: regardless of the order the two requests reported, the revoked key must be GONE.
    // A resurrecting PATCH (old code) leaves it PRESENT here.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

/// `rotate_key` is a check-then-act (get_key → mint →
/// put_key over the UPSERT), so — exactly like update_key/delete_key — it must hold
/// EXISTENCE_GATE across lookup→write. Without it a DELETE that revokes the key between rotate's
/// read and its `put_key` is clobbered by the put, RESURRECTING the revoked key with a fresh
/// (attacker-usable) secret. Same deterministic `BarrierStore` interleaving as the PATCH test.
#[tokio::test]
async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;

    // Arm the barrier so rotate's put_key (the next put) pauses between its check and its write.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let rotate_url = format!("http://{addr}/api/v1/admin/keys/{}/rotate", key.id);
    let rotate_task = tokio::spawn(async move {
        reqwest::Client::new()
            .post(&rotate_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Wait until rotate is parked inside put_key.
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("ROTATE must reach the instrumented put_key");

    let delete_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = rotate_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    // DECISIVE: the revoked key must be GONE. A resurrecting rotate (ungated) leaves it PRESENT.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "rotate must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

#[test]
fn test_existence_gate_is_std_sync_mutex_lockable_without_runtime() {
    // The gate MUST be a
    // `std::sync::Mutex<()>`, not a `tokio::sync::Mutex<()>`. The fix binds the gate's lifetime to
    // the SYNCHRONOUS store mutation by locking it INSIDE the `spawn_blocking` closure (which has no
    // async runtime in scope); a `tokio::sync::Mutex` cannot be locked there — its `.lock()` returns
    // a future. This test locks the gate from a PLAIN (non-async) thread with no Tokio runtime
    // present: that only compiles/runs for a `std::sync::Mutex`. Against the old `tokio::sync::Mutex`
    // this call would not typecheck as a blocking lock (and `into_inner` on poison is std-only), so
    // the gate-type regression is pinned. We assert the guarded unit value round-trips.
    let guard = super::EXISTENCE_GATE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // The guarded data is the unit type; dereferencing proves we hold a std MutexGuard<()>.
    let () = *guard;
    drop(guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
    // The R25 fix held
    // the gate across the cancellable outer `.await`. If the client dropped the request, the async
    // guard dropped — but the already-scheduled (uncancellable) `spawn_blocking` closure kept
    // running its lookup→write with the gate NO LONGER held, re-opening the resurrection /
    // double-revoke races. The R26 fix locks the gate INSIDE the blocking closure, so the gate is
    // held for the entire lookup→write regardless of any outer-future drop.
    //
    // We force the exact condition with `BarrierStore`: a PATCH parks inside `put_key` (between its
    // existence check and its write). We then DROP (cancel) the PATCH's driving future while it is
    // parked, and fire a DELETE. The DELETE must NOT be able to complete while the PATCH's blocking
    // mutation is still in flight:
    // - Old code (async guard owned by the dropped PATCH future): cancelling releases the gate, so
    // the DELETE acquires it and COMPLETES within the window -> this test's "DELETE still
    // pending" assertion FAILS.
    // - Fixed code (gate locked inside the still-running blocking closure): the DELETE blocks on
    // the gate until the PATCH's `put_key` finishes -> the DELETE is STILL PENDING in the
    // window -> this test PASSES. Releasing the barrier then lets both drain.
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    // PATCH in the background — it will read the key, acquire the gate inside the blocking closure,
    // then block inside put_key. We keep the JoinHandle so we can ABORT (cancel) it.
    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await;
    });

    // Wait until the PATCH is parked inside put_key (gate held by the blocking closure).
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    // CANCEL the PATCH: abort its driving future. The Tokio JoinHandle abort drops the async task;
    // in the old design this dropped the async existence guard. The blocking closure keeps running.
    patch_task.abort();
    let _ = patch_task.await; // joins the cancellation

    // Fire a DELETE. Old code: gate is free -> DELETE completes quickly. Fixed code: gate is still
    // held by the parked blocking closure -> DELETE blocks.
    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Poll (rather than one sample at a fixed delay) for the DELETE completing during the window:
    // a single late sample can MISS an early completion that happened and then quiesced before the
    // sample, which is a false-pass in exactly the direction load makes worse (more time between
    // dispatch and sample, not less). Polling for "never finished" over the whole window is
    // strictly stronger than one sample and no slower in the happy (still-blocked) case.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        assert!(
            !delete_task.is_finished(),
            "a cancelled PATCH must keep the EXISTENCE_GATE held for its full blocking mutation; \
             the DELETE must remain blocked on the gate (old async-guard code releases it on \
             cancel)"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Release the parked PATCH put_key so the gate frees and the DELETE can finish — proves no
    // deadlock and lets the task drain cleanly.
    release_tx.send(()).unwrap();
    let del_status = delete_task.await.unwrap();
    // The PATCH's put_key resurrected/updated the row (it ran to completion despite cancellation),
    // so the DELETE that follows under the gate observes it and revokes it: 204. (The point of this
    // test is the BLOCKING, not the final status — but it must be a coherent 204, not a 404.)
    assert_eq!(
        del_status, 204,
        "the DELETE runs after the gate frees and revokes the (now-present) key"
    );
    handle.abort();
}

// ── plugin admin endpoints, end-to-end over the live router ───────────────────────────────────────

/// Serve a router whose App points its plugin surface at `dir` (allow_unsigned posture, no
/// publishers), with a known admin token — for the install/list/remove/reload plugin endpoints.
async fn serve_with_plugins_dir(
    dir: std::path::PathBuf,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // The lifecycle test installs an UNSIGNED plugin tarball, so opt in to unsigned plugins (the
    // trust DEFAULT rejects unsigned artifacts). The trust-default behavior itself is covered by
    // the dedicated trust tests; this test is about the install/list/reload/remove lifecycle.
    let mut plugins_cfg = crate::config::PluginsCfg::default();
    plugins_cfg.trust.allow_unsigned = true;
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir)
        .plugins_cfg(plugins_cfg)
        .build();
    let (router, _handle) = crate::build_router_with_limits(
        app,
        256 * 1024 * 1024,
        0,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// As `serve_with_plugins_dir`, but with a caller-supplied `hook_env` — for tests that need the
/// live `hook_env.registry` (e.g. `GET /plugins/{name}/schema`) populated from the dir's actual
/// contents, since the plain `TestApp` builder defaults it to an empty registry regardless of
/// `plugins_dir` (that field only feeds the filesystem-scanning install/list/remove/reload paths).
async fn serve_with_plugins_dir_and_hook_env(
    dir: std::path::PathBuf,
    hook_env: crate::hooks::HookEnv,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut plugins_cfg = crate::config::PluginsCfg::default();
    plugins_cfg.trust.allow_unsigned = true;
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir)
        .plugins_cfg(plugins_cfg)
        .hook_env(hook_env)
        .build();
    let (router, _handle) = crate::build_router_with_limits(
        app,
        256 * 1024 * 1024,
        0,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// Build an UNSIGNED (structurally valid) plugin tarball in memory for the HTTP lifecycle tests.
fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    admin_test_tarball_versioned(name, alias, "1.0.0")
}

/// As `admin_test_tarball`, with an explicit version so a test can build two SAME-NAME tarballs that
/// differ only in version (and thus filename) - the same-name-different-file case.
fn admin_test_tarball_versioned(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} {version} (never dlopened)").into_bytes();
    let lib = lib.as_slice();
    let m = busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: version.into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// FULL LIFECYCLE over the wire: `POST /plugins` installs an (unsigned, allow_unsigned-posture)
/// plugin tarball → `GET /plugins?type=store` lists it as a dynamic-library row → `POST
/// /plugins/reload` reports it → `DELETE /plugins/{file}` removes it (204) → a second DELETE is
/// 404. Every mutation is admin-token guarded and audited; the uploaded code is never executed.
#[tokio::test]
async fn test_admin_v1_plugin_install_list_reload_remove() {
    use base64::Engine as _;
    crate::metrics::init();
    let tarball = admin_test_tarball("acme-store-junk", "junkstore");
    let file = "acme-store-junk.tar.gz";
    let dir =
        std::env::temp_dir().join(format!("busbar-admin-plugins-http-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // INSTALL — 201 with a trust verdict of "unverified" (unsigned under allow_unsigned).
    let body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
    });
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "install returns 201 Created");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["file"], file);
    assert_eq!(v["trust"], "unverified");
    assert_eq!(
        v["name"], "acme-store-junk",
        "identity from the signed manifest"
    );
    assert!(dir.join(file).exists(), "tarball published to disk");

    // A mutation WITHOUT the admin token is rejected (401) — the whole surface is guarded.
    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    // LIST — the store catalog reports the memory head + our dynamic plugin (ready).
    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items[0]["name"], "memory");
    let dyn_row = items
        .iter()
        .find(|p| p["loader"] == "dynamic-library")
        .expect("dynamic-library row present");
    assert_eq!(dyn_row["valid"], true);
    assert_eq!(dyn_row["target"], file);
    assert_eq!(dyn_row["name"], "acme-store-junk");

    // RELOAD — reports the reconciled dynamic set (no memory head).
    let reload: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reload["plugins"].as_array().unwrap().len(), 1);

    // REMOVE — 204, then a second remove is 404 in the frozen envelope.
    let del = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);
    assert!(!dir.join(file).exists(), "tarball removed from disk");

    let del2 = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del2.status().as_u16(), 404);
    let b: serde_json::Value = del2.json().await.unwrap();
    assert_eq!(b["error"]["code"], "not_found");

    // The install + remove both left audit rows (every mutation is audited).
    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"plugin.install"),
        "install audited: {actions:?}"
    );
    assert!(
        actions.contains(&"plugin.remove"),
        "remove audited: {actions:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// As `admin_test_tarball_versioned`, but for an arbitrary plugin `kind` (the `type=secret`
/// support / richer `auth` rows need a non-`store` fixture to test against).
fn admin_test_tarball_kind(name: &str, alias: &str, kind: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} (never dlopened)").into_bytes();
    let lib = lib.as_slice();
    let m = busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi(kind)
            .iter()
            .max()
            .unwrap_or(&1),
        sha256: busbar_plugin_sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// `GET /plugins?type=secret` lists `kind: secret` plugins ONLY — a `kind: store`
/// tarball dropped in the same directory does not leak into it, and vice versa (the pre-existing
/// scan used to be unfiltered by kind at all, so this also proves the fix rather than just the
/// addition). `type=secret` previously did not exist as an accepted value (400 `invalid_request`
/// before this change).
#[tokio::test]
async fn test_admin_v1_plugins_type_secret_lists_secret_kind_only() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-secret-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let install = |file: &'static str, tarball: Vec<u8>| {
        let client = client.clone();
        async move {
            let body = serde_json::json!({
                "file": file,
                "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
            });
            let resp = client
                .post(format!("http://{addr}/api/v1/admin/plugins"))
                .header("x-admin-token", "admintok")
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 201, "install must succeed");
        }
    };
    install(
        "acme-secret-vault.tar.gz",
        admin_test_tarball_kind("acme-secret-vault", "vault", "secret"),
    )
    .await;
    install(
        "acme-store-junk.tar.gz",
        admin_test_tarball_kind("acme-store-junk", "junkstore", "store"),
    )
    .await;

    let secret_list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=secret"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret_names: Vec<&str> = secret_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        secret_names,
        vec!["acme-secret-vault"],
        "type=secret lists ONLY the secret-kind plugin: {secret_list}"
    );
    for row in secret_list["items"].as_array().unwrap() {
        assert_eq!(row["type"], "secret");
    }

    let store_list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let store_names: Vec<&str> = store_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        store_names.contains(&"memory") && store_names.contains(&"acme-store-junk"),
        "type=store still lists the compiled-in default + the store plugin: {store_list}"
    );
    assert!(
        !store_names.contains(&"acme-secret-vault"),
        "type=store must NOT leak the secret-kind plugin: {store_list}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// `GET /plugins` list rows carry `schema_url`: a non-null, admin-prefixed RELATIVE path
/// whenever the manifest declared `settings_schema` at all — and
/// following it returns the SAME schema `GET /plugins/{name}/schema` would. A plugin with no
/// `settings_schema` gets `schema_url: null` (absence, not an empty string or omitted field).
#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_schema_url() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-schemaurl-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"url": {"type": "string"}},
    });
    let lib = b"junk lib bytes for acme-store-schemaurl".to_vec();
    let m = busbar_plugin_sign::Manifest {
        name: "acme-store-schemaurl".into(),
        alias: "schemaurl".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .unwrap(),
        sha256: busbar_plugin_sign::sha256_hex(&lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: Some(schema.to_string()),
        schema_derived: false,
        host: None,
    };
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", &lib).unwrap();
    // Write directly to disk (not via `POST /plugins`) so `hook_env.registry` — which the
    // per-plugin `GET /plugins/{name}/schema` endpoint resolves against, a SEPARATE path from the
    // directory-scanning list endpoint below — can be built from the same directory's real
    // contents up front (mirrors `test_admin_v1_plugin_schema_round_trips_from_manifest`, since the
    // plain `TestApp`/`serve_with_plugins_dir` builder otherwise defaults `hook_env` to an empty
    // registry regardless of `plugins_dir`).
    std::fs::write(dir.join("acme-store-schemaurl.tar.gz"), &tarball).unwrap();
    let policy = busbar_plugin_sign::TrustPolicy {
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).unwrap();
    let hook_env = crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "acme-store-schemaurl")
        .expect("the schema-carrying row is present");
    let schema_url = row["schema_url"].as_str().expect("schema_url is non-null");
    assert_eq!(
        schema_url, "/api/v1/admin/plugins/acme-store-schemaurl/schema",
        "always the admin-prefixed relative path — never absolute, never a catalog URL"
    );
    assert_eq!(row["schema_error"], serde_json::Value::Null);

    // Following it returns the same schema.
    let followed: serde_json::Value = client
        .get(format!("http://{addr}{schema_url}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(followed["schema"], schema);

    // The `memory` compiled-in row (no manifest at all) has `schema_url: null` — absence, not an
    // error, and distinct from "declared but unparseable".
    let memory_row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "memory")
        .expect("compiled-in memory row present");
    assert_eq!(memory_row["schema_url"], serde_json::Value::Null);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// `GET /plugins` list rows carry `file` (the artifact
/// filename — the exact string `DELETE /plugins/{file}` and `GET /plugins/{file}/schema` key off)
/// and `has_schema` (mirrors `schema_url.is_some()`, so a catalog can flag configurable rows
/// without a fetch per row). Covers a dynamic-library row WITH a schema, a dynamic-library row
/// WITHOUT one, and the compiled-in `memory` row (no backing artifact at all).
#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_file_and_has_schema() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-file-hasschema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"url": {"type": "string"}},
    });
    let lib_with = b"junk lib bytes for acme-store-filecheck-with".to_vec();
    let m_with = busbar_plugin_sign::Manifest {
        name: "acme-store-filecheck-with".into(),
        alias: "filecheckwith".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .unwrap(),
        sha256: busbar_plugin_sign::sha256_hex(&lib_with),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: Some(schema.to_string()),
        schema_derived: false,
        host: None,
    };
    let tarball_with =
        busbar_plugin_loader::tarball::package(&m_with, "lib.so", &lib_with).unwrap();
    // Deliberately different FILENAME than the manifest NAME, so a test that only checked `name`
    // could not accidentally pass — `file` must be the on-disk artifact filename.
    std::fs::write(
        dir.join("acme-store-filecheck-with-1.0.0.tar.gz"),
        &tarball_with,
    )
    .unwrap();

    let lib_without = b"junk lib bytes for acme-store-filecheck-without".to_vec();
    let m_without = busbar_plugin_sign::Manifest {
        name: "acme-store-filecheck-without".into(),
        alias: "filecheckwithout".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .unwrap(),
        sha256: busbar_plugin_sign::sha256_hex(&lib_without),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let tarball_without =
        busbar_plugin_loader::tarball::package(&m_without, "lib.so", &lib_without).unwrap();
    std::fs::write(
        dir.join("acme-store-filecheck-without-1.0.0.tar.gz"),
        &tarball_without,
    )
    .unwrap();

    let policy = busbar_plugin_sign::TrustPolicy {
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).unwrap();
    let hook_env = crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();

    let with_row = items
        .iter()
        .find(|p| p["name"] == "acme-store-filecheck-with")
        .expect("the schema-carrying row is present");
    assert_eq!(
        with_row["file"], "acme-store-filecheck-with-1.0.0.tar.gz",
        "`file` is the on-disk artifact filename, not the manifest name"
    );
    assert_eq!(with_row["has_schema"], true);
    assert!(
        with_row["schema_url"].is_string(),
        "sanity: has_schema tracks schema_url"
    );

    // Round-trip: `file` is exactly what `DELETE /plugins/{file}` and `GET /plugins/{file}/schema`
    // take.
    let file = with_row["file"].as_str().unwrap();
    let schema_resp: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/plugins/{}/schema",
            with_row["name"].as_str().unwrap()
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(schema_resp["schema"], schema);
    let delete_status = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        delete_status, 204,
        "`file` from the list row is a valid DELETE key"
    );

    let without_row = items
        .iter()
        .find(|p| p["name"] == "acme-store-filecheck-without")
        .expect("the schema-less row is present");
    assert_eq!(
        without_row["file"], "acme-store-filecheck-without-1.0.0.tar.gz",
        "`file` is populated even when the manifest has no schema"
    );
    assert_eq!(without_row["has_schema"], false);
    assert_eq!(without_row["schema_url"], serde_json::Value::Null);

    let memory_row = items
        .iter()
        .find(|p| p["name"] == "memory")
        .expect("compiled-in memory row present");
    assert_eq!(
        memory_row["file"],
        serde_json::Value::Null,
        "no backing artifact for a compiled-in row"
    );
    assert_eq!(memory_row["has_schema"], false);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

// ── POST /plugins/inspect ──────────────────────────────────────────────────────────────────────

/// Over the wire: a candidate tarball previews cleanly, NEVER lands on disk, and never appears in
/// `GET /plugins?type=store` afterward — inspect is genuinely stateless, not "install with extra
/// steps".
#[tokio::test]
async fn test_admin_v1_plugins_inspect_previews_without_installing() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-inspect-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let tarball = admin_test_tarball("acme-store-candidate", "candidate");
    let body = serde_json::json!({
        "file": "candidate.tar.gz",
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
    });
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["name"], "acme-store-candidate");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["kind"], "store");
    assert_eq!(v["source"], "manifest");
    assert_eq!(v["trust"], "unverified");

    // NOTHING was written — a subsequent list shows no such plugin, and the directory is empty.
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "inspect must never write to plugins.dir"
    );
    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "acme-store-candidate"),
        "an inspected candidate must not appear in the catalog: {list}"
    );

    // A read-only-scoped token (no `full`/`mint`/`hooks-register`) can still call it — `read-only`
    // scope, not a mutation scope (docs/admin-api.md).
    // (This server's operator token already holds `full`, which trivially satisfies `read-only` —
    // the scope MATRIX assignment itself is asserted structurally in contract::mod.rs's own tests;
    // this test's job is the wire behavior, not re-deriving the scope lattice.)

    // Malformed body (bad base64) is a 400, never a panic/500.
    let bad = serde_json::json!({"file": "x.tar.gz", "tarball_b64": "not-base64!!"});
    let bad_resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_resp.status().as_u16(), 400);
    let bad_body: serde_json::Value = bad_resp.json().await.unwrap();
    assert_eq!(bad_body["error"]["code"], "invalid_request");

    // Malformed JSON body entirely is also a 400.
    let malformed_resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed_resp.status().as_u16(), 400);

    // No admin token at all → 401, same as every other admin endpoint.
    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// The manifest-embedded `settings_schema` round-trips over the
/// wire: install a tarball whose SIGNED manifest carries a JSON Schema document, then `GET
/// /plugins/{file}/schema` returns it as real parsed JSON (not a JSON string containing JSON). A
/// plugin installed WITHOUT a `settings_schema` reports `"schema": null` rather than 404/erroring —
/// absence is a valid, common state (most plugins today have none), not a fault.
#[tokio::test]
async fn test_admin_v1_plugin_schema_round_trips_from_manifest() {
    crate::metrics::init();
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "url": {"type": "string", "x-busbar-secret": true},
        },
        "required": ["url"],
    });
    let lib = b"junk library bytes for acme-store-withschema (never dlopened)".to_vec();
    let m = busbar_plugin_sign::Manifest {
        name: "acme-store-withschema".into(),
        alias: "withschema".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(&lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: Some(schema.to_string()),
        schema_derived: false,
        host: None,
    };
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", &lib).unwrap();
    let file = "acme-store-withschema.tar.gz";
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-schema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Drop the tarball into the plugins dir BEFORE boot (the same "file-drop-then-boot" mechanism a
    // real operator uses) and scan it into a REAL `PluginRegistry` (the same
    // `scan_and_validate` production boot uses) so `hook_env.registry` — what `GET .../schema`
    // reads — is populated exactly as it would be at a real boot.
    std::fs::write(dir.join(file), &tarball).unwrap();
    let policy = busbar_plugin_sign::TrustPolicy {
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).unwrap();
    let hook_env = crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    // GET .../schema returns the schema as real JSON, resolved by NAME (not filename).
    let got_resp = client
        .get(format!(
            "http://{addr}/api/v1/admin/plugins/acme-store-withschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let got_status = got_resp.status();
    let got: serde_json::Value = got_resp.json().await.unwrap();
    assert_eq!(got_status.as_u16(), 200, "schema get body: {got}");
    assert_eq!(got["name"], "acme-store-withschema");
    assert_eq!(got["schema"], schema);
    assert_eq!(got["schema_error"], serde_json::Value::Null);
    assert_eq!(got["source"], "manifest");
    // Unsigned tarball under an `allow_unsigned` posture (no publisher allowlist) → "unverified",
    // the real catalog vocabulary (never "verified").
    assert_eq!(got["trust"], "unverified");

    handle.abort();

    // A schemaless plugin reports `"schema": null`, not an error — dropped in and
    // rebooted the same way, since (as above) ephemeral test apps only pick up the plugins dir at
    // initial load.
    let no_schema_tarball = admin_test_tarball("acme-store-junk", "junkstore");
    std::fs::write(dir.join("acme-store-junk.tar.gz"), &no_schema_tarball).unwrap();
    let registry2 = busbar_plugin_loader::scan_and_validate(&dir, &policy).unwrap();
    let hook_env2 = crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry2),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let (addr2, handle2) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env2).await;
    let got2: serde_json::Value = client
        .get(format!(
            "http://{addr2}/api/v1/admin/plugins/acme-store-junk/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got2["schema"], serde_json::Value::Null);
    // The schema-carrying plugin from the first boot is still resolvable (both files on disk now).
    let got1_again: serde_json::Value = client
        .get(format!(
            "http://{addr2}/api/v1/admin/plugins/acme-store-withschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got1_again["schema"], schema);

    let _ = std::fs::remove_dir_all(&dir);
    handle2.abort();

    // A manifest that SET settings_schema but to unparseable text reports `schema_error`,
    // distinct from a manifest that never set the field at all (both used to
    // collapse to `schema: null` via `.ok()`, silently hiding a real authoring bug).
    let bad_lib = b"junk library bytes for acme-store-badschema (never dlopened)".to_vec();
    let bad_m = busbar_plugin_sign::Manifest {
        name: "acme-store-badschema".into(),
        alias: "badschema".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(&bad_lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: Some("{ not valid json".into()),
        schema_derived: false,
        host: None,
    };
    let bad_tarball = busbar_plugin_loader::tarball::package(&bad_m, "lib.so", &bad_lib).unwrap();
    let bad_dir = std::env::temp_dir().join(format!(
        "busbar-admin-plugins-badschema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&bad_dir);
    std::fs::create_dir_all(&bad_dir).unwrap();
    std::fs::write(bad_dir.join("acme-store-badschema.tar.gz"), &bad_tarball).unwrap();
    let bad_registry = busbar_plugin_loader::scan_and_validate(&bad_dir, &policy).unwrap();
    let bad_hook_env = crate::hooks::HookEnv::new(
        std::sync::Arc::new(bad_registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let (bad_addr, bad_handle) =
        serve_with_plugins_dir_and_hook_env(bad_dir.clone(), bad_hook_env).await;
    let got_bad: serde_json::Value = client
        .get(format!(
            "http://{bad_addr}/api/v1/admin/plugins/acme-store-badschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got_bad["schema"], serde_json::Value::Null);
    assert!(
        got_bad["schema_error"].as_str().is_some(),
        "corrupt settings_schema reports schema_error, not a bare null: {got_bad}"
    );
    // An unknown plugin name is 404, distinguishing "no schema" from "no such plugin".
    let missing = client
        .get(format!(
            "http://{bad_addr}/api/v1/admin/plugins/nope/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    let _ = std::fs::remove_dir_all(&bad_dir);
    bad_handle.abort();
}

/// Bricks next boot: installing a SAME-NAME plugin under a DIFFERENT filename (e.g. a version
/// bump `-1.1.0.tar.gz` over an installed `-1.0.0.tar.gz`) must be a 409, NOT admitted. Two files
/// claiming the same plugin name are a hard conflict at boot (registry::conflicts()) - admitting the
/// second bricks the next restart. A same-name upgrade must REUSE the existing filename. The old gate
/// exempted this case (`&& existing.manifest.name != manifest.name`).
#[tokio::test]
async fn test_admin_v1_plugin_install_same_name_different_file_is_409() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-admin-plugins-h2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let install = |file: &'static str, tarball: Vec<u8>| {
        let client = client.clone();
        let body = serde_json::json!({
            "file": file,
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
        });
        async move {
            client
                .post(format!("http://{addr}/api/v1/admin/plugins"))
                .header("x-admin-token", "admintok")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // v1.0.0 installs cleanly.
    let v1 = admin_test_tarball_versioned("busbar-store-x", "storex", "1.0.0");
    let r1 = install("busbar-store-x-1.0.0.tar.gz", v1).await;
    assert_eq!(r1.status().as_u16(), 201, "first install succeeds");

    // v1.1.0 - SAME manifest name, DIFFERENT filename - must be a 409 (boot would reject two files
    // claiming the same name), NOT a silent second publish.
    let v2 = admin_test_tarball_versioned("busbar-store-x", "storex", "1.1.0");
    let r2 = install("busbar-store-x-1.1.0.tar.gz", v2).await;
    assert_eq!(
        r2.status().as_u16(),
        409,
        "same-name under a different filename must conflict, not brick the next boot"
    );
    let b: serde_json::Value = r2.json().await.unwrap();
    assert_eq!(b["error"]["code"], "conflict");
    assert!(
        !dir.join("busbar-store-x-1.1.0.tar.gz").exists(),
        "the conflicting second file must NOT be published"
    );
    // The original is untouched (still exactly one plugin file on disk).
    let tars: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
        .collect();
    assert_eq!(tars.len(), 1, "only the original v1.0.0 file remains");

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// Fail-open: a CORRUPT tarball already sitting in the plugins dir makes scan_and_validate Err.
/// The old `if let Ok(reg)` SILENTLY SKIPPED the conflict check and published anyway. Now a new
/// install returns an error (never 201) until the offending tarball is fixed/removed.
#[tokio::test]
async fn test_admin_v1_plugin_install_corrupt_existing_tarball_blocks_publish() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-admin-plugins-m7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Plant a corrupt (non-tarball) *.tar.gz that discover() picks up but examine() cannot parse.
    std::fs::write(
        dir.join("busbar-store-corrupt.tar.gz"),
        b"not a real tarball",
    )
    .unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let good = admin_test_tarball("busbar-store-good", "goodstore");
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "file": "busbar-store-good.tar.gz",
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&good),
        }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        201,
        "an unvalidatable installed set must NOT let a new install publish (fail-open closed)"
    );
    assert_eq!(resp.status().as_u16(), 409, "surfaced as a conflict");
    assert!(
        !dir.join("busbar-store-good.tar.gz").exists(),
        "nothing published while the installed set is unvalidatable"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// A malformed install body (bad base64) is a `400 invalid_request` in the frozen envelope, a
/// non-tarball upload is a `400`, and an UNSIGNED upload under the STRICT default posture is a
/// `409 conflict` (the trust gate cannot be bypassed by pushing over the API) — nothing is
/// published in any case, and the rejects are audited.
#[tokio::test]
async fn test_admin_v1_plugin_install_rejections() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-admin-plugins-rej-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // Bad base64.
    let bad = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file": "x.tar.gz", "tarball_b64": "!!!not base64!!!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    let b: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(b["error"]["code"], "invalid_request");

    // Valid base64 but not a plugin tarball → structural validation fails (400).
    let notplugin = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "file": "nope.tar.gz",
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(b"not a tarball"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(notplugin.status().as_u16(), 400);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing published"
    );

    // TRUST NO-BYPASS: a STRICT-posture server rejects an unsigned upload as 409 conflict.
    {
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let strict_dir = std::env::temp_dir().join(format!(
            "busbar-admin-plugins-strict-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&strict_dir);
        std::fs::create_dir_all(&strict_dir).unwrap();
        let app = TestApp::new()
            .governance(gov)
            .plugins_dir(strict_dir.clone())
            .plugins_cfg(crate::config::PluginsCfg::default())
            .build();
        let (router, _h) = crate::build_router_with_limits(
            app,
            256 * 1024 * 1024,
            0,
            crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let strict_addr = listener.local_addr().unwrap();
        let strict_handle =
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let tarball = admin_test_tarball("acme-store-x", "acmex");
        let resp = client
            .post(format!("http://{strict_addr}/api/v1/admin/plugins"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({
                "file": "x.tar.gz",
                "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            409,
            "the strict default posture rejects an unsigned upload over the API"
        );
        let b: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(b["error"]["code"], "conflict");
        assert_eq!(
            std::fs::read_dir(&strict_dir).unwrap().count(),
            0,
            "nothing published on a trust rejection"
        );
        let _ = std::fs::remove_dir_all(&strict_dir);
        strict_handle.abort();
    }

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// The 1.5.0 mint surface: `budget_group` + `labels` round-trip through create/list, a mint naming
/// a MISSING budget_group is a 400 that names the offender (fail-closed at the mint boundary), and
/// the key-usage read derives spend at the current cost model.
#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // An App whose cost model KNOWS the "growth" group; "ghost" stays unconfigured.
    let cost = {
        let groups = std::collections::BTreeMap::from([(
            "growth".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![crate::config::groups::LimitCfg {
                    metric: crate::config::groups::LimitMetric::Budget,
                    amount: 1_000_000,
                    per: Some(crate::config::groups::LimitWindow::Month),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        )]);
        crate::cost::CostModel::resolve_parts(None, 0, &groups)
    };
    let app = TestApp::new().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // A mint naming a MISSING group is a 400 naming the offender (the field is `group` in 1.5.0).
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k", "group": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("group 'ghost' does not exist"),
        "the 400 names the missing group: {body}"
    );

    // A mint binding a CONFIGURED group with labels succeeds and echoes both. key_meta surfaces the
    // binding under its 1.5.0 name `group`.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "name": "grouped",
            "group": "growth",
            "labels": {"team": "growth", "env": "prod"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "configured group mints");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["group"], "growth");
    assert_eq!(body["labels"]["env"], "prod");
    let id = body["id"].as_str().unwrap().to_string();

    // The list surface carries both fields too (metadata round-trip, never the secret).
    let list: serde_json::Value = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id.as_str())
        .expect("minted key listed");
    assert_eq!(row["group"], "growth");
    assert_eq!(row["labels"]["team"], "growth");

    handle.abort();
}

// ── self-service mint: auto-provision + delegated mint scope + max_keys_per_principal ────────────

/// A `budget` limit for a group tree (helper to keep the test trees readable).
fn budget_limit(cents: u64) -> crate::config::groups::LimitCfg {
    crate::config::groups::LimitCfg {
        metric: crate::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(crate::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

/// AUTO-PROVISION ON MINT: minting into a NONEXISTENT `user:<sub>` leaf under a team carrying a
/// `child_default` creates the leaf with the TEMPLATE limits, binds the key, and the new leaf is
/// live in the enforcement chain (its resolved limits carry the template budget). Nearest-ancestor
/// wins, so the leaf gets the team's per-head default. Also: `group_provisioned: true` is echoed.
#[tokio::test]
async fn test_mint_auto_provisions_leaf_from_child_default() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    // acme (org) → team-payments (team, child_default $20/mo per head). No user leaf yet.
    let groups = std::collections::BTreeMap::from([
        (
            "acme".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(5_000_000)],
                ..Default::default()
            },
        ),
        (
            "team-payments".to_string(),
            crate::config::GroupCfg {
                parent: Some("acme".to_string()),
                limits: vec![budget_limit(2_000_000)],
                child_default: Some(crate::config::groups::ChildDefault {
                    limits: vec![budget_limit(2000)],
                }),
                ..Default::default()
            },
        ),
    ]);
    let app = TestApp::new().governance(gov).groups_tree(groups).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Mint into a leaf that does NOT exist, naming its team as the parent → auto-provision.
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "name": "alice-cli",
            "group": "user:alice",
            "parent": "team-payments"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "auto-provision + mint succeeds"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["group"], "user:alice", "key bound to the new leaf");
    assert_eq!(
        body["group_provisioned"], true,
        "the mint reports it created the leaf"
    );

    // The leaf now EXISTS, parented to the team, with the team's child_default limits stamped on.
    let leaf: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/groups/user:alice"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(leaf["parent"], "team-payments");
    assert_eq!(leaf["enabled"], true);
    assert_eq!(leaf["limits"][0]["metric"], "budget");
    assert_eq!(
        leaf["limits"][0]["amount"], 2000,
        "leaf carries the nearest-ancestor child_default budget"
    );
    // The leaf is a per-user bucket, not itself a template source.
    assert!(leaf.get("child_default").is_none());

    // ENFORCEMENT CHAIN: the leaf's usage read projects the template budget as its cap (the limit is
    // live in the cost model / governance projection — the chain will AND leaf ∩ team ∩ org).
    let usage: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/groups/user:alice/usage"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let month_bucket = usage["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["window"] == "month")
        .expect("a month bucket exists for the leaf");
    assert_eq!(
        month_bucket["budget_cap"], 2000,
        "the leaf's budget cap is enforced from the stamped template"
    );

    // A SECOND mint into the now-existing leaf binds as-is (no re-provision).
    let resp2 = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "name": "alice-cli-2",
            "group": "user:alice",
            "parent": "team-payments"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 201);
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(
        body2["group_provisioned"], false,
        "binding to an existing leaf does not re-provision"
    );

    handle.abort();
}

/// PARENT-MISMATCH 409: minting into an EXISTING group while naming a `parent` that is NOT its
/// actual parent is a conflict — a mint must never silently re-home an existing leaf. Naming the
/// CORRECT parent (or none) binds fine.
#[tokio::test]
async fn test_mint_parent_mismatch_is_409() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([
        (
            "team-a".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "team-b".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "user:bob".to_string(),
            crate::config::GroupCfg {
                parent: Some("team-a".to_string()),
                limits: vec![budget_limit(3000)],
                ..Default::default()
            },
        ),
    ]);
    let app = TestApp::new().governance(gov).groups_tree(groups).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Bob exists under team-a; a mint naming team-b as parent is a 409 (never re-home).
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k", "group": "user:bob", "parent": "team-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "parent mismatch is a conflict");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("already exists with parent"),
        "the 409 explains the re-home refusal: {body}"
    );

    // Naming the CORRECT parent binds fine (parent matches).
    let ok = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k2", "group": "user:bob", "parent": "team-a"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 201, "matching parent binds");

    handle.abort();
}

/// `max_keys_per_principal`: with the cap set to 2, a group's 3rd mint is a 409 that
/// names the cap; a DIFFERENT group is unaffected (the cap is per group = per principal). Cap `0`
/// (default, tested elsewhere) is unlimited.
#[tokio::test]
async fn test_max_keys_per_principal_cap_trips() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "other".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
    ]);
    let mut app = TestApp::new().governance(gov).groups_tree(groups).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 2;
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");
    let mint = |name: &str, group: &str| {
        client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": name, "group": group}))
            .send()
    };

    // Two keys into `capped` — both fine (at the cap, not over it).
    assert_eq!(mint("a", "capped").await.unwrap().status().as_u16(), 201);
    assert_eq!(mint("b", "capped").await.unwrap().status().as_u16(), 201);
    // The THIRD trips the cap → 409 naming the limit.
    let r = mint("c", "capped").await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "3rd key into a capped group is a conflict"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the 409 names the cap: {body}"
    );

    // A DIFFERENT group is unaffected — the cap is per group (= per principal).
    assert_eq!(mint("d", "other").await.unwrap().status().as_u16(), 201);

    handle.abort();
}

/// The idempotency RESERVATION frees itself on an AT-CAP refusal specifically — a DIFFERENT exit
/// than `test_admin_v1_idempotency_reservation_frees_on_failure`'s pre-validation 400: this one
/// only reserves after the request has been handed to the transaction/mint (`IdemState::InFlight`,
/// via `IdemReservation::clear()`'s explicit call at the `MintOutcome::AtCap` arm), so Drop alone
/// (which only clears a still-`Reserved` sentinel) would NOT free it. Prove the reservation is
/// genuinely released, not merely coincidentally re-tripping the same cap: free capacity between
/// the two calls and confirm the SAME Idempotency-Key mints on retry.
#[tokio::test]
async fn test_admin_v1_idempotency_reservation_frees_on_at_cap_refusal() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        crate::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    let mut app = TestApp::new().governance(gov).groups_tree(groups).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 1;
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    // Fill the cap (1) with an unrelated key first — no Idempotency-Key, not part of the reuse test.
    let filler = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "filler", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(filler.status().as_u16(), 201);
    let filler_id = filler.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The reserving mint: the group is already at cap, so this trips `MintOutcome::AtCap` — the
    // reservation was inserted, promoted to InFlight, and must be freed by `r.clear()` here.
    let at_cap = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "reuse-at-cap")
        .json(&serde_json::json!({"name": "second", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        at_cap.status().as_u16(),
        409,
        "the reserving mint trips the cap"
    );

    // Free capacity (delete the filler) so a retry CAN succeed if — and only if — the reservation
    // was actually released.
    let deleted = client
        .delete(format!("{keys_url}/{filler_id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // The SAME Idempotency-Key now mints successfully. If `IdemReservation::clear()` were a no-op,
    // this would instead see the stale `Null` sentinel and get the idempotency-in-flight 409
    // forever, never a fresh cap check.
    let retry = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "reuse-at-cap")
        .json(&serde_json::json!({"name": "second", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        retry.status().as_u16(),
        201,
        "a retry under the same key mints once capacity is free — the AtCap reservation was \
         released, not stuck in-flight: {}",
        retry.text().await.unwrap_or_default()
    );

    handle.abort();
}

/// `update_key`'s cap gate fires only when a PATCH would ADD a live key to its destination bucket:
/// `will_be_counted && (!was_counted || dest_group != before.group)`. A TRUE no-op PATCH on an
/// ALREADY-live key already counted in a group — same group, still enabled, nothing that changes
/// its count — must stay editable (`!was_counted` is false, group is unchanged, so the `||` is
/// false and the cap is never consulted).
///
/// `check_key_cap`'s own `exclude_id` (the mover is never counted against itself) means a simple
/// "mint exactly `cap` keys via the normal admin-mint path, then no-op PATCH one of them" does NOT
/// distinguish the mutation: excluding the patched key always leaves the OTHER `cap - 1` keys,
/// which is under `cap` either way. The real-world case that DOES distinguish it is a cap that was
/// TIGHTENED after the keys already existed (an operator lowering `limits.max_keys_per_principal`
/// live) — two keys pre-seeded directly via `GovState::create_key` (bypassing the admin mint path's
/// own cap enforcement, exactly like this file's `key_cap_tests` module does) under a cap of 1: the
/// bucket is now genuinely OVER cap even excluding the one being patched (1 other live key >= cap
/// of 1). Only in that shape does `!was_counted` vs `was_counted` change the outcome.
#[tokio::test]
async fn test_admin_v1_patch_no_op_on_an_already_counted_key_is_not_an_admission() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mint = |name: &str| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                allowed_pools: None,
                group: Some("capped".to_string()),
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .expect("mint")
        .0
    };
    let a = mint("a");
    let _b = mint("b"); // a second live key in the SAME bucket, pre-existing the cap tightening below.

    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        crate::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    let mut app = TestApp::new().governance(gov).groups_tree(groups).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        // Tightened to 1 AFTER both `a` and `b` already exist — the bucket is now over cap even
        // excluding whichever key a PATCH is touching.
        inner.max_keys_per_principal = 1;
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // A genuinely empty PATCH on `a`: no `enabled`, no `group` — nothing that could change the
    // count. `a` was already live+counted in `capped` before this PATCH and stays so after it.
    let noop = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", a.id))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = noop.status().as_u16();
    let body = noop.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "a true no-op PATCH on an already-counted key must not be treated as a NEW admission to \
         its bucket, even though the bucket is now over a since-tightened cap: {body}"
    );

    handle.abort();
}

/// The three anti-sprawl refusals, driven end-to-end. Split out of the `#[tokio::test]` so the
/// class-level drift test can run it too.
///
/// 1. **`PATCH /keys/{id}` rebind into an at-cap group**. Only its pure
///    predicate (`check_key_cap`) was tested; the HANDLER arm that turns it into a 409 had no test
///    at all, so `contract::taxonomy` never declared `Conflict/AtKeyCap` for that operation and
///    `openapi.json` documented a `409` that named only `GovernanceOff`. The under-claim guard could
///    not catch it either: it compared `ErrKind` alone, and `Conflict` WAS declared.
/// 2. **RE-ENABLE past the cap** — the same ratchet, reached through the other field. `check_key_cap` counts LIVE keys, so `disable → mint → re-enable` walks a bucket past
///    its ceiling with every single request passing the guard. Now gated by the same 409.
///
/// (1.5.2 scope collapse removed the former case 3 — the delegated-mint-must-bind 400 — since the
/// narrower `mint` scope that could reach it no longer exists; only a `full` operator mints, and the
/// operator may legitimately mint an unbound key.)
///
/// It also asserts the audit consequence: every one of these refusals writes a `rejected` row —
/// a refused mint is an attempt to issue a credential, and it must leave a trace.
async fn drive_key_cap_and_delegation_errors() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "roomy".to_string(),
            crate::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
    ]);
    let mut app = TestApp::new().governance(gov).groups_tree(groups).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 2;
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let mint = |name: &'static str, group: &'static str| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            let r = c
                .post(&u)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name, "group": group}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 201, "mint {name}/{group}");
            let b: serde_json::Value = r.json().await.unwrap();
            b["id"].as_str().unwrap().to_string()
        }
    };
    let patch = |id: String, body: serde_json::Value| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            c.patch(format!("{u}/{id}"))
                .header("x-admin-token", "admintok")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // Fill `capped` to its ceiling of 2, and park one key in `roomy` to rebind with.
    let cap_a = mint("a", "capped").await;
    let _cap_b = mint("b", "capped").await;
    let roamer = mint("roamer", "roomy").await;

    // ── 1. REBIND into an at-cap bucket → 409 `conflict` naming the cap ───────────────────────
    let r = patch(roamer.clone(), serde_json::json!({"group": "capped"})).await;
    assert_eq!(r.status().as_u16(), 409, "rebind into an at-cap group");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the rebind 409 names the cap: {body}"
    );

    // ── 2. RE-ENABLE past the cap → the SAME 409 ──────────────────────────────────────────────
    // Disable one of `capped`'s keys: the bucket now counts 1 live, so a fresh mint is admitted.
    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "disabling is always allowed — it can only free a slot"
    );
    let _cap_c = mint("c", "capped").await;
    // …and NOW re-enabling the parked key would make 3 live keys in a bucket capped at 2.
    let r = patch(cap_a.clone(), serde_json::json!({"enabled": true})).await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "re-enabling past the cap is the same admission as a rebind past the cap"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the re-enable 409 names the cap: {body}"
    );
    // A DISABLED key can still be edited in every other way — the guard fires on admission, not on
    // touching an at-cap bucket (otherwise an at-cap bucket would freeze).
    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "a no-op disable of a key in an at-cap bucket is not an admission"
    );

    // The operator (`full`) may mint an UNBOUND key — the tree's owner is not gated (1.5.2 removed
    // the delegated-mint-must-bind refusal along with the narrower `mint` scope).
    let r = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "unbound-by-operator"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "the operator owns the tree and may still mint an unbound key"
    );

    // ── THE AUDIT CONSEQUENCE ─────────────────────────────────────────────────────────────────
    // Every refusal above wrote a `rejected` row: a refused mint is a stopped attempt to issue a
    // credential, and must leave a trace. The rows are asserted through
    // the live `GET /audit` surface, and only for EXISTENCE (the log is a process-global other
    // tests append to, so "at least one" is the only stable predicate).
    let audit_rows = |action: &'static str| {
        let (c, a) = (client.clone(), addr);
        async move {
            let r = c
                .get(format!("http://{a}/api/v1/admin/audit?action={action}"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap();
            let b: serde_json::Value = r.json().await.unwrap();
            b["items"].as_array().cloned().unwrap_or_default()
        }
    };
    // The cap refusals above are `key.patch` (rebind + re-enable); each must leave a `rejected` row.
    for action in ["key.patch"] {
        let rejected = audit_rows(action)
            .await
            .iter()
            .filter(|e| e["outcome"] == "rejected")
            .count();
        assert!(
            rejected > 0,
            "no `{action}` audit row with outcome=rejected — a refusal that leaves no trail is \
             the gap `KeyAudit` exists to make unrepresentable"
        );
    }

    server.abort();
}

/// The `#[tokio::test]` wrapper for [`drive_key_cap_and_delegation_errors`].
#[tokio::test]
async fn key_cap_and_delegation_refusals_are_reachable_declared_and_audited() {
    drive_key_cap_and_delegation_errors().await;
}

/// N concurrent mints into a
/// group sitting one below the cap must NOT all pass. Before the fix the count and the mint ran in
/// two separate `spawn_blocking` tasks with an `.await` between and no lock spanning them, so
/// concurrent callers all read `n < cap` and all minted, overshooting the cap by up to `N-1`. The
/// fix folds the count and the mint into ONE `spawn_blocking` under `EXISTENCE_GATE`, serializing
/// callers at the boundary. Here: cap = 3, seed the group with 2 keys, fire 6 concurrent mints ⇒
/// EXACTLY one succeeds (fills the last slot) and the rest 409, and the group ends at EXACTLY the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_max_keys_per_principal_atomic_under_concurrent_mint() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        crate::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    let mut app = TestApp::new()
        .governance(gov.clone())
        .groups_tree(groups)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 3;
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");
    let mint = |name: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name, "group": "capped"}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // Seed the group to cap-1 (2 of 3) sequentially so exactly one slot remains.
    assert_eq!(mint("seed-a".to_string()).await, 201);
    assert_eq!(mint("seed-b".to_string()).await, 201);

    // Fire 6 mints CONCURRENTLY at the boundary. Only ONE may fill the last slot; the rest 409.
    let mut set = tokio::task::JoinSet::new();
    for i in 0..6 {
        set.spawn(mint(format!("race-{i}")));
    }
    let mut statuses = Vec::new();
    while let Some(res) = set.join_next().await {
        statuses.push(res.unwrap());
    }
    let created = statuses.iter().filter(|s| **s == 201).count();
    let conflicts = statuses.iter().filter(|s| **s == 409).count();
    assert_eq!(
        created, 1,
        "exactly ONE concurrent mint may fill the last cap slot (got {created} 201s): {statuses:?}"
    );
    assert_eq!(
        conflicts, 5,
        "the other five concurrent mints must 409 at the cap: {statuses:?}"
    );

    // The store must hold EXACTLY the cap (3) keys bound to `capped` — never more.
    let n = gov
        .all_keys()
        .unwrap()
        .iter()
        .filter(|k| k.group.as_deref() == Some("capped"))
        .count();
    assert_eq!(
        n, 3,
        "the group must end at EXACTLY the cap under concurrency, never over it (got {n})"
    );

    handle.abort();
}

// ── 1.5.0 signed-token key coverage ──────────────────────────────────────────────────────────────

/// The MINT returns a busbar-SIGNED `token` (prefix `bbk_`) + an `expires_at`, and that token is
/// NEVER stored: a subsequent `GET /keys/{id}` returns the binding metadata but no `token`, and the
/// token string appears nowhere in the read body. The token is the credential, shown exactly once.
#[tokio::test]
async fn test_signed_mint_returns_token_and_expiry_never_stored() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "svc"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let token = created["token"]
        .as_str()
        .expect("mint returns a token")
        .to_string();
    assert!(
        token.starts_with("bbk_"),
        "the token is a busbar-signed token: {token}"
    );
    assert!(
        created["expires_at"].as_u64().is_some(),
        "mint returns an absolute expires_at: {created}"
    );

    // The token is NEVER returned by a read - GET carries the binding metadata only, never the
    // once-shown credential.
    let read = client
        .get(format!("{url}/{id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(read.status().as_u16(), 200);
    let text = read.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["id"], id);
    assert!(
        body.get("token").is_none(),
        "a read never returns the token: {body}"
    );
    assert!(
        !text.contains(&token),
        "the once-shown token must not appear in any read body"
    );

    handle.abort();
}

/// `expires_in` duration parsing sets `expires_at` at ~now+duration; an absolute `expires_at` works
/// verbatim; both together is a 400; a past `expires_at` is a 400; a malformed duration is a 400.
#[tokio::test]
async fn test_signed_mint_expiry_parsing_matrix() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");
    let post = |body: serde_json::Value| {
        client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&body)
            .send()
    };

    // `expires_in: "7d"` -> expires_at ~= now + 7*86400 (allow a few seconds of clock slop).
    let now = crate::store::now();
    let seven_d: serde_json::Value = post(serde_json::json!({"name": "k", "expires_in": "7d"}))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let exp = seven_d["expires_at"].as_u64().expect("expires_at present");
    let want = now + 7 * 86_400;
    assert!(
        exp.abs_diff(want) <= 5,
        "7d must set expires_at ~= now+7d: got {exp}, want ~{want}"
    );

    // An absolute `expires_at` is used verbatim.
    let abs_at = now + 999_999;
    let absolute: serde_json::Value = post(serde_json::json!({"name": "k", "expires_at": abs_at}))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        absolute["expires_at"].as_u64(),
        Some(abs_at),
        "an absolute expires_at is used verbatim"
    );

    // Both together -> 400 (mutually exclusive).
    let both = post(serde_json::json!({
        "name": "k", "expires_in": "1h", "expires_at": abs_at
    }))
    .await
    .unwrap();
    assert_eq!(
        both.status().as_u16(),
        400,
        "expires_in + expires_at is a 400"
    );

    // A past absolute expiry -> 400.
    let past = post(serde_json::json!({"name": "k", "expires_at": now - 1}))
        .await
        .unwrap();
    assert_eq!(past.status().as_u16(), 400, "a past expires_at is a 400");

    // A malformed duration -> 400.
    let bad = post(serde_json::json!({"name": "k", "expires_in": "7 fortnights"}))
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "a malformed duration is a 400");

    handle.abort();
}

/// A minted token VERIFIES against the binding via `gov.verify_token` (resolving the subject's
/// enabled binding). After a DELETE the same token fails verify (the subject is denylisted AND its
/// binding is gone - revoke-then-delete). `is_revoked(sub)` becomes true.
#[tokio::test]
async fn test_signed_mint_verify_then_delete_denies() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "verifiable"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();

    // The token resolves its binding right after mint.
    let now = crate::store::now();
    let resolved = gov
        .verify_token(&token, now, None)
        .expect("a fresh token verifies");
    assert_eq!(
        resolved.id, id,
        "verify resolves the minted subject's binding"
    );
    assert!(!gov.is_revoked(&id), "a fresh subject is not revoked");

    // DELETE revokes-then-deletes: the same token now fails verify (denylist + binding gone).
    let del = client
        .delete(format!("{url}/{id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "delete is a 204");
    assert!(gov.is_revoked(&id), "delete denylists the subject");
    assert!(
        gov.verify_token(&token, now, None).is_none(),
        "a deleted key's token no longer verifies"
    );

    handle.abort();
}

/// `POST /keys/{id}/revoke` denylists WITHOUT deleting: `GET /keys/{id}` still shows the binding for
/// the record, `verify_token` now returns `None`, and `is_revoked(sub)` is true. Revoke is
/// idempotent (a second revoke is still 200).
#[tokio::test]
async fn test_signed_revoke_denylists_without_deleting() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "revokable"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    let now = crate::store::now();
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "verifies before revoke"
    );

    // Revoke (no delete): 200.
    let r = client
        .post(format!("{url}/{id}/revoke"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "revoke is a 200");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["revoked"], id.as_str());

    // The binding is STILL present (revoke, not delete) - GET still returns it…
    let read = client
        .get(format!("{url}/{id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(read.status().as_u16(), 200, "the binding is still readable");
    assert_eq!(read.json::<serde_json::Value>().await.unwrap()["id"], id);

    // …but the subject is denylisted, so the token no longer verifies.
    assert!(gov.is_revoked(&id), "the subject is denylisted");
    assert!(
        gov.verify_token(&token, now, None).is_none(),
        "a revoked subject's token no longer verifies"
    );

    // Idempotent: a second revoke is still 200.
    let again = client
        .post(format!("{url}/{id}/revoke"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(again.status().as_u16(), 200, "revoke is idempotent");

    handle.abort();
}

/// `PATCH {enabled:false}` (reversible pause), `POST /keys/{id}/revoke` (permanent denylist),
/// and `DELETE /keys/{id}` (permanent denylist + tombstone) used to all collapse to the SAME
/// `GET /keys/{id}` response, `{..., "enabled": false}` — byte-identical, with no field anywhere
/// distinguishing them. This proves the fix: three keys, one put through each verb, each subsequent
/// `GET /keys/{id}` now reports a DISTINCT `state`.
#[tokio::test]
async fn test_key_state_distinguishes_disable_revoke_and_tombstone() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let mint = |name: &'static str| {
        let client = client.clone();
        let url = url.clone();
        async move {
            let created: serde_json::Value = client
                .post(&url)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                created["state"], "active",
                "a freshly minted key's own response is state:active"
            );
            created["id"].as_str().unwrap().to_string()
        }
    };
    let disabled_id = mint("paused").await;
    let revoked_id = mint("revoked").await;
    let tombstoned_id = mint("tombstoned").await;

    // PATCH {enabled:false} — reversible pause.
    let patched: serde_json::Value = client
        .patch(format!("{url}/{disabled_id}"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(patched["enabled"], false);
    assert_eq!(
        patched["state"], "disabled",
        "PATCH's own response already carries the distinguishing state"
    );

    // POST /revoke — permanent denylist, binding kept.
    let revoked: serde_json::Value = client
        .post(format!("{url}/{revoked_id}/revoke"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revoked["revoked"], revoked_id.as_str());

    // DELETE — permanent denylist + tombstone.
    let del = client
        .delete(format!("{url}/{tombstoned_id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);

    // The three cases used to be byte-identical on GET (`{..., "enabled": false}` all round). Now
    // each `state` is distinct, and the OLD collapsed field (`enabled`) is still false on all three
    // — this is exactly the wire shape this state field was added for.
    let get_state = |id: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            let body: serde_json::Value = client
                .get(format!("{url}/{id}"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                body["enabled"], false,
                "id={id}: all three cases still collapse `enabled` to false — that's the bug \
                 `state` exists to fix, not something this test should regress"
            );
            body["state"].as_str().unwrap().to_string()
        }
    };
    let disabled_state = get_state(disabled_id).await;
    let revoked_state = get_state(revoked_id).await;
    let tombstoned_state = get_state(tombstoned_id).await;

    assert_eq!(disabled_state, "disabled");
    assert_eq!(revoked_state, "revoked");
    assert_eq!(tombstoned_state, "tombstoned");
    // Belt-and-braces: the whole point is that these three are PAIRWISE distinct, not just that
    // each matches its own expected literal (a bug that mapped both revoke and delete to the same
    // wrong string would still pass three individual `assert_eq!`s above).
    assert_ne!(disabled_state, revoked_state);
    assert_ne!(revoked_state, tombstoned_state);
    assert_ne!(disabled_state, tombstoned_state);

    handle.abort();
}

/// Secondary point: a tombstoned key is silently omitted from a plain `GET /keys` — "it is
/// gone" and "it never existed" looked the same. `?include=tombstoned` opts back in, additively;
/// the default (omitted) list is unaffected.
#[tokio::test]
async fn test_list_keys_include_tombstoned() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "will-be-tombstoned"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let del = client
        .delete(format!("{url}/{id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);

    // Default: the tombstoned row is omitted, exactly as before this fix.
    let plain: serde_json::Value = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let plain_ids: Vec<&str> = plain["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].as_str().unwrap())
        .collect();
    assert!(
        !plain_ids.contains(&id.as_str()),
        "a plain GET /keys must still omit tombstoned rows by default"
    );

    // `?include=tombstoned` opts back in, and its row's `state` reads "tombstoned".
    let included: serde_json::Value = client
        .get(format!("{url}?include=tombstoned"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = included["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id.as_str())
        .expect("?include=tombstoned must surface the tombstoned row");
    assert_eq!(row["state"], "tombstoned");

    // An unrecognized `include` value is a loud 400, not a silently-ignored filter.
    let bad = client
        .get(format!("{url}?include=bogus"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);

    handle.abort();
}

/// `group: None` (omitted) mints a key with NO group - authed + unlimited (access only); key_meta's
/// `group` is null. A pool ACL matrix: OMITTED `allowed_pools` binds ALL pools (empty vec in the
/// binding), while an explicit `[]` binds NO pools.
#[tokio::test]
async fn test_signed_mint_group_none_and_pool_acl_matrix() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // group omitted -> a groupless key; key_meta.group is null.
    let no_group: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "groupless"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        no_group["group"].is_null(),
        "an omitted group is null: {no_group}"
    );

    // allowed_pools OMITTED = ALL pools: the binding stores the empty vec (the "all" encoding).
    let all_pools_id = no_group["id"].as_str().unwrap().to_string();
    let binding = gov.lookup_by_sub(&all_pools_id).expect("binding present");
    assert!(
        binding.allowed_scopes.is_none(),
        "omitted allowed_pools = the empty-vec ALL encoding"
    );
    assert!(binding.group.is_none(), "no group bound");

    // allowed_pools = explicit [] -> the binding stores an explicit empty list too. On the wire the
    // two are the same empty array; the distinction (all vs none) is a runtime interpretation of the
    // stored vec, so we assert the binding round-trips the explicit empty and key_meta echoes it.
    let none_pools: serde_json::Value = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "nopools", "allowed_pools": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        none_pools["allowed_pools"],
        serde_json::json!([]),
        "an explicit [] echoes as an empty pool list: {none_pools}"
    );

    handle.abort();
}

/// `POST /api/v1/admin/signing-key/rotate` reports the current kid + the revoke-all intent
/// (`revoke_all: true`), and is admin-gated.
#[tokio::test]
async fn test_signing_key_rotate_reports_kid_and_revoke_all() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/signing-key/rotate");

    // Admin-gated.
    let unauth = client.post(&url).send().await.unwrap();
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "signing-key rotate is admin-guarded"
    );

    let r = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["current_kid"],
        crate::governance::signing::DEFAULT_KID,
        "reports the current signing-key id: {body}"
    );
    assert_eq!(body["revoke_all"], true, "rotation is revoke-all by design");

    // The endpoint rotates NOTHING — it reads the current kid and returns instructions. The audit
    // row must not claim otherwise: `signing_key.rotate`/`applied` told a reader every outstanding
    // token had been revoked. The row itself stays, because a valid admin token calling this
    // repeatedly is exactly the probing the log exists to record.
    //
    // Scoped by resource ("signing-key") only, over the whole 1000-entry ring: the negative
    // assertion below (no `signing_key.rotate` row) holds only because no OTHER test currently
    // emits that action against this resource, and a large concurrent audit-writing burst could in
    // principle evict this test's own `signing_key.report` row before the read. Latent; accepted —
    // bracketing by seq would narrow the window but not defeat eviction.
    let rows = crate::admin::audit::AUDIT.list_filtered(
        0,
        crate::admin::audit::MAX_AUDIT_ENTRIES,
        None,
        Some("signing-key"),
    );
    assert!(
        rows.iter().any(|e| e.action == "signing_key.report"
            && e.outcome == crate::admin::audit::OUTCOME_APPLIED),
        "the report is recorded under a verb that does not claim a mutation"
    );
    assert!(
        !rows.iter().any(|e| e.action == "signing_key.rotate"),
        "and never under a verb asserting key material changed"
    );

    handle.abort();
}

// ── per-section overlay RESET (DELETE /overlay/{section}) ──────────────────────────────────────────

/// Write a minimal on-disk config.yaml (with one base group `team`) + providers.yaml under a fresh
/// temp dir, returning `(dir, config_path, providers_path)`. The reset endpoint re-reads disk truth,
/// so a reset test needs real files to revert to. Caller removes the dir.
fn write_reset_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-reset-{}-{}-{}",
        tag,
        std::process::id(),
        crate::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_RESET_NO_SUCH_KEY
",
    )
    .unwrap();
    // Base config: one model/pool + a base group `team` with a month budget. This IS the truth a
    // reset reverts to.
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
providers:
  test-provider:
    api_key: { env: BUSBAR_TEST_RESET_NO_SUCH_KEY }
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
groups:
  team:
    limits:
      - { budget: 20000, per: month }
",
    )
    .unwrap();
    (dir, config_path, providers_path)
}

/// RESET GROUPS after a runtime group POST: the runtime group is gone, the cost model reflects base
/// (only `team` remains), the config version bumped, and the mutation is audited + version-logged.
/// The overlay file's groups section is cleared while the (empty) hooks section is preserved.
#[tokio::test]
async fn test_admin_v1_overlay_reset_groups_reverts_to_base() {
    crate::metrics::init();
    let (dir, config_path, providers_path) = write_reset_fixture("groups");
    let overlay = dir.join("overlay.json");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        // The live App starts consistent with disk: `team` is a base group.
        .group(
            "team",
            crate::config::GroupCfg {
                limits: vec![serde_yaml::from_str("{ budget: 20000, per: month }").unwrap()],
                ..Default::default()
            },
        )
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // Create a runtime leaf group parented to the base `team`.
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/groups")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "user:alice",
                "config": {"parent": "team", "limits": [{"budget": 5000, "per": "month"}]}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);
    // It is live in the group tree + written to the overlay.
    let listed: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["name"] == "user:alice"),
        "the runtime group is live before the reset"
    );
    assert!(
        crate::config::overlay::read(&overlay)
            .expect("overlay written")
            .groups
            .contains_key("user:alice"),
        "the runtime group is in the overlay before the reset"
    );
    let ver_before: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/info")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let v_before = ver_before["config_version"].as_u64().unwrap();

    // RESET the groups section.
    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/groups")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "groups");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");
    let v_after = body["config_version"].as_u64().unwrap();
    assert!(v_after > v_before, "the reset bumped the config version");

    // The runtime group is gone; only the base `team` remains.
    let after: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = after["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["team"],
        "reverted to base groups only: {names:?}"
    );

    // The overlay's groups section is cleared on disk (the durable half survives a restart).
    let doc = crate::config::overlay::read(&overlay).expect("overlay still present");
    assert!(
        doc.groups.is_empty() && doc.deleted_groups.is_empty(),
        "the overlay groups section is cleared"
    );

    // Audited + version-logged.
    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?action=overlay.reset"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    // The audit log is a process-global static shared across parallel tests, so match on BOTH the
    // resource AND the applied outcome (another test may log an `overlay:groups`/rejected first).
    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["resource"] == "overlay:groups" && e["outcome"] == "applied"),
        "the applied reset is audited"
    );
    let versions: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        versions["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["summary"]
                .as_str()
                .is_some_and(|s| s.contains("overlay.reset groups"))),
        "the reset landed a version-log entry"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// RESET HOOKS after a runtime hook change restores base hooks: a runtime-registered hook is gone
/// after the reset and the base (disk) hook surface is what remains.
#[tokio::test]
async fn test_admin_v1_overlay_reset_hooks_reverts_to_base() {
    crate::metrics::init();
    let (dir, config_path, providers_path) = write_reset_fixture("hooks");
    let overlay = dir.join("overlay.json");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // Register a runtime hook (the base config declares none).
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "runtime_gate",
                "config": {"kind": "gate", "plugin": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);
    assert!(
        crate::config::overlay::read(&overlay)
            .expect("overlay written")
            .hooks
            .contains_key("runtime_gate"),
        "runtime hook in the overlay before the reset"
    );

    // RESET hooks.
    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/hooks")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    assert_eq!(
        reset.json::<serde_json::Value>().await.unwrap()["reset"],
        "hooks"
    );

    // The runtime hook is gone; the base hook surface (empty here) is restored.
    let hooks: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        hooks["items"].as_array().unwrap().is_empty(),
        "the runtime hook is discarded, base hooks restored: {hooks}"
    );
    let doc = crate::config::overlay::read(&overlay).expect("overlay present");
    assert!(
        doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty(),
        "the overlay hooks section is cleared"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stale `If-Match` on the reset is a `version_conflict` (409) that changes nothing — the same
/// optimistic-concurrency guard every config-plane mutation honors.
#[tokio::test]
async fn test_admin_v1_overlay_reset_stale_if_match_conflicts() {
    crate::metrics::init();
    let (dir, config_path, providers_path) = write_reset_fixture("ifmatch");
    let overlay = dir.join("overlay.json");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .group(
            "team",
            crate::config::GroupCfg {
                limits: vec![serde_yaml::from_str("{ budget: 20000, per: month }").unwrap()],
                ..Default::default()
            },
        )
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // Put SOMETHING in the overlay so the reset is not the empty-section no-op path.
    admin(client.post(format!("http://{addr}/api/v1/admin/groups")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "user:bob", "config": {"parent": "team"}}).to_string())
        .send()
        .await
        .unwrap();

    // A deliberately-stale If-Match (0 is never the current version after a mutation).
    let stale = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/groups")))
        .header("If-Match", "\"0\"")
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    assert_eq!(
        stale.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "version_conflict"
    );
    // Nothing changed: the runtime group is still there.
    let listed: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["name"] == "user:bob"),
        "a rejected reset changes nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unknown section name is a `400 invalid_request` — only `groups`|`hooks` are valid.
#[tokio::test]
async fn test_admin_v1_overlay_reset_unknown_section_400() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for bad in ["auth", "plugins", "Groups", "keys"] {
        let r = client
            .delete(format!("http://{addr}/api/v1/admin/overlay/{bad}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "`{bad}` is not a valid section");
        assert_eq!(
            r.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );
    }

    handle.abort();
}

/// An EMPTY section (no overlay entries/tombstones) is an idempotent success no-op: `changed:false`
/// and the config version does NOT bump. Works even with no config files on disk (nothing persisted
/// ⇒ every section is definitionally already at base).
#[tokio::test]
async fn test_admin_v1_overlay_reset_empty_section_is_idempotent_noop() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = std::env::temp_dir().join(format!(
        "busbar-reset-empty-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let v_before: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // No overlay writes have happened → both sections are empty. A reset is a clean no-op success.
    for section in ["groups", "hooks"] {
        let r = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            200,
            "empty {section} reset is a success"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["changed"], false,
            "an empty-section reset changes nothing"
        );
    }
    let v_after: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v_before["config_version"], v_after["config_version"],
        "an idempotent no-op reset does not bump the version"
    );

    handle.abort();
    let _ = std::fs::remove_file(&overlay);
}

/// SCOPE: a section reset is a FULL-scope mutation (the `/overlay/*` fallthrough in the scope
/// matrix), so a read-only principal is forbidden. The matrix is the ONE source the middleware
/// enforces, so asserting it here is the authoritative scope check; the surface is also
/// admin-guarded (an unauthenticated caller never even reaches the scope check).
#[tokio::test]
async fn test_admin_v1_overlay_reset_requires_full_scope() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // The scope matrix requires `full` for DELETE /overlay/{section} — a read-only (or
    // hooks-register) principal cannot pass it.
    for section in ["groups", "hooks"] {
        let scope = crate::admin::v1::contract::required_scope(
            &axum::http::Method::DELETE,
            &format!("/api/v1/admin/overlay/{section}"),
        );
        assert_eq!(
            scope.as_str(),
            "full",
            "a {section} reset is a full-scope mutation"
        );
    }
    // And an unauthenticated caller is rejected (admin-guarded) — the surface never leaks.
    let unauth = client
        .delete(format!("http://{addr}/api/v1/admin/overlay/groups"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401, "the reset is admin-guarded");

    handle.abort();
}

/// RESET a NAMED-MAP section (`DELETE /overlay/export`): every API-applied exporter definition is
/// discarded and the section reverts to base `config.yaml` truth, exactly as `groups`/`hooks`/`root`
/// already did.
///
/// `named_maps` was in NONE of `OverlaySection`'s variants, so there was no way to revert
/// API-applied identity-provider or export definitions to config.yaml at all: the endpoint answered
/// `400 unknown overlay section`. Every other durable overlay section had a revert and this one did
/// not, while the docs listed the four-value set as COMPLETE.
#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_section_reverts_to_base() {
    let (dir, overlay, addr, handle) = named_map_app("resetnamedmap", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // An API-applied exporter, alongside the fixture's base-config `base-metrics`.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    assert!(
        crate::config::overlay::read(&overlay)
            .expect("overlay written")
            .named_maps
            .get("export")
            .is_some_and(|e| e.contains_key("runtime-sink")),
        "the definition is in the overlay before the reset"
    );

    // RESET the section.
    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/export")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "export");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");

    // The API-applied exporter is gone; the base-config one is untouched.
    let gone = admin(client.get(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        gone.status().as_u16(),
        404,
        "the API-applied definition reverted to base"
    );
    let base = admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        base.status().as_u16(),
        200,
        "a base config.yaml definition is NOT what a reset removes"
    );
    // The durable half: the section is cleared on disk, so the revert survives a restart.
    assert!(
        crate::config::overlay::read(&overlay).is_none_or(|d| !d.named_maps.contains_key("export")),
        "the overlay `export` section is cleared on disk"
    );
    // A SIBLING named-map section is untouched by another section's reset.
    let idp = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/base-idp"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(idp.status().as_u16(), 200, "sibling sections survive");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// REFERENTIAL INTEGRITY on a BULK reset: a section reset that would leave another config site
/// naming a definition that no longer exists is refused as a terminal `conflict` NAMING both the
/// entry and its referent, and nothing changes.
///
/// This is the guard the per-entry `DELETE /identity-providers/{name}` already had, applied to the
/// bulk path. Without it a reset would be accepted, the rebuild would fail deeper down with the far
/// less actionable "references X, which is not defined", and the operator would be left guessing
/// which of the definitions they just discarded was the one still in use.
#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_refuses_a_dangling_reference() {
    let (dir, _overlay, addr, handle) = named_map_app("resetdangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // The fixture's base `auth.admin_auth:` names `corp-ad`; this PUT is the only definition of it.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    let reset = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/overlay/identity-providers"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        409,
        "a reset that would dangle a reference is refused"
    );
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("corp-ad") && msg.contains("auth.admin_auth"),
        "the refusal names the entry AND the referent so an operator knows what to fix: {body}"
    );

    // NOTHING changed: the definition is still live and still on disk.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused reset changed nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ── /config/settings — 1.5.0 full-config coverage (the overlay `root` section) ──────────────────────

/// Build an overlay-backed app wired to on-disk config files (the `write_reset_fixture` truth), spin
/// up an HTTP server, and return everything the `/config/settings` tests need. The app starts on base
/// config (no root overlay), so a `PUT /config/settings` is the first root mutation.
async fn settings_test_app(
    tag: &str,
) -> (
    std::path::PathBuf,   // temp dir (caller removes)
    std::path::PathBuf,   // overlay path
    std::net::SocketAddr, // server addr
    tokio::task::JoinHandle<()>,
) {
    crate::metrics::init();
    // A per-test tag keeps parallel `/config/settings` tests on DISTINCT temp dirs (the fixture dir
    // is keyed on pid + coarse timestamp, which collides for same-second parallel starts).
    let (dir, config_path, providers_path) = write_reset_fixture(&format!("settings-{tag}"));
    let overlay = dir.join("overlay.json");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (dir, overlay, addr, handle)
}

/// ROUND-TRIP + RESTART SURVIVAL: a `PUT /config/settings` with LIVE-swappable sections (rate_card +
/// per_request_fee + a limits field) applies live (200, version bumps), is written to the overlay
/// `root` section, is reflected by `GET /config/settings`, and — crucially — survives a
/// `POST /config/reload` (the restart-equivalent disk re-read). Audited + version-logged.
#[tokio::test]
async fn test_admin_v1_config_settings_round_trip_survives_reload() {
    let (dir, overlay, addr, handle) = settings_test_app("roundtrip").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let before: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v_before = before["config_version"].as_u64().unwrap();

    // PUT live-swappable sections only.
    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "per_request_fee": 7,
                "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
                "limits": { "tls_handshake_timeout_secs": 30 }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(body["settings"]["per_request_fee"], 7);
    assert_eq!(body["settings"]["limits"]["tls_handshake_timeout_secs"], 30);
    assert!(
        body["settings"]["rate_card"]["m0"].is_object(),
        "rate_card round-trips"
    );

    // The overlay `root` section is on disk (the durable half).
    let doc = crate::config::overlay::read(&overlay).expect("overlay written");
    let root = doc.root.expect("root section present");
    assert_eq!(root.per_request_fee, Some(7));

    // The version bumped (a live swap happened).
    let after: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        after["config_version"].as_u64().unwrap() > v_before,
        "the PUT bumped the config version"
    );

    // RESTART EQUIVALENT: re-run the BOOT disk-load pipeline (the exact path a fresh process takes)
    // and confirm the overlay root re-merges onto the base DeployCfg — the settings survive a
    // restart. (`config/reload` over HTTP resolves the overlay path from the `BUSBAR_CONFIG_OVERLAY`
    // env var, which the direct-App test harness does not set; this asserts the same merge that boot
    // performs, without a process-global env var that would race parallel tests.)
    {
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        let mut loaded = crate::load_config_from_disk(
            &config_path,
            Some(&providers_path),
            false,
            crate::config::EnvSubst::Strict,
        )
        .expect("disk reload");
        // Simulate the env-derived overlay read (boot reads it via BUSBAR_CONFIG_OVERLAY).
        loaded.overlay_doc = crate::config::overlay::read(&overlay);
        assert_eq!(
            loaded.deploy.per_request_fee, 0,
            "base config.yaml has no fee (the override lives only in the overlay)"
        );
        if let Some(doc) = loaded.overlay_doc.as_ref() {
            crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
        }
        assert_eq!(
            loaded.deploy.per_request_fee, 7,
            "the root overlay re-merges onto base at boot (survives a restart)"
        );
    }

    // Audited (applied) + version-logged.
    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?action=config.settings"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["resource"] == "config:settings" && e["outcome"] == "applied"),
        "the applied PUT is audited"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// FULL restart-simulation at the BOOT-RESOLVED DEFAULT overlay path: boot-with-defaults (no
/// `config.overlay`, no env var) → a REAL admin-API `PUT /config/settings` → a fresh
/// `load_config_from_disk` (the exact path a restarted process takes) re-reads the mutation, WITHOUT
/// the test manually substituting `overlay_doc`. This closes the gap the round-trip test leaves: it
/// proves boot's OWN resolved overlay path (`busbar-overlay.json` next to config.yaml) is the SAME
/// file the serving App persists mutations to — a divergence between the two would be invisible to a
/// test that hand-feeds `overlay_doc` from a path it chose itself.
///
/// If `load_config_from_disk`'s default-overlay resolution and the App's serving
/// overlay path ever diverge (or resolution regresses to `None`/RAM-only), the freshly-loaded
/// `overlay_doc` is absent and the `per_request_fee` assertion fails.
#[tokio::test]
async fn test_admin_v1_config_settings_survives_a_real_boot_reload_at_default_overlay() {
    crate::metrics::init();
    let (dir, config_path, providers_path) = write_reset_fixture("boot-default-overlay");
    // The App persists to the SAME path `load_config_from_disk` resolves by default (no `config.overlay`
    // in config.yaml, no `BUSBAR_CONFIG_OVERLAY`): `busbar-overlay.json` next to config.yaml.
    let default_overlay = dir.join("busbar-overlay.json");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(default_overlay.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 9 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);

    // A FRESH boot disk-load — no `overlay_doc` hand-substitution. It must resolve the default overlay
    // path ITSELF and read back the mutation the running App just persisted there.
    let loaded = crate::load_config_from_disk(
        &config_path,
        Some(&providers_path),
        false,
        crate::config::EnvSubst::Strict,
    )
    .expect("fresh boot disk-load");
    assert_eq!(
        loaded.overlay_path.as_deref(),
        Some(default_overlay.as_path()),
        "boot must resolve the SAME default overlay path the App persists to"
    );
    let root = loaded
        .overlay_doc
        .as_ref()
        .and_then(|d| d.root.as_ref())
        .expect("the fresh boot load reads the overlay root the admin PUT wrote");
    assert_eq!(
        root.per_request_fee,
        Some(9),
        "the admin mutation survives a real boot reload at the boot-resolved default path"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// PROCESS-LEVEL flagging: a `PUT` touching a socket-rebind field (`listen`) and the durable `store`
/// backend stores them durably but flags them `reload_to_apply` (they cannot hot-swap), while a
/// live-swappable field in the SAME request is not flagged. The note explains the split.
#[tokio::test]
async fn test_admin_v1_config_settings_process_level_flagged_reload_to_apply() {
    let (dir, overlay, addr, handle) = settings_test_app("proclevel").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "listen": "127.0.0.1:0",
                "store": { "module": "memory" },
                "per_request_fee": 3
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        flagged.contains(&"listen") && flagged.contains(&"store"),
        "process-level binds flagged reload-to-apply: {flagged:?}"
    );
    assert!(
        !flagged.contains(&"per_request_fee"),
        "a live-swappable field is NOT flagged: {flagged:?}"
    );
    assert!(
        body["note"].as_str().unwrap().contains("reload"),
        "the note explains the reload-to-apply split"
    );
    // But they ARE durably stored (the overlay carries the new listen).
    let doc = crate::config::overlay::read(&overlay).expect("overlay written");
    assert_eq!(
        doc.root.unwrap().listen.as_deref(),
        Some("127.0.0.1:0"),
        "the reload-to-apply field is still durably persisted"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `main.rs`'s `UpstreamClients` is REUSED across a config apply (warm connection
/// pools are deliberately kept) — its `else` builder arm is the ONLY place
/// `pool_max_idle_per_host` / `pool_idle_timeout_secs` / `upstream_request_timeout_secs` are read, so
/// changing them via `PUT /config/settings` is silently boot-scoped. `reload_to_apply_fields` did not
/// flag them, so the endpoint returned `reload_to_apply: []` and a `note` saying "applied live" for a
/// change that changes nothing at runtime — a false success. Assert the field IS flagged (dotted,
/// since `limits` is a nested `Option` section, not a top-level one — flagging bare `"limits"` would
/// wrongly also mark the genuinely-live `request_body_max_bytes` as restart-scoped).
#[tokio::test]
async fn test_admin_v1_config_settings_boot_scoped_limits_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle) = settings_test_app("bootscopedlimits").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "limits": { "pool_max_idle_per_host": 16 }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        flagged.contains(&"limits.pool_max_idle_per_host"),
        "a boot-scoped UpstreamClients field must be flagged reload-to-apply, not silently \
         'applied live': {flagged:?}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `limits.max_inbound_concurrent` is frozen by a DIFFERENT mechanism than the `UpstreamClients`
/// reuse above: `main.rs` captures it ONCE in `main()` and bakes it into a
/// `tower::limit::GlobalConcurrencyLimitLayer` on the DATA ROUTER at process start. A config apply
/// swaps only `Arc<App>` (`AppHandle::swap`) — the router, and therefore the semaphore's permit
/// count, is never rebuilt. `reload_to_apply_fields` did not flag it, so a
/// `PUT {"limits":{"max_inbound_concurrent":512}}` returned `reload_to_apply: []` and a note saying
/// "applied live" for a change that changes nothing at runtime until a restart — the exact
/// false-success class the sibling `UpstreamClients` fields were already fixed for. Assert the field
/// IS flagged (dotted, its own mechanism, deserving its own regression separate from the
/// `UpstreamClients` test above).
#[tokio::test]
async fn test_admin_v1_config_settings_max_inbound_concurrent_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle) = settings_test_app("maxinboundconcurrent").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "limits": { "max_inbound_concurrent": 512 }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        flagged.contains(&"limits.max_inbound_concurrent"),
        "the router-level GlobalConcurrencyLimitLayer is boot-frozen and must be flagged \
         reload-to-apply, not silently 'applied live': {flagged:?}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `observability` section is live EXCEPT two fields: the `advanced.response_headers` block
/// (formerly `observability.emit_server_timing`) is boot-frozen the same way — baked into router
/// middleware composition and a process-global `OnceLock`, neither rebuilt by a config apply — so it
/// must be flagged reload-to-apply (dotted, same reasoning as `limits.*`).
#[tokio::test]
async fn test_admin_v1_config_settings_boot_scoped_observability_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle) = settings_test_app("bootscopedobs").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "advanced": {
                    "response_headers": { "server_timing": true, "route_policy": true }
                }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        flagged.contains(&"advanced.response_headers"),
        "router-baked middleware state / OnceLock-seeded response-header toggles must be flagged \
         reload-to-apply: {flagged:?}"
    );
    // 1.5.3: the whole `observability:` block is DELETED — the request-log webhook and
    // the OTLP trace sink are both named `export:` instances now, edited in config.yaml and applied
    // via plugin reload, so neither is part of the single-value settings surface at all. Assert the
    // section is REJECTED rather than silently accepted-and-ignored.
    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "observability": { "otlp_url": "https://o:4317" } }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the DELETED observability section must be rejected, never silently ignored"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// PARTIAL UPDATE: a second `PUT` naming only `per_request_fee` preserves the earlier `rate_card`
/// A store secret reference that does not resolve HERE must not be rejected. The store is
/// restart-to-apply, so staging a ref whose secret the orchestrator mounts on the next deploy is a
/// legitimate workflow — and `tls`, the block beside it with the identical failure mode, already
/// accepts exactly that. The operator gets a loud warn naming the field and the restart
/// consequence; rejecting instead would make a config they can legally write into `config.yaml`
/// un-PUT-able.
#[tokio::test]
async fn test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects() {
    let (dir, overlay, addr, handle) = settings_test_app("storesecret").await;
    let client = reqwest::Client::new();
    let var = format!("BUSBAR_TEST_STORE_SECRET_MISSING_{}", std::process::id());
    std::env::remove_var(&var);

    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": { "module": "memory", "settings": { "licenseKey": { "env": var } } }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let st = put.status().as_u16();
    let body = put.text().await.unwrap_or_default();
    assert_eq!(
        st, 200,
        "an unresolvable store ref is staged, not refused: {body}"
    );

    // And it is persisted, so the next restart uses it — which is the point of staging.
    let doc = crate::config::overlay::read(&overlay).expect("overlay written");
    assert!(
        doc.root
            .as_ref()
            .and_then(|r| r.store.as_ref())
            .is_some_and(|s| s.settings.contains_key("licenseKey")),
        "the staged reference reaches the overlay"
    );

    handle.abort();
    drop(dir);
}

/// override (partial-merge semantics, like a group PATCH).
#[tokio::test]
async fn test_admin_v1_config_settings_partial_update_preserves_prior() {
    let (dir, _overlay, addr, handle) = settings_test_app("partial").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "rate_card": { "m0": { "input_utok": 9.0 } } }).to_string())
        .send()
        .await
        .unwrap();
    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 5 }).to_string())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(body["settings"]["per_request_fee"], 5, "new field set");
    assert!(
        body["settings"]["rate_card"]["m0"].is_object(),
        "the earlier rate_card override is preserved by the partial update"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// RESET: `DELETE /overlay/root` discards the root overrides and reverts to base config.yaml — the
/// overlay `root` section is cleared on disk (the sibling hooks/groups sections would survive).
/// SERIALISES the three tests that assert on `AUDIT` rows for the `overlay:root` resource.
///
/// `AUDIT` is a PROCESS-WIDE ring and `resource: "overlay:root"` is a fixed literal every
/// overlay-reset test shares — that literal is production behaviour, not a test artifact, so it
/// cannot be made unique per test without changing what an operator sees.
///
/// Bracketing by `seq` was the previous fix and it is not sufficient: it excludes rows written
/// BEFORE a test starts, but a sibling running CONCURRENTLY can land its own legitimate APPLIED row
/// between this test's two REJECTED rows, and the "never APPLIED" assertion then fails on a tree
/// with nothing wrong with it. That is what made this an intermittent red rather than a real one.
///
/// A TOKIO mutex, not a `std` one, and that is not a preference. The guard is held across `.await`
/// points — the HTTP calls that sit between taking it and reading the ring — and a
/// `std::sync::MutexGuard` held across an await can deadlock when the task is moved between runtime
/// threads. Clippy's `await_holding_lock` caught exactly that on the first version of this guard.
/// Tokio's mutex is await-aware and has no poisoning, so there is nothing to recover from either.
static OVERLAY_ROOT_AUDIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn test_admin_v1_config_settings_reset_reverts_to_base() {
    // Taken FIRST, before any HTTP. This test performs a LEGITIMATE applied reset, and its row is
    // the one that was landing inside a sibling's window as `seq: 4, outcome: "applied"`. Guarding
    // only the readers was not enough: the writer has to be inside the same critical section, or it
    // simply writes while a reader is mid-window.
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle) = settings_test_app("reset").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        crate::config::overlay::read(&overlay)
            .and_then(|d| d.root)
            .is_some(),
        "root override present before reset"
    );

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "root");
    assert_eq!(
        body["changed"], true,
        "the reset discarded the root override"
    );

    // Root section cleared on disk; GET reflects base (empty overrides).
    assert!(
        crate::config::overlay::read(&overlay)
            .and_then(|d| d.root)
            .is_none(),
        "the overlay root section is cleared"
    );
    let after: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        after["settings"]["per_request_fee"].is_null(),
        "no root override after reset (base config.yaml stands)"
    );

    // A second reset is an idempotent no-op (changed:false).
    let again: serde_json::Value =
        admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        again["changed"], false,
        "an already-empty root reset is a no-op"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reset pre-flight probe (`overlay_empty`) must NOT treat a CORRUPT overlay as "no overlay
/// state" — that short-circuits to a `200 changed:false` + `OUTCOME_APPLIED` audit row without ever
/// running the fail-closed `clear_section`, which every sibling durable-write path on an unreadable
/// overlay refuses. Write a non-empty root override first (so the overlay exists), then corrupt the
/// file bytes and reset — the corruption must be REFUSED (400), not silently reported as an
/// idempotent no-op.
#[tokio::test]
async fn test_admin_v1_config_settings_reset_refuses_when_overlay_is_corrupt() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle) = settings_test_app("reset-corrupt").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // Bracket by seq, not just by action/resource: `AUDIT` is a process-wide ring, and
    // `resource: "overlay:root"` is a FIXED literal every overlay-reset test shares (see the
    // sibling `..._is_too_new` test right below, which resets the same `overlay:root` resource) --
    // so a concurrently-running sibling's legitimate APPLIED reset can land between this test's own
    // two REJECTED rows and fail the "never APPLIED" assertion. Same pattern as
    // `test_admin_v1_restart_refuses_when_it_cannot_restart`'s baseline_seq bracketing.
    let baseline_seq = crate::admin::audit::AUDIT
        .list(1)
        .first()
        .map(|e| e.seq)
        .unwrap_or(0);

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        crate::config::overlay::read(&overlay)
            .and_then(|d| d.root)
            .is_some(),
        "root override present before corrupting the overlay"
    );

    std::fs::write(&overlay, b"{ not json").unwrap();

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        400,
        "a reset probe over a corrupt overlay must refuse, not report a false no-op: {:?}",
        reset.text().await
    );

    let rows: Vec<_> = crate::admin::audit::AUDIT
        .list_filtered(
            0,
            crate::admin::audit::MAX_AUDIT_ENTRIES,
            None,
            Some("overlay:root"),
        )
        .into_iter()
        .filter(|e| e.seq > baseline_seq)
        .collect();
    assert!(
        rows.iter()
            .any(|e| e.action == "overlay.reset"
                && e.outcome == crate::admin::audit::OUTCOME_REJECTED),
        "the corrupt-overlay reset must be audited as REJECTED, never APPLIED: {rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.action == "overlay.reset"
                && e.outcome == crate::admin::audit::OUTCOME_APPLIED),
        "a corrupt-overlay reset must never be recorded as a successful apply: {rows:?}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same probe, the OTHER non-`Absent` classification: an overlay written by a NEWER busbar than
/// this one is intact and meaningful (unlike `Unreadable`), and `load_config_from_disk` already
/// refuses to boot on one (`main.rs`). The reset pre-flight probe must not paper over that refusal
/// with a false `changed:false`.
#[tokio::test]
async fn test_admin_v1_config_settings_reset_refuses_when_overlay_is_too_new() {
    // Held even though this test ASSERTS on no audit rows: it still WRITES one, by resetting the
    // same process-wide `overlay:root` resource its two siblings read. An unguarded writer is just
    // as good at landing an `applied` row inside a reader's window as an unguarded reader is at
    // seeing one -- which is exactly what it did, as `seq: 4, outcome: "applied"`.
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle) = settings_test_app("reset-too-new").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&overlay).unwrap()).unwrap();
    doc["version"] = serde_json::json!(crate::config::overlay::OVERLAY_VERSION + 1);
    std::fs::write(&overlay, serde_json::to_vec(&doc).unwrap()).unwrap();

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        400,
        "a reset probe over a too-new overlay must refuse: {:?}",
        reset.text().await
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `PUT /config/settings` re-resolves `auth.admin_auth`'s admin-token
/// secret ref on every apply and, when it changed, swaps the new digest into the shared,
/// process-lifetime `GovState` — the SAME `GovState` the OLD (still-serving) `App` snapshot also
/// points at. If the transaction's PERSIST step (writing the merged settings to the overlay) fails
/// AFTER that swap, the handler reports "nothing was changed (the running engine is unaffected)" —
/// but the credential rotation must not have already landed on the shared `GovState`, or that
/// message is a lie: the admin token the operator believes is still "admintok-v1" would already be
/// rejected fleet-locally. Forces the persist failure the same deterministic way
/// `test_admin_v1_config_settings_reset_refuses_when_overlay_is_corrupt` does (a corrupt overlay
/// file `load_for_rmw` refuses to read-modify-write).
#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-settings-gov-rotate-persist-fail-{}-{}",
        std::process::id(),
        crate::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "admintok-v1").unwrap();
    std::fs::write(
        &providers_path,
        "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_GOV_ROTATE_NO_SUCH_KEY
",
    )
    .unwrap();
    // `auth.admin_auth` DECLARES the admin-tokens module with a file-backed ref — the precondition
    // (main.rs's `declares_admin_tokens`) for `build_app_from_config` to re-resolve and queue a
    // rotation on every apply.
    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:0
providers:
  test-provider:
    api_key: {{ env: BUSBAR_TEST_GOV_ROTATE_NO_SUCH_KEY }}
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
auth:
  admin_auth:
    - admin-tokens: {{ token: {{ file: {token_path:?} }} }}
"
        ),
    )
    .unwrap();
    let overlay = dir.join("overlay.json");
    // Corrupt from the start: `load_for_rmw` refuses an unparseable-but-present overlay, so the
    // apply's persist step (`overlay::persist_root`) fails deterministically every time.
    std::fs::write(&overlay, b"{ not json").unwrap();

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok-v1".to_string()));
    let before_hash = gov.admin_token_hash();
    let mut app = TestApp::new()
        .governance(gov.clone())
        .overlay_path(overlay.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // THE ROTATION INPUT: the secret behind the ref changes BEFORE the apply that will re-resolve
    // it — exactly the operational sequence this supports (rotate the file, then apply).
    std::fs::write(&token_path, "admintok-v2").unwrap();

    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok-v1")
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the corrupt overlay must fail the persist step: {:?}",
        put.text().await
    );

    assert_eq!(
        gov.admin_token_hash(),
        before_hash,
        "a persist failure must leave the shared GovState's admin-token digest untouched — the \
         response just claimed nothing was changed, and this is the process-lifetime object the \
         OLD (still-serving) App snapshot also points at"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `GET /config/settings` on a corrupt/unreadable overlay renders `settings: {}` (the honest
/// "no overrides visible" answer given the fail-soft `read`), but the misreport must be
/// ATTRIBUTABLE to THIS read — a generic `overlay.rs` warn is not enough, because a reader can't
/// tell which of the many overlay-reading endpoints produced it. Drives the handler directly
/// (not over HTTP) so the thread-local `WarnCapture` subscriber sees the synchronous warn.
#[test]
fn test_get_config_settings_warns_when_overlay_is_unreadable() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = std::env::temp_dir().join(format!(
        "busbar-get-settings-corrupt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = dir.join("overlay.json");
    std::fs::write(&overlay, b"{ not json").unwrap();

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = None;
        inner.providers_path = None;
    }
    let handle = std::sync::Arc::new(crate::state::AppHandle::new(app));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let resp = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(crate::admin::v1::json::get_config_settings(
            axum::extract::State(handle),
        ))
    });
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a corrupt overlay must not brick the read; it renders no overrides"
    );

    assert!(
        cap.contains("/config/settings"),
        "GET /config/settings on a corrupt overlay must emit a warn naming THIS endpoint, not just \
         overlay.rs's generic boot-time warn: {:?}",
        cap.messages()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ETAG / If-Match: a stale `If-Match` on the PUT is a 409 version_conflict that changes nothing.
#[tokio::test]
async fn test_admin_v1_config_settings_stale_if_match_conflicts() {
    let (dir, _overlay, addr, handle) = settings_test_app("ifmatch").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // A wildly-stale version number.
    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .header("if-match", "\"999999\"")
        .body(serde_json::json!({ "per_request_fee": 1 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match is a conflict");
    let body: serde_json::Value = stale.json().await.unwrap();
    assert_eq!(body["error"]["code"], "version_conflict");

    // A GET emits the config-plane ETag a caller chains off.
    let get = admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
        .send()
        .await
        .unwrap();
    assert!(
        get.headers().get("etag").is_some(),
        "GET /config/settings carries the config-plane ETag"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A typo'd root field is a loud 400 (deny_unknown_fields), audited as rejected — never a silent
/// no-op. An invalid config after merge would likewise 400 and change nothing.
#[tokio::test]
async fn test_admin_v1_config_settings_unknown_field_400() {
    let (dir, _overlay, addr, handle) = settings_test_app("badfield").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let bad = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "lissten": "0.0.0.0:9000" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "a typo'd field is rejected");
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same fixture as `settings_test_app`, but a LOCKED app (1.5.3: `config.locked: true` ⇒ no overlay
/// backend, `overlay_path: None`), while config/providers files still exist on disk (so the separate
/// ephemeral-mode guard does not fire first). A locked config refuses every admin-API config mutation.
async fn settings_test_app_no_overlay(
    tag: &str,
) -> (
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    crate::metrics::init();
    let (dir, config_path, providers_path) = write_reset_fixture(&format!("settings-no-ov-{tag}"));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new().governance(gov).no_overlay().build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (dir, addr, handle)
}

/// 1.5.3 (was "reports in memory only"): the OLD behavior — a PUT on a busbar with no overlay applied
/// LIVE, IN MEMORY ONLY (200) — is GONE. A config with no overlay backend is now a LOCKED config, and
/// a locked config REFUSES the mutation (400). The silent non-durable-mutation outcome this test used
/// to assert is exactly what the release removes, so the test is inverted: it now proves the refusal.
///
/// On the pre-1.5.3 code this asserted a 200 with an "IN MEMORY ONLY" note; the new
/// assertion (400 refusal) fails there, and passes only once the locked/durable model is in place.
#[tokio::test]
async fn test_admin_v1_config_settings_put_on_locked_config_is_refused() {
    let (dir, addr, handle) = settings_test_app_no_overlay("truthful").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "listen": "127.0.0.1:0" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 400, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("config.locked") || msg.contains("no writable config overlay"),
        "the refusal must explain the locked/no-overlay posture: {body}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.3: `"persist": true` on a LOCKED config must REFUSE (400) naming the locked/overlay posture —
/// not the old `BUSBAR_CONFIG_OVERLAY` precondition, and NOT the `deny_unknown_fields` 400 (`persist`
/// is stripped before the typed parse). The assertion is on the message, since the status alone does
/// not discriminate.
#[tokio::test]
async fn test_admin_v1_config_settings_put_refuses_when_persistence_is_explicitly_requested_and_unavailable(
) {
    let (dir, addr, handle) = settings_test_app_no_overlay("refuse").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "listen": "127.0.0.1:0", "persist": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 400, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("config.locked") || msg.contains("no writable config overlay"),
        "the refusal must name the locked/no-overlay posture, not just be a generic 400: {body}"
    );
    assert!(
        !msg.contains("unknown field"),
        "this must be the locked-config refusal, not the OLD deny_unknown_fields 400 \
         that fires on this body today: {body}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The positive half of case 3: `"persist": true` WITH an overlay present must still persist
/// exactly as an implicit persist does today.
#[tokio::test]
async fn test_admin_v1_config_settings_put_with_persist_true_still_persists_when_overlay_exists() {
    let (dir, overlay, addr, handle) = settings_test_app("persist-true").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 7, "persist": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let on_disk = crate::config::overlay::read(&overlay)
        .and_then(|d| d.root)
        .expect("root section persisted");
    assert_eq!(
        on_disk.per_request_fee,
        Some(7),
        "persist:true with an overlay present stores the value on disk"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `"persist"` rejects a non-boolean — the message must name it, discriminating from the OLD
/// `unknown field` 400 the same body triggers today (status alone does not discriminate here
/// either, since both are 400s).
#[tokio::test]
async fn test_admin_v1_config_settings_put_rejects_a_non_boolean_persist() {
    let (dir, addr, handle) = settings_test_app_no_overlay("nonbool").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "persist": "yes" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 400, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("persist") && msg.contains("boolean"),
        "the refusal must name `persist` as needing a boolean: {body}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// REGRESSION PROOF (passes before AND after): stripping `persist` before the typed parse must NOT
/// weaken `deny_unknown_fields` — a TYPO of the control key is still a loud 400, which is the whole
/// justification for choosing a body field over a query param (the in-tree
/// `Query<HashMap<String,String>>` idiom drops unknown keys silently).
#[tokio::test]
async fn test_admin_v1_config_settings_put_still_rejects_an_unknown_field_including_persist_typo() {
    let (dir, addr, handle) = settings_test_app_no_overlay("typo").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "persits": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 400, "{:?}", put.text().await);
    let body: serde_json::Value = put.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("unknown field"),
        "a typo of `persist` must still be an unknown-field 400, not a silently-ignored request: \
         {body}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `persist_root(None, ..)` (the default-deployment no-op) must log. It used to return a
/// silent `Ok` with a warning — the exact lie ("saved" for a change that vanishes on restart) 1.5.3
/// removes. It now returns `Err`, so a locked config's mutation is refused rather than
/// falsely reported durable.
///
/// The pre-1.5.3 code returned `Ok` here, so this `is_err()` assertion fails there;
/// it passes only once the lying no-op branch is gone.
#[test]
fn test_persist_root_without_an_overlay_errs() {
    let result = crate::config::overlay::persist_root(
        None,
        &crate::config::overlay::RootSettings::default(),
    );
    assert!(
        result.is_err(),
        "persist_root(None, ..) must NOT silently succeed — a None backend means a locked config, so \
         the mutation is refused, never falsely reported as persisted"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("config.locked") || msg.contains("no writable config overlay"),
        "the error must explain the locked/no-overlay posture: {msg}"
    );
}

/// SCOPE: `PUT /config/settings` is a FULL-scope mutation (the config-plane fallthrough), `GET` is
/// read-only — the matrix the middleware enforces.
#[test]
fn test_config_settings_scope_matrix() {
    use axum::http::Method;
    assert_eq!(
        crate::admin::v1::contract::required_scope(&Method::PUT, "/api/v1/admin/config/settings")
            .as_str(),
        "full",
        "PUT /config/settings is a full-scope mutation"
    );
    assert_eq!(
        crate::admin::v1::contract::required_scope(&Method::GET, "/api/v1/admin/config/settings")
            .as_str(),
        "read-only",
        "GET /config/settings is read-only"
    );
    // And `root` is a valid reset section requiring full scope.
    assert_eq!(
        crate::admin::v1::contract::required_scope(&Method::DELETE, "/api/v1/admin/overlay/root")
            .as_str(),
        "full",
        "a root reset is a full-scope mutation"
    );
}

// ── KEYS ERROR SURFACE — BYTE-PARITY LOCK ────────────────────────────────────────────────────────
//
// The keys handlers historically spoke their OWN error vocabulary (`error_response` + `ERR_TYPE_*`,
// re-mapped onto the frozen `code` enum in a second place) while every other v1 handler spoke
// `AdminError` + `err_json`. That second vocabulary is collapsed onto the one
// taxonomy. The collapse must be INVISIBLE on the wire: this test pins the EXACT status,
// content-type and body BYTES of every keys error path, so the refactor is provably a no-op for
// clients and any future divergence between the two surfaces is a red test, not a support ticket.
//
// Regenerate deliberately with `UPDATE_KEYS_ERROR_GOLDEN=1 cargo test -p busbar
// keys_error_surface_is_byte_stable` — a diff in that file is a WIRE CHANGE on a frozen surface.

/// The governance posture a keys error case is exercised against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeysFixture {
    /// Governance on, signing key present — the normal server.
    Signing,
    /// Governance on, NO signing key — mint and signing-key rotate have nothing to sign with.
    NoSigner,
    /// Governance off entirely — the whole keys resource is unavailable.
    Off,
}

/// One pinned keys error case: a request, and the fixture it runs against.
struct KeysErrCase {
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,
    /// Path relative to `/api/v1/admin`; `{live}` is substituted with the id of a minted key.
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
}

/// The committed byte-for-byte snapshot of the keys error wire.
const KEYS_ERROR_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/admin/tests/keys_error_wire.json"
);

/// Serve one fixture, returning its address, the server task, and the id of a live key (empty for
/// the postures that cannot mint).
async fn serve_keys_fixture(
    fixture: KeysFixture,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, String) {
    let store: Arc<dyn crate::governance::Store> = Arc::new(MemoryStore::new());
    let app = match fixture {
        KeysFixture::Signing => {
            let gov = gov_with_signer(store, Some("admintok".to_string()));
            TestApp::new().governance(gov).build()
        }
        KeysFixture::NoSigner => {
            let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
            TestApp::new().governance(gov).build()
        }
        // Governance OFF: there is no governance to hold an operator token, so the fixture uses
        // the explicit `admin_auth: []` OPEN posture (the documented dev posture) to authenticate.
        // Otherwise every case would 401 in the middleware and never reach a keys handler.
        KeysFixture::Off => {
            let cfg = crate::config::AuthCfg {
                admin_auth: Vec::new(),
                ..crate::config::AuthCfg::default_none()
            };
            TestApp::new()
                .auth(Arc::new(crate::auth::AuthMiddleware::new_builtin(&cfg)))
                .admin_chain(Vec::new())
                .build()
        }
    };
    let router = crate::build_router(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    // A live key id for the stale-ETag cases (only mintable on the signing fixture).
    let live = if fixture == KeysFixture::Signing {
        let (key, _) = app
            .governance
            .as_ref()
            .unwrap()
            .mint_signed(
                NewKeySpec {
                    name: "live".into(),
                    allowed_pools: None,
                    group: None,
                    labels: Default::default(),
                },
                crate::store::now() + 3600,
                crate::store::now(),
            )
            .unwrap();
        key.id
    } else {
        String::new()
    };
    (addr, handle, live)
}

/// BYTE-PARITY LOCK: every keys error response — status, content-type and body
/// BYTES — is pinned. The keys surface is frozen v1; collapsing its private error vocabulary onto
/// `AdminError` + `err_json` may change how the bytes are PRODUCED, never what they ARE.
#[tokio::test]
async fn keys_error_surface_is_byte_stable() {
    drive_keys_error_surface().await;
}

/// Drive every pinned keys error path and assert the wire is byte-identical to the golden. Split
/// out of the `#[tokio::test]` so the class-level over-claim test can RUN it (and collect its
/// emissions) without depending on test ordering.
async fn drive_keys_error_surface() {
    crate::metrics::init();
    // A 65-character id (the cap is 64) and an id that cannot exist.
    const OVERLONG: &str = "vk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MISSING: &str = "vk_0000000000000000";
    // A well-formed but WRONG key ETag (16 hex chars) — the stale-If-Match guard, not the parser.
    const STALE_ETAG: &str = "\"00000000000000ff\"";
    let cases: &[KeysErrCase] = &[
        // ── GET /keys — the query string is validated at the door ─────────────────────────────
        c(
            "list_bad_cursor",
            KeysFixture::Signing,
            "GET",
            "/keys?cursor=%21%21",
            &[],
            None,
        ),
        c(
            "list_bad_enabled",
            KeysFixture::Signing,
            "GET",
            "/keys?enabled=maybe",
            &[],
            None,
        ),
        c(
            "list_bad_limit",
            KeysFixture::Signing,
            "GET",
            "/keys?limit=lots",
            &[],
            None,
        ),
        // ── POST /keys ────────────────────────────────────────────────────────────────────────
        c(
            "mint_bad_json",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some("{"),
        ),
        c(
            "mint_reserved_label",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","labels":{"key":"v"}}"#),
        ),
        c(
            "mint_both_expiry_fields",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1h","expires_at":9999999999}"#),
        ),
        c(
            "mint_bad_duration",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1x"}"#),
        ),
        c(
            "mint_expires_in_the_past",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_at":1}"#),
        ),
        c(
            "mint_parent_without_group",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","parent":"team"}"#),
        ),
        c(
            "mint_unknown_group_no_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"nope"}"#),
        ),
        c(
            "mint_unknown_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"leaf","parent":"nope"}"#),
        ),
        c(
            "mint_no_signing_key",
            KeysFixture::NoSigner,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        c(
            "mint_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        // ── GET /keys/{id} ────────────────────────────────────────────────────────────────────
        c(
            "read_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "read_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "read_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        // ── PATCH /keys/{id} ──────────────────────────────────────────────────────────────────
        c(
            "patch_overlong_id",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{overlong}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_malformed_if_match",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            Some("{}"),
        ),
        c(
            "patch_bad_json",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{"),
        ),
        c(
            "patch_rebind_target_missing",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some(r#"{"group":"nope"}"#),
        ),
        c(
            "patch_unknown",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_stale_etag",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            Some("{}"),
        ),
        c(
            "patch_governance_off",
            KeysFixture::Off,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        // ── DELETE /keys/{id} ─────────────────────────────────────────────────────────────────
        c(
            "delete_overlong_id",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "delete_malformed_if_match",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            None,
        ),
        c(
            "delete_unknown",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "delete_stale_etag",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            None,
        ),
        c(
            "delete_governance_off",
            KeysFixture::Off,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        // ── GET /keys/{id}/usage ──────────────────────────────────────────────────────────────
        c(
            "usage_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}/usage",
            &[],
            None,
        ),
        c(
            "usage_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        c(
            "usage_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        // ── POST /keys/{id}/rotate ────────────────────────────────────────────────────────────
        c(
            "rotate_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        c(
            "rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        // ── POST /keys/{id}/revoke ────────────────────────────────────────────────────────────
        c(
            "revoke_overlong_id",
            KeysFixture::Signing,
            "POST",
            "/keys/{overlong}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        // ── POST /signing-key/rotate ──────────────────────────────────────────────────────────
        c(
            "signing_rotate_no_key",
            KeysFixture::NoSigner,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
        c(
            "signing_rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
    ];

    let client = reqwest::Client::new();
    let mut observed = serde_json::Map::new();
    for fixture in [
        KeysFixture::Signing,
        KeysFixture::NoSigner,
        KeysFixture::Off,
    ] {
        let (addr, server, live) = serve_keys_fixture(fixture).await;
        for case in cases.iter().filter(|c| c.fixture == fixture) {
            let path = case
                .path
                .replace("{overlong}", OVERLONG)
                .replace("{missing}", MISSING)
                .replace("{live}", &live);
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(case.method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{path}"),
                )
                .header("x-admin-token", "admintok");
            for (k, v) in case.headers {
                req = req.header(*k, *v);
            }
            if let Some(body) = case.body {
                req = req
                    .header("content-type", "application/json")
                    .body(body.to_string());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = resp.text().await.unwrap();
            assert!(
                (400..600).contains(&status),
                "{} expected an error response, got {status}: {body}",
                case.name
            );
            observed.insert(
                case.name.to_string(),
                serde_json::json!({"status": status, "content_type": content_type, "body": body}),
            );
        }
        server.abort();
    }

    let fresh = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::Value::Object(observed))
            .expect("serialize keys error wire")
    );
    if std::env::var("UPDATE_KEYS_ERROR_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(KEYS_ERROR_GOLDEN, &fresh)
            .unwrap_or_else(|e| panic!("write {KEYS_ERROR_GOLDEN}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(KEYS_ERROR_GOLDEN)
        .unwrap_or_else(|e| panic!("read {KEYS_ERROR_GOLDEN}: {e}"));
    assert_eq!(
        committed, fresh,
        "the keys error WIRE changed — status/content-type/body bytes on a FROZEN surface. If this \
         is deliberate, regenerate with `UPDATE_KEYS_ERROR_GOLDEN=1`."
    );
}

/// Terse constructor for a [`KeysErrCase`] row.
const fn c(
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
) -> KeysErrCase {
    KeysErrCase {
        name,
        fixture,
        method,
        path,
        headers,
        body,
    }
}

// ── WITNESS DRIVER FOR THE DECLARED ERROR SET ─────────────────────────────────────────────────────
//
// `contract::taxonomy::declared_errors` is what `openapi.json` documents. Under-claim (a handler
// emits a kind the declaration omits) is already fatal on the spot — the v1 router's recording layer
// panics inside whichever test triggered it. OVER-claim (the declaration lists a response no handler
// can produce) has no such moment: it needs a WITNESS. This test is the driver that produces one for
// every declared entry the rest of the suite does not already exercise, so
// `declared_error_set_has_no_over_claim` (in the json tests) can assert that every documented error
// is a real one. A declared 409 nobody can trigger is a lie in the contract; this is how it stays
// impossible to keep.

/// Drive the non-keys admin error paths that the rest of the suite leaves unexercised: the group
/// CRUD errors, the version-guard errors on every If-Match-guarded mutation, the list-GET query
/// rejections and the config-plane read errors. Assertions are deliberately thin (status + code) —
/// the POINT of the test is the emission, which the router's recording layer witnesses.
#[tokio::test]
async fn admin_error_surface_witnesses_every_declared_response() {
    drive_admin_error_surface().await;
}

/// Build a FRESH admin fixture for the error-surface driver: a base-config group (`team`) and hook
/// (`basehook`) — file-owned, so the `conflict` base-defined arms are reachable — plus an OVERLAY
/// group (`og`) and hook (`oh`) created over the API, for the arms that must NOT hit the
/// base-defined guard. Returns the address and the server task.
///
/// Each batch of cases gets its own fixture: the admin surface enforces a per-principal, per-class
/// MUTATION BUDGET (10/min for the config plane), and a driver that exercises every declared error
/// blows straight through it. A fresh App carries a fresh limiter, so the batching keeps the driver
/// exercising HANDLERS rather than the rate limiter.
async fn admin_error_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .group(
            "team",
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![],
                child_default: None,
            },
        )
        .base_hook(
            "basehook",
            crate::config::HookCfg {
                kind: crate::config::HookKind::Gate,
                plugin: "test-hook".to_string(),
                timeout_ms: 25,
                on_error: "reject".to_string(),
                prompt: crate::config::PromptAccess::No,
                user: crate::config::UserAccess::No,
                priority: 0,
                at: None,
                settings: serde_json::Map::new(),
                on_empty: None,
                global: false,
                default: false,
                signals: Vec::new(),
                groups: Vec::new(),
                phase: Vec::new(),
            },
        )
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    for (rel, body) in [
        (
            "/groups",
            r#"{"name":"og","config":{"parent":"team","limits":[]}}"#,
        ),
        (
            "/hooks",
            r#"{"name":"oh","config":{"kind":"gate","plugin":"test-hook"}}"#,
        ),
    ] {
        let created = client
            .post(format!("http://{addr}/api/v1/admin{rel}"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201, "fixture: POST {rel}");
    }
    (addr, server)
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_admin_error_surface() {
    crate::metrics::init();
    // A syntactically valid but WRONG config-plane ETag — the stale guard, not the parser.
    const STALE: &str = "\"999999\"";
    const BAD_ETAG: &str = "not-an-etag";
    let group_body = r#"{"config":{"limits":[]}}"#;
    // (label, method, rel, if-match, body, expected status, expected code)
    /// One driven error case: (label, method, relative path, `If-Match`, body, expected status,
    /// expected frozen `code`).
    type ErrCase = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        u16,
        &'static str,
    );
    let cases: &[ErrCase] = &[
        // ── POST /groups ──────────────────────────────────────────────────────────────────────
        (
            "groups_post_invalid_tree",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"x","config":{"parent":"ghost","limits":[]}}"#),
            400,
            "invalid_request",
        ),
        (
            "groups_post_base_defined",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"team","config":{"limits":[]}}"#),
            409,
            "conflict",
        ),
        (
            "groups_post_stale",
            "POST",
            "/groups",
            Some(STALE),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            409,
            "version_conflict",
        ),
        (
            "groups_post_bad_if_match",
            "POST",
            "/groups",
            Some(BAD_ETAG),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            400,
            "invalid_request",
        ),
        // ── PUT /groups/{name} ────────────────────────────────────────────────────────────────
        (
            "groups_put_bad_if_match",
            "PUT",
            "/groups/og",
            Some(BAD_ETAG),
            Some(group_body),
            400,
            "invalid_request",
        ),
        (
            "groups_put_unknown",
            "PUT",
            "/groups/ghost",
            None,
            Some(group_body),
            404,
            "not_found",
        ),
        (
            "groups_put_base_defined",
            "PUT",
            "/groups/team",
            None,
            Some(group_body),
            409,
            "conflict",
        ),
        (
            "groups_put_stale",
            "PUT",
            "/groups/og",
            Some(STALE),
            Some(group_body),
            409,
            "version_conflict",
        ),
        // ── PATCH /groups/{name} ──────────────────────────────────────────────────────────────
        (
            "groups_patch_bad_if_match",
            "PATCH",
            "/groups/og",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "groups_patch_unknown",
            "PATCH",
            "/groups/ghost",
            None,
            Some("{}"),
            404,
            "not_found",
        ),
        (
            "groups_patch_base_defined",
            "PATCH",
            "/groups/team",
            None,
            Some("{}"),
            409,
            "conflict",
        ),
        (
            "groups_patch_stale",
            "PATCH",
            "/groups/og",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "groups_patch_invalid_tree",
            "PATCH",
            "/groups/og",
            None,
            Some(r#"{"parent":"ghost"}"#),
            400,
            "invalid_request",
        ),
        // ── DELETE /groups/{name} ─────────────────────────────────────────────────────────────
        (
            "groups_delete_bad_if_match",
            "DELETE",
            "/groups/og",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "groups_delete_unknown",
            "DELETE",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "groups_delete_base_defined",
            "DELETE",
            "/groups/team",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "groups_delete_stale",
            "DELETE",
            "/groups/og",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        // ── Hooks: the version-guard arms the escalation tests don't reach ─────────────────────
        (
            "hooks_post_stale",
            "POST",
            "/hooks",
            Some(STALE),
            Some(r#"{"name":"h2","config":{"kind":"gate","plugin":"test-hook"}}"#),
            409,
            "version_conflict",
        ),
        (
            "hooks_put_bad_if_match",
            "PUT",
            "/hooks/oh",
            Some(BAD_ETAG),
            Some(r#"{"config":{"kind":"gate","plugin":"test-hook"}}"#),
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_bad_if_match",
            "DELETE",
            "/hooks/oh",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_stale",
            "DELETE",
            "/hooks/oh",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        (
            "hook_settings_bad_if_match",
            "PATCH",
            "/hooks/oh/settings",
            Some(BAD_ETAG),
            Some(r#"{"settings":{}}"#),
            400,
            "invalid_request",
        ),
        (
            "hook_settings_base_defined",
            "PATCH",
            "/hooks/basehook/settings",
            None,
            Some(r#"{"settings":{}}"#),
            409,
            "conflict",
        ),
        (
            "hook_settings_stale",
            "PATCH",
            "/hooks/oh/settings",
            Some(STALE),
            Some(r#"{"settings":{}}"#),
            409,
            "version_conflict",
        ),
        // ── List/read GETs whose query string is rejected at the door ─────────────────────────
        (
            "pools_bad_detail",
            "GET",
            "/pools?detail=maybe",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "usage_bad_window",
            "GET",
            "/usage?window=soon",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "audit_bad_cursor",
            "GET",
            "/audit?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "versions_bad_cursor",
            "GET",
            "/config/versions?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_missing_params",
            "GET",
            "/config/diff",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_unknown_version",
            "GET",
            "/config/diff?from=900&to=901",
            None,
            None,
            404,
            "not_found",
        ),
        // ── Config plane ──────────────────────────────────────────────────────────────────────
        (
            "config_rollback_bad_body",
            "POST",
            "/config/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_rollback_bad_if_match",
            "POST",
            "/config/rollback",
            Some(BAD_ETAG),
            Some(r#"{"version":1}"#),
            400,
            "invalid_request",
        ),
        (
            "config_apply_bad_body",
            "POST",
            "/config/apply",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_settings_bad_if_match",
            "PUT",
            "/config/settings",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_bad_if_match",
            "PUT",
            "/admin-auth",
            Some(BAD_ETAG),
            Some(r#"{"admin_auth":[]}"#),
            400,
            "invalid_request",
        ),
        // ── Plugins ───────────────────────────────────────────────────────────────────────────
        (
            "plugin_rollback_bad_body",
            "POST",
            "/plugins/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_bad_if_match",
            "POST",
            "/plugins/rollback",
            Some(BAD_ETAG),
            Some(r#"{"file":"p.tar.gz"}"#),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_stale",
            "POST",
            "/plugins/rollback",
            Some(STALE),
            Some(r#"{"file":"p.tar.gz"}"#),
            409,
            "version_conflict",
        ),
        // ── Single-resource reads: the 404 every templated GET carries ────────────────────────
        (
            "pool_unknown",
            "GET",
            "/pools/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_unknown",
            "GET",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_health_unknown",
            "GET",
            "/hooks/ghost/health",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_schema_unknown",
            "GET",
            "/hooks/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_status_unknown",
            "GET",
            "/hooks/ghost/status",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_schema_unknown",
            "GET",
            "/plugins/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_unknown",
            "GET",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_usage_unknown",
            "GET",
            "/groups/ghost/usage",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "version_non_numeric",
            "GET",
            "/config/versions/abc",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "version_unknown",
            "GET",
            "/config/versions/999",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_missing_type",
            "GET",
            "/plugins",
            None,
            None,
            400,
            "invalid_request",
        ),
        // ── POST /restart's 3 declared conditions ─────────────────────────────────────────────
        // These 3 have their own dedicated behavioral test (`test_admin_v1_restart_refuses_when_
        // it_cannot_restart`, which also asserts the exact refusal MESSAGE distinguishing the two
        // 409s) -- but that test's witnesses must not be this audit's only source of them, per
        // this function's own doc comment ("independent of whether they [other tests] ran"). Under
        // parallel `cargo test` scheduling there is no guarantee that test's HTTP calls land before
        // this function's caller takes its `observed::snapshot()`, so relying on it alone is a real
        // race, not just a theoretical one -- these 3 rows close it. `can_restart()` is backed by a
        // `OnceLock` never populated in a test binary, so `confirm: true` deterministically reaches
        // the NotRestartable gate regardless of environment; `restart_no_supervisor` forces the
        // unsupervised environment deterministically (see `restart::with_forced_unsupervised`'s doc
        // comment) rather than assuming the real env lacks the supervisor markers -- CI runners were
        // found to genuinely set INVOCATION_ID themselves, which broke that original assumption.
        (
            "restart_malformed_body",
            "POST",
            "/restart",
            None,
            Some(r#"{"confrim": true}"#),
            400,
            "invalid_request",
        ),
        (
            "restart_no_supervisor",
            "POST",
            "/restart",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "restart_not_restartable",
            "POST",
            "/restart",
            None,
            Some(r#"{"confirm": true}"#),
            409,
            "conflict",
        ),
        // ── Hook definition lifecycle ─────────────────────────────────────────────────────────
        (
            "hooks_post_bad_body",
            "POST",
            "/hooks",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_bad_if_match",
            "POST",
            "/hooks",
            Some(BAD_ETAG),
            Some(r#"{"name":"h3","config":{"kind":"gate","plugin":"test-hook"}}"#),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_base_defined",
            "POST",
            "/hooks",
            None,
            Some(r#"{"name":"basehook","config":{"kind":"gate","plugin":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_post_grant_change",
            "POST",
            "/hooks",
            None,
            Some(r#"{"name":"oh","config":{"kind":"tap","plugin":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_put_unknown",
            "PUT",
            "/hooks/ghost",
            None,
            Some(r#"{"config":{"kind":"gate","plugin":"test-hook"}}"#),
            404,
            "not_found",
        ),
        (
            "hooks_put_base_defined",
            "PUT",
            "/hooks/basehook",
            None,
            Some(r#"{"config":{"kind":"gate","plugin":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_put_stale",
            "PUT",
            "/hooks/oh",
            Some(STALE),
            Some(r#"{"config":{"kind":"gate","plugin":"test-hook"}}"#),
            409,
            "version_conflict",
        ),
        (
            "hooks_delete_unknown",
            "DELETE",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hooks_delete_base_defined",
            "DELETE",
            "/hooks/basehook",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "hook_settings_unknown",
            "PATCH",
            "/hooks/ghost/settings",
            None,
            Some(r#"{"settings":{}}"#),
            404,
            "not_found",
        ),
        // ── Overlay reset ─────────────────────────────────────────────────────────────────────
        (
            "overlay_unknown_section",
            "DELETE",
            "/overlay/nosuch",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "overlay_stale",
            "DELETE",
            "/overlay/groups",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        // ── Config plane ──────────────────────────────────────────────────────────────────────
        (
            "cache_flush_bad_body",
            "POST",
            "/auth/cache/flush",
            None,
            Some("["),
            400,
            "invalid_request",
        ),
        (
            "config_validate_bad_body",
            "POST",
            "/config/validate",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_reload_ephemeral",
            "POST",
            "/config/reload",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "config_apply_stale",
            "POST",
            "/config/apply",
            Some(STALE),
            Some(r#"{"config":{"listen":"127.0.0.1:0","providers":{},"models":{},"pools":{}}}"#),
            409,
            "version_conflict",
        ),
        (
            "config_rollback_unknown",
            "POST",
            "/config/rollback",
            None,
            Some(r#"{"version":999}"#),
            404,
            "not_found",
        ),
        (
            "config_rollback_stale",
            "POST",
            "/config/rollback",
            Some(STALE),
            Some(r#"{"version":1}"#),
            409,
            "version_conflict",
        ),
        (
            "config_settings_stale",
            "PUT",
            "/config/settings",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_unknown_module",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["definitely-not-a-module"]}"#),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_stale",
            "PUT",
            "/admin-auth",
            Some(STALE),
            Some(r#"{"admin_auth":["admin-tokens"]}"#),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_lockout",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["test-scope-module"]}"#),
            409,
            "conflict",
        ),
    ];

    // The per-principal mutation budget is 10/min for the config class, so run the table in small
    // batches, each against a fresh fixture (and therefore a fresh limiter).
    let client = reqwest::Client::new();
    for batch in cases.chunks(6) {
        let (addr, server) = admin_error_fixture().await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req.header("content-type", "application/json").body(*b);
            }
            // `restart_no_supervisor` needs a deterministically-unsupervised environment to reach
            // the real NoSupervisor 409 through the real handler -- CI runners were found to
            // genuinely set INVOCATION_ID themselves, so the env alone can't be trusted. See
            // `restart::with_forced_unsupervised`'s doc comment for why this is thread-local, not
            // an env var.
            let resp = if *label == "restart_no_supervisor" {
                crate::admin::restart::with_forced_unsupervised(|| req.send()).await
            } else {
                req.send().await
            }
            .unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}");
        }
        server.abort();
    }
}

/// WITNESS: the two `POST /plugins/rollback` errors that need a real plugins directory —
/// a target file that is not there (404 `not_found`) and one that IS there but does not pass the
/// running trust posture even with the anti-downgrade floor lowered to its own version (409
/// `conflict`; a rollback authenticates the OPERATOR, never the bytes).
#[tokio::test]
async fn plugin_rollback_reports_missing_and_untrusted_targets() {
    drive_plugin_rollback_errors().await;
}

/// `POST /plugins/reload` 400s when the on-disk config no longer rebuilds. The operation declared NO
/// 4xx at all until this driver existed -- `openapi.json` hid a response clients hit, and the
/// router's under-claim panic could not catch it because nothing produced it.
#[tokio::test]
async fn plugin_reload_reports_an_unrebuildable_disk_config() {
    drive_plugin_reload_errors().await;
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_plugin_reload_errors() {
    crate::metrics::init();
    // `pid` alone collides: this helper is called from TWO `#[tokio::test]`s in the same binary
    // (`plugin_reload_reports_an_unrebuildable_disk_config` and
    // `declared_error_set_is_exactly_what_the_handlers_emit`), which can run concurrently and would
    // otherwise `remove_dir_all` / overwrite each other's fixture mid-request. A per-CALL monotonic
    // ticket makes every call's directory unique, matching the `stage.rs::next_seq` idiom (pid+tag
    // is not enough here because it's the SAME tag from two call sites, not distinct ones).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-reload-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // DISK TRUTH that does not parse: the rebuild is reached (not the ephemeral branch) and fails.
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&config, "this: [is not: valid: yaml\n").unwrap();
    std::fs::write(&providers, "providers: {}\n").unwrap();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir.clone())
        .disk_paths(config, providers)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "an unrebuildable disk config: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_plugin_rollback_errors() {
    crate::metrics::init();
    // Same per-call collision as `drive_plugin_reload_errors` above (two callers, same pid) — see
    // that function's comment.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-rollback-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = dir.join("overlay.yaml");
    // An UNSIGNED artifact sitting in the plugins directory, under the DEFAULT trust posture
    // (unsigned not opted in) — so it is present but not loadable.
    let tarball = admin_test_tarball("rollme", "rollme");
    let file = "rollme-1.0.0.tar.gz";
    std::fs::write(dir.join(file), &tarball).unwrap();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir.clone())
        .plugins_cfg(crate::config::PluginsCfg::default())
        .overlay_path(overlay)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let rollback = |body: String| {
        client
            .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
    };

    let r = rollback(r#"{"file":"nosuch-9.9.9.tar.gz"}"#.to_string())
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 404,
        "a target that is not in the plugins dir: {body}"
    );
    assert_eq!(body["error"]["code"], "not_found");

    let r = rollback(format!(r#"{{"file":"{file}"}}"#)).await.unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 409,
        "an untrusted target is a terminal conflict, not a validation error: {body}"
    );
    assert_eq!(body["error"]["code"], "conflict");

    // The sibling INSTALL + REMOVE errors, driven against the same directory: a malformed body, a
    // filename that is not a plugin archive, an artifact the trust posture rejects, and a removal
    // of something that was never installed.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&tarball);
    for (label, rel, method, body, want_status, want_code) in [
        (
            "install_bad_body",
            "/plugins",
            "POST",
            Some("{".to_string()),
            400,
            "invalid_request",
        ),
        (
            "install_bad_filename",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"not-an-archive","tarball_b64":"{b64}"}}"#
            )),
            400,
            "invalid_request",
        ),
        (
            "install_untrusted",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"fresh-1.0.0.tar.gz","tarball_b64":"{b64}"}}"#
            )),
            409,
            "conflict",
        ),
        (
            "remove_bad_filename",
            "/plugins/not-an-archive",
            "DELETE",
            None,
            400,
            "invalid_request",
        ),
        (
            "remove_unknown",
            "/plugins/ghost-1.0.0.tar.gz",
            "DELETE",
            None,
            404,
            "not_found",
        ),
    ] {
        let mut req = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{addr}/api/v1/admin{rel}"),
            )
            .header("x-admin-token", "admintok");
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(status, want_status, "{label}: {parsed}");
        assert_eq!(parsed["error"]["code"], want_code, "{label}");
    }
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE CONDITION-WITNESS DEBT LEDGER — a ratchet, not a suppression.
///
/// Witness driver for `POST /plugins/inspect`'s declared 400 (`Validation`): a body whose
/// `tarball_b64` is not valid base64 is rejected with `invalid_request`. The wire behavior itself is
/// also asserted in `test_admin_v1_plugins_inspect_previews_without_installing`; this driver exists
/// so `declared_error_set_is_exactly_what_the_handlers_emit` witnesses the emission through the v1
/// router's recording layer without depending on test order.
async fn drive_plugin_inspect_errors() {
    crate::metrics::init();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-inspect-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = dir.join("overlay.yaml");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir.clone())
        .plugins_cfg(crate::config::PluginsCfg::default())
        .overlay_path(overlay)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // tarball_b64 that is not valid base64 → AdminError::Validation → 400 invalid_request. This is the
    // witness for the operation's declared 400.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(r#"{"file":"witness-1.0.0.tar.gz","tarball_b64":"not-base64!!"}"#.to_string())
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "invalid base64 tarball_b64: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `declared_error_set_is_exactly_what_the_handlers_emit` requires every declared `(operation,
/// ErrKind, Cond)` to be witness-backed. Where an operation declares the SAME `ErrKind` under two or
/// more conditions, an untagged emission proves only that SOME condition fired -- so the emission
/// has to name its condition (`err_json_cond`) for the declaration to mean anything. These are the
/// declarations that do not yet.
///
/// The entry is enforced in BOTH directions, which is what makes it a ratchet rather than a
/// suppression list: nothing outside it may be unwitnessed (a NEW ambiguous declaration is rejected
/// on arrival), and every row in it must still be a live declaration AND still unwitnessed (so a row
/// cannot be left behind once its emission starts naming its condition, or its declaration is
/// deleted). The list can only shrink.
const COND_WITNESS_DEBT: &[(
    crate::admin::v1::contract::taxonomy::MethodTag,
    &str,
    crate::admin::v1::contract::taxonomy::ErrKind,
    crate::admin::v1::contract::taxonomy::Cond,
)] = {
    use crate::admin::v1::contract::taxonomy::Cond::*;
    use crate::admin::v1::contract::taxonomy::ErrKind::*;
    use crate::admin::v1::contract::taxonomy::MethodTag::*;
    &[
        (Delete, "/groups/{name}", Conflict, BaseDefined),
        (Delete, "/groups/{name}", Conflict, BoundKeys),
        (Delete, "/groups/{name}", Conflict, StillParent),
        (Delete, "/overlay/{section}", Validation, InvalidConfig),
        (Delete, "/overlay/{section}", Validation, MalformedIfMatch),
        (Delete, "/overlay/{section}", Validation, NoDiskBase),
        (Delete, "/overlay/{section}", Validation, UnknownSection),
        (Patch, "/groups/{name}", Validation, InvalidTree),
        (Patch, "/groups/{name}", Validation, MalformedBody),
        (Patch, "/hooks/{name}/settings", Conflict, BaseDefined),
        (Patch, "/hooks/{name}/settings", Conflict, SettingsPush),
        (Patch, "/hooks/{name}/settings", Validation, HookNoAck),
        (Patch, "/hooks/{name}/settings", Validation, MalformedBody),
        (Post, "/config/apply", Validation, InvalidConfig),
        (Post, "/config/apply", Validation, MalformedBody),
        (Post, "/config/apply", Validation, MalformedIfMatch),
        (Post, "/config/reload", Validation, InvalidConfig),
        (Post, "/config/reload", Validation, NoDiskBase),
        (Post, "/config/rollback", Validation, InvalidConfig),
        (Post, "/config/rollback", Validation, MalformedBody),
        (Post, "/groups", Validation, InvalidTree),
        (Post, "/groups", Validation, MalformedBody),
        (Post, "/hooks", Conflict, BaseDefined),
        (Post, "/hooks", Conflict, GrantChange),
        (Post, "/hooks", Validation, MalformedBody),
        (Post, "/keys", Conflict, AtKeyCap),
        (Post, "/keys", Conflict, BaseDefined),
        (Post, "/keys", Conflict, IdempotencyInFlight),
        (Post, "/keys", Validation, InvalidTree),
        (Post, "/keys", Validation, Overlong),
        (Post, "/keys/{id}/rotate", Conflict, IdempotencyInFlight),
        (Post, "/plugins", Conflict, NameCollision),
        (Post, "/plugins", Conflict, UntrustedUpload),
        (Post, "/plugins", Validation, InvalidFilename),
        (Post, "/plugins", Validation, MalformedBody),
        (Post, "/plugins", Validation, NotLoadable),
        (Post, "/plugins/rollback", Validation, InvalidFilename),
        (Post, "/plugins/rollback", Validation, MalformedBody),
        (Post, "/plugins/rollback", Validation, NoDiskBase),
        (Put, "/admin-auth", Validation, MalformedBody),
        (Put, "/admin-auth", Validation, UnknownModule),
        (Put, "/config/settings", Validation, InvalidConfig),
        (Put, "/config/settings", Validation, MalformedBody),
        (Put, "/config/settings", Validation, NoDiskBase),
        (Put, "/groups/{name}", Validation, InvalidTree),
        (Put, "/groups/{name}", Validation, MalformedBody),
        (Put, "/hooks/{name}", Conflict, BaseDefined),
        (Put, "/hooks/{name}", Conflict, GrantChange),
        (Put, "/hooks/{name}", Validation, MalformedBody),
    ]
};

/// THE CLASS-LEVEL GUARANTEE: for EVERY documented operation, the declared error set
/// equals the set the handlers can actually emit. The two directions are enforced by two different
/// mechanisms, both structural:
///
/// - **UNDER-CLAIM** (a handler emits a kind the declaration omits → `openapi.json` would hide a
/// response clients hit) is fatal AT THE EMISSION: the v1 router's recording layer panics inside
/// whichever test produced it. Every test in the suite is a driver; nothing accumulates and
/// nothing depends on test order. That check is live for the whole suite, not just this test.
/// - **OVER-CLAIM** (the declaration lists a response no handler can produce → `openapi.json`
/// documents fiction) needs a WITNESS, which is what this test drives. It runs the error-surface
/// drivers directly — no reliance on other tests having run — and then asserts every declared
/// entry was seen. A declared 409 no test can trigger IS an over-claim until proven otherwise.
///
/// The witness is required at **`(operation, ErrKind, Cond)`** granularity, which is what the design
/// claims and what an `(operation, ErrKind)` check silently did not give: a 409 whose code path had
/// been deleted (`GroupRaceOnMint`, removed with the mint race) stayed documented indefinitely
/// because a SIBLING 409 on the same operation kept the check green. Where an operation declares one
/// condition per kind the untagged witness is unambiguous and still counts; where it declares
/// several, only a `err_json_cond`-tagged emission distinguishes them, and the declarations not yet
/// tagged are ledgered in `COND_WITNESS_DEBT`, which only shrinks.
///
/// Consequence: what used to be a per-endpoint hunt for "another missing 4xx" is now a
/// machine set-comparison over every operation at once. There is no endpoint left to be next.
#[tokio::test]
async fn declared_error_set_is_exactly_what_the_handlers_emit() {
    use crate::admin::v1::contract::taxonomy::{declared_errors, MethodTag};
    // Drive every error path the declaration claims. (Other tests contribute to the same registry;
    // calling the drivers here makes the assertion independent of whether they ran.)
    drive_admin_error_surface().await;
    drive_keys_error_surface().await;
    drive_plugin_rollback_errors().await;
    drive_plugin_reload_errors().await;
    drive_plugin_inspect_errors().await;
    drive_key_cap_and_delegation_errors().await;
    drive_named_map_errors().await;
    // The MCP trust verbs' own drivers, called here for the same reason as every line above it: a
    // condition witnessed only by a sibling test is witnessed nowhere.
    crate::mcp::admin_view::adminverbs_tests::drive_mcp_verb_errors().await;
    // And the A2A plane's, for the same reason — the two trust surfaces are the same shape and the
    // witness obligation is the same obligation.
    crate::a2a::verbs::adminverbs_tests::drive_a2a_verb_errors().await;

    let witnessed = crate::admin::v1::contract::taxonomy::observed::snapshot();
    // Every (operation, ErrKind) the suite has actually produced, and every (operation, ErrKind,
    // Cond) TRIPLE for the emissions that named their condition.
    let seen: std::collections::BTreeSet<(String, MethodTag, _)> = witnessed
        .iter()
        .map(|(rel, method, kind, _cond)| (rel.clone(), *method, *kind))
        .collect();
    let seen_triple: std::collections::BTreeSet<_> = witnessed
        .iter()
        .filter_map(|(rel, method, kind, cond)| cond.map(|c| (rel.clone(), *method, *kind, c)))
        .collect();

    // Walk the DOCUMENTED operations and require a witness for each declared entry AT CONDITION
    // GRANULARITY, which is what the design claims and what a `(op, ErrKind)` check does not give.
    //
    // The two cases differ in what counts as proof, and the difference is exact, not a concession:
    // * the op declares this ErrKind under exactly ONE Cond — then no other condition on this
    // operation can produce that kind, so ANY witness of the kind witnesses that condition;
    // * the op declares the SAME ErrKind under two or more Conds — then an untagged witness is
    // genuinely ambiguous (it proves one of them, and cannot say which), so the emission must
    // name its condition via `err_json_cond` for the declaration to be witness-backed at all.
    // A declared condition that only the ambiguous case can reach is therefore an over-claim until
    // its emission site says which condition it is: that is precisely how a 409 whose code path was
    // deleted (`GroupRaceOnMint`, removed with the mint race) went on being documented while a
    // sibling 409 on the same operation kept the check green.
    let mut over_claimed = Vec::new();
    for (rel, method) in documented_operations() {
        let declared = declared_errors(method, &rel);
        for de in declared {
            let ambiguous = declared.iter().filter(|o| o.kind == de.kind).count() > 1;
            let proven = if ambiguous {
                seen_triple.contains(&(rel.clone(), method, de.kind, de.cond))
            } else {
                seen.contains(&(rel.clone(), method, de.kind))
            };
            if !proven {
                if COND_WITNESS_DEBT.contains(&(method, rel.as_str(), de.kind, de.cond)) {
                    continue;
                }
                over_claimed.push(format!(
                    "{} {rel} declares {:?}/{:?} ({} {}) — {}",
                    method.as_str().to_uppercase(),
                    de.kind,
                    de.cond,
                    de.kind.status(),
                    de.kind.code(),
                    if ambiguous {
                        "no test produced it with its CONDITION named (this operation declares \
                         several conditions for the same kind, so an untagged emission proves \
                         nothing about which one is reachable — emit it via `err_json_cond`)"
                    } else {
                        "no test ever produced it"
                    },
                ));
            }
        }
    }
    assert!(
        over_claimed.is_empty(),
        "OpenAPI OVER-CLAIM — openapi.json documents {} response(s) nothing can emit:\n  {}\n\
         Either the declaration is wrong (delete the entry) or the condition is real and needs a \
         negative test that triggers it. A documented error no test can produce is not a contract.",
        over_claimed.len(),
        over_claimed.join("\n  ")
    );

    // THE RATCHET'S OTHER DIRECTION: a debt row must still name a LIVE, AMBIGUOUS declaration.
    // Delete the declaration (as `GroupRaceOnMint` was) or give its kind a single condition, and the
    // row has to go with it -- otherwise the ledger would quietly become a permanent exemption list
    // that outlives the thing it exempted.
    //
    // Deliberately keyed on the DECLARATION TABLE and not on "was it witnessed": `observed` is a
    // process-global registry that accumulates whatever tests happened to run, so a witness-based
    // staleness check would pass or fail depending on the test filter. The declaration table is the
    // same in every run.
    let stale: Vec<_> = COND_WITNESS_DEBT
        .iter()
        .filter(|(m, rel, k, c)| {
            let declared = declared_errors(*m, rel);
            let ambiguous = declared.iter().filter(|o| o.kind == *k).count() > 1;
            !ambiguous || !declared.iter().any(|d| d.kind == *k && d.cond == *c)
        })
        .map(|(m, rel, k, c)| format!("{} {rel} {k:?}/{c:?}", m.as_str().to_uppercase()))
        .collect();
    assert!(
        stale.is_empty(),
        "COND_WITNESS_DEBT has {} row(s) whose declaration is gone or no longer ambiguous — delete \
         them; the ledger only shrinks:\n  {}",
        stale.len(),
        stale.join("\n  ")
    );

    // Sanity: the drivers really did exercise the surface (a registry that silently stopped
    // recording would make the assertion above vacuously true).
    assert!(
        seen.len() >= 60,
        "the error-surface drivers witnessed only {} (operation, kind) pairs — the recording layer \
         is probably not installed",
        seen.len()
    );
}

/// Every (relative path, method) the admin surface documents — read off the COMMITTED
/// `openapi.json`, the exact bytes the runtime serves via `include_str!`.
///
/// This used to be a hand-maintained list that nothing tied to anything: an operation could be added
/// to the router and the doc and simply never appear here, and its declared 4xx set would go
/// unaudited forever. The committed doc is a projection of the code (`openapi_json_matches_committed_file`
/// fails the build the moment it drifts) and every path in it is proven mounted
/// (`test_admin_v1_openapi_paths_all_resolve`), so keying off it closes the loop: router → doc →
/// this audit.
fn documented_operations() -> Vec<(String, crate::admin::v1::contract::taxonomy::MethodTag)> {
    use crate::admin::v1::contract::taxonomy::MethodTag;
    let doc: serde_json::Value = serde_json::from_str(crate::admin::v1::json::OPENAPI_JSON)
        .expect("the committed openapi.json parses");
    let paths = doc["paths"]
        .as_object()
        .expect("openapi.json has a paths object");
    let mut ops = Vec::new();
    for (abs, item) in paths {
        let rel = abs
            .strip_prefix(crate::admin::v1::contract::ADMIN_PREFIX)
            .unwrap_or(abs);
        for key in item.as_object().into_iter().flatten().map(|(k, _)| k) {
            // `x-*` specification extensions share the path-item object with real operations.
            if let Some(m) = MethodTag::from_op_key(key) {
                ops.push((rel.to_string(), m));
            }
        }
    }
    assert!(
        ops.len() >= 40,
        "only {} operations read out of the committed openapi.json — the projection is broken",
        ops.len()
    );
    ops
}

/// `docs/admin-api.md`'s mutation rate-limit table names the CONFIG-class (10/min) endpoint set by
/// hand. Until this test existed, nothing tied that prose list to
/// `admin::rate::classify_mutation` — the classifier that actually decides which budget a request
/// spends from. This walks every mutation operation in the committed `openapi.json`
/// (`documented_operations`, itself a projection nothing can silently drift from), classifies each
/// one, and requires the resulting CONFIG set to equal the doc's `config` row EXACTLY — under- and
/// over-listing both fail, same bidirectional-equality idiom as
/// `declared_error_set_is_exactly_what_the_handlers_emit`.
#[test]
fn rate_limit_doc_table_matches_classifier() {
    use crate::admin::v1::contract::taxonomy::MethodTag;

    // The doc's `config` row, parsed straight out of the committed file — not retyped here — so
    // editing the row is the only step needed to change what this test expects.
    let doc = include_str!("../../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| l.trim_start().starts_with("| config | 10/min |"))
        .expect("docs/admin-api.md has a `config` row in the mutation rate-limit table");
    let doc_config: std::collections::BTreeSet<(String, MethodTag)> = row
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|token| {
            let mut parts = token.splitn(2, ' ');
            let method = parts.next().unwrap();
            let path = parts.next().unwrap_or_else(|| {
                panic!("doc token {token:?} is not \"METHOD /path\"");
            });
            let m = MethodTag::from_op_key(&method.to_lowercase())
                .unwrap_or_else(|| panic!("unrecognized HTTP method {method:?} in doc row"));
            (path.to_string(), m)
        })
        .collect();
    assert!(
        doc_config.len() >= 6,
        "only parsed {} endpoints out of the doc's config row — the parser is broken: {row:?}",
        doc_config.len()
    );

    // `documented_operations` yields `/overlay/{section}` verbatim (the templated openapi path),
    // matching the doc's literal spelling — no normalization needed on either side.
    let code_config: std::collections::BTreeSet<(String, MethodTag)> = documented_operations()
        .into_iter()
        .filter(|(rel, method)| {
            matches!(
                method,
                MethodTag::Post | MethodTag::Put | MethodTag::Patch | MethodTag::Delete
            ) && crate::admin::rate::classify_mutation(rel)
                == crate::admin::rate::MutationClass::Config
        })
        .collect();

    let missing_from_doc: Vec<_> = code_config.difference(&doc_config).collect();
    let missing_from_code: Vec<_> = doc_config.difference(&code_config).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's config-class row has drifted from admin::rate::classify_mutation.\n\
         In classifier's CONFIG class but not in the doc: {missing_from_doc:?}\n\
         In the doc but not classified CONFIG: {missing_from_code:?}"
    );
}

/// `docs/admin-api.md`'s `DELETE /overlay/{section}` row names the valid section set by hand, and
/// it called that set COMPLETE while it was not: `named_maps` shipped as a durable, API-writable
/// overlay section with no reset at all, and the reference documentation asserted the resulting
/// functional gap did not exist. Prose that describes a gap as a closed set is worse than prose that
/// says nothing, because it stops the reader from looking.
///
/// So the row is parsed out of the committed file and required to equal `OverlaySection::all()`
/// EXACTLY, in both directions: a section live in the code but missing from the doc fails, and a
/// section the doc claims but the parser rejects fails too.
#[test]
fn overlay_reset_doc_row_matches_the_section_set() {
    use crate::config::overlay::OverlaySection;

    let doc = include_str!("../../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with("| `DELETE /overlay/{section}` |")
        })
        .expect("docs/admin-api.md has a `DELETE /overlay/{section}` row");
    // The set is spelled `(`section` ∈ `a` \| `b` \| …)`. Take the backticked tokens between the
    // marker and the closing paren, which is the only place the row enumerates section names.
    let (_, after) = row
        .split_once("(`section` ∈ ")
        .expect("the row states the section set as \"(`section` ∈ …)\"");
    let enumerated = after
        .split_once(')')
        .expect("the section set is parenthesised")
        .0;
    let doc_sections: std::collections::BTreeSet<&str> =
        enumerated.split('`').skip(1).step_by(2).collect();
    assert!(
        doc_sections.len() >= 4,
        "only parsed {} section names out of the doc row; the parser is broken and this test must \
         not report a pass on an empty set: {enumerated:?}",
        doc_sections.len()
    );

    let all = OverlaySection::all();
    let code_sections: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        code_sections.len(),
        all.len(),
        "OverlaySection::all() yields a duplicate wire name"
    );
    let missing_from_doc: Vec<_> = code_sections.difference(&doc_sections).collect();
    let missing_from_code: Vec<_> = doc_sections.difference(&code_sections).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's `DELETE /overlay/{{section}}` row has drifted from \
         OverlaySection::all().\nLive in the code but absent from the doc (an operator is told the \
         section does not exist): {missing_from_doc:?}\nClaimed by the doc but rejected by \
         `OverlaySection::parse` (an operator is told to call something that 400s): \
         {missing_from_code:?}"
    );

    // Every name the doc lists really is accepted by the parser, not merely present in the enum.
    for name in &doc_sections {
        assert!(
            OverlaySection::parse(name).is_some(),
            "the doc lists section `{name}` but `OverlaySection::parse` rejects it"
        );
    }
}

/// `POST /api/v1/admin/restart` is how the restart-scoped settings get applied without an SSH
/// session, so its refusals matter as much as its success: exiting is only a RESTART if something
/// restarts the process, and a test binary has no shutdown channel at all.
///
/// Drives all three declared conditions. The success path cannot be driven here — it would end the
/// test process — which is why the endpoint checks restartability BEFORE recording an applied
/// restart, so a refusal is never audited as a restart that then failed.
#[tokio::test]
async fn test_admin_v1_restart_refuses_when_it_cannot_restart() {
    crate::metrics::init();
    // Bracket by seq, not just by action: `AUDIT` is a process-wide ring every admin mutation in
    // the binary writes to, unscoped by principal (every admin-token test shares the SAME fixed
    // operator principal id, so scoping by principal would not distinguish this test's rows from a
    // concurrent sibling's). Rows from THIS test's own restart attempts are bracketed by seq.
    let baseline_seq = crate::admin::audit::AUDIT
        .list(1)
        .first()
        .map(|e| e.seq)
        .unwrap_or(0);
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, _h) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");
    let url = format!("http://{addr}/api/v1/admin/restart");

    // A typo'd field is a 400, not a silent restart.
    let resp = admin(client.post(&url))
        .header("content-type", "application/json")
        .body(r#"{"confrim": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "unknown field must not restart"
    );

    // No supervisor detected and no confirmation: refuse rather than risk leaving busbar down.
    // Forced deterministically unsupervised (see `restart::with_forced_unsupervised`'s doc comment)
    // rather than gated on an env-var guess -- CI runners were found to genuinely set INVOCATION_ID
    // themselves, which silently skipped this whole assertion block under the old `if unsupervised`
    // env check.
    let resp = crate::admin::restart::with_forced_unsupervised(|| admin(client.post(&url)).send())
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "an unsupervised restart must be refused unless confirmed"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("confirm"),
        "the refusal must tell the operator how to proceed: {body}"
    );

    // Confirmed, so the supervisor check passes — but a test binary published no shutdown channel,
    // so the process genuinely cannot restart itself and says so. There are TWO distinct 409 exits
    // (NoSupervisor above, NotRestartable here); a bare status code can't tell them apart, and a
    // regression that ignored `confirm` (e.g. a serde-default flip) would still land on the FIRST
    // 409 and this assertion would not notice. Check the message instead.
    let resp = admin(client.post(&url))
        .header("content-type", "application/json")
        .body(r#"{"confirm": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "a process with no shutdown channel cannot restart itself"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("cannot restart itself"),
        "with `confirm: true` the supervisor gate must be PASSED and the refusal must come from \
         the no-shutdown-channel gate, not the supervisor gate: {body}"
    );
    assert!(
        !msg.contains("confirm"),
        "a confirmed request must never be refused for lack of confirmation: {body}"
    );

    // Every refusal is audited — the operator's only evidence, since a real restart takes the
    // connection that would have carried the response.
    let entries = crate::admin::audit::AUDIT.list(crate::admin::audit::MAX_AUDIT_ENTRIES);
    let restarts: Vec<_> = entries
        .iter()
        .filter(|e| e.action == "admin.restart" && e.seq > baseline_seq)
        .collect();
    assert!(
        restarts.len() >= 2,
        "each refusal must be audited, got {restarts:?}"
    );
    assert!(
        restarts
            .iter()
            .all(|e| e.outcome == crate::admin::audit::OUTCOME_REJECTED),
        "a refused restart must never be recorded as applied: {restarts:?}"
    );
}

/// `?limit=0` must never produce a self-referential cursor: `page_cursor` truncates the page to
/// zero items and would otherwise emit `next_cursor = encode(start + 0) == start`, so a
/// cursor-following client that keeps requesting `limit=0` loops forever on the same offset.
/// Covers all THREE parse sites — `get_audit`/`list_config_versions` (through the shared
/// `page_cursor`) and `list_keys` (its own match arm, a different code path to the same hole).
#[tokio::test]
async fn limit_zero_does_not_produce_a_self_referential_cursor() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    // Seed rows for all three lists: minting keys produces audit entries AND `list_keys` rows;
    // registering + deleting a hook produces config-version rows.
    for n in ["ka", "kb"] {
        let resp = admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
            .header("content-type", "application/json")
            .body(serde_json::json!({"name": n}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201);
    }
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": "lz-hook", "config": {"kind": "tap", "plugin": "test-hook"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/lz-hook")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // A self-referential cursor decodes to the SAME offset the request was served at (0, since no
    // `?cursor=` was supplied). Anything else — null, or an offset strictly greater than 0 — proves
    // the client would make forward progress.
    let assert_not_self_referential = |label: &str, body: &serde_json::Value| {
        let next = body.get("next_cursor").and_then(|c| c.as_str());
        match next {
            None => {} // no further page — fine
            Some(c) => {
                let decoded = crate::admin::v1::contract::decode_offset_cursor(c)
                    .unwrap_or_else(|| panic!("{label}: cursor did not decode: {c}"));
                assert!(
                    decoded > 0,
                    "{label}: limit=0 produced a self-referential cursor (offset {decoded}): {body}"
                );
            }
        }
    };

    let audit_body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/audit?limit=0")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_not_self_referential("get_audit", &audit_body);

    let versions_body: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/config/versions?limit=0"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_not_self_referential("list_config_versions", &versions_body);

    let keys_body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/keys?limit=0")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_not_self_referential("list_keys", &keys_body);

    handle.abort();
}

// ── THE GENERIC NAMED-DEFINITION MAP CRUD ────────────────────────────────────────────────────────
//
// `/identity-providers` and `/export` are served by ONE parameterized handler set
// (`admin::v1::json::named_map`), so these tests deliberately drive BOTH sections through the same
// tables: a behavior that held for one section and not the other would mean the generic path had
// quietly forked.

/// Write the on-disk base config the named-map tests rebuild against: one model/pool plus a BASE
/// entry in each named map (the base-protection target).
///
/// `reference_corp_ad` additionally makes `auth.admin_auth:` name `corp-ad` — a REFERENCE SITE whose
/// definition lives only in the overlay. That is the shape the dangling-reference test needs: create
/// `corp-ad` through the API (the rebuild resolves, because the overlay supplies the definition),
/// then watch the DELETE get refused because the reference would be left dangling. Every other
/// fixture leaves it off, since a config whose chain names an undefined provider cannot resolve.
/// `base_export == false` writes a config that declares NO exporter at all — the deployment that
/// booted without `export.prometheus`, so `/metrics` was never registered on the router.
fn write_named_map_fixture(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-namedmap-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_NAMEDMAP_NO_SUCH_KEY
",
    )
    .unwrap();
    std::fs::write(
        &config_path,
        ("listen: 127.0.0.1:0
providers:
  test-provider:
    api_key: { env: BUSBAR_TEST_NAMEDMAP_NO_SUCH_KEY }
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
identity-providers:
  base-idp:
    module: keys
  admin-tokens:
    module: admin-tokens
    token: { file: ADMIN_TOKEN_FILE }
tools:
  base-mcp:
    url: https://mcp.internal/fs
    pin: { mechanism: cert_spki, key: \"sha256/BASE=\" }
agents:
  base-agent:
    url: https://a2a.example/planner
    pin:
      mechanism: unpinned
"
        .to_string()
            + if base_export {
                "export:\n  base-metrics:\n    module: prometheus\n    settings: { buffer_seconds: 60 }\n"
            } else {
                ""
            })
        .replace(
            "ADMIN_TOKEN_FILE",
            &dir.join("admin.token").to_string_lossy(),
        ) + if reference_corp_ad {
            "auth:\n  admin_auth: [admin-tokens, corp-ad]\n"
        } else {
            ""
        },
    )
    .unwrap();
    // The operator credential lives in the FILE the base config points at, so it survives every
    // rebuild-and-swap these tests trigger — a fixture whose admin token only existed on the
    // pre-mutation `App` would start 401-ing the moment a mutation succeeded.
    std::fs::write(dir.join("admin.token"), "admintok").unwrap();
    if reference_corp_ad {
        // The overlay-defined `corp-ad` is a SECOND `admin-tokens` provider on the admin chain, with
        // its own credential file — so the rebuilt chain still admits the fixture's own `admintok`
        // through the first entry, and the test is measuring the dangling guard rather than an
        // accidentally-broken admin credential.
        std::fs::write(dir.join("corp.token"), "corp-secret").unwrap();
    }
    (dir, config_path, providers_path)
}

/// A running admin server over the named-map disk fixture. The live `App` is seeded with the SAME
/// base entries the file declares (a `TestApp` does not parse config.yaml), so the read surface and
/// disk truth agree exactly as they do after a real boot.
async fn named_map_app(
    tag: &str,
    reference_corp_ad: bool,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    named_map_app_opts(tag, reference_corp_ad, true).await
}

/// [`named_map_app`] with the base `export:` entry made OPTIONAL. `base_export == false` is the
/// deployment that BOOTED WITH NO EXPORTER: no `export:` in the base config, no export definition on
/// the live snapshot, and — the part that matters — an empty `boot_route_paths`, i.e. `/metrics` was
/// never registered on this process's router.
async fn named_map_app_opts(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    crate::metrics::init();
    let (dir, config_path, providers_path) =
        write_named_map_fixture(tag, reference_corp_ad, base_export);
    // The DEFAULT overlay filename next to config.yaml — the same path `load_config_from_disk`
    // resolves for a config with no explicit `config.overlay` block. A named-map mutation rebuilds
    // from disk truth PLUS the on-disk overlay, so a fixture whose live overlay path differed from
    // the resolved one would silently lose every prior API-applied definition on the next mutation.
    let overlay = dir.join(crate::config::overlay::DEFAULT_OVERLAY_FILENAME);
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut builder = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .disk_paths(config_path, providers_path)
        .identity_provider(
            "base-idp",
            serde_json::from_value(serde_json::json!({"module": "keys"})).unwrap(),
        )
        .identity_provider(
            "admin-tokens",
            serde_json::from_value(serde_json::json!({
                "module": "admin-tokens",
                "token": {"file": dir.join("admin.token").to_string_lossy()}
            }))
            .unwrap(),
        )
        // The MCP plane's base entry, seeded to match the file exactly — same reason the
        // identity-provider and export base entries are: a `TestApp` does not parse config.yaml, so
        // without this the read surface and disk truth would disagree and the base-protection guard
        // would be measuring the disagreement rather than the guard.
        .mcp_server(
            "base-mcp",
            serde_json::from_value(serde_json::json!({
                "url": "https://mcp.internal/fs",
                "pin": {"mechanism": "cert_spki", "key": "sha256/BASE="}
            }))
            .unwrap(),
        );
    // The A2A plane's base entry, mirroring the fixture config above. It is `unpinned` on purpose:
    // the point of these fixtures is the generic CRUD surface, and an entry with a real root would
    // need key material that says nothing about the routes under test.
    builder = builder.agent_def(
        "base-agent",
        serde_yaml::from_str("url: https://a2a.example/planner\npin:\n  mechanism: unpinned\n")
            .unwrap(),
    );
    builder = if base_export {
        builder.export_def(
            "base-metrics",
            serde_json::from_value(serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 60}
            }))
            .unwrap(),
        )
    } else {
        // No exporter at boot ⇒ no plugin route was ever mounted on this process's router. The
        // explicit form matters: the harness's default table keys on the PROCESS-GLOBAL recorder
        // (`metrics::init()` above), so merely omitting the definition would still yield `/metrics`.
        builder.no_plugin_routes()
    };
    let app = builder.build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (dir, overlay, addr, handle)
}

/// LIST / GET / PUT for EVERY named-map section through the one generic handler: the base entry is
/// listed and readable, a PUT creates a new definition that is immediately readable, the config
/// version bumps, and the definition lands in the `named_maps` overlay section (so it survives a
/// restart). `identity-providers` additionally projects its ceiling/credential fields while
/// `/export` omits them entirely — the one-view-per-pattern contract.
#[tokio::test]
async fn test_admin_v1_named_maps_list_get_and_put_round_trip() {
    let (dir, overlay, addr, handle) = named_map_app("roundtrip", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // (section, base entry, the definition a PUT stores under `new-<section>`)
    let cases: [(&str, &str, serde_json::Value); 2] = [
        (
            "identity-providers",
            "base-idp",
            serde_json::json!({"module": "keys", "max_admin_scope": "read-only"}),
        ),
        (
            "export",
            "base-metrics",
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            }),
        ),
    ];
    for (section, base, def) in &cases {
        // LIST — the base entry is there, and the list carries the config-plane ETag.
        let r = admin(client.get(format!("http://{addr}/api/v1/admin/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "GET /{section}");
        let etag = r
            .headers()
            .get("etag")
            .expect("the list read emits the config-plane ETag")
            .to_str()
            .unwrap()
            .to_string();
        let body: serde_json::Value = r.json().await.unwrap();
        let names: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(base), "GET /{section} lists {base}: {body}");

        // GET one.
        let one: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{base}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(one["name"], *base);
        assert!(one["module"].is_string(), "the definition names its module");
        if *section == "identity-providers" {
            assert_eq!(
                one["token_configured"], false,
                "an identity provider projects WHETHER a credential is configured, never the \
                 reference itself"
            );
        } else {
            assert!(
                one.get("max_admin_scope").is_none() && one.get("token_configured").is_none(),
                "an exporter carries no ceiling and no credential, so those fields are omitted \
                 entirely: {one}"
            );
        }

        // PUT a NEW definition, chaining the ETag we just read into the guard.
        let name = format!("new-{section}");
        let put = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/{name}")))
            .header("if-match", etag)
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            put.status().as_u16(),
            200,
            "PUT /{section}/{name}: {:?}",
            put.text().await
        );

        // Readable immediately (the swap already happened) …
        let after: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{name}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            after["name"], name,
            "the PUT definition reads back: {after}"
        );
        assert_eq!(after["module"], def["module"]);

        // … and DURABLE: the raw definition is in the overlay's `named_maps` section, so a restart
        // replays exactly the document that was PUT.
        let doc = crate::config::overlay::read(&overlay).expect("overlay written");
        assert_eq!(
            doc.named_maps[*section][&name], *def,
            "the overlay stores the definition VERBATIM"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// SECRET CONTAINMENT ON THE NAMED-MAP READS. The `settings:` bag is where an
/// operator legitimately puts a credential VALUE — an OIDC `client_secret`, a `generic-webhook`
/// `auth_header.value` — and `GET <section>[/{name}]` is served at READ-ONLY admin scope. So the
/// read projects the settings KEY NAMES (`settings_keys`) and NEVER the values: a read-only admin
/// credential can see WHAT is configured without being handed the deployment's secrets. Driven on
/// BOTH sections and on BOTH the list and the single read, since one generic handler serves all four.
#[tokio::test]
async fn test_admin_v1_named_map_reads_project_settings_keys_never_values() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = TestApp::new()
        .governance(gov)
        .identity_provider(
            "corp-oidc",
            serde_json::from_value(serde_json::json!({
                "module": "oidc",
                "settings": {
                    "issuer": "https://idp.example.com",
                    "client_secret": "hunter2-idp"
                }
            }))
            .unwrap(),
        )
        .export_def(
            "siem",
            serde_json::from_value(serde_json::json!({
                "module": "generic-webhook",
                "settings": {
                    "url": "https://siem.example.com/in",
                    "auth_header": {"name": "authorization", "value": "Bearer hunter2-siem"}
                }
            }))
            .unwrap(),
        )
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for (section, name, secret, keys) in [
        (
            "identity-providers",
            "corp-oidc",
            "hunter2-idp",
            ["client_secret", "issuer"],
        ),
        ("export", "siem", "hunter2-siem", ["auth_header", "url"]),
    ] {
        for url in [
            format!("http://{addr}/api/v1/admin/{section}"),
            format!("http://{addr}/api/v1/admin/{section}/{name}"),
        ] {
            let body = client
                .get(&url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(
                !body.contains(secret),
                "{url} projected a settings VALUE — this read is reachable at READ-ONLY admin \
                 scope, so an operator credential just leaked: {body}"
            );
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            let def = json
                .get("items")
                .and_then(|i| i.get(0))
                .cloned()
                .unwrap_or(json);
            assert_eq!(
                def["settings_keys"],
                serde_json::json!(keys),
                "{url} must project the settings KEY NAMES (sorted), so `what is configured` \
                 introspection survives the redaction"
            );
            assert!(
                def.get("settings").is_none(),
                "the raw settings bag must not be projected at all: {def}"
            );
        }
    }
    handle.abort();
}

/// OPTIMISTIC CONCURRENCY: a stale `If-Match` on a named-map write is a RETRYABLE
/// `version_conflict` (409) and changes nothing — the same one mechanism every other config-plane
/// mutation speaks. Driven on both sections, since they share one guard.
#[tokio::test]
async fn test_admin_v1_named_map_put_honors_expected_version() {
    let (dir, _overlay, addr, handle) = named_map_app("ifmatch", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    for (section, def) in [
        ("identity-providers", serde_json::json!({"module": "keys"})),
        (
            "export",
            serde_json::json!({"module": "prometheus", "settings": {"buffer_seconds": 30}}),
        ),
    ] {
        let r = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .header("if-match", "\"9999\"")
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 409, "a stale guard rejects");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "version_conflict",
            "RETRYABLE, distinct from a terminal conflict: {body}"
        );
        // Nothing was created.
        let after = admin(client.get(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            after.status().as_u16(),
            404,
            "the rejected PUT stored nothing"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// SCOPE: every named-map WRITE requires `full` (the route matrix), while the reads are
/// `read-only`. An under-scoped principal reads the definitions and is refused every mutation with
/// the frozen `forbidden` envelope — the authorization decision is made from METHOD+PATH alone,
/// never from the body, so no definition a caller sends can talk its way past it.
#[tokio::test]
async fn test_admin_v1_named_map_rejects_an_under_scoped_caller() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = TestApp::new()
        .governance(gov)
        .export_def(
            "base-metrics",
            serde_json::from_value(serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 60}
            }))
            .unwrap(),
        )
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            crate::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let viewer = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "grp:viewers")
            .header("content-type", "application/json")
    };

    for section in ["identity-providers", "export"] {
        let r = viewer(client.get(format!("http://{addr}/api/v1/admin/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "read-only CAN read /{section}");

        for (label, req) in [
            (
                "put",
                viewer(client.put(format!("http://{addr}/api/v1/admin/{section}/x")))
                    .body(r#"{"module":"keys"}"#),
            ),
            (
                "patch-settings",
                viewer(client.patch(format!(
                    "http://{addr}/api/v1/admin/{section}/base-metrics/settings"
                )))
                .body(r#"{"settings":{}}"#),
            ),
            (
                "delete",
                viewer(client.delete(format!("http://{addr}/api/v1/admin/{section}/base-metrics"))),
            ),
        ] {
            let r = req.send().await.unwrap();
            assert_eq!(
                r.status().as_u16(),
                403,
                "read-only cannot {label} /{section}"
            );
            let body: serde_json::Value = r.json().await.unwrap();
            assert_eq!(body["error"]["code"], "forbidden", "{label} /{section}");
        }
    }
    handle.abort();
}

/// THE TRUST-CEILING RULE: `identity-providers.<name>.max_admin_scope` may be LOWERED or left
/// alone through the admin API, and RAISING it is refused outright (409 `conflict`) — including on
/// a brand-new provider, whose baseline is the most restrictive default, so an escalating ceiling
/// cannot ride in on a create either. Every attempt is audited.
///
/// AND the token must be one the ENGINE accepts: exactly `read-only` or `full`. There is no `none`
/// — omit the key for the most restrictive default (`read-only`), and to grant NO admin authority
/// through a provider grant no `admin_scope` under that provider's `role_bindings:`. An unknown
/// token is a hard boot error (`config_validate`'s chain-entry rule, reached because `resolve_auth`
/// copies the definition's ceiling onto every resolved chain entry), so accepting it here would
/// answer 200 to a write that leaves the deployment unbootable.
#[tokio::test]
async fn test_admin_v1_identity_provider_refuses_raising_max_admin_scope() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("ceiling", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // (a) A NEW provider asking for `full` is a RAISE over the default baseline — refused.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "raising the ceiling is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_admin_scope"),
        "the refusal names the ceiling: {body}"
    );
    // Nothing was stored.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // (b) A ceiling token the ENGINE does not accept is refused by the API too. The accepted values
    // are exactly `read-only` and `full` — the two `Scope::parse` knows; `config_validate`'s
    // chain-entry rule turns anything else into a HARD BOOT ERROR, because `resolve_auth` copies the
    // definition's ceiling onto every resolved chain entry. `none` in particular is NOT a value:
    // there is no "no admin authority" ceiling. Omit the key for the most restrictive default
    // (`read-only`); to grant no admin authority through a provider, grant no `admin_scope` under
    // that provider's `role_bindings:`. Accepting `none` here reported success on a write that left
    // the deployment unbootable at the next restart.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "`none` is not a ceiling the engine accepts, so the API must refuse it"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("expected read-only or full"),
        "the refusal names the accepted values: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // (b2) The most restrictive ceiling the engine DOES accept is `read-only` — applied.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "`read-only` can never be a raise: {:?}",
        r.text().await
    );

    // (c) …and a subsequent RAISE on the now-existing provider is still refused.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a raise in place is refused too");
    let still: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        still["max_admin_scope"], "read-only",
        "the live ceiling is untouched by the refused raise: {still}"
    );

    // AUDITED — both the applied change and the refusals.
    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?resource=identity-provider:corp-ad"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let items = audit["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["outcome"] == "rejected" && i["action"] == "identity-provider.replace"),
        "a refused ceiling raise is audited: {audit}"
    );
    assert!(
        items
            .iter()
            .any(|i| i["outcome"] == "applied" && i["action"] == "identity-provider.replace"),
        "the accepted change is audited: {audit}"
    );
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A MUTATION THAT ADDS A ROUTE SAYS "RESTART REQUIRED", instead of reporting
/// plain success for a route this process will never serve.
///
/// Each declared plugin-route PATH is registered on the axum router ONCE, at boot; a config apply
/// swaps only `Arc<App>` and never rebuilds the router. So a `PUT /export/{name}` that introduces a
/// `prometheus` instance where none existed at boot is durably stored, live on the snapshot, and
/// `/metrics` keeps 404ing until the process restarts. The `export:` named map had no restart-required
/// signal (unlike `PUT /config/settings`'s `reload_to_apply`), so the operator was told nothing.
///
/// The signal must be exact in BOTH directions, which is why this walks all four cases: an exporter
/// that declares no route is silent, the route-adding PUT flags exactly `/metrics`, a LATER unrelated
/// mutation does not re-flag it (the signal is keyed on the mutation's own delta), and a REMOVAL is
/// silent because removing genuinely does take effect live.
#[tokio::test]
async fn test_admin_v1_export_put_that_adds_a_route_reports_restart_required() {
    // `base_export: false` ⇒ booted with NO exporter, so `/metrics` was never mounted.
    let (dir, _overlay, addr, handle) = named_map_app_opts("bootfrozen", false, false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // (1) An exporter that declares NO plugin route (a PUSH sink) is fully live on the swap — silent.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/reqlog")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/reqlog")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        body.get("reload_to_apply").is_none(),
        "a sink that declares no route needs no restart: {body}"
    );

    // (2) THE DEFECT: adding a `prometheus` instance introduces `GET /metrics`, which this process's
    // router does not have. Accepted (it is stored, and correct after a restart) but NOT reported as
    // simply applied.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/prom")))
        .body(
            serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 30}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "the definition is still stored");
    let body: serde_json::Value = r.json().await.unwrap();
    let empty = Vec::new();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["/metrics"],
        "the ADDED route the router cannot serve is named: {body}"
    );
    assert!(
        body["note"].as_str().unwrap_or("").contains("RESTART"),
        "the note tells the operator what to do about it: {body}"
    );
    // The response is still the stored definition — the signal is ADDITIVE, not a replacement body.
    assert_eq!(body["name"], "prom");
    assert_eq!(body["module"], "prometheus");
    // And the route really is unserved on this process, which is what the signal is about.
    assert_eq!(
        client
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "`/metrics` is not mounted, exactly as the response just said"
    );

    // (3) NO SPURIOUS RE-FLAG: a later mutation that introduces no new path is silent, even though
    // `/metrics` is still pending a restart (the same "keyed on what this request changed" rule
    // `reload_to_apply_fields` follows).
    let r = admin(client.patch(format!("http://{addr}/api/v1/admin/export/reqlog/settings")))
        .body(
            serde_json::json!({"settings": {"path": dir.join("req2.jsonl").to_string_lossy()}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body.get("reload_to_apply").is_none(),
        "an edit that adds no path must not re-flag an already-pending route: {body}"
    );

    // (4) REMOVAL is live (the dispatcher resolves the owner from the current snapshot and 404s), so
    // it carries no notice at all.
    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/prom")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204, "a removal applies live");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN UNREFERENCED DEFINITION IS STILL VALIDATED. Most of the identity-provider rules live in
/// `resolve_auth`, which only ever sees providers already NAMED by `auth.chain:`/`auth.admin_auth:`
/// — so a definition written through the admin API and not yet referenced used to escape them: the
/// API answered 200, persisted the definition into the overlay, and the error surfaced only later,
/// when something finally named the provider (or, for a `config.yaml` edit that named it, at the
/// next BOOT, which then failed). The definition-side write path now runs the same rules on the same
/// shared functions, so the value is refused where it is written.
#[tokio::test]
async fn test_admin_v1_identity_provider_validates_an_unreferenced_definition() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unreferenced", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // `token:` is the built-in `admin-tokens` operator credential. On any other module it is inert —
    // a MISPLACED SECRET the config grammar fails loud on (`resolve_auth`). Nothing references
    // `stray` yet, so nothing used to check it.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","token":{"env":"BUSBAR_STRAY_TOKEN"}}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `token:` on a non-`admin-tokens` module is a misplaced secret, referenced or not"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("meaningless on `module: keys`"),
        "the refusal states the placement rule: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored no credential"
    );

    // Same for a ceiling token the engine cannot boot with, on a provider in no chain: the chain-entry
    // rule in `config_validate` never sees this definition, so the DEFINITION-side check is the only
    // thing standing between the operator and an unbootable next restart.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unreferenced provider's ceiling is checked where it is written"
    );

    // The legal shape is accepted.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN UNREFERENCED DEFINITION'S `module:` MUST NAME A MODULE THAT EXISTS. The sibling rules above
/// are VALUE-level (a token, a ceiling) and need only the definition itself; this one needs the
/// plugin REGISTRY, because a valid identity-provider module is either a built-in
/// (`BUILTIN_IDENTITY_PROVIDERS`) or a loaded `kind: auth` plugin. `export:` has had this check
/// since 1.5.3 (`resolve_export` refuses an unknown exporter and names the built-ins), but the
/// identity-provider side had nothing: `resolve_auth` is keyed off the RESOLVED chain and
/// `plugins_preflight` derived its auth refs from `auth.chain` alone, so a definition that nothing
/// references — the exact thing this endpoint writes — was checked by no layer at all. The API
/// answered 200 and stored a provider that can never authenticate anyone.
#[tokio::test]
async fn test_admin_v1_identity_provider_rejects_an_unknown_module() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unknown-module", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"not-a-real-idp"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `module:` naming nothing that exists must be refused where it is written"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("not-a-real-idp"),
        "the refusal names the unknown module: {body}"
    );
    assert!(
        msg.contains("keys") && msg.contains("admin-tokens"),
        "the refusal lists the valid modules, the way the `streams:` error names its whole valid \
         set: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // The CONTROL: a built-in module through the identical path is still accepted, so the new rule
    // rejects the unknown name and nothing else.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"keys"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// DANGLING-REFERENCE GUARD: a DELETE that would leave another config section naming a definition
/// that no longer exists is refused as a TERMINAL `conflict` naming the referent — never applied
/// and then discovered at the next resolve. The fixture's base `auth.role_bindings` names
/// `corp-ad`, so creating that provider through the API and then deleting it is exactly the
/// dangling case.
#[tokio::test]
async fn test_admin_v1_identity_provider_delete_rejects_a_dangling_reference() {
    let (dir, _overlay, addr, handle) = named_map_app("dangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // Create the referenced provider (the fixture's `auth.admin_auth:` already names it, with no
    // definition anywhere but the overlay this PUT writes).
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    // … then try to delete it while `auth.role_bindings.corp-ad` still names it.
    let r = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a dangling delete is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("auth.admin_auth"),
        "the refusal NAMES the referent so an operator knows what to fix: {body}"
    );
    // Still live.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused delete changed nothing"
    );

    // An UNREFERENCED definition deletes cleanly — the guard is about references, not about
    // refusing deletes.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        204,
        "an unreferenced definition deletes"
    );
    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status().as_u16(), 404, "and is gone");
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// WITNESS DRIVER for the generic named-map surface: produces EVERY `(operation, ErrKind, Cond)`
/// triple `contract::taxonomy::declared_errors` claims for `/identity-providers` and `/export`, so
/// `declared_error_set_is_exactly_what_the_handlers_emit` can prove none of them is an over-claim.
/// Every emission on this surface names its condition (`err_json_cond`), so nothing here needs a
/// `COND_WITNESS_DEBT` row.
///
/// Batched: these are CONFIG-class mutations (10/min per principal — each rebuilds and swaps the
/// whole App), and a driver that walked the whole table on one fixture would measure the rate
/// limiter instead of the handlers. A fresh fixture carries a fresh limiter.
async fn drive_named_map_errors() {
    let big_settings = {
        let mut m = serde_json::Map::new();
        m.insert("blob".into(), serde_json::json!("x".repeat(70_000)));
        serde_json::json!({ "settings": m }).to_string()
    };
    let ok_def = |section: &str| match section {
        "identity-providers" => r#"{"module":"keys"}"#.to_string(),
        // The MCP plane has no backing plugin, so its valid definition names no `module:` at all —
        // which is exactly the asymmetry `NamedMapSection::requires_module` exists to carry.
        "tools" => r#"{"url":"https://x/","pin":{"mechanism":"unpinned"}}"#.to_string(),
        // The A2A plane's entries are NOT plugin instances, so a legal definition here names a URL
        // and a pin rather than a module. That asymmetry is the reason `requires_module()` exists.
        "agents" => r#"{"url":"https://a2a.example/x","pin":{"mechanism":"unpinned"}}"#.to_string(),
        _ => r#"{"module":"prometheus","settings":{"buffer_seconds":30}}"#.to_string(),
    };
    // (label, method, relative path, If-Match, body, want status, want code)
    type Case = (
        String,
        &'static str,
        String,
        Option<&'static str>,
        Option<String>,
        u16,
        &'static str,
    );
    let mut cases: Vec<Case> = Vec::new();
    for (section, base) in [
        ("identity-providers", "base-idp"),
        ("export", "base-metrics"),
        ("tools", "base-mcp"),
        ("agents", "base-agent"),
    ] {
        let c = |label: &str,
                 method: &'static str,
                 rel: String,
                 im: Option<&'static str>,
                 body: Option<String>,
                 status: u16,
                 code: &'static str|
         -> Case {
            (
                format!("{section}_{label}"),
                method,
                rel,
                im,
                body,
                status,
                code,
            )
        };
        cases.extend([
            // PUT — the upsert. Every declared Validation condition, plus the base-config guard.
            c(
                "put_malformed_body",
                "PUT",
                format!("/{section}/x"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "put_bad_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("not-a-version"),
                Some(ok_def(section)),
                400,
                "invalid_request",
            ),
            c(
                // On a plugin-instance section this is the empty-`module:` guard. On `tools:` there
                // is no `module:` at all, so the same document is refused by the typed
                // `deny_unknown_fields` parse — one status, two reasons, and both are the section's
                // own grammar rather than a hardcoded rule in the handler.
                "put_bad_definition",
                "PUT",
                format!("/{section}/x"),
                None,
                Some(if section == "agents" {
                    // A pin whose mechanism needs material and carries none. On the other sections
                    // the equivalent nonsense is an empty `module:`; the CONDITION being witnessed
                    // (`Validation/InvalidConfig`) is the same one either way.
                    r#"{"url":"https://a2a.example/x","pin":{"mechanism":"jws_issuer_key"}}"#
                        .to_string()
                } else {
                    r#"{"module":""}"#.to_string()
                }),
                400,
                "invalid_request",
            ),
            c(
                "put_base_defined",
                "PUT",
                format!("/{section}/{base}"),
                None,
                Some(ok_def(section)),
                409,
                "conflict",
            ),
            c(
                "put_stale_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("\"9999\""),
                Some(ok_def(section)),
                409,
                "version_conflict",
            ),
            // PATCH …/settings.
            c(
                "patch_malformed_body",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_bad_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("not-a-version"),
                Some(r#"{"settings":{}}"#.into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_oversized_settings",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(big_settings.clone()),
                400,
                "invalid_request",
            ),
            c(
                "patch_unknown",
                "PATCH",
                format!("/{section}/ghost/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                404,
                "not_found",
            ),
            c(
                "patch_base_defined",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                409,
                "conflict",
            ),
            c(
                "patch_stale_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("\"9999\""),
                Some(r#"{"settings":{}}"#.into()),
                409,
                "version_conflict",
            ),
            // DELETE.
            c(
                "delete_bad_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("not-a-version"),
                None,
                400,
                "invalid_request",
            ),
            c(
                "delete_unknown",
                "DELETE",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
            c(
                "delete_base_defined",
                "DELETE",
                format!("/{section}/{base}"),
                None,
                None,
                409,
                "conflict",
            ),
            c(
                "delete_stale_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("\"9999\""),
                None,
                409,
                "version_conflict",
            ),
            // The single-definition READ.
            c(
                "get_unknown",
                "GET",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
        ]);
        if section == "identity-providers" {
            cases.push(c(
                "put_raises_trust_ceiling",
                "PUT",
                format!("/{section}/ceil"),
                None,
                Some(r#"{"module":"keys","max_admin_scope":"full"}"#.into()),
                409,
                "conflict",
            ));
        }
    }

    let client = reqwest::Client::new();
    for (batch_i, batch) in cases.chunks(8).enumerate() {
        let (dir, _overlay, addr, handle) =
            named_map_app(&format!("witness-{batch_i}"), false).await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req
                    .header("content-type", "application/json")
                    .body(b.clone());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}: {parsed}");
        }
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // NO DISK BASE: an EPHEMERAL busbar (started without config files) has no base truth to merge a
    // named-map change onto, so every write verb refuses up front — the condition the disk fixtures
    // above can never reach.
    //
    // ONE SERVER PER SECTION, and that is about the RATE LIMITER rather than isolation. Every verb
    // below is a CONFIG-class admin mutation, budgeted at 10/min PER PRINCIPAL, and failed attempts
    // spend the budget too (that is the anti-enumeration rule, working as designed). The section
    // list is now four long — the two 1.5.3 sections plus a plane section each for `tools:` and
    // `agents:` — so twelve probes against one server would start answering 429 at the eleventh and
    // the error taxonomy this test exists to pin would go unchecked from there on. The limiter is a
    // field on `App`, so a fresh fixture is a fresh budget; raising the limit instead would have
    // made the test pass by weakening the thing it shares with production.
    for section in ["identity-providers", "export", "tools", "agents"] {
        crate::metrics::init();
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        {
            for (label, method, rel, body) in [
                (
                    "put",
                    "PUT",
                    format!("/{section}/x"),
                    Some(r#"{"module":"keys"}"#),
                ),
                (
                    "patch",
                    "PATCH",
                    format!("/{section}/x/settings"),
                    Some(r#"{"settings":{}}"#),
                ),
                ("delete", "DELETE", format!("/{section}/x"), None),
            ] {
                let mut req = client
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                        format!("http://{addr}/api/v1/admin{rel}"),
                    )
                    .header("x-admin-token", "admintok");
                if let Some(b) = body {
                    req = req.header("content-type", "application/json").body(b);
                }
                let resp = req.send().await.unwrap();
                let status = resp.status().as_u16();
                let parsed: serde_json::Value = resp.json().await.unwrap();
                assert_eq!(status, 400, "{section} {label} (ephemeral): {parsed}");
                assert_eq!(parsed["error"]["code"], "invalid_request");
            }
        }
        handle.abort();
    }

    // STILL REFERENCED: the dangling-delete conflict needs a config that already NAMES a provider
    // the overlay defines, so it gets its own fixture (see `write_named_map_fixture`).
    {
        let (dir, _overlay, addr, handle) = named_map_app("witness-dangling", true).await;
        let admin = |r: reqwest::RequestBuilder| {
            r.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };
        let r = admin(client.put(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .body(
            serde_json::json!({
                "module": "admin-tokens",
                "token": {"file": dir.join("corp.token").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a dangling delete is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");

        // ...and the BULK twin, on the same fixture (the refused per-entry delete above left
        // `corp-ad` in place, which is exactly the state a dangling reset needs).
        //
        // This drives `DELETE /overlay/{section}`'s `Conflict/StillReferenced`. It has a test of
        // its own (`test_admin_v1_overlay_reset_named_map_refuses_a_dangling_reference`), and that
        // was not enough: the gate calls these drivers precisely SO THAT its verdict does not
        // depend on whether some other test ran, so a condition witnessed only by a sibling test is
        // witnessed nowhere as far as the gate is concerned. It read as an OVER-CLAIM — a
        // documented 409 nothing could produce — while the guard, and a passing test for it, were
        // both sitting right there. A driver that covers the per-entry case and skips its bulk twin
        // is the same "scoped to where the bug was first seen" shape the whole taxonomy exists to
        // catch.
        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/overlay/identity-providers"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a bulk reset that would dangle a reference is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The driver above, as a test in its own right — so the named-map error surface is exercised even
/// when the class-level audit is filtered out of a run.
#[tokio::test]
async fn named_map_error_surface_answers_its_declared_taxonomy() {
    drive_named_map_errors().await;
}

/// CONFIG STABILITY: THE ADMIN API AND THE FILE PARSER MUST SHARE ONE GRAMMAR. A PUT body
/// carrying a field the section's `deny_unknown_fields` config struct rejects is exactly what
/// `config.yaml` would refuse at boot — so the API must refuse it too, loudly and BEFORE persisting.
///
/// It did not. The handler only did a generic `serde_json::Value` parse plus "is it an object with a
/// non-empty `module`", answered 200, wrote the document verbatim into the overlay, and then DROPPED
/// it at the rebuild (`apply_named_maps_to_deploy` swallowed the typed parse error into a
/// `tracing::error!`). The operator got a success for config that never took effect and vanished on
/// every subsequent read — two paths disagreeing about the one frozen 1.5.3 grammar.
#[tokio::test]
async fn test_admin_v1_named_map_put_rejects_what_the_file_parser_rejects() {
    let (dir, overlay, addr, handle) = named_map_app("typedparse", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // `buffer` is not a field of `ExportDefCfg` (the operator meant `settings.buffer_seconds`).
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(r#"{"module":"prometheus","buffer":30}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unknown field is the same loud reject config.yaml gives"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("buffer"),
        "the refusal carries serde's own message naming the offending field: {body}"
    );

    // NOTHING was persisted and nothing is readable — the reject happens before the overlay write.
    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the rejected definition was never stored"
    );
    if let Ok(bytes) = std::fs::read(&overlay) {
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            doc["named_maps"]["export"]["spare"].is_null(),
            "the rejected definition is absent from the overlay: {doc}"
        );
    }

    // The SAME shape with the fields spelled correctly is accepted — this is a grammar check, not
    // a blanket refusal.
    let good = serde_json::json!({
        "module": "request-log-file",
        "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
    });
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(good.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    // The identity-providers section speaks the same rule through the same generic path.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo-idp"
    )))
    .body(r#"{"module":"keys","max_admin_scopes":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "the typed parse is per-section and driven by the section's own struct: {:?}",
        r.text().await
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// DISCOVERABILITY: an overlay-stored definition this binary cannot parse is DROPPED
/// at every rebuild. It used to be announced exactly once, at boot, in a log line — and the API read
/// surface answered 404 for the name, which is indistinguishable from "you never wrote it". An
/// operator who does not tail boot logs could not discover their own stored-but-inert config.
///
/// It is now surfaced through the READ, explicitly flagged (`unparseable` carries the parse error),
/// on both the collection and the single-entry read. The operator's data is only ever REPORTED —
/// never auto-deleted, never rewritten.
#[tokio::test]
async fn test_admin_v1_named_map_read_flags_an_unparseable_overlay_entry() {
    let (dir, overlay, addr, handle) = named_map_app("unparseable", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // An overlay holding a definition whose typed struct rejects it (a downgrade whose struct lost
    // the field, or a hand-edited overlay) — never applied, so absent from the live `export:` map.
    std::fs::write(
        &overlay,
        serde_json::json!({
            "version": 1,
            "named_maps": {
                "export": {
                    "ghost": {"module": "prometheus", "from_the_future": true,
                              "settings": {"buffer_seconds": 60}}
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let body: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/export")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ghost = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ghost")
        .unwrap_or_else(|| {
            panic!("the stored-but-inert entry is discoverable in the list: {body}")
        });
    assert!(
        ghost["unparseable"]
            .as_str()
            .is_some_and(|e| e.contains("from_the_future")),
        "and is EXPLICITLY flagged with the parse error rather than looking live: {ghost}"
    );
    assert_eq!(
        ghost["module"], "prometheus",
        "the operator's own raw document is projected back so they can see what they wrote"
    );

    // The single-entry read answers the flagged view rather than a 404 for a name that is sitting in
    // the operator's own overlay.
    let one = admin(client.get(format!("http://{addr}/api/v1/admin/export/ghost")))
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);
    let one: serde_json::Value = one.json().await.unwrap();
    assert!(one["unparseable"].is_string(), "{one}");

    // A LIVE definition is never flagged.
    let base: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        base["unparseable"].is_null(),
        "a parseable, live definition carries no flag: {base}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// SECRET CONTAINMENT ON THE HOOK-REGISTRY READS. Same class as the named-map reads above, and
/// the same fix: `GET /hooks` and `GET /hooks/{name}` are READ-ONLY admin scope, and a hook's
/// `settings:` bag is a `SecretRef` carrier by design (busbar resolves it before every configure
/// push) — so a literal credential written there is fully supported and must never be projected.
/// The `HookView` doc used to claim hook settings are "never a secret by contract", the SAME claim
/// `NamedDefView` had to retract.
#[tokio::test]
async fn test_admin_v1_hook_reads_project_settings_keys_never_values() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut cfg: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "plugin": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    cfg.settings = serde_json::json!({
        "endpoint": "https://gate.example.com",
        "api_token": "hunter2-hook"
    })
    .as_object()
    .unwrap()
    .clone();
    let app = TestApp::new().governance(gov).hook("baa-gate", cfg).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for url in [
        format!("http://{addr}/api/v1/admin/hooks"),
        format!("http://{addr}/api/v1/admin/hooks/baa-gate"),
    ] {
        let body = client
            .get(&url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            !body.contains("hunter2-hook"),
            "{url} projected a hook settings VALUE at READ-ONLY admin scope: {body}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let view = json
            .get("items")
            .and_then(|i| i.get(0))
            .cloned()
            .unwrap_or(json);
        assert_eq!(
            view["settings_keys"],
            serde_json::json!(["api_token", "endpoint"]),
            "the hook read must project the settings KEY NAMES, sorted"
        );
        assert!(
            view.get("settings").is_none(),
            "the raw hook settings bag must not be projected at all: {view}"
        );
    }
    handle.abort();
}

/// SECRET CONTAINMENT ON `GET /api/v1/admin/config/settings`. This read serializes the WHOLE
/// `RootSettings`, which carries `store: Option<StoreCfg>` and therefore `store.settings` — the bag
/// busbar's own docs spell with a credential (`url: rediss://:password@…`), and whose `url`
/// `plugin-pack` marks `x-busbar-secret`. `PUT /config/settings` requires FULL scope; this GET
/// requires only READ-ONLY — so unredacted it handed a read-only reader the governance ledger's
/// credential (keys, budgets, the hash-chained audit log) entirely out of band of busbar.
#[tokio::test]
async fn test_admin_v1_config_settings_read_redacts_every_settings_bag() {
    let (dir, _overlay, addr, handle) = settings_test_app("secretbag").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // An operator configures the durable store the way the docs show — credential in the URL.
    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": {
                    "module": "memory",
                    "settings": { "url": "rediss://:hunter2-store@ledger.internal:6379" }
                }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);

    let body = admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !body.contains("hunter2-store"),
        "the store credential reached a READ-ONLY-scope read: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let store = &json["settings"]["store"];
    assert_eq!(
        store["module"], "memory",
        "the non-secret shape still introspects: {json}"
    );
    assert_eq!(
        store["settings_keys"],
        serde_json::json!(["url"]),
        "the bag is projected as KEY NAMES, so `what is configured` survives: {json}"
    );
    assert!(
        store.get("settings").is_none(),
        "no raw settings bag anywhere on this wire: {json}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
