use busbar_kernel::audit_ring;
use busbar_kernel::config::migrated_store_module;
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel_testkit::test_support::governance::GovStateFixtures;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
use busbar_kernel_testkit::test_support::TestOverlayStore;
use std::sync::Arc;

#[path = "cache_flush_tests.rs"]
mod cache_flush_tests;

#[path = "store_overlay_tests.rs"]
mod store_overlay_tests;

#[path = "price_activation_tests.rs"]
mod price_activation_tests;

#[path = "config_boundary_tests.rs"]
mod config_boundary_tests;

const OAS_OPERATION_STATUSES: &str =
    include_str!("../../tests/fixtures/openapi_operation_statuses_key.txt").trim_ascii();

const LOCKED_CONFIG_MUTATION_MESSAGE: &str = "config mutation refused: this busbar has no writable Store-backed config overlay; edit config.yaml and reload a locked deployment";

fn gov_with_signer(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    let gov = gov_without_at_rest_key(store, admin_token);
    gov.set_at_rest_keys(Some(busbar_kernel::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
    gov
}

fn gov_without_at_rest_key(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

fn audit_principal(app: &mut Arc<busbar_kernel::state::App>, role: &str) {
    let inner = Arc::get_mut(app).expect("sole owner");
    let module = "test-scope-module";
    inner.admin_chain.insert(0, module.to_string());
    inner
        .role_bindings
        .entry(module.to_string())
        .or_default()
        .insert(
            role.to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
    inner
        .auth_scope_caps
        .insert(module.to_string(), "full".to_string());
}

async fn spin_up(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, reqwest::Client::new())
}

async fn serve_with_gov(gov: Arc<GovState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (addr, handle)
}

#[tokio::test]
async fn test_admin_v1_topology_reads_pools_models_providers() {
    use busbar_kernel_testkit::test_support::LaneSpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let app = crate::new_test_app()
        .governance(gov)
        .lane(
            LaneSpec::new("model-a", crate::linked_protocol(), "http://127.0.0.1:1/")
                .provider("prov-x"),
        )
        .lane(
            LaneSpec::new("model-b", crate::linked_protocol(), "http://127.0.0.1:1/")
                .provider("prov-y"),
        )
        .pool("mypool", &[(0, 3), (1, 1)])
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_keys_surface_governance_disabled_semantics() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let mut app = crate::new_test_app().build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = Vec::new();
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "collection GET is 200-empty");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());

    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

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
    use busbar_kernel_testkit::test_support::LaneSpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .lane(LaneSpec::new("m1", crate::linked_protocol(), "http://127.0.0.1:1/").provider("p"))
        .pool("mypool", &[(0, 5)])
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

    assert_eq!(m["usable"], true);
    assert_eq!(m["cooldown_remaining_seconds"], 0);
    assert!(m["available_concurrency"].is_number());
    assert!(m["inflight"].is_number());
    assert!(m["ok"].is_number());
    assert!(m["dead"].is_boolean());

    assert_eq!(m["trip_count"], 0);
    assert!(m["last_trip_at"].is_null());

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

#[tokio::test]
async fn test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell() {
    use busbar_kernel_testkit::test_support::LaneSpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .lane(LaneSpec::new("m1", crate::linked_protocol(), "http://127.0.0.1:1/").provider("p"))
        .pool("fast", &[(0, 1)])
        .pool("cheap", &[(0, 1)])
        .build();
    let now = busbar_kernel::store::now();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .store
        .force_open_in("fast", 0, now + 300);

    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_usage_meters_by_model_and_key() {
    use busbar_kernel::governance::NewKeySpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());

    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let rate = busbar_kernel::config::RateEntryCfg {
        input_utok: 500.0,
        output_utok: 500.0,
        cache_read_utok: 500.0,
        cache_write_utok: 500.0,
        ..Default::default()
    };
    let rate_card: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> = [
        ("model-1".to_string(), rate.clone()),
        ("model-2".to_string(), rate),
    ]
    .into_iter()
    .collect();
    let cost = busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rate_card),
        1,
        &std::collections::BTreeMap::new(),
    );
    let now = busbar_kernel::store::now();
    let (minted, minted_secret) = gov
        .create_key(
            NewKeySpec {
                name: "team-a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            now,
        )
        .unwrap();

    let usage = busbar_contract::billing::TokenUsage {
        input: 700,
        output: 200,
        cache_read: Some(100),
        cache_creation: None,
        ..Default::default()
    };

    gov.record_metering(&minted.id, "model-1", "vendor-a", Some(&usage), now);
    gov.record_metering(&minted.id, "model-1", "vendor-a", Some(&usage), now);
    gov.record_metering(&minted.id, "model-2", "acme", None, now);
    gov.flush_metering();
    let app = crate::new_test_app().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

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

    assert_eq!(body["total"]["requests"], 3);
    assert_eq!(body["total"]["tokens_input"], 1400);
    assert_eq!(body["total"]["tokens_output"], 400);
    assert_eq!(body["total"]["tokens_cache_read"], 200);
    assert_eq!(body["total"]["tokens_cache_creation"], 0);
    assert_eq!(body["total"]["spend_micros"], 1_030_000);

    let by_model = body["by_model"].as_array().unwrap();
    assert_eq!(by_model.len(), 2, "{by_model:?}");
    let x = by_model.iter().find(|m| m["model"] == "model-1").unwrap();
    assert_eq!(x["provider"], "vendor-a");
    assert_eq!(x["requests"], 2);
    assert_eq!(x["tokens_input"], 1400);

    assert_eq!(x["spend_micros"], 1_020_000);
    let z = by_model.iter().find(|m| m["model"] == "model-2").unwrap();
    assert_eq!(
        z["requests"], 1,
        "a flat (zero-token) response still counts"
    );
    assert_eq!(
        z["spend_micros"], 10_000,
        "1 req x 1 cent = 10_000 micro-units"
    );

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

#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let env =
        busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], Default::default());
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let env_for_warm = env.clone();
    let app = crate::new_test_app().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let (addr, serve, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "cfg-hook",
                "config": {"kind": "gate", "module": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let warm: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "settings": {"ratio": 0.4}
    }))
    .expect("hook cfg");
    assert!(
        busbar_kernel_testkit::test_support::hooks::await_transport_published(
            "cfg-hook",
            &warm,
            &env_for_warm
        )
        .await,
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

    assert_eq!(
        got["settings_keys"],
        serde_json::json!(["ratio"]),
        "committed settings visible as KEY NAMES: {got}"
    );
    assert!(
        got.get("settings").is_none(),
        "the raw settings bag must never be on this wire: {got}"
    );

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

#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_plugin_schema_falls_back_to_manifest_when_describe_answers_null() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let manifest_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"order": {"type": "array"}},
    });
    let env = busbar_kernel_testkit::test_support::test_hook_env_with_schema(
        &["test-hook-fallback"],
        Default::default(),
        Some(&manifest_schema.to_string()),
    );
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let env_for_warm = env.clone();
    let app = crate::new_test_app().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let (addr, serve, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "fallback-hook",
                "config": {"kind": "gate", "module": "test-hook-fallback"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);

    let warm: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook-fallback", "settings": {"empty_management": true}
    }))
    .expect("hook cfg");
    assert!(
        busbar_kernel_testkit::test_support::hooks::await_transport_published(
            "fallback-hook",
            &warm,
            &env_for_warm
        )
        .await,
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

#[tokio::test]
async fn test_admin_v1_config_apply_body_swaps_and_carries_health() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .lane(busbar_kernel_testkit::test_support::LaneSpec::new(
            "m0",
            crate::linked_protocol(),
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
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let body = serde_json::json!({
        "providers": {
            "test-provider": {"protocol": crate::linked_protocol(), "base_url": "http://127.0.0.1:1/"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "store": {"module": migrated_store_module()},
            "providers": {"test-provider": {"api_key": "none"}},
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

    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "store": {"module": migrated_store_module()}, "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);

    let malformed = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"not-a-version\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "store": {"module": migrated_store_module()}, "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status().as_u16(), 400);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_reload_swaps_disk_truth_and_carries_health() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let dir = std::env::temp_dir().join(format!("busbar-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
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
    let mut app = crate::new_test_app()
        .lane(busbar_kernel_testkit::test_support::LaneSpec::new(
            "m0",
            crate::linked_protocol(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());

        inner.store.record_hard_down(0, "tripped before reload");
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

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

    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
store: {module: memory}
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

#[tokio::test]
async fn test_admin_v1_mutation_rate_limit_config_class() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_scope_ladder_e2e_with_group_mapped_principals() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            busbar_kernel::config::operator_provider().to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );

        table.insert(
            "admins".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);

        let mut other = std::collections::BTreeMap::new();
        other.insert(
            "sneaky".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("other-module".to_string(), other);

        inner
            .auth_scope_caps
            .insert("test-scope-module".to_string(), "full".to_string());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let with = |tok: &'static str, req: reqwest::RequestBuilder| {
        req.header("x-admin-token", tok)
            .header("content-type", "application/json")
    };
    let hook_body = serde_json::json!({
        "name": "scoped-hook",
        "config": {"kind": "tap", "module": "test-hook"}
    })
    .to_string();
    let key_body = serde_json::json!({"name": "k"}).to_string();

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

    let r = with(
        "grp:strangers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "unmapped groups grant nothing");

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

#[tokio::test]
async fn test_admin_v1_idempotency_key_is_principal_scoped() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            busbar_kernel::config::operator_provider().to_string(),
        ];

        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "admins".to_string(),
            busbar_kernel::config::RoleBindingCfg {
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
    let (addr, handle, client) = spin_up(router).await;
    let mint = |tok: &'static str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .header("idempotency-key", "shared-value")
            .body(serde_json::json!({"name": "k"}).to_string())
            .send()
    };

    let a: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();

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

    let a2: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
    assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

    handle.abort();
}

struct CachingDoor(std::sync::atomic::AtomicUsize);

const FLUSHED: u64 = 3;

struct Passed;

impl std::future::Future for Passed {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::Verifying for Passed {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::AuthCalls for CachingDoor {
    fn name(&self) -> &str {
        "caching-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Passed)
    }
    fn refresh(&self) -> Result<u64, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FLUSHED)
    }
}

#[tokio::test]
async fn test_admin_v1_credential_cache_and_flush_endpoint() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let door = Arc::new(CachingDoor(std::sync::atomic::AtomicUsize::new(0)));

    let operator = busbar_kernel::config::operator_provider();
    let mut app = crate::new_test_app()
        .governance(gov)
        .admin_door("ext-idp", door.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            "ext-idp".to_string(),
            operator.to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let flush = |token: &'static str, body: Option<serde_json::Value>| {
        let mut r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", token);
        if let Some(body) = body {
            r = r
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        r.send()
    };

    let r = flush("grp:viewers", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 0);

    let r = flush("admintok", Some(serde_json::json!({"module": "ext-idp"})))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["flushed"], FLUSHED,
        "what the plugin reported dropping"
    );
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", Some(serde_json::json!({"module": operator})))
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], 0);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], FLUSHED);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 2);

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

#[tokio::test]
async fn test_admin_v1_put_auth_accepts_a_renamed_operator_provider() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let test_app = crate::new_test_app();
    let ops: busbar_kernel::config::IdentityProviderCfg = serde_yaml::from_str(&format!(
        "module: {}",
        busbar_kernel::config::operator_provider()
    ))
    .expect("a provider definition");
    let app = test_app
        .governance(gov)
        .identity_provider("ops", ops)
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let put = |chain: serde_json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({ "admin_auth": chain }).to_string())
            .send()
    };
    let r = put(serde_json::json!(["ops"])).await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap();
    assert_eq!(
        status, 200,
        "a provider backed by the operator module applies: {body}"
    );
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the operator token admits through `ops`"
    );
    let r = put(serde_json::json!(["saml"])).await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a name no admin module answers is refused"
    );
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_put_auth_dry_run_guard() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");

        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            busbar_kernel::config::operator_provider().to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "admins".to_string(),
            busbar_kernel::config::RoleBindingCfg {
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
    let (addr, handle, client) = spin_up(router).await;
    let put = |tok: &'static str, body: serde_json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    let r = put("admintok", serde_json::json!({"admin_auth": ["saml"]}))
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "unknown module is invalid_request"
    );

    let r = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("if-match", "\"999\"")
        .body(
            serde_json::json!({"admin_auth": [busbar_kernel::config::operator_provider()]})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "stale If-Match conflicts");

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

    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "grp:admins")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

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

#[tokio::test]
async fn test_admin_v1_put_auth_applies_an_empty_chain_as_1_5_5_did() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let r = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"admin_auth": []}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "1.5.5 applied an empty admin_auth chain live"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["applied"], true, "{body}");

    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "the open posture is in force");

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_put_auth_refused_on_locked_config() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let app = crate::new_test_app().governance(gov).no_overlay().build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let resp = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"admin_auth": [busbar_kernel::config::operator_provider()]})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a locked config must refuse PUT /admin-auth"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(LOCKED_CONFIG_MUTATION_MESSAGE),
        "the refusal names the locked/no-overlay reason: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_apply_refused_on_locked_config() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .lane(busbar_kernel_testkit::test_support::LaneSpec::new(
            "m0",
            crate::linked_protocol(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .no_overlay()
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let body = serde_json::json!({
        "providers": {
            "test-provider": {"protocol": "acme", "base_url": "http://127.0.0.1:1/"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "store": {"module": migrated_store_module()},
            "providers": {"test-provider": {"api_key": "none"}},
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
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(LOCKED_CONFIG_MUTATION_MESSAGE),
        "the refusal names the locked/no-overlay reason: {body}"
    );
    handle.abort();
}

struct GatedKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    entered: tokio::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    landed: tokio::sync::mpsc::Sender<String>,
    fired: std::sync::atomic::AtomicBool,
}
impl busbar_kernel::governance::RecordStore for GatedKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        if self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return self.inner.put_key(key);
        }

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
        if out.is_ok() {
            let _ = self.landed.try_send(key.id.clone());
        }
        out
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

struct SlowNthPutKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    delay: std::time::Duration,
    calls: std::sync::atomic::AtomicUsize,
    slow_on_call: usize,
}
impl busbar_kernel::governance::RecordStore for SlowNthPutKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == self.slow_on_call {
            std::thread::sleep(self.delay);
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test]
async fn an_idempotency_key_survives_a_client_disconnect_mid_mint() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let inner = Arc::new(MemoryStore::new());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (landed_tx, mut landed_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let gated_store: Arc<dyn busbar_kernel::governance::RecordStore> = Arc::new(GatedKeyStore {
        inner,
        entered: entered_tx,
        release: std::sync::Mutex::new(Some(release_rx)),
        landed: landed_tx,
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let gov = gov_with_signer(gated_store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

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

    let doomed_url = keys_url.clone();
    let doomed = tokio::spawn(async move {
        let client = reqwest::Client::new();
        post(&client, &doomed_url).await
    });

    const RENDEZVOUS_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::time::timeout(RENDEZVOUS_BACKSTOP, entered_rx.recv())
        .await
        .expect(
            "waited 60s for the mint to enter the store's put_key and it never did. The request \
             did not get as far as the blocking mint, so there is no mid-mint window to disconnect \
             inside and this test would be asserting nothing.",
        )
        .expect("the gated store was dropped before the mint entered put_key");

    doomed.abort();
    let joined = doomed.await;
    assert!(
        joined.as_ref().is_err_and(|e| e.is_cancelled()),
        "the doomed request must have been cancelled mid-flight; it instead completed, which means \
         the store gate did not hold the mint open and there was no mid-mint disconnect: {:?}",
        joined.map(|r| r.map(|resp| resp.status()))
    );

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

    release_tx
        .send(())
        .expect("the parked mint hung up on its release channel");
    let committed_id = tokio::time::timeout(RENDEZVOUS_BACKSTOP, landed_rx.recv())
        .await
        .expect(
            "waited 60s after releasing the parked mint and its write never committed. A mint \
             whose client disconnected must still run to completion on the uncancellable blocking \
             task; observed instead: released, then silence.",
        )
        .expect("the gated store was dropped before the released mint could commit");

    let normal_client = reqwest::Client::new();
    let retry = post(&normal_client, &keys_url).await.unwrap();

    assert!(
        matches!(retry.status().as_u16(), 201 | 409),
        "a retry must replay the first answer or refuse the held claim: {}",
        retry.status()
    );
    if retry.status().as_u16() == 201 {
        let replay: serde_json::Value = retry.json().await.unwrap();
        assert_eq!(
            replay["id"].as_str(),
            Some(committed_id.as_str()),
            "a cached 201 must name the first committed key, never a second mint"
        );
    }

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
    assert!(
        items
            .iter()
            .any(|key| key["id"].as_str() == Some(committed_id.as_str())),
        "the one retained key must be the first committed key"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_key_rotate_and_pagination() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov.clone()).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

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
        gov.verify_token(&new_token, busbar_kernel::store::now(), None)
            .is_some(),
        "the re-minted token authenticates"
    );

    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/keys/vk_nope/rotate")))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let inner = Arc::new(MemoryStore::new());

    let slow_store: Arc<dyn busbar_kernel::governance::RecordStore> =
        Arc::new(SlowNthPutKeyStore {
            inner,
            delay: std::time::Duration::from_millis(500),
            calls: std::sync::atomic::AtomicUsize::new(0),
            slow_on_call: 1,
        });
    let gov = gov_with_signer(slow_store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
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

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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

#[tokio::test]
async fn create_and_rotate_operation_namespaces_survive_cache_loss() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    for create_first in [true, false] {
        for lose_cache in [false, true] {
            let store = Arc::new(MemoryStore::new());
            let gov = gov_with_signer(store, Some("admintok".to_string()));
            let (mut addr, mut server) = serve_with_gov(gov.clone()).await;
            let client = reqwest::Client::new();
            let created: serde_json::Value = client
                .post(format!("http://{addr}/api/v1/admin/keys"))
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "rotate-target"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let target = created["id"]
                .as_str()
                .expect("the target was minted")
                .to_string();
            let original_token = created["token"]
                .as_str()
                .expect("mint returned a token")
                .to_string();
            let rotate_header = "operation-collision";
            let create_header = crate::idempotency::rotate_replay_key(&target, rotate_header);
            for first in [true, false] {
                if !first && lose_cache {
                    server.abort();
                    let _ = server.await;
                    (addr, server) = serve_with_gov(gov.clone()).await;
                }
                let create = first == create_first;
                let request = if create {
                    client
                        .post(format!("http://{addr}/api/v1/admin/keys"))
                        .header("idempotency-key", &create_header)
                        .json(&serde_json::json!({"name": "independent-create"}))
                } else {
                    client
                        .post(format!("http://{addr}/api/v1/admin/keys/{target}/rotate"))
                        .header("idempotency-key", rotate_header)
                };
                let response = request
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), if create { 201 } else { 200 });
                let body: serde_json::Value = response.json().await.unwrap();
                let id = body["id"].as_str().expect("the operation returns a key id");
                let token = body["token"]
                    .as_str()
                    .filter(|t| !t.is_empty())
                    .expect("a real token");
                if create {
                    assert!(
                        id != target,
                        "create must mint its own key, never replay the rotation"
                    );
                } else {
                    assert!(id == target, "rotate must answer for its actual target");
                    assert!(
                        token != original_token,
                        "rotate must retire the original token"
                    );
                }
            }
            assert_eq!(
                gov.all_keys().unwrap().len(),
                2,
                "one target and one independent create"
            );
            server.abort();
        }
    }
}

#[tokio::test]
async fn test_admin_v1_put_hook_replaces_live_with_guards() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "rep",
                "config": {"kind": "tap", "module": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook-v2"}}).to_string())
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

    let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(
            serde_json::json!({"config": {"kind": "gate", "module": "test-hook", "prompt": "rw"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "module": "test-hook"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

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
                "config": {"kind": "tap", "module": "test-hook"},
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

#[tokio::test]
async fn test_admin_v1_config_versions_rollback_and_diff() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    let body = serde_json::json!({
        "name": "rbk",
        "config": {"kind": "tap", "module": "test-hook"}
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

    let rb = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(rb.status().as_u16(), 200);
    let rb_body: serde_json::Value = rb.json().await.unwrap();
    assert_eq!(rb_body["restored_version"], 1);
    assert_eq!(rb_body["config_version"], 3);
    let restored = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        restored.status().as_u16(),
        200,
        "the rolled-back hook is live again"
    );

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
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

    let body = serde_json::json!({
        "name": "compress",
        "config": {
            "kind": "gate",
            "module": "test-hook",
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

    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    for reserved in [
        "reject",
        "weighted",
        "nothing",
        "cheapest",
        busbar_kernel::config::operator_provider(),
    ] {
        let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": reserved,
                    "config": {"kind": "gate", "module": "test-hook"}
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

    let bad = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "bad",
                "config": {"kind": "tap", "module": "test-hook", "prompt": "rw"}
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

    let escalate = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "compress",
                "config": {"kind": "gate", "module": "test-hook", "prompt": "ro"}
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

#[tokio::test]
async fn test_admin_v1_audit_records_mutations() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let name = "audit_probe_hook_x7";
    client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": name,
                "config": {"kind": "tap", "module": "test-hook", "global": true}
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

#[tokio::test]
async fn test_admin_v1_hook_mutation_404_is_audited() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let put_name = "ghost_put_hook_q3";
    let patch_name = "ghost_patch_hook_q3";

    let put_resp = client
        .put(format!("http://{addr}/api/v1/admin/hooks/{put_name}"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook"}}).to_string())
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

#[tokio::test]
async fn test_admin_v1_list_keys_filters() {
    use busbar_kernel::governance::NewKeySpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (minted, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "filter-probe".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            busbar_kernel::store::now(),
        )
        .unwrap();
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
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

    let by_prefix = get(format!("?prefix={}", minted.id)).await;
    let keys = by_prefix["items"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], minted.id);

    let none = get("?prefix=vk_does_not_exist".into()).await;
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    let enabled = get("?enabled=true".into()).await;
    assert!(enabled["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["id"] == minted.id));

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_list_keys_group_filter() {
    use busbar_kernel::governance::NewKeySpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mint = |name: &str, group: Option<&str>| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                allowed_pools: None,
                group: group.map(String::from),
                labels: Default::default(),
                ..Default::default()
            },
            busbar_kernel::store::now(),
        )
        .unwrap()
        .0
    };

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

    let by_group = get("?group=alpha".into()).await;
    let items = by_group["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the alpha-bound key: {by_group}");
    assert_eq!(items[0]["id"], alpha.id);
    assert_eq!(items[0]["group"], "alpha");

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

#[tokio::test]
async fn test_admin_v1_config_plane_golden_path() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("t".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, c) = spin_up(router).await;
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

    let created = c
        .post(format!("{base}/api/v1/admin/hooks"))
        .header("x-admin-token", "t")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": name, "config":
                    {"kind": "gate", "module": "test-hook", "global": true}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    assert!(get("/api/v1/admin/hooks".into()).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == name));
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 1);
    assert_eq!(get("/api/v1/admin/config".into()).await["version"], 1);
    assert!(busbar_kernel::config::overlay::read(&overlay.backend())
        .unwrap()
        .hooks
        .contains_key(name));

    assert!(
        get(format!("/api/v1/admin/audit?resource=hook:{name}")).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "hook.register" && e["outcome"] == "applied")
    );

    let deleted = c
        .delete(format!("{base}/api/v1/admin/hooks/{name}"))
        .header("x-admin-token", "t")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 2);
    assert!(!busbar_kernel::config::overlay::read(&overlay.backend())
        .unwrap()
        .hooks
        .contains_key(name));

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_hook_register_persists_to_overlay() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "persisted_gate",
                "config": {"kind": "gate", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay written");
    assert!(doc.hooks.contains_key("persisted_gate"));
    assert!(doc.global_hooks.iter().any(|g| g == "persisted_gate"));

    let fresh_deploy: busbar_kernel::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    let mut fresh =
        busbar_kernel::config::resolve(&fresh_deploy, &std::collections::HashMap::new())
            .expect("minimal config resolves");
    busbar_kernel::config::overlay::merge_into(&mut fresh, doc);
    assert!(
        fresh.hooks.contains_key("persisted_gate"),
        "the runtime-registered hook survives a restart via the overlay"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_apply_preserves_the_persisted_overlay() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

    let applied = client
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"config": {"providers": {}, "models": {}, "store": {"module": migrated_store_module()}}}).to_string())
        .send()
        .await
        .unwrap();
    let st = applied.status().as_u16();
    let body = applied.text().await.unwrap_or_default();
    assert_eq!(st, 200, "the apply itself succeeds: {body}");

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

    assert_eq!(create_group("second_team").await, 201);
    let doc =
        busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay still readable");
    assert!(
        doc.groups.contains_key("api_team"),
        "the next group write must not erase the earlier one from the overlay"
    );
    assert!(
        doc.groups.contains_key("second_team"),
        "and records the new one"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_base_hook_is_read_only_via_api() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = crate::new_test_app()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let (addr, _handle, client) = spin_up(router).await;

    let shadow = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "pii-guard",
                "config": {"kind": "gate", "module": "test-hook", "prompt": "no", "global": true}
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

#[tokio::test]
async fn base_hook_delete_conflict_outranks_a_stale_if_match() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = crate::new_test_app()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let (addr, _handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_delete_hook_takes_effect_live() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let tok = ("x-admin-token", "admintok");

    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header(tok.0, tok.1)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "logger",
                "config": {"kind": "tap", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let absent = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status().as_u16(), 404);

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

#[tokio::test]
async fn test_admin_v1_hooks_read_surface() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let gate = busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 25,
        on_error: "reject".to_string(),
        prompt: busbar_kernel::config::PromptAccess::Rw,
        user: busbar_kernel::config::UserAccess::Ro,
        priority: 7,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .hook("compress", gate)
        .global_hook("compress")
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

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

#[tokio::test]
async fn test_admin_v1_hook_health_best_effort() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mk = |plugin: &str| busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::PromptAccess::No,
        user: busbar_kernel::config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .hook("web", mk("web-hook-plugin"))
        .hook("sock", mk("sock-hook-plugin"))
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
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

    let missing = get("nope").await;
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

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

#[tokio::test]
async fn test_admin_v1_plugins_catalog_by_type() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let gate = busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::PromptAccess::No,
        user: busbar_kernel::config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .hook("myhook", gate)
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

    let auth: serde_json::Value = get("auth").await.json().await.unwrap();
    let a_items = auth["items"].as_array().unwrap();
    let keys = a_items
        .iter()
        .find(|p| p["name"] == "keys")
        .expect("the built-in keys verifier is always listed");
    assert_eq!(keys["loader"], "compiled-in");
    assert_eq!(keys["type"], "auth");
    let admin_tokens = a_items
        .iter()
        .find(|p| p["name"] == busbar_kernel::config::operator_provider());
    assert_eq!(
        admin_tokens.is_some(),
        busbar_kernel::preflight::linked_auth_names()
            .contains(&busbar_kernel::config::operator_provider()),
        "the operator credential is listed iff linked"
    );
    if let Some(admin_tokens) = admin_tokens {
        assert_eq!(admin_tokens["loader"], "compiled-in");
        assert_eq!(admin_tokens["type"], "auth");
    }

    let hooks: serde_json::Value = get("hooks").await.json().await.unwrap();
    let h_items = hooks["items"].as_array().unwrap();
    assert!(h_items
        .iter()
        .any(|p| p["name"] == "weighted" && p["loader"] == "compiled-in"));
    for linked in busbar_kernel::preflight::root_rows().hook_names {
        assert!(
            h_items
                .iter()
                .any(|p| p["name"] == *linked && p["loader"] == "compiled-in"),
            "the linked hook row `{linked}` is listed compiled-in: {h_items:?}"
        );
    }
    let ext = h_items
        .iter()
        .find(|p| p["name"] == "myhook")
        .expect("external hook listed");
    assert_eq!(ext["loader"], "external");
    assert_eq!(ext["active"], true);
    assert_eq!(ext["target"], "test-hook");

    let bad = get("nope").await;
    assert_eq!(bad.status().as_u16(), 400);
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_validate_dry_run() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/config/validate");

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

    let proposed = serde_json::json!({
        "config": {
            "providers": { "acme": { "api_key": { "env": "ACME_KEY" } } },
            "store": {"module": migrated_store_module()},
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
            .any(|e| e.as_str().unwrap_or("").contains("acme")),
        "the dangling provider is named in an error: {errors:?}"
    );

    let proposed = serde_json::json!({
        "config": {
            "secrets": { "acme-vault": { "settings": {} } },
            "providers": {},
            "store": {"module": migrated_store_module()},
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

#[tokio::test]
async fn test_admin_v1_config_validate_accepts_1_6_0_additive_top_level_keys() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/config/validate");

    let proposed = serde_json::json!({
        "config": {
            "oauth_as": null,
            "providers": {},
            "store": {"module": migrated_store_module()},
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
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        status, 200,
        "a 1.6.0-additive top-level key must not be refused as a malformed request: {body}"
    );
    assert_eq!(
        body["ok"], true,
        "an otherwise-empty config with a null oauth_as: should validate clean: {body}"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_apply_accepts_the_boot_shape_and_refuses_an_unknown_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/config/apply");
    let apply = |config: serde_json::Value| {
        client
            .post(&url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"config": config, "providers": {}}).to_string())
            .send()
    };

    let lifted = apply(serde_json::json!({
        "oauth_as": null,
        "providers": {},
        "store": {"module": migrated_store_module()},
        "models": {}
    }))
    .await
    .unwrap();
    let status = lifted.status().as_u16();
    let body = lifted.text().await.unwrap();
    assert_eq!(status, 200, "a key the boot pre-pass lifts applies: {body}");

    let unknown = apply(serde_json::json!({
        "not_a_config_key": true,
        "providers": {},
        "store": {"module": migrated_store_module()},
        "models": {}
    }))
    .await
    .unwrap();
    let status = unknown.status().as_u16();
    let body = unknown.text().await.unwrap();
    assert_eq!(status, 400, "a key boot does not know is refused: {body}");
    assert!(body.contains("not_a_config_key"), "{body}");

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_effective_snapshot_no_secrets() {
    use busbar_kernel_testkit::test_support::LaneSpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let gate = busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::PromptAccess::No,
        user: busbar_kernel::config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .lane(LaneSpec::new("m", crate::linked_protocol(), "http://127.0.0.1:1/").provider("prov"))
        .pool("p", &[(0, 1)])
        .hook("g", gate)
        .global_hook("g")
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/config"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();

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

    for needle in ["admintok", "client_tokens", "api_key", "secret"] {
        assert!(
            !text.contains(needle),
            "effective config must not leak `{needle}`: {text}"
        );
    }

    handle.abort();
}

/// ROUTER ↔ DOCUMENT PARITY FOR THE WHOLE ADMIN SURFACE (item 370), in both directions, over the
/// document the node actually SERVES (`GET /openapi.json`, every plane configured so nothing is
/// filtered out) — never a hand-kept list of paths.
///
/// The test checks that every documented operation resolves on its method, including named-map section routes and plane trust verbs, and that the router exposes no undocumented operation:
///
///
///
/// 1. DOCUMENT → ROUTER: every documented `(method, path)` this crate's router answers is asked
///    live, and must answer neither the router's unmatched-path fallback nor a 405 — and the status
///    it answers must be one of the operation's documented response codes. The kernel loop's
///    operations (the closed-table rows the NODE's administrative loop answers, not this router)
///    are excluded by the table, never by anything the document says about itself.
/// 2. ROUTER → DOCUMENT, per path: on every documented path, every method the document does NOT
///    list must answer the router's 405 (or the unmatched fallback) — a handler hung on an extra
///    method of a documented path is an undocumented operation.
/// 3. ROUTER → DOCUMENT, per route: every `(method, path)` the JSON transport mounts by literal
///    `.route(..)` (read out of the router's own source, `v1/json/mod.rs`) is documented. The
///    loop-mounted routes (named-map sections, plane trust verbs) come from the same registries the
///    document is generated from and are reconciled by `served_surface.rs`.
///
/// Also pins the document's identity and the stable error-code enum.
#[tokio::test]
async fn test_admin_v1_openapi_paths_all_resolve() {
    use std::collections::{BTreeMap, BTreeSet};
    const PREFIX: &str = crate::v1::contract::ADMIN_PREFIX;
    const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::ensure_seam();

    let every_plane: Vec<&'static str> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| d.config_section)
        .collect();

    let spawn = || {
        let gov = gov_with_signer(Arc::new(MemoryStore::new()), Some("admintok".to_string()));
        let app = crate::new_test_app()
            .governance(gov)
            .plane_sections(&every_plane)
            .build();
        let router = crate::build_router(app);
        async move {
            let (addr, handle, _) = spin_up(router).await;
            (addr, handle)
        }
    };
    let client = reqwest::Client::new();
    let ask = |addr: std::net::SocketAddr, method: &str, path: &str| {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let req = client
            .request(method.clone(), format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok");

        let req = if method == reqwest::Method::GET {
            req
        } else {
            req.header("content-type", "application/json").body("{")
        };
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };

    let (addr, handle) = spawn().await;
    let doc: serde_json::Value =
        serde_json::from_str(&ask(addr, "GET", &format!("{PREFIX}/openapi.json")).await.1)
            .expect("the served openapi.json parses");
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Busbar Admin API");
    let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]
        ["enum"]
        .as_array()
        .unwrap();
    assert!(codes.iter().any(|c| c == "not_found"));

    let mut documented: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (key, op) in item.as_object().expect("path item") {
            if key.starts_with("x-") {
                continue;
            }
            let method = key.to_ascii_uppercase();
            assert!(
                METHODS.contains(&method.as_str()),
                "{path} documents `{key}`, which is no admin operation method"
            );
            let statuses = op[OAS_OPERATION_STATUSES]
                .as_object()
                .unwrap_or_else(|| panic!("{method} {path} documents no status"))
                .keys()
                .cloned()
                .collect();
            documented.insert((method, path.clone()), statuses);
        }
    }

    for (rel, _) in crate::v1::json::V1_GET_PATHS {
        assert!(
            documented.contains_key(&("GET".to_string(), format!("{PREFIX}{rel}"))),
            "GET {PREFIX}{rel} is missing from the served document"
        );
    }
    for m in METHODS {
        assert!(
            documented.keys().any(|(dm, _)| dm == m),
            "the served document documents no {m} operation at all"
        );
    }

    let loop_verbs: BTreeSet<&'static str> = crate::verb::NEW_VERBS
        .iter()
        .chain(crate::verb::LEDGER_VERBS)
        .chain(crate::verb::AUDIT_VERBS)
        .filter_map(|v| crate::verb::verb_name(*v))
        .collect();
    let kernel_loop: BTreeSet<(String, String)> = crate::admin_codec::verbs::table()
        .into_iter()
        .filter(|row| loop_verbs.contains(row.verb))
        .map(|row| (row.method.to_string(), row.template.to_string()))
        .collect();
    let concrete = |path: &str| {
        path.split('/')
            .map(|seg| {
                if seg.starts_with('{') {
                    "resolve-probe"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut fallback: BTreeMap<&str, (u16, String)> = BTreeMap::new();
    for m in METHODS {
        fallback.insert(
            m,
            ask(addr, m, &format!("{PREFIX}/no-such-admin-route/resolve")).await,
        );
    }
    assert_eq!(
        fallback["GET"].0, 404,
        "the unmatched-path control is the router's 404"
    );

    let mut failures: Vec<String> = Vec::new();

    handle.abort();

    let mut probed = 0usize;
    let paths: BTreeSet<&String> = documented.keys().map(|(_, p)| p).collect();
    for path in paths {
        let (addr, handle) = spawn().await;
        for m in METHODS {
            let op = (m.to_string(), path.clone());
            let answer = match documented.get(&op) {
                Some(_) if kernel_loop.contains(&op) => continue,
                _ => ask(addr, m, &concrete(path)).await,
            };
            let Some(statuses) = documented.get(&op) else {
                if answer.0 != 405 && answer != fallback[m] {
                    failures.push(format!(
                        "{m} {path} is NOT documented but the router serves it ({}): {}",
                        answer.0, answer.1
                    ));
                }
                continue;
            };

            probed += 1;
            if answer == fallback[m] {
                failures.push(format!(
                    "{m} {path} is documented but the router answers its unmatched-path \
                     fallback: nothing serves it (phantom endpoint)"
                ));
            } else if answer.0 == 405 {
                failures.push(format!(
                    "{m} {path} is documented but the router mounts the path without this method"
                ));
            } else if !statuses.contains(&answer.0.to_string()) {
                failures.push(format!(
                    "{m} {path} answered {} which its documented statuses {statuses:?} do not \
                     list: {}",
                    answer.0, answer.1
                ));
            }
        }
        handle.abort();
    }
    assert!(
        probed > crate::v1::json::V1_GET_PATHS.len() * 4,
        "only {probed} documented operations were probed on the router"
    );

    let literal = literal_admin_routes(include_str!("../v1/json/mod.rs"));
    assert!(
        literal.len() >= 50,
        "only {} literal admin routes were read out of v1/json/mod.rs — the scanner lost the \
         router",
        literal.len()
    );
    for (method, rel) in &literal {
        let path = format!("{PREFIX}{rel}");
        if !documented.contains_key(&(method.clone(), path.clone())) {
            failures.push(format!(
                "{method} {path} is mounted by v1/json/mod.rs but is in NO served document"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "admin router / OpenAPI document disagree:\n  {}",
        failures.join("\n  ")
    );
}

fn literal_admin_routes(src: &str) -> Vec<(String, String)> {
    use crate::v1::contract as c;
    let consts: [(&str, &str); 5] = [
        ("PATH_HOOKS", c::PATH_HOOKS),
        ("PATH_GROUPS", c::PATH_GROUPS),
        ("PATH_PLUGINS_INSPECT", c::PATH_PLUGINS_INSPECT),
        ("PATH_ADMIN_AUTH", c::PATH_ADMIN_AUTH),
        ("PATH_CONFIG_VALIDATE", c::PATH_CONFIG_VALIDATE),
    ];
    let start = src
        .find("impl AdminTransport for JsonV1")
        .expect("v1/json/mod.rs implements the JSON transport");
    let body = &src[start..];
    let body = &body[..body
        .find(".fallback(")
        .expect("the router ends in its fallback")];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(".route(") {
        let after = &rest[at + ".route(".len()..];

        let mut depth = 1usize;
        let mut end = 0usize;
        for (i, ch) in after.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let args = &after[..end];
        rest = &after[end..];
        let (first, second) = args.split_once(',').expect(".route(path, method_router)");
        let first = first.trim();
        let rel = if let Some(lit) = first.strip_prefix('"') {
            lit.trim_end_matches('"').to_string()
        } else {
            consts
                .iter()
                .find(|(name, _)| *name == first)
                .unwrap_or_else(|| {
                    panic!("v1/json/mod.rs mounts a route at `{first}`, a path this scanner cannot resolve — name its value here")
                })
                .1
                .to_string()
        };

        let mut depth = 0usize;
        let mut ident = String::new();
        let mut methods = Vec::new();
        for ch in second.chars() {
            match ch {
                '(' => {
                    if depth == 0
                        && ["get", "post", "put", "patch", "delete"].contains(&ident.as_str())
                    {
                        methods.push(ident.to_ascii_uppercase());
                    }
                    depth += 1;
                    ident.clear();
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    ident.clear();
                }
                c if c.is_ascii_alphanumeric() || c == '_' => ident.push(c),
                _ => ident.clear(),
            }
        }
        assert!(
            !methods.is_empty(),
            "the route at {rel} mounts no method this scanner recognises: {second}"
        );
        for m in methods {
            out.push((m, rel.clone()));
        }
    }
    out
}

#[tokio::test]
async fn test_admin_v1_all_reads_require_admin_token() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    for (rel, _) in crate::v1::json::V1_GET_PATHS {
        let path = format!("{}{rel}", crate::v1::contract::ADMIN_PREFIX);

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

#[test]
fn test_create_key_unconfigured_allowed_pool_is_nonfatal_and_quiet() {
    use tracing_subscriber::layer::SubscriberExt as _;

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let app = crate::new_test_app()
        .lane(busbar_kernel_testkit::test_support::LaneSpec::new(
            "m",
            crate::linked_protocol(),
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
            let body1 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-typo",
                    "allowed_pools": ["smart", "smrt"]
                })
                .to_string(),
            );
            let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
            let r1 = super::create_key(
                axum::extract::State(handle.clone()),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
                body1,
            )
            .await;
            let s1 = r1.status().as_u16();

            let body2 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-ok",
                    "allowed_pools": ["smart"]
                })
                .to_string(),
            );
            let r2 = super::create_key(
                axum::extract::State(handle),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
                body2,
            )
            .await;
            let s2 = r2.status().as_u16();
            (s1, s2)
        })
    });

    assert_eq!(
        unknown_status, 201,
        "an unconfigured allowed_pool must NOT 400 — the key is still minted"
    );
    assert_eq!(
        known_status, 201,
        "a configured allowed_pool creates the key"
    );

    let msgs = cap.messages();

    let pool_warns: Vec<&String> = msgs
        .iter()
        .filter(|m| m.contains("allowed_pools entry names no configured pool"))
        .collect();
    assert_eq!(
        pool_warns.len(),
        0,
        "the unconfigured allowed_pool hint is benign (debug), so it must NOT surface at WARN: {msgs:?}"
    );
}

#[tokio::test]
async fn proof_role_binding_mode_ceiling_bounds_a_delegated_admin() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    async fn mint_under(
        principal: &busbar_kernel::auth::Principal,
        allowed_modes: Vec<String>,
    ) -> (u16, usize) {
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let mut ceilings = std::collections::BTreeMap::new();
        ceilings.insert(
            "app-admin".to_string(),
            busbar_kernel::governance::mint_policy::RoleCeiling {
                max_ttl_secs: None,
                allowed_pools: None,
                binding_modes: Some(allowed_modes),
            },
        );
        let policy = busbar_kernel::governance::mint_policy::MintPolicy {
            self_mint: None,
            block_max_ttl_secs: None,
            block_binding_modes: None,
            ceilings,
        };
        let app = crate::new_test_app()
            .governance(gov.clone())
            .mint_policy(policy)
            .build();
        let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
        let body = axum::body::Bytes::from(serde_json::json!({ "name": "svc" }).to_string());
        let resp = super::create_key(
            axum::extract::State(handle),
            axum::Extension(busbar_kernel::auth::AuthPrincipal(Some(principal.clone()))),
            axum::http::HeaderMap::new(),
            axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
            body,
        )
        .await;
        let live = gov
            .all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count();
        (resp.status().as_u16(), live)
    }

    let (refused_status, refused_rows) =
        mint_under(&principal, vec!["user-bound".to_string()]).await;
    assert_eq!(
        refused_status, 400,
        "a role whose binding_modes excludes time-bound must be refused at the mint ceiling"
    );
    assert_eq!(refused_rows, 0, "the refused mint writes NO key row");

    let (ok_status, ok_rows) = mint_under(&principal, vec!["time-bound".to_string()]).await;
    assert_eq!(
        ok_status, 201,
        "a role whose binding_modes includes time-bound mints the key"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
}

#[tokio::test]
async fn proof_max_ttl_ceiling_refuses_overask_and_clamps_default() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const CEIL: u64 = 24 * 3600;

    async fn mint(body: serde_json::Value) -> (u16, Arc<GovState>, Option<u64>) {
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let policy = busbar_kernel::governance::mint_policy::MintPolicy {
            self_mint: None,
            block_max_ttl_secs: Some(CEIL),
            block_binding_modes: None,
            ceilings: Default::default(),
        };
        let app = crate::new_test_app()
            .governance(gov.clone())
            .mint_policy(policy)
            .build();
        let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
        let resp = super::create_key(
            axum::extract::State(handle),
            axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
            axum::http::HeaderMap::new(),
            axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
            axum::body::Bytes::from(body.to_string()),
        )
        .await;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        let exp = json.get("expires_at").and_then(|v| v.as_u64());
        (status, gov, exp)
    }

    fn live_rows(gov: &GovState) -> usize {
        gov.all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count()
    }

    let t0 = busbar_kernel::store::now();
    let (refused, gov_refused, _) =
        mint(serde_json::json!({ "name": "svc", "expires_in": "48h" })).await;
    assert_eq!(
        refused, 400,
        "an explicit expires_in over the max_ttl ceiling MUST be refused"
    );
    assert_eq!(
        live_rows(&gov_refused),
        0,
        "the refused over-ask writes NO key row"
    );

    let (ok, _gov_ok, exp) = mint(serde_json::json!({ "name": "svc" })).await;
    assert_eq!(ok, 201, "a mint with no expiry succeeds");
    let exp = exp.expect("the 201 response carries expires_at");
    assert!(
        (t0 + CEIL..=busbar_kernel::store::now() + CEIL).contains(&exp),
        "the default lifetime is CLAMPED to the 24h ceiling (exp≈now+24h): exp={exp}, ceiling={CEIL}"
    );

    assert!(
        exp < t0 + busbar_kernel::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
        "the clamped exp is strictly below the unclamped 90-day default"
    );
}

#[tokio::test]
async fn proof_max_ttl_ceiling_clamps_a_rotated_token() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const CEIL: u64 = 24 * 3600;
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let policy = busbar_kernel::governance::mint_policy::MintPolicy {
        self_mint: None,
        block_max_ttl_secs: Some(CEIL),
        block_binding_modes: None,
        ceilings: Default::default(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .mint_policy(policy)
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    let created: serde_json::Value = admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
        .body(serde_json::json!({"name": "rotated-under-ceiling"}).to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"]
        .as_str()
        .expect("the mint answers an id")
        .to_string();
    let t0 = busbar_kernel::store::now();
    let rotated = admin(client.post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate")))
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status().as_u16(), 200, "the rotate answers");
    let rotated: serde_json::Value = rotated.json().await.unwrap();
    let exp = rotated["expires_at"]
        .as_u64()
        .expect("a signed-token rotate answers expires_at");
    assert!(
        exp <= busbar_kernel::store::now() + CEIL,
        "the rotated token outlives the 24h max_ttl ceiling: exp={exp}, now={t0}, ceiling={CEIL}"
    );
    assert!(
        exp >= t0 + CEIL,
        "the rotated token's default lifetime is clamped TO the ceiling, not below it: exp={exp}"
    );
    handle.abort();
}

#[tokio::test]
async fn proof_role_mint_ceiling_bounds_a_delegated_admin() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const ROLE_TTL: u64 = 3600;

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    async fn mint_under(
        principal: &busbar_kernel::auth::Principal,
        body: serde_json::Value,
    ) -> (u16, usize) {
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let mut ceilings = std::collections::BTreeMap::new();
        ceilings.insert(
            "app-admin".to_string(),
            busbar_kernel::governance::mint_policy::RoleCeiling {
                max_ttl_secs: Some(ROLE_TTL),
                allowed_pools: Some(vec!["pool-ok".to_string()]),
                binding_modes: None,
            },
        );
        let policy = busbar_kernel::governance::mint_policy::MintPolicy {
            self_mint: None,
            block_max_ttl_secs: None,
            block_binding_modes: None,
            ceilings,
        };
        let app = crate::new_test_app()
            .governance(gov.clone())
            .mint_policy(policy)
            .build();
        let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
        let resp = super::create_key(
            axum::extract::State(handle),
            axum::Extension(busbar_kernel::auth::AuthPrincipal(Some(principal.clone()))),
            axum::http::HeaderMap::new(),
            axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
            axum::body::Bytes::from(body.to_string()),
        )
        .await;
        let live = gov
            .all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count();
        (resp.status().as_u16(), live)
    }

    let (bad_pool, bad_pool_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-forbidden"], "expires_in": "10m" }),
    )
    .await;
    assert_eq!(
        bad_pool, 400,
        "a pool outside the role mint ceiling MUST be refused"
    );
    assert_eq!(
        bad_pool_rows, 0,
        "the refused out-of-ceiling-pool mint writes NO key row"
    );

    let (over_ttl, over_ttl_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-ok"], "expires_in": "24h" }),
    )
    .await;
    assert_eq!(
        over_ttl, 400,
        "a TTL over the role mint ceiling MUST be refused"
    );
    assert_eq!(
        over_ttl_rows, 0,
        "the refused over-ceiling-TTL mint writes NO key row"
    );

    let (ok, ok_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-ok"], "expires_in": "10m" }),
    )
    .await;
    assert_eq!(
        ok, 201,
        "an in-ceiling mint (allowed pool, within-ceiling TTL) succeeds"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
}

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
impl busbar_kernel::governance::RecordStore for CountingStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.get_key_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.list_keys_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    fn add_denylist(
        &self,
        sub: &str,
        reason: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> busbar_kernel::governance::RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[tokio::test]
async fn test_single_key_reads_use_get_key_not_list_keys() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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

#[tokio::test]
async fn test_single_key_writes_use_get_key_for_their_existence_check() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
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
                ..Default::default()
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

struct BarrierStore {
    inner: MemoryStore,
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl busbar_kernel::governance::RecordStore for BarrierStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_kernel::governance::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.entered.send(());

            let _ = self.release.lock().unwrap().recv();
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_kernel::governance::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }

    fn add_denylist(
        &self,
        sub: &str,
        reason: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> busbar_kernel::governance::RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_patch_interleaved_with_delete_never_resurrects_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

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

    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

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

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = patch_task.await.unwrap();
    let _ = delete_task.await.unwrap();

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

#[tokio::test]
async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;

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
fn test_existence_gate_is_claimable_without_runtime() {
    let first = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(first);
    let again = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(again);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await;
    });

    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    patch_task.abort();
    let _ = patch_task.await;

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

    release_tx.send(()).unwrap();
    let del_status = delete_task.await.unwrap();

    assert_eq!(
        del_status, 204,
        "the DELETE runs after the gate frees and revokes the (now-present) key"
    );
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_of_another_key_is_not_held_behind_a_patch_parked_in_the_store() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let mint = |name: &str| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                ..Default::default()
            },
            0,
        )
        .unwrap()
        .0
    };
    let (parked_key, other_key) = (mint("parked"), mint("other"));
    let (addr, handle) = serve_with_gov(gov).await;
    let url = |id: &str| format!("http://{addr}/api/v1/admin/keys/{id}");

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let patch_url = url(&parked_key.id);
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
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(10))
    })
    .await
    .unwrap()
    .expect("the PATCH reached the instrumented put_key");

    let delete = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::Client::new()
            .delete(url(&other_key.id))
            .header("x-admin-token", "admintok")
            .send(),
    )
    .await;
    release_tx.send(()).unwrap();
    let patch_status = patch_task.await.unwrap();
    let delete_status = delete
        .expect("a DELETE of another key waited on a PATCH parked in the store")
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(delete_status, 204);
    assert_eq!(patch_status, 200);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let cost = {
        let groups = std::collections::BTreeMap::from([(
            "growth".to_string(),
            busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_kernel::config::groups::LimitCfg {
                    metric: busbar_kernel::config::groups::LimitMetric::Budget,
                    amount: 1_000_000,
                    per: Some(busbar_kernel::config::groups::LimitWindow::Month),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &groups)
    };
    let app = crate::new_test_app().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/keys");

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

fn budget_limit(cents: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(busbar_kernel::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

#[tokio::test]
async fn test_admin_v1_patch_no_op_on_an_already_counted_key_is_not_an_admission() {
    use busbar_kernel::governance::NewKeySpec;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mint = |name: &str| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                allowed_pools: None,
                group: Some("capped".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            busbar_kernel::store::now(),
        )
        .expect("mint")
        .0
    };
    let a = mint("a");
    let _b = mint("b");

    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        busbar_kernel::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    let mut app = crate::new_test_app()
        .governance(gov)
        .groups_tree(groups)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");

        inner.max_keys_per_principal = 1;
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

fn write_reset_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-reset-{}-{}-{}",
        tag,
        std::process::id(),
        busbar_kernel::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
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

#[tokio::test]
async fn test_admin_v1_overlay_reset_groups_reverts_to_base() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("groups");
    let overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .group(
            "team",
            busbar_kernel::config::GroupCfg {
                limits: vec![serde_yaml::from_str("{ budget: 20000, per: month }").unwrap()],
                ..Default::default()
            },
        )
        .build();
    audit_principal(&mut app, "audit-overlay-groups");
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

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
        busbar_kernel::config::overlay::read(&overlay.backend())
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

    let reset = client
        .delete(format!("http://{addr}/api/v1/admin/overlay/groups"))
        .header("x-admin-token", "grp:audit-overlay-groups")
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "groups");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");
    let v_after = body["config_version"].as_u64().unwrap();
    assert!(v_after > v_before, "the reset bumped the config version");

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

    let doc =
        busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay still present");
    assert!(
        doc.groups.is_empty() && doc.deleted_groups.is_empty(),
        "the overlay groups section is cleared"
    );

    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?action=overlay.reset"
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
            .any(|e| e["resource"] == "overlay:groups"
                && e["outcome"] == "applied"
                && e["principal"] == "test:audit-overlay-groups"),
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

#[tokio::test]
async fn test_admin_v1_overlay_reset_hooks_reverts_to_base() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("hooks");
    let overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "runtime_gate",
                "config": {"kind": "gate", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);
    assert!(
        busbar_kernel::config::overlay::read(&overlay.backend())
            .expect("overlay written")
            .hooks
            .contains_key("runtime_gate"),
        "runtime hook in the overlay before the reset"
    );

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/hooks")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    assert_eq!(
        reset.json::<serde_json::Value>().await.unwrap()["reset"],
        "hooks"
    );

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
    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay present");
    assert!(
        doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty(),
        "the overlay hooks section is cleared"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_stale_if_match_conflicts() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("ifmatch");
    let overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .group(
            "team",
            busbar_kernel::config::GroupCfg {
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
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.post(format!("http://{addr}/api/v1/admin/groups")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "user:bob", "config": {"parent": "team"}}).to_string())
        .send()
        .await
        .unwrap();

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

#[tokio::test]
async fn test_admin_v1_overlay_reset_unknown_section_400() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_overlay_reset_empty_section_is_idempotent_noop() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let v_before: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

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
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_requires_full_scope() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    for section in ["groups", "hooks"] {
        let scope = crate::v1::contract::required_scope(
            &axum::http::Method::DELETE,
            &format!("/api/v1/admin/overlay/{section}"),
        );
        assert_eq!(
            scope.as_str(),
            "full",
            "a {section} reset is a full-scope mutation"
        );
    }

    let unauth = client
        .delete(format!("http://{addr}/api/v1/admin/overlay/groups"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401, "the reset is admin-guarded");

    handle.abort();
}

async fn settings_test_app(
    tag: &str,
) -> (
    std::path::PathBuf,
    TestOverlayStore,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let limits_lock = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let (dir, config_path, providers_path) = write_reset_fixture(&format!("settings-{tag}"));
    let overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    audit_principal(&mut app, &format!("audit-settings-{tag}"));
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (dir, overlay, addr, handle, limits_lock)
}

#[tokio::test]
async fn test_admin_v1_config_settings_round_trip_survives_reload() {
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("roundtrip").await;
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

    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "grp:audit-settings-roundtrip")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "per_request_fee": 7,
                "rate_card": { "m0": {
                    "input_utok": 1.5, "output_utok": 2.0, "units": free_open_units()
                } },
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

    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay written");
    let root = doc.root.expect("root section present");
    assert_eq!(root.per_request_fee, Some(7));

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

    {
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        let mut loaded = busbar_kernel::load_config_from_disk_with_store(
            &config_path,
            Some(&providers_path),
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &busbar_kernel::appbuild::AcceptAll,
            Some(overlay.backend()),
        )
        .expect("disk reload");
        assert_eq!(
            loaded.deploy.per_request_fee, 0,
            "base config.yaml has no fee (the override lives only in the overlay)"
        );
        if let Some(doc) = loaded.overlay_doc.as_ref() {
            busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
        }
        assert_eq!(
            loaded.deploy.per_request_fee, 7,
            "the root overlay re-merges onto base at boot (survives a restart)"
        );
    }

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
            .any(|e| e["resource"] == "config:settings"
                && e["outcome"] == "applied"
                && e["principal"] == "test:audit-settings-roundtrip"),
        "the applied PUT is audited"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_survives_a_real_store_reload() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("boot-default-overlay");
    let default_overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(default_overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 9 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);

    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &busbar_kernel::appbuild::AcceptAll,
        Some(default_overlay.backend()),
    )
    .expect("fresh boot disk-load");
    assert_eq!(
        loaded.overlay_path.as_ref().unwrap().read_bytes().unwrap(),
        default_overlay.read_bytes(),
        "the reopened carrier reads the configured Store's persisted generation"
    );
    let root = loaded
        .overlay_doc
        .as_ref()
        .and_then(|d| d.root.as_ref())
        .expect("the fresh boot load reads the overlay root the admin PUT wrote");
    assert_eq!(
        root.per_request_fee,
        Some(9),
        "the admin mutation survives a real reload from the configured Store"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_process_level_flagged_reload_to_apply() {
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("proclevel").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "listen": "127.0.0.1:0",
                "store": {"module": migrated_store_module()},
                "store": { "module": migrated_store_module() },
                "tls": { "cert": { "file": "/etc/busbar/tls/cert.pem" }, "key": { "file": "/etc/busbar/tls/key.pem" } },
                "admin_listen": "127.0.0.1:0",
                "admin_tls": {
                    "cert": { "file": "/etc/busbar/tls/admin-cert.pem" },
                    "key": { "file": "/etc/busbar/tls/admin-key.pem" },
                    "client_ca": { "file": "/etc/busbar/tls/admin-ca.pem" }
                },
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

    for field in ["tls", "admin_tls", "admin_listen"] {
        assert!(
            flagged.contains(&field),
            "{field} is read at boot, so a change to it is flagged reload-to-apply: {flagged:?}"
        );
    }
    assert!(
        !flagged.contains(&"per_request_fee"),
        "a live-swappable field is NOT flagged: {flagged:?}"
    );
    assert!(
        body["note"].as_str().unwrap().contains("reload"),
        "the note explains the reload-to-apply split"
    );

    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay written");
    assert_eq!(
        doc.root.unwrap().listen.as_deref(),
        Some("127.0.0.1:0"),
        "the reload-to-apply field is still durably persisted"
    );
    let root = busbar_kernel::config::overlay::read(&overlay.backend())
        .expect("overlay written")
        .root
        .unwrap();
    assert!(
        root.tls.is_some() && root.admin_tls.is_some(),
        "the tls / admin_tls changes are durably stored too, for the next boot"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_boot_scoped_limits_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("bootscopedlimits").await;
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

#[tokio::test]
async fn test_admin_v1_config_settings_max_inbound_concurrent_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle, _limits_lock) =
        settings_test_app("maxinboundconcurrent").await;
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

#[tokio::test]
async fn test_admin_v1_config_settings_boot_scoped_observability_flagged_reload_to_apply() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("bootscopedobs").await;
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

#[tokio::test]
async fn test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects() {
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("storesecret").await;
    let client = reqwest::Client::new();
    let var = format!("BUSBAR_TEST_STORE_SECRET_MISSING_{}", std::process::id());
    std::env::remove_var(&var);

    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": { "module": migrated_store_module(), "settings": { "token": { "env": var } } }
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

    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay written");
    assert!(
        doc.root
            .as_ref()
            .and_then(|r| r.store.as_ref())
            .is_some_and(|s| s.settings.contains_key("token")),
        "the staged reference reaches the overlay"
    );

    handle.abort();
    drop(dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_partial_update_preserves_prior() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("partial").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let first = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "rate_card": { "m0": {
                "input_utok": 9.0, "units": free_open_units()
            } } })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 200, "{:?}", first.text().await);
    let second = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 5 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 200, "{:?}", second.text().await);
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

static OVERLAY_ROOT_AUDIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn test_admin_v1_config_settings_reset_reverts_to_base() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("reset").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        busbar_kernel::config::overlay::read(&overlay.backend())
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

    assert!(
        busbar_kernel::config::overlay::read(&overlay.backend())
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

#[tokio::test]
async fn test_admin_v1_config_settings_reset_refuses_when_overlay_is_corrupt() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("reset-corrupt").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let baseline_seq = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, 1, None, None)
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
        busbar_kernel::config::overlay::read(&overlay.backend())
            .and_then(|d| d.root)
            .is_some(),
        "root override present before corrupting the overlay"
    );

    overlay.seed_bytes(b"{ not json");

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

    let rows: Vec<_> = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, audit_ring::MAX_AUDIT_ENTRIES, None, Some("overlay:root"))
        .into_iter()
        .filter(|e| e.seq > baseline_seq)
        .collect();
    assert!(
        rows.iter()
            .any(|e| e.action == "overlay.reset" && e.outcome == audit_ring::OUTCOME_REJECTED),
        "the corrupt-overlay reset must be audited as REJECTED, never APPLIED: {rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.action == "overlay.reset" && e.outcome == audit_ring::OUTCOME_APPLIED),
        "a corrupt-overlay reset must never be recorded as a successful apply: {rows:?}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_reset_refuses_when_overlay_is_too_new() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("reset-too-new").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&overlay.read_bytes().unwrap()).unwrap();
    doc["version"] = serde_json::json!(busbar_kernel::config::overlay::OVERLAY_VERSION + 1);
    overlay.seed_bytes(&serde_json::to_vec(&doc).unwrap());

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

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_install_limits() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let _limits_lock = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    let (dir, config_path, providers_path) = write_reset_fixture("limits-persist-fail");
    let overlay = TestOverlayStore::new();
    overlay.fail_writes(true);

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    let before = busbar_kernel::config::limits::installed();

    let rejected_cap: usize = 7_654_321;
    let put = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "limits": { "request_body_max_bytes": rejected_cap } }).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    let after = busbar_kernel::config::limits::installed();
    assert_ne!(
        after.as_ref().map(|l| l.request_body_max_bytes),
        Some(rejected_cap),
        "a persist failure must leave the REJECTED config's limits uninstalled — the response just \
         claimed nothing was changed, and these are process-wide values the old (still-serving) App \
         reads through"
    );
    assert_eq!(
        after.map(|l| l.request_body_max_bytes),
        before.map(|l| l.request_body_max_bytes),
        "the limits installed before the rejected apply are the ones still installed after it"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let dir = std::env::temp_dir().join(format!(
        "busbar-settings-gov-rotate-persist-fail-{}-{}",
        std::process::id(),
        busbar_kernel::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "admintok-v1").unwrap();
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:0
store: {{module: memory}}
providers:
  test-provider:
    api_key: none
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
    - {operator}: {{ token: {{ file: {token_path:?} }} }}
",
            operator = busbar_kernel::config::operator_provider()
        ),
    )
    .unwrap();
    let overlay = TestOverlayStore::new();

    overlay.fail_writes(true);

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok-v1".to_string()));
    let before_hash = gov.admin_token_hash();
    let mut app = crate::new_test_app()
        .governance(gov.clone())
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

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
        "the Store refusal must fail the persist step: {:?}",
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

#[test]
fn test_get_config_settings_warns_when_overlay_is_unreadable() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = std::env::temp_dir().join(format!(
        "busbar-get-settings-corrupt-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = TestOverlayStore::new();
    overlay.seed_bytes(b"{ not json");

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = None;
        inner.providers_path = None;
    }
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let resp = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(crate::v1::json::get_config_settings(axum::extract::State(
            handle,
        )))
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

#[tokio::test]
async fn test_admin_v1_config_settings_stale_if_match_conflicts() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("ifmatch").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

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

#[tokio::test]
async fn test_admin_v1_config_settings_unknown_field_400() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("badfield").await;
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

async fn settings_test_app_no_overlay(
    tag: &str,
) -> (
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture(&format!("settings-no-ov-{tag}"));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app().governance(gov).no_overlay().build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (dir, addr, handle)
}

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
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        msg, LOCKED_CONFIG_MUTATION_MESSAGE,
        "the refusal must explain the locked/no-overlay posture: {body}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

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
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        msg, LOCKED_CONFIG_MUTATION_MESSAGE,
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

#[tokio::test]
async fn test_admin_v1_config_settings_put_with_persist_true_still_persists_when_overlay_exists() {
    let (dir, overlay, addr, handle, _limits_lock) = settings_test_app("persist-true").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 7, "persist": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let stored = busbar_kernel::config::overlay::read(&overlay.backend())
        .and_then(|d| d.root)
        .expect("root section persisted");
    assert_eq!(
        stored.per_request_fee,
        Some(7),
        "persist:true with an overlay present stores the value in the Store"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

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

#[test]
fn test_persist_root_without_an_overlay_errs() {
    let result = busbar_kernel::config::overlay::persist_root(
        None,
        &busbar_kernel::config::overlay::RootSettings::default(),
    );
    assert!(
        result.is_err(),
        "persist_root(None, ..) must NOT silently succeed — a None backend means a locked config, so \
         the mutation is refused, never falsely reported as persisted"
    );
    let msg = result.unwrap_err();
    assert_eq!(
        msg, LOCKED_CONFIG_MUTATION_MESSAGE,
        "the error must explain the locked/no-overlay posture: {msg}"
    );
}

#[test]
fn test_config_settings_scope_matrix() {
    use axum::http::Method;
    assert_eq!(
        crate::v1::contract::required_scope(&Method::PUT, "/api/v1/admin/config/settings").as_str(),
        "full",
        "PUT /config/settings is a full-scope mutation"
    );
    assert_eq!(
        crate::v1::contract::required_scope(&Method::GET, "/api/v1/admin/config/settings").as_str(),
        "read-only",
        "GET /config/settings is read-only"
    );

    assert_eq!(
        crate::v1::contract::required_scope(&Method::DELETE, "/api/v1/admin/overlay/root").as_str(),
        "full",
        "a root reset is a full-scope mutation"
    );
}

#[tokio::test]
async fn test_admin_v1_restart_refuses_when_it_cannot_restart() {
    if std::env::var_os("BUSBAR_ADMIN_RESTART_UNSUPERVISED_PROCESS").is_none() {
        let current = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", current.name().expect("test name"), "--nocapture"])
            .env("BUSBAR_ADMIN_RESTART_UNSUPERVISED_PROCESS", "1")
            .env_remove("INVOCATION_ID")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .output()
            .expect("run the restart assertions in an unsupervised process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "unsupervised restart assertions failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let baseline_seq = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, 1, None, None)
        .first()
        .map(|e| e.seq)
        .unwrap_or(0);
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (addr, _h) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");
    let url = format!("http://{addr}/api/v1/admin/restart");

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

    let resp = admin(client.post(&url)).send().await.unwrap();
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

    let entries = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        None,
        None,
    );
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
            .all(|e| e.outcome == audit_ring::OUTCOME_REJECTED),
        "a refused restart must never be recorded as applied: {restarts:?}"
    );
}

#[tokio::test]
async fn limit_zero_does_not_produce_a_self_referential_cursor() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

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
            serde_json::json!({"name": "lz-hook", "config": {"kind": "tap", "module": "test-hook"}})
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

    let assert_not_self_referential = |label: &str, body: &serde_json::Value| {
        let next = body.get("next_cursor").and_then(|c| c.as_str());
        match next {
            None => {}
            Some(c) => {
                let decoded = crate::v1::contract::decode_offset_cursor(c)
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

fn linked_export_axis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(busbar_kernel_testkit::test_support::export_axis::install_export_axis);
}

#[tokio::test]
async fn test_admin_v1_named_map_reads_project_settings_keys_never_values() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .identity_provider(
            "corp-oidc",
            serde_json::from_value(serde_json::json!({
                "module": "acme-idp",
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
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_named_map_rejects_an_under_scoped_caller() {
    linked_export_axis();
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .export_def(
            "base-metrics",
            serde_json::from_value(serde_json::json!({
                "module": "acme-metrics", "settings": {"buffer_seconds": 60}
            }))
            .unwrap(),
        )
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            busbar_kernel::config::operator_provider().to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
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

#[tokio::test]
async fn test_admin_v1_hook_reads_project_settings_keys_never_values() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut cfg: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
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
    let app = crate::new_test_app()
        .governance(gov)
        .hook("baa-gate", cfg)
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

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

#[tokio::test]
async fn test_admin_v1_config_settings_read_redacts_every_settings_bag() {
    let (dir, _overlay, addr, handle, _limits_lock) = settings_test_app("secretbag").await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": {
                    "module": migrated_store_module(),
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
        store["module"],
        migrated_store_module(),
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

async fn node_over(
    store: &Arc<MemoryStore>,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    spin_up(crate::build_router(app)).await
}

#[tokio::test]
async fn an_idempotent_mint_retried_after_a_restart_is_refused_not_minted_twice() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let mint = |addr: std::net::SocketAddr, client: reqwest::Client| async move {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "restart-mint")
            .body(serde_json::json!({"name": "once"}).to_string())
            .send()
            .await
            .unwrap()
    };

    let (addr, before, client) = node_over(&store).await;
    let first = mint(addr, client).await;
    assert_eq!(first.status().as_u16(), 201);
    let first: serde_json::Value = first.json().await.unwrap();
    before.abort();

    let (addr, after, client) = node_over(&store).await;
    let retry = mint(addr, client).await;
    assert_eq!(
        retry.status().as_u16(),
        409,
        "a retry after a restart must not mint again"
    );
    let retry: serde_json::Value = retry.json().await.unwrap();
    let id = first["id"].as_str().expect("the mint names its key");
    assert!(
        retry.to_string().contains(id),
        "the refusal names the key the first request made: {retry}"
    );
    let minted = busbar_kernel::governance::RecordStore::list_keys(&*store)
        .unwrap()
        .into_iter()
        .filter(|k| k.name == "once")
        .count();
    assert_eq!(minted, 1, "exactly one key exists for one Idempotency-Key");
    after.abort();
}

#[tokio::test]
async fn an_idempotent_rotate_retried_after_a_restart_is_refused_not_rotated_twice() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());

    let (addr, before, client) = node_over(&store).await;
    let created: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "rotated"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let rotate = |addr: std::net::SocketAddr, client: reqwest::Client, id: String| async move {
        client
            .post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate"))
            .header("x-admin-token", "admintok")
            .header("idempotency-key", "restart-rotate")
            .send()
            .await
            .unwrap()
    };
    let first = rotate(addr, client, id.clone()).await;
    assert_eq!(first.status().as_u16(), 200);
    let first: serde_json::Value = first.json().await.unwrap();
    before.abort();

    let (addr, after, client) = node_over(&store).await;
    let retry = rotate(addr, client.clone(), id.clone()).await;
    assert_eq!(
        retry.status().as_u16(),
        409,
        "a retry after a restart must not rotate again"
    );

    let token = first["token"]
        .as_str()
        .expect("the rotate hands out a token");
    let got = client
        .get(format!("http://{addr}/api/v1/admin/keys/{id}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(got.status().as_u16(), 200);
    let gov = gov_with_signer(store.clone(), None);
    assert!(
        gov.verify_token(token, busbar_kernel::store::now(), None)
            .is_some(),
        "the first rotate's token still authenticates: no second rotate ran"
    );
    after.abort();
}

#[tokio::test]
async fn a_stuck_mint_or_rotate_is_refused_in_flight_however_old_its_sentinel() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov.clone()).build();
    let cache: Arc<crate::keys::KeyReplayCache> = Arc::new(crate::keys::KeyReplayCache::new());
    let router = crate::build_router(app).layer(axum::Extension(cache.clone()));
    let (addr, handle, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "rotated"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let generation = || {
        gov.all_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.id == id)
            .map(|k| k.generation_hash)
    };
    let before = generation();
    for key in [
        (
            "admin".to_string(),
            crate::idempotency::create_replay_key("stuck-mint"),
        ),
        (
            "admin".to_string(),
            crate::idempotency::rotate_replay_key(&id, "stuck-rotate"),
        ),
    ] {
        match cache.probe(key, 1) {
            crate::idempotency::Probe::Reserved(r) => r.leak(),
            _ => panic!("a fresh cache reserves the first sighting"),
        }
    }

    let mint = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("idempotency-key", "stuck-mint")
        .body(serde_json::json!({"name": "k"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        mint.status().as_u16(),
        409,
        "the retry of a mint still in flight is refused, not minted a second time"
    );
    let rotate = client
        .post(format!("{keys_url}/{id}/rotate"))
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "stuck-rotate")
        .send()
        .await
        .unwrap();
    assert_eq!(
        rotate.status().as_u16(),
        409,
        "the retry of a rotate still in flight is refused, not rotated a second time"
    );
    assert_eq!(
        gov.all_keys().unwrap().len(),
        1,
        "the retried mint minted nothing"
    );
    assert_eq!(
        generation(),
        before,
        "the retried rotate issued no new credential"
    );

    handle.abort();
}

fn free_open_units() -> serde_json::Value {
    crate::ensure_seam();
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .find(|decl| decl.fallback)
        .expect("the linked test planes carry the fallback plane")
        .billable_classes
        .iter()
        .map(|c| c.class)
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .map(|c| (c.to_string(), serde_json::json!(0)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

#[test]
fn auth_modules_list_inbound_rows_only() {
    let inbound: busbar_kernel::preflight::LinkedAuth = (
        "inbound-row",
        "canonical-name",
        busbar_kernel_testkit::test_support::operator_double::door,
    );
    assert_eq!(
        busbar_kernel::preflight::inbound_auth_names(&[inbound]),
        vec!["inbound-row"]
    );
}

async fn rotate_under_a_pool_ceiling(
    bound_pools: Option<Vec<String>>,
) -> (u16, serde_json::Value, bool) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _token) = gov
        .create_key(
            NewKeySpec {
                name: "svc".to_string(),
                allowed_pools: bound_pools,
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        busbar_kernel::governance::mint_policy::RoleCeiling {
            max_ttl_secs: None,
            allowed_pools: Some(vec!["pool-ok".to_string()]),
            binding_modes: None,
        },
    );
    let policy = busbar_kernel::governance::mint_policy::MintPolicy {
        self_mint: None,
        block_max_ttl_secs: None,
        block_binding_modes: None,
        ceilings,
    };
    let app = crate::new_test_app()
        .governance(gov.clone())
        .mint_policy(policy)
        .build();
    let before = gov
        .store()
        .get_key(&key.id)
        .unwrap()
        .unwrap()
        .generation_hash;

    use crate::transport::AdminTransport;
    let router = crate::v1::json::JsonV1
        .router()
        .layer(axum::Extension(busbar_kernel::auth::AuthPrincipal(Some(
            principal,
        ))))
        .with_state(Arc::new(busbar_kernel::state::AppHandle::new(app)));
    let (addr, server, client) = spin_up(router).await;
    let resp = client
        .post(format!("http://{addr}/keys/{}/rotate", key.id))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    server.abort();
    let after = gov
        .store()
        .get_key(&key.id)
        .unwrap()
        .unwrap()
        .generation_hash;
    (status, body, before != after)
}

#[tokio::test]
async fn proof_role_pool_ceiling_refuses_an_over_ceiling_rotate() {
    let (status, body, moved) = rotate_under_a_pool_ceiling(None).await;
    assert_eq!(
        status, 400,
        "rotating an all-pools key past the role's pool ceiling must be refused: {body}"
    );
    assert_eq!(body["error"]["code"], "invalid_request", "{body}");
    assert!(
        body.get("token").is_none(),
        "a refused rotate shows no token"
    );
    assert!(
        !moved,
        "a refused rotate leaves the key's credential as it was"
    );
}

#[tokio::test]
async fn proof_role_pool_ceiling_rotates_an_in_ceiling_key() {
    let (status, body, moved) =
        rotate_under_a_pool_ceiling(Some(vec!["pool-ok".to_string()])).await;
    assert_eq!(status, 200, "an in-ceiling rotate answers: {body}");
    assert!(body["token"].is_string(), "{body}");
    assert!(moved, "the rotate retired the previous generation");
}

#[tokio::test]
async fn a_past_ceiling_rotate_releases_its_idempotency_claim() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let (key, _token) = gov
        .create_key(
            NewKeySpec {
                name: "svc".to_string(),
                allowed_pools: None,
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        busbar_kernel::governance::mint_policy::RoleCeiling {
            max_ttl_secs: None,
            allowed_pools: Some(vec!["pool-ok".to_string()]),
            binding_modes: None,
        },
    );
    let policy = busbar_kernel::governance::mint_policy::MintPolicy {
        self_mint: None,
        block_max_ttl_secs: None,
        block_binding_modes: None,
        ceilings,
    };
    let app = crate::new_test_app()
        .governance(gov.clone())
        .mint_policy(policy)
        .build();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "idempotency-key",
        axum::http::HeaderValue::from_static("past-ceiling"),
    );
    for attempt in ["first", "retry after a restart"] {
        let resp = super::rotate_key(
            busbar_kernel::state::CurrentApp(app.clone()),
            axum::Extension(busbar_kernel::auth::AuthPrincipal(Some(principal.clone()))),
            axum::extract::Path(key.id.clone()),
            headers.clone(),
            axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the {attempt} rotate is refused by the ceiling, not as in flight"
        );
    }
}
