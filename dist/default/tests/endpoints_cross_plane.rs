// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked {
    use busbar_kernel::plane_driver::registry::PlaneDecl;
    pub(super) fn install() {
        crate::dist_root_install::install();
    }
    pub(super) fn planes() -> &'static [&'static PlaneDecl] {
        install();
        busbar_kernel::plane_driver::registry::plane_decls()
    }
    pub(super) fn fallback() -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| decl.fallback)
            .expect("the actual distribution declares its fallback")
    }
}

use axum::extract::Extension;
use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_kernel::endpoints::{catalog_names, stats};
use busbar_kernel::governance::GovCtx;
use busbar_kernel::state::{App, CurrentApp};
use busbar_kernel::store::now;
#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;
use serde_json::{json, Value};
use std::sync::Arc;

fn register_planes() {
    linked::install();
}

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

fn topology_app() -> Arc<App> {
    register_planes();
    let yaml = r#"providers:
  fixture: {api_key: none}
models:
  model-a0: {provider: fixture}
  model-a1: {provider: fixture}
  model-b: {provider: fixture}
pools:
  pool-a: {members: [model-a0, model-a1]}
  pool-b: {members: [model-b]}
"#;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "endpoints_cross_plane-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document: serde_json::Value =
        serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
    document["store"] = serde_json::json!({"module": module, "settings": settings});
    document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
    document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(
        &deploy,
        &std::collections::HashMap::from([(
            "fixture".to_string(),
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("provider definition"),
        )]),
    )
    .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    app
}

async fn stats_json(app: Arc<App>, gov: GovCtx) -> Value {
    let resp = stats(CurrentApp(app), Extension(gov)).await;
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect /stats body");
    serde_json::from_slice(&bytes).expect("/stats body is JSON")
}

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

#[tokio::test]
async fn test_stats_no_key_sees_full_topology() {
    let app = topology_app();
    let body = stats_json(app, GovCtx::default()).await;

    let pools = body["pools"].as_object().expect("pools object");
    assert!(pools.contains_key("pool-a") && pools.contains_key("pool-b"));
    assert_eq!(body["lanes"].as_array().expect("lanes array").len(), 3);
}

#[tokio::test]
async fn test_stats_reports_at_capacity_when_lane_saturated() {
    register_planes();
    let yaml = r#"providers:
  fixture: {api_key: none}
models:
  bounded: {provider: fixture, max_concurrent: 1}
  unbounded: {provider: fixture}
pools:
  p: {members: [bounded, unbounded]}
"#;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "endpoints_cross_plane-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document: serde_json::Value =
        serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
    document["store"] = serde_json::json!({"module": module, "settings": settings});
    document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
    document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(
        &deploy,
        &std::collections::HashMap::from([(
            "fixture".to_string(),
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("provider definition"),
        )]),
    )
    .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let lane_index = app
        .engine_tables_view()
        .model_index("bounded")
        .expect("configured model");
    let sem = app
        .store
        .lane_semaphore(lane_index)
        .expect("actual lane semaphore");

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

    assert_eq!(bounded["availability"], json!("available"));
    assert_eq!(bounded["recovery_hint_ms"], Value::Null);
    assert_eq!(bounded["breaker_state"], json!("closed"));
    let unbounded = lane(&body, "unbounded");
    assert_eq!(unbounded["available"], json!("unbounded"));
    assert_eq!(unbounded["at_capacity"], json!(false));
    assert_eq!(unbounded["availability"], json!("available"));

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

#[tokio::test]
async fn test_stats_limit_is_numeric_alias_of_max_concurrent() {
    register_planes();
    let yaml = r#"providers:
  fixture: {api_key: none}
models:
  bounded: {provider: fixture, max_concurrent: 3}
  unbounded: {provider: fixture}
pools:
  p: {members: [bounded, unbounded]}
"#;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "endpoints_cross_plane-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document: serde_json::Value =
        serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
    document["store"] = serde_json::json!({"module": module, "settings": settings});
    document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
    document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(
        &deploy,
        &std::collections::HashMap::from([(
            "fixture".to_string(),
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("provider definition"),
        )]),
    )
    .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

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

#[tokio::test]
async fn test_stats_surfaces_open_and_at_capacity_independently() {
    register_planes();
    let yaml = r#"providers:
  fixture: {api_key: none}
models:
  wedged: {provider: fixture, max_concurrent: 1}
pools:
  p: {members: [wedged]}
"#;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "endpoints_cross_plane-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document: serde_json::Value =
        serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
    document["store"] = serde_json::json!({"module": module, "settings": settings});
    document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
    document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(
        &deploy,
        &std::collections::HashMap::from([(
            "fixture".to_string(),
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("provider definition"),
        )]),
    )
    .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let lane_index = app
        .engine_tables_view()
        .model_index("wedged")
        .expect("configured model");
    let sem = app
        .store
        .lane_semaphore(lane_index)
        .expect("actual lane semaphore");

    let t = now();
    app.store.force_open_in("p", lane_index, t + 60);
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

    assert_eq!(
        lane["breaker_state"],
        json!("open"),
        "the Open breaker must be visible so operators see why recovery never fires; got {lane}"
    );
    assert_eq!(lane["at_capacity"], json!(true), "capacity axis: saturated");
    assert_eq!(lane["available"], json!(0), "0 free permits");

    assert_eq!(
        lane["availability"],
        json!("breaker_open"),
        "availability classifies breaker-open (breaker-first); got {lane}"
    );
}

async fn models_ids(app: Arc<App>, gov: GovCtx) -> Vec<String> {
    catalog_names(&app, &gov)
}

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

#[tokio::test]
async fn test_v1_models_empty_allowed_pools_sees_all() {
    let app = topology_app();
    let gov = GovCtx {
        key: Some(vkey(&[])),
    };
    let ids = models_ids(app, gov).await;
    assert_eq!(ids.len(), 5);
}

const LISTING_KIND: &str = "listing_door_entry";

fn with_listing_door(
    key: &'static str,
    section: &'static str,
    names: &'static [&'static str],
) -> Arc<App> {
    use busbar_contract::plane_calls::{DoorFacing, PlaneRegistration};
    use busbar_kernel::plane_driver::door::{fold, DoorSection, DoorSlot};
    let reg = PlaneRegistration {
        key,
        section,
        owns: Vec::new(),
        consumes: Vec::new(),
        requires: Vec::new(),
        secret_refs: Vec::new(),
        admin_routes: Vec::new(),
        admin_openapi: None,
        streaming_content_types: Vec::new(),
        label: "Listing",
        subject_noun: "entry",
        admin_noun: "entry",
        audit_kind: "listing_entry",
        signing: None,
        dialects: Vec::new(),
        dialect_flags: Vec::new(),
        scope_kinds: vec![LISTING_KIND],
        billable_classes: Vec::new(),
        fee_units: Vec::new(),
        record_kinds: Vec::new(),
        trust_keys: Vec::new(),
        caller_credential_refusal: None,
        fallback: false,
        provider_keys: None,
        validate: Arc::new(|_: &[u8]| Ok(())),
        facing: Arc::new(
            move |_: &[u8],
                  _: &[u8],
                  _: Option<&str>,
                  _: &[busbar_contract::plane_calls::DialectFacts]| {
                Ok(DoorFacing {
                    listed: names.iter().map(|n| (*n).to_string()).collect(),
                    ..DoorFacing::default()
                })
            },
        ),
    };
    let facing = (reg.facing)(b"", b"", None, &[]).expect("faces");
    let decl = fold(reg).expect("the listing door folds");
    let mut app = topology_app();
    Arc::make_mut(&mut app).plane_slots.insert(
        decl.key,
        Arc::new(DoorSlot {
            section: DoorSection::new(decl.door, section, serde_yaml::Value::Null),
            facing,
            opened: true,
        }),
    );
    app
}

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

#[tokio::test]
async fn test_v1_models_bytes_unchanged_when_no_plane_lists_a_name() {
    let quiet = with_listing_door("v1-models-quiet", "v1_models_quiet", &[]);
    for gov in [
        GovCtx::default(),
        GovCtx {
            key: Some(vkey(&["pool-a"])),
        },
    ] {
        assert_eq!(
            catalog_names(&quiet, &gov),
            catalog_names(&topology_app(), &gov),
            "a plane listing nothing moves no name"
        );
    }
}

fn opening_door() -> &'static busbar_kernel::plane_driver::registry::PlaneDecl {
    busbar_kernel::plane_driver::door::fold(busbar_contract::plane_calls::PlaneRegistration {
        key: "healthz-lanes-door",
        section: "healthz_lanes_door",
        owns: Vec::new(),
        consumes: Vec::new(),
        requires: Vec::new(),
        secret_refs: Vec::new(),
        admin_routes: Vec::new(),
        admin_openapi: None,
        streaming_content_types: Vec::new(),
        label: "Door",
        subject_noun: "door member",
        admin_noun: "member",
        audit_kind: "door_member",
        signing: None,
        dialects: Vec::new(),
        dialect_flags: Vec::new(),
        scope_kinds: Vec::new(),
        billable_classes: Vec::new(),
        fee_units: Vec::new(),
        record_kinds: Vec::new(),
        trust_keys: Vec::new(),
        caller_credential_refusal: None,
        fallback: false,
        provider_keys: None,
        validate: Arc::new(|_: &[u8]| Ok(())),
        facing: Arc::new(
            |_: &[u8],
             _: &[u8],
             _: Option<&str>,
             _: &[busbar_contract::plane_calls::DialectFacts]| {
                Ok(busbar_contract::plane_calls::DoorFacing::default())
            },
        ),
    })
    .expect("folds")
}

#[tokio::test]
async fn healthz_with_model_lanes_every_cell_open_stays_unready_beside_an_opened_plane() {
    register_planes();
    let fallback = linked::fallback();
    let door = opening_door();
    let section = busbar_kernel::plane_driver::door::DoorSection::new(
        door.door,
        door.config_section,
        serde_yaml::from_str("member: {url: 'https://m'}").unwrap(),
    );
    let section_defs = section.as_defs();
    let slot = (door.build)(
        door,
        &busbar_kernel::plane_driver::registry::BuildCtx {
            endpoint_slot: None,
            plane_defs: &section_defs,
            public_url: None,
            prior: None,
            providers: None,
        },
    )
    .expect("the configured door builds its generation's slot");
    assert!(
        busbar_kernel::plane_driver::door::opened(slot.as_ref()),
        "the door opened"
    );
    let yaml = r#"providers:
  fixture: {api_key: none}
models:
  model-h: {provider: fixture}
pools:
  p: {members: [model-h]}
"#;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "endpoints_cross_plane-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document: serde_json::Value =
        serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
    document["store"] = serde_json::json!({"module": module, "settings": settings});
    document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
    document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(
        &deploy,
        &std::collections::HashMap::from([(
            "fixture".to_string(),
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("provider definition"),
        )]),
    )
    .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let mut app = app;
    let state = Arc::make_mut(&mut app);
    state.plane_slots.insert(door.key, slot);
    state.plane_sections = Some(
        [fallback.config_section, door.config_section]
            .into_iter()
            .collect(),
    );

    let healthz = |app: Arc<App>| async move {
        let resp = busbar_kernel::endpoints::healthz(CurrentApp(app)).await;
        let status = resp.status().as_u16();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        (status, body.to_vec())
    };
    assert_eq!(
        healthz(app.clone()).await,
        (200, b"ok".to_vec()),
        "a ready lane answers ready"
    );
    let t = now();
    app.store.force_open_in("", 0, t + 600);
    app.store.force_open_in("p", 0, t + 600);
    assert_eq!(
        healthz(app).await,
        (503, b"no usable lanes".to_vec()),
        "with model lanes, every cell Open is unready whatever else opened"
    );
}
