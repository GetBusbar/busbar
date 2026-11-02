// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn test_admin_v1_topology_reads_pools_models_providers() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_topology_reads_pools_models_providers-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the distribution declares its actual linked OpenAI provider dialect");
    let mut definitions = std::collections::HashMap::new();
    definitions.insert(
        "prov-x".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("the actual provider definition parses"),
    );
    document["providers"]["prov-x"] = serde_json::json!({ "api_key": { "file": upstream_key } });
    definitions.insert(
        "prov-y".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("the actual provider definition parses"),
    );
    document["providers"]["prov-y"] = serde_json::json!({ "api_key": { "file": upstream_key } });
    document["models"] =
        serde_json::json!({"model-a": {"provider": "prov-x"}, "model-b": {"provider": "prov-y"}});
    document["pools"] = serde_json::json!({"mypool": {"members": [{"model": "model-a", "weight": 3}, {"model": "model-b", "weight": 1}]}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
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

#[tokio::test]
async fn test_admin_v1_pool_detail_live_status() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("test_admin_v1_pool_detail_live_status-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the distribution declares its actual linked OpenAI provider dialect");
    let mut definitions = std::collections::HashMap::new();
    definitions.insert(
        "p".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("the actual provider definition parses"),
    );
    document["providers"]["p"] = serde_json::json!({ "api_key": { "file": upstream_key } });
    document["models"] = serde_json::json!({"m1": {"provider": "p"}});
    document["pools"] = serde_json::json!({"mypool": {"members": [{"model": "m1", "weight": 5}]}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
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
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the distribution declares its actual linked OpenAI provider dialect");
    let mut definitions = std::collections::HashMap::new();
    definitions.insert(
        "p".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("the actual provider definition parses"),
    );
    document["providers"]["p"] = serde_json::json!({ "api_key": { "file": upstream_key } });
    document["models"] = serde_json::json!({"m1": {"provider": "p"}});
    document["pools"] = serde_json::json!({"fast": {"members": [{"model": "m1", "weight": 1}]}, "cheap": {"members": [{"model": "m1", "weight": 1}]}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let now = busbar_kernel::store::now();
    let breaker = busbar_kernel::store::BreakerCfg {
        base_cooldown_secs: 300,
        max_cooldown_secs: 300,
        trip: busbar_kernel::store::TripConfig {
            mode: busbar_kernel::store::TripMode::Consecutive,
            consecutive_n: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        app.store
            .record_transient_in_at("fast", 0, now, &breaker, Some(300)),
        "the actual failed dispatch outcome must trip only the fast pool's cell"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
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
