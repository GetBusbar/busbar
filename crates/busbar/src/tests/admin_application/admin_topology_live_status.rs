// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{JsonContainerTrait, JsonValueTrait, Map, Value};

/// GET one admin path as the operator, parsed.
async fn read(client: &reqwest::Client, addr: std::net::SocketAddr, path: &str) -> Value {
    let bytes = client
        .get(format!("http://{addr}/api/v1/admin{path}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    busbar_contract::json::parse_value(&bytes).unwrap()
}

/// The `core/routing` view `pools` (ADMIN-API-1.6 §5.5; `/pools` is removed, §0.2): each
/// positional row keyed back by its field names. `pool` narrows to one pool.
async fn pool_rows(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    pool: Option<&str>,
) -> Vec<Value> {
    let filter = pool
        .map(|p| format!("?filter=pool:{p}"))
        .unwrap_or_default();
    let view = read(
        client,
        addr,
        &format!("/kinds/core/instances/routing/views/pools{filter}"),
    )
    .await;
    let names: Vec<String> = view["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_owned())
        .collect();
    view["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let mut keyed = Map::new();
            for (name, cell) in names.iter().zip(row.as_array().unwrap().iter()) {
                keyed.insert(name, cell.clone());
            }
            Value::from(keyed)
        })
        .collect()
}

#[tokio::test]
async fn test_admin_v1_topology_reads_pools_models_providers() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_21F2E6F67B18";
    const WITNESS: &str =
        "actual root case test_admin_v1_topology_reads_pools_models_providers completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_topology_reads_pools_models_providers-actual-store",
    );
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // `/pools`, `/models` and `/providers` are removed in 1.6.0 (ADMIN-API-1.6 §0.2, CON-6): the
    // topology is core/routing's configuration.
    let routing = read(&client, addr, "/kinds/core/instances/routing").await;
    let config = &routing["config"];
    let members = config["pools"]["definitions"]["mypool"]["members"]
        .as_array()
        .unwrap_or_else(|| panic!("mypool present: {routing}"));
    assert_eq!(members.len(), 2, "pool has two members");
    let weight_a = members.iter().find(|m| m["model"] == "model-a").unwrap()["weight"].as_u64();
    assert_eq!(weight_a, Some(3), "model-a weight projected");

    assert_eq!(config["models"]["model-a"]["provider"], "prov-x");
    assert_eq!(config["models"]["model-b"]["provider"], "prov-y");

    for provider in ["prov-x", "prov-y"] {
        assert!(
            config["providers"].get(provider).is_some(),
            "{provider} is configured: {routing}"
        );
    }
    let rows = pool_rows(&client, addr, None).await;
    assert_eq!(
        rows.iter().filter(|r| r["pool"] == "mypool").count(),
        2,
        "the live view carries one row per pool member"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_pool_detail_live_status() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_81388CFC1A25";
    const WITNESS: &str = "actual root case test_admin_v1_pool_detail_live_status completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_pool_detail_live_status-actual-store",
    );
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // `/pools/{name}` and `/pools?detail=true` are removed in 1.6.0 (ADMIN-API-1.6 §0.2): the live
    // per-member status is the core/routing view `pools`, one row per member.
    let rows = pool_rows(&client, addr, Some("mypool")).await;
    assert_eq!(rows.len(), 1);
    let m = &rows[0];
    assert_eq!(m["pool"], "mypool");
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

    let every = pool_rows(&client, addr, None).await;
    assert_eq!(every.len(), 1, "the unfiltered view carries every member");
    assert_eq!(every[0]["pool"], "mypool");
    assert_eq!(
        every[0]["usable"], true,
        "rows carry the live status inline"
    );
    assert_eq!(every[0]["trip_count"], 0);

    assert!(
        pool_rows(&client, addr, Some("nope")).await.is_empty(),
        "an unknown pool has no rows"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_BC0E05B756BE";
    const WITNESS: &str =
        "actual root case test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_pool_detail_reports_the_per_pool_breaker_cell-actual-store",
    );
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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

    let fast = pool_rows(&client, addr, Some("fast")).await;
    let fm = &fast[0];
    let fast = Value::from(fast.clone());
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

    let cheap = pool_rows(&client, addr, Some("cheap")).await;
    let cm = &cheap[0];
    let cheap = Value::from(cheap.clone());
    assert_eq!(
        cm["usable"], true,
        "an untouched pool's own cell must still be usable, not the any-cell aggregate: {cheap}"
    );
    assert_eq!(
        cm["cooldown_remaining_seconds"], 0,
        "an untouched pool must not inherit another pool's max-cell cooldown: {cheap}"
    );

    handle.abort();
    println!("{WITNESS}");
}
