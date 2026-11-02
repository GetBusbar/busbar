// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn test_admin_v1_config_apply_body_swaps_and_carries_health() {
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
        plugins::scratch("test_admin_v1_config_apply_body_swaps_and_carries_health-actual-store");
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
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
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
        (Some(config_path.clone()), Some(providers_path)),
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
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
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
            "test-provider": {"protocol": protocol, "base_url": "http://127.0.0.1:1/"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "store": {"module": module, "settings": settings},
            "providers": {"test-provider": {"api_key": {"file": upstream_key}}},
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
                "config": {"listen": "127.0.0.1:0", "store": {"module": module, "settings": settings}, "providers": {}, "models": {}, "pools": {}},
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
                "config": {"listen": "127.0.0.1:0", "store": {"module": module, "settings": settings}, "providers": {}, "models": {}, "pools": {}},
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
        "test_admin_v1_config_reload_swaps_disk_truth_and_carries_health-actual-store",
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
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    let mut disk = document.clone();
    disk["models"]["m-new"] = serde_json::json!({"provider":"test-provider","max_concurrent":4});
    disk["pools"] =
        serde_json::json!({"reload-pool":{"members":[{"model":"m0"},{"model":"m-new"}]}});
    std::fs::write(&config_path, serde_json::to_vec_pretty(&disk).unwrap()).unwrap();
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
        (Some(config_path.clone()), Some(providers_path)),
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
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
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

    let invalid = serde_json::json!({
        "listen":"127.0.0.1:0",
        "store":{"module":module,"settings":settings},
        "providers":{},
        "models":{"broken":{"provider":"nope","max_concurrent":1}},
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&invalid).unwrap()).unwrap();
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
