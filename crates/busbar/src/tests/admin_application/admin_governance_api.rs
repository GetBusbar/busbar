// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn test_1_5_2_admin_path_bypasses_governance_and_mints() {
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
        plugins::scratch("test_1_5_2_admin_path_bypasses_governance_and_mints-actual-store");
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
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
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
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let (_key, _secret) = app
        .governance
        .as_ref()
        .expect("actual governance")
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .expect("the actual configured signer and Store mint the pre-existing key");
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "minted-via-admin"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "admin token must authenticate the admin API and mint (got {})",
        r.status()
    );

    let bad = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "nope")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "x"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong admin token must be rejected"
    );
    handle.abort();
}

#[tokio::test]
async fn test_governance_admin_api() {
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
    let directory = plugins::scratch("test_governance_admin_api-actual-store");
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
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
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
    let base = format!("http://{addr}");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "no admin token → unauthorized");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .json(&serde_json::json!({"name": "team-a", "allowed_pools": ["allowedpool"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201, "admin create → 201");
    let created: serde_json::Value = r.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let secret = created["token"].as_str().unwrap().to_string();
    assert!(secret.starts_with("bbk_"), "signed token returned once");
    assert!(
        created.get("generation_hash").is_none(),
        "hash never returned"
    );
    assert!(created.get("secret").is_none(), "no legacy secret in 1.5.0");

    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed: serde_json::Value = r.json().await.unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    assert!(listed["items"][0].get("generation_hash").is_none());

    let r = client
        .get(format!("{base}/api/v1/admin/keys/{id}/usage"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let r = client
        .post(format!("{base}/allowedpool/v1/messages"))
        .bearer_auth(&secret)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        404,
        "minted key authenticates + ACL passes"
    );

    let r = client
        .delete(format!("{base}/api/v1/admin/keys/{id}"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed: serde_json::Value = r.json().await.unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 0, "deleted");

    handle.abort();
}
