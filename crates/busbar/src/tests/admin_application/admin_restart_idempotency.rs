// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn an_idempotent_mint_retried_after_a_restart_is_refused_not_minted_twice() {
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
        "an_idempotent_mint_retried_after_a_restart_is_refused_not_minted_twice-actual-store",
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
    let restart_document = document.clone();
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
    let restart_plugins = plugin_config.clone();
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let store = anchor.records.clone();
    let calls = anchor
        .calls
        .as_ref()
        .expect("the actual Store exposes typed calls")
        .clone();
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
    let before = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
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

    let first = mint(addr, client).await;
    assert_eq!(first.status().as_u16(), 201);
    let first: serde_json::Value = first.json().await.unwrap();
    before.abort();
    let _ = before.await;

    let deploy = busbar_kernel::config::deploy_from_deserializer(restart_document)
        .expect("the same normal configuration reparses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the same normal configuration resolves");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls.clone())
        .expect("a fresh carrier reads the actual Store");
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: Some(calls),
    };
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        restart_plugins,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        false,
    )
    .expect("the real root cold-composes a new App and governance over the same actual Store");
    assert_eq!(
        app.config_version, 0,
        "the second App is a cold generation, not a reload carrying the first App"
    );
    limits.keep().expect("actual restarted limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let after = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

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
        "an_idempotent_rotate_retried_after_a_restart_is_refused_not_rotated_twice-actual-store",
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
    let restart_document = document.clone();
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
    let restart_plugins = plugin_config.clone();
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let store = anchor.records.clone();
    let calls = anchor
        .calls
        .as_ref()
        .expect("the actual Store exposes typed calls")
        .clone();
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
    let before = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
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
    let _ = before.await;

    let deploy = busbar_kernel::config::deploy_from_deserializer(restart_document)
        .expect("the same normal configuration reparses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the same normal configuration resolves");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls.clone())
        .expect("a fresh carrier reads the actual Store");
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: Some(calls),
    };
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        restart_plugins,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        false,
    )
    .expect("the real root cold-composes a new App and governance over the same actual Store");
    assert_eq!(
        app.config_version, 0,
        "the second App is a cold generation, not a reload carrying the first App"
    );
    limits.keep().expect("actual restarted limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the fresh actual governance exists")
        .clone();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let after = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

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
    assert!(
        gov.verify_token(token, busbar_kernel::store::now(), None)
            .is_some(),
        "the first rotate's token still authenticates: no second rotate ran"
    );
    after.abort();
}
