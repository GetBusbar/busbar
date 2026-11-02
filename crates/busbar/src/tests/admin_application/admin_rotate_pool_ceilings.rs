// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const AUDIENCE: &str = "api://admin-rotate-pool-ceiling";

#[tokio::test]
async fn proof_role_pool_ceiling_refuses_an_over_ceiling_rotate() {
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
        plugins::scratch("proof_role_pool_ceiling_refuses_an_over_ceiling_rotate-actual-store");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token =
        common::credentials::token_for("delegated-admin", &["app-admin"], AUDIENCE);
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
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] =
        serde_json::json!({"mint_ceilings":{"app-admin":{"allowed_pools":["pool-ok"]}}});
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
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router = busbar_kernel::build_router(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let request = serde_json::json!({"name":"svc"});
    let created: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"]
        .as_str()
        .expect("the actual operator minted the existing key")
        .to_string();
    let before = gov.store().get_key(&id).unwrap().unwrap().generation_hash;
    let response = client
        .post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate"))
        .header("x-admin-token", &delegated_token)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    handle.abort();
    let after = gov.store().get_key(&id).unwrap().unwrap().generation_hash;
    let moved = before != after;
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
        plugins::scratch("proof_role_pool_ceiling_rotates_an_in_ceiling_key-actual-store");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token =
        common::credentials::token_for("delegated-admin", &["app-admin"], AUDIENCE);
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
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] =
        serde_json::json!({"mint_ceilings":{"app-admin":{"allowed_pools":["pool-ok"]}}});
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
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router = busbar_kernel::build_router(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let mut request = serde_json::json!({"name":"svc"});
    request["allowed_pools"] = serde_json::json!(["pool-ok"]);
    let created: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"]
        .as_str()
        .expect("the actual operator minted the existing key")
        .to_string();
    let before = gov.store().get_key(&id).unwrap().unwrap().generation_hash;
    let response = client
        .post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate"))
        .header("x-admin-token", &delegated_token)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    handle.abort();
    let after = gov.store().get_key(&id).unwrap().unwrap().generation_hash;
    let moved = before != after;
    assert_eq!(status, 200, "an in-ceiling rotate answers: {body}");
    assert!(body["token"].is_string(), "{body}");
    assert!(moved, "the rotate retired the previous generation");
}

#[tokio::test]
async fn a_past_ceiling_rotate_releases_its_idempotency_claim() {
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
        plugins::scratch("a_past_ceiling_rotate_releases_its_idempotency_claim-actual-store");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token =
        common::credentials::token_for("delegated-admin", &["app-admin"], AUDIENCE);
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
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] =
        serde_json::json!({"mint_ceilings":{"app-admin":{"allowed_pools":["pool-ok"]}}});
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
        false,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let router = busbar_kernel::build_router(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let request = serde_json::json!({"name":"svc"});
    let created: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"]
        .as_str()
        .expect("the actual operator minted the existing key")
        .to_string();
    handle.abort();
    let _ = handle.await;
    for attempt in ["first", "retry after a restart"] {
        let router = busbar_kernel::build_router(app.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate"))
            .header("x-admin-token", &delegated_token)
            .header("idempotency-key", "past-ceiling")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the {attempt} rotate is refused by the ceiling, not as in flight"
        );
        server.abort();
        let _ = server.await;
    }
}
