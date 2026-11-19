// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use busbar_contract::json::{self, JsonValueTrait as _};
use std::collections::HashSet;
use std::sync::Arc;

use crate::test_common as common;

const AUDIENCE: &str = "api://admin-overlay-audit";

#[tokio::test]
async fn test_admin_v1_overlay_reset_groups_reverts_to_base() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_overlay_reset_groups_reverts_to_base-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the actual built OIDC product is required");
    let oidc_module = crate::root::test_plugins::native_image(&oidc_path).name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let audit_token =
        common::credentials::token_for("audit-overlay-groups", &["audit-overlay-groups"], AUDIENCE);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module":oidc_module,"settings":common::credentials::settings(AUDIENCE),"max_admin_scope":"full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] =
        json::json!({"test-scope-module":{"audit-overlay-groups":{"admin_scope":"full"}}});
    document["groups"] = json::json!({"team":{"limits":[{"budget":20000,"per":"month"}]}});
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual audit Store hydrates before mutations");
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("authorization", "Bearer admintok");

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/groups")))
        .header("content-type", "application/json")
        .body(
            json::json!({
                "name": "user:alice",
                "config": {"parent": "team", "limits": [{"budget": 5000, "per": "month"}]}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);

    let listed = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
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
        busbar_kernel::config::overlay::read_async(&overlay)
            .await
            .expect("overlay written")
            .groups
            .contains_key("user:alice"),
        "the runtime group is in the overlay before the reset"
    );
    let ver_before = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/info")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let v_before = ver_before["config_version"].as_u64().unwrap();

    let reset = client
        .delete(format!("http://{addr}/api/v1/admin/overlay/groups"))
        .header("authorization", format!("Bearer {}", &audit_token))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body = json::parse_value(&reset.bytes().await.unwrap()).unwrap();
    assert_eq!(body["reset"], "groups");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");
    let v_after = body["config_version"].as_u64().unwrap();
    assert!(v_after > v_before, "the reset bumped the config version");

    let after = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
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

    let doc = busbar_kernel::config::overlay::read_async(&overlay)
        .await
        .expect("overlay still present");
    assert!(
        doc.groups.is_empty() && doc.deleted_groups.is_empty(),
        "the overlay groups section is cleared"
    );

    let audit = json::parse_value(
        &admin(client.get(format!(
            "http://{addr}/api/v1/admin/audit?action=overlay.reset"
        )))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap(),
    )
    .unwrap();

    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["resource"] == "overlay:groups"
                && e["outcome"] == "applied"
                && e["principal"] == common::credentials::principal_id("audit-overlay-groups")),
        "the applied reset is audited"
    );
    let versions = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_stale_if_match_conflicts() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_overlay_reset_stale_if_match_conflicts-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::json!({"team":{"limits":[{"budget":20000,"per":"month"}]}});
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("authorization", "Bearer admintok");

    admin(client.post(format!("http://{addr}/api/v1/admin/groups")))
        .header("content-type", "application/json")
        .body(json::json!({"name": "user:bob", "config": {"parent": "team"}}).to_string())
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
        json::parse_value(&stale.bytes().await.unwrap()).unwrap()["error"]["code"],
        "version_conflict"
    );

    let listed = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/groups")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_empty_section_is_idempotent_noop() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_overlay_reset_empty_section_is_idempotent_noop-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("authorization", "Bearer admintok");

    let v_before = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/info")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
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
        let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(
            body["changed"], false,
            "an empty-section reset changes nothing"
        );
    }
    let v_after = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/info")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        v_before["config_version"], v_after["config_version"],
        "an idempotent no-op reset does not bump the version"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_requires_full_scope() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_overlay_reset_requires_full_scope-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for section in ["groups", "hooks"] {
        let scope = busbar_core_admin::v1::contract::required_scope(
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_survives_a_real_store_reload() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_config_settings_survives_a_real_store_reload-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("authorization", "Bearer admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(json::json!({ "per_request_fee": 9 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);

    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        rules.as_ref(),
        Some(overlay.clone()),
    )
    .await
    .expect("fresh boot disk-load");
    assert_eq!(
        loaded
            .overlay_path
            .as_ref()
            .unwrap()
            .read_bytes_async()
            .await
            .unwrap(),
        overlay.read_bytes_async().await.unwrap(),
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let candidate_module = module.as_str();
    let staged_plugins = crate::root::test_plugins::trusted_config(&directory);
    let build = busbar_kernel::preflight::root_rows()
        .registry_build
        .expect("the actual root installs its registry builder");
    let linked = build(
        busbar_kernel::preflight::RegistryIn {
            linked: busbar_kernel::preflight::linked_rows(),
            plugins: Some(&staged_plugins),
            data_dir: None,
            inventory_only: true,
        },
        &mut |_| {},
    )
    .expect("the actual staged Store registry resolves");
    assert!(
        linked
            .secret_slots(candidate_module)
            .into_iter()
            .chain(linked.reference_slots(candidate_module))
            .any(|slot| slot == "db_path"),
        "the staged actual Store declares its database-path reference"
    );
    let var = format!("BUSBAR_TEST_STORE_SECRET_MISSING_{}", std::process::id());
    std::env::remove_var(&var);

    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("authorization", "Bearer admintok")
        .header("content-type", "application/json")
        .body(
            json::json!({
                "store": { "module": candidate_module, "settings": { "db_path": { "env": var } } }
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

    let doc = busbar_kernel::config::overlay::read_async(&overlay)
        .await
        .expect("overlay written");
    assert!(
        doc.root
            .as_ref()
            .and_then(|r| r.store.as_ref())
            .is_some_and(|s| json::to_value(
                &s.settings.authoring(&busbar_kernel::seal::acquire())
            )
            .unwrap()
            .get("db_path")
                == Some(&json::json!({"env": var}))),
        "the staged reference reaches the overlay"
    );

    handle.abort();
    drop(dir);
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_reset_reverts_to_base() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "overlay");
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_config_settings_reset_reverts_to_base-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let admin = |r: reqwest::RequestBuilder| r.header("authorization", "Bearer admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        busbar_kernel::config::overlay::read_async(&overlay)
            .await
            .and_then(|d| d.root)
            .is_some(),
        "root override present before reset"
    );

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body = json::parse_value(&reset.bytes().await.unwrap()).unwrap();
    assert_eq!(body["reset"], "root");
    assert_eq!(
        body["changed"], true,
        "the reset discarded the root override"
    );

    assert!(
        busbar_kernel::config::overlay::read_async(&overlay)
            .await
            .and_then(|d| d.root)
            .is_none(),
        "the overlay root section is cleared"
    );
    let after = json::parse_value(
        &admin(client.get(format!("http://{addr}/api/v1/admin/config/settings")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        after["settings"]["per_request_fee"].is_null(),
        "no root override after reset (base config.yaml stands)"
    );

    let again = json::parse_value(
        &admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/root")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        again["changed"], false,
        "an already-empty root reset is a no-op"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
