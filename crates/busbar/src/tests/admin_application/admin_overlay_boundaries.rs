// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::root::test_plugins as plugins;
use crate::test_common as common;

const AUDIENCE: &str = "api://admin-overlay-audit";

#[tokio::test]
async fn test_admin_v1_overlay_reset_groups_reverts_to_base() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_overlay_reset_groups_reverts_to_base-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the actual built OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("actual OIDC statement reads")
        .expect("actual OIDC states its door");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("valid actual OIDC statement")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let audit_token =
        common::credentials::token_for("audit-overlay-groups", &["audit-overlay-groups"], AUDIENCE);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module":oidc_module,"settings":common::credentials::settings(AUDIENCE),"max_admin_scope":"full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] =
        serde_json::json!({"test-scope-module":{"audit-overlay-groups":{"admin_scope":"full"}}});
    document["groups"] = serde_json::json!({"team":{"limits":[{"budget":20000,"per":"month"}]}});
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .expect("the actual audit Store hydrates before mutations");
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
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
        busbar_kernel::config::overlay::read(&overlay)
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
        .header("x-admin-token", &audit_token)
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

    let doc = busbar_kernel::config::overlay::read(&overlay).expect("overlay still present");
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
                && e["principal"] == "oidc:audit-overlay-groups"),
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_stale_if_match_conflicts() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_overlay_reset_stale_if_match_conflicts-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["groups"] = serde_json::json!({"team":{"limits":[{"budget":20000,"per":"month"}]}});
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_empty_section_is_idempotent_noop() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_overlay_reset_empty_section_is_idempotent_noop-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_requires_full_scope() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root overlay boundary assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_overlay_reset_requires_full_scope-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
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
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_config_settings_survives_a_real_store_reload-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
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

    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        rules.as_ref(),
        Some(overlay.clone()),
    )
    .expect("fresh boot disk-load");
    assert_eq!(
        loaded.overlay_path.as_ref().unwrap().read_bytes().unwrap(),
        overlay.read_bytes().unwrap(),
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
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // The application remains on SQLite; the staged candidate names the actual linked Store
    // whose Statement declares this credential slot.
    let candidate_module = busbar_kernel::config::migrated_store_module();
    let build = busbar_kernel::preflight::root_rows()
        .registry_build
        .expect("the actual root installs its registry builder");
    let linked = build(
        busbar_kernel::preflight::RegistryIn {
            linked: busbar_kernel::preflight::linked_rows(),
            plugins: None,
            data_dir: None,
            inventory_only: true,
        },
        &mut |_| {},
    )
    .expect("the actual linked registry resolves");
    assert!(
        linked
            .secret_slots(candidate_module)
            .into_iter()
            .chain(linked.reference_slots(candidate_module))
            .any(|slot| slot == "token"),
        "the staged actual Store declares its token credential reference"
    );
    let var = format!("BUSBAR_TEST_STORE_SECRET_MISSING_{}", std::process::id());
    std::env::remove_var(&var);

    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": { "module": candidate_module, "settings": { "token": { "env": var } } }
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

    let doc = busbar_kernel::config::overlay::read(&overlay).expect("overlay written");
    assert!(
        doc.root
            .as_ref()
            .and_then(|r| r.store.as_ref())
            .is_some_and(|s| s.settings.contains_key("token")),
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
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root overlay witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root overlay witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_admin_v1_config_settings_reset_reverts_to_base-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        busbar_kernel::config::overlay::read(&overlay)
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
        busbar_kernel::config::overlay::read(&overlay)
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
    println!("{WITNESS}");
}
