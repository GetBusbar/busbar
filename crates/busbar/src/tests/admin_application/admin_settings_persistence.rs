// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const AUDIENCE: &str = "api://admin-settings-audit";

fn free_open_units() -> serde_json::Value {
    crate::dist_root_install::install();
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .find(|decl| decl.fallback)
        .expect("the actual linked planes carry the fallback plane")
        .billable_classes
        .iter()
        .map(|c| c.class)
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .map(|c| (c.to_string(), serde_json::json!(0)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

#[tokio::test]
async fn test_admin_v1_config_settings_round_trip_survives_reload() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_PERSISTENCE_CHILD";
    const WITNESS: &str = "actual root settings persistence assertions completed";
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
                    "the actual-root settings witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root settings witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
        plugins::scratch("test_admin_v1_config_settings_round_trip_survives_reload-actual-store");
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
        .expect("the actual built OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC states its door");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let audit_token = common::credentials::token_for(
        "audit-settings-roundtrip",
        &["audit-settings-roundtrip"],
        AUDIENCE,
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
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module, "settings": common::credentials::settings(AUDIENCE), "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "audit-settings-roundtrip": { "admin_scope": "full" } },
    });
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI dialect is required");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] =
        serde_json::json!({ "test-provider": { "api_key": { "file": upstream_key } } });
    document["models"] =
        serde_json::json!({ "m0": { "provider": "test-provider", "max_concurrent": 4 } });
    document["pools"] = serde_json::json!({ "p": { "members": [{ "model": "m0" }] } });
    document["groups"] =
        serde_json::json!({ "team": { "limits": [{ "budget": 20000, "per": "month" }] } });
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize actual base config"),
    )
    .expect("write the actual base configuration");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).expect("serialize actual provider definitions"),
    )
    .expect("write the actual provider definitions");
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
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
        .header("x-admin-token", &audit_token)
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

    let doc = busbar_kernel::config::overlay::read(&overlay).expect("overlay written");
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
            rules.as_ref(),
            Some(overlay.clone()),
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
                && e["principal"] == "oidc:audit-settings-roundtrip"),
        "the applied PUT is audited"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_process_level_flagged_reload_to_apply() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_PERSISTENCE_CHILD";
    const WITNESS: &str = "actual root settings persistence assertions completed";
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
                    "the actual-root settings witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root settings witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
        "test_admin_v1_config_settings_process_level_flagged_reload_to_apply-actual-store",
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
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI dialect is required");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] =
        serde_json::json!({ "test-provider": { "api_key": { "file": upstream_key } } });
    document["models"] =
        serde_json::json!({ "m0": { "provider": "test-provider", "max_concurrent": 4 } });
    document["pools"] = serde_json::json!({ "p": { "members": [{ "model": "m0" }] } });
    document["groups"] =
        serde_json::json!({ "team": { "limits": [{ "budget": 20000, "per": "month" }] } });
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize actual base config"),
    )
    .expect("write the actual base configuration");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).expect("serialize actual provider definitions"),
    )
    .expect("write the actual provider definitions");
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
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

    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "listen": "127.0.0.1:0",
                "store": {"module": module, "settings": settings},
                "store": { "module": module, "settings": settings },
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

    let doc = busbar_kernel::config::overlay::read(&overlay).expect("overlay written");
    assert_eq!(
        doc.root.unwrap().listen.as_deref(),
        Some("127.0.0.1:0"),
        "the reload-to-apply field is still durably persisted"
    );
    let root = busbar_kernel::config::overlay::read(&overlay)
        .expect("overlay written")
        .root
        .unwrap();
    assert!(
        root.tls.is_some() && root.admin_tls.is_some(),
        "the tls / admin_tls changes are durably stored too, for the next boot"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_partial_update_preserves_prior() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_PERSISTENCE_CHILD";
    const WITNESS: &str = "actual root settings persistence assertions completed";
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
                    "the actual-root settings witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root settings witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
        "test_admin_v1_config_settings_partial_update_preserves_prior-actual-store",
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
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI dialect is required");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] =
        serde_json::json!({ "test-provider": { "api_key": { "file": upstream_key } } });
    document["models"] =
        serde_json::json!({ "m0": { "provider": "test-provider", "max_concurrent": 4 } });
    document["pools"] = serde_json::json!({ "p": { "members": [{ "model": "m0" }] } });
    document["groups"] =
        serde_json::json!({ "team": { "limits": [{ "budget": 20000, "per": "month" }] } });
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize actual base config"),
    )
    .expect("write the actual base configuration");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).expect("serialize actual provider definitions"),
    )
    .expect("write the actual provider definitions");
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
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
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_put_with_persist_true_still_persists_when_overlay_exists() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_PERSISTENCE_CHILD";
    const WITNESS: &str = "actual root settings persistence assertions completed";
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
                    "the actual-root settings witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root settings witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
        plugins::scratch("test_admin_v1_config_settings_put_with_persist_true_still_persists_when_overlay_exists-actual-store");
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
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI dialect is required");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] =
        serde_json::json!({ "test-provider": { "api_key": { "file": upstream_key } } });
    document["models"] =
        serde_json::json!({ "m0": { "provider": "test-provider", "max_concurrent": 4 } });
    document["pools"] = serde_json::json!({ "p": { "members": [{ "model": "m0" }] } });
    document["groups"] =
        serde_json::json!({ "team": { "limits": [{ "budget": 20000, "per": "month" }] } });
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize actual base config"),
    )
    .expect("write the actual base configuration");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).expect("serialize actual provider definitions"),
    )
    .expect("write the actual provider definitions");
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
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

    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 7, "persist": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 200, "{:?}", put.text().await);
    let stored = busbar_kernel::config::overlay::read(&overlay)
        .and_then(|d| d.root)
        .expect("root section persisted");
    assert_eq!(
        stored.per_request_fee,
        Some(7),
        "persist:true with an overlay present stores the value in the Store"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_read_redacts_every_settings_bag() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_PERSISTENCE_CHILD";
    const WITNESS: &str = "actual root settings persistence assertions completed";
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
                    "the actual-root settings witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root settings witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
        "test_admin_v1_config_settings_read_redacts_every_settings_bag-actual-store",
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
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI dialect is required");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] =
        serde_json::json!({ "test-provider": { "api_key": { "file": upstream_key } } });
    document["models"] =
        serde_json::json!({ "m0": { "provider": "test-provider", "max_concurrent": 4 } });
    document["pools"] = serde_json::json!({ "p": { "members": [{ "model": "m0" }] } });
    document["groups"] =
        serde_json::json!({ "team": { "limits": [{ "budget": 20000, "per": "month" }] } });
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize actual base config"),
    )
    .expect("write the actual base configuration");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).expect("serialize actual provider definitions"),
    )
    .expect("write the actual provider definitions");
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
        Some(overlay.clone()),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
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

    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let put = admin(client.put(format!("http://{addr}/api/v1/admin/config/settings")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "store": {
                    "module": module,
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
        store["module"], module,
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
    println!("{WITNESS}");
}
