// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;
use std::sync::Arc;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn rollback_refuses_the_anchor_below_its_operator_bootstrap_floor_before_any_pin_is_returned()
{
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
        "admin-service-bootstrap-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let target_name = "acme-anchor".to_string();
    let target_alias = "anchor-alias".to_string();
    document["store"]["module"] = serde_json::json!(target_alias);
    let base_floor = "2.0.0";
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let publisher_key = plugins::key(68);
    let publisher_hex = hex::encode(publisher_key.verifying_key().to_bytes());
    app.plugins_cfg
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "acme".into(),
            public_key: publisher_hex.clone(),
        });
    app.plugins_cfg
        .min_versions
        .insert(target_name.clone(), "1.4.0".into());
    manifest.name = target_name.clone();
    manifest.alias = target_alias.clone();
    manifest.publisher = "acme".into();
    manifest.version = "1.4.0".into();
    let target = plugins::signed(&publisher_key, manifest.clone(), &library);
    if target_name == "acme-anchor" {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":{"publishers":[{"name":"acme", "public_key":publisher_hex}]},
        "min_versions":{(target_name.clone()):base_floor},
        "fetch":[{"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}]
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(
        &providers_path,
        "{}
",
    )
    .unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots in its Store");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls)
        .expect("the actual Store opens its overlay");
    app.overlay_path = Some(overlay.clone());
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let prior = overlay
        .read_required()
        .unwrap()
        .map(|doc| doc.plugin_versions);
    let response = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"target.tar.gz"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let error: serde_json::Value = response.json().await.unwrap();
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("bootstrap dependency")
            && message.contains("base config.yaml")
            && message.contains(&target_name),
        "{error}"
    );
    assert_eq!(
        overlay
            .read_required()
            .unwrap()
            .map(|doc| doc.plugin_versions),
        prior,
        "a refused bootstrap rollback returns no new target pin"
    );

    server.abort();
}

#[tokio::test]
async fn safe_anchor_and_nonanchor_rollbacks_preserve_the_existing_pin_merge() {
    for anchor_target in [true, false] {
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
            "admin-service-bootstrap-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let archive = plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest.clone(),
            &library,
        );
        std::fs::write(directory.join("store.tar.gz"), &archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let operator_token = directory.join("operator-token");
        let signing_key = directory.join("signing-key");
        std::fs::write(&operator_token, "admintok").unwrap();
        std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
        let operator = busbar_kernel::config::operator_provider();
        let mut document = serde_json::json!({
            "providers": {},
            "models": {},
            "groups": {},
            "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
            "identity-providers": {},
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
        document["identity-providers"][operator] =
            serde_json::json!({"module": operator, "token": {"file": operator_token}});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
            .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the actual product builds the swap deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let target_name = if anchor_target {
            "acme-anchor".to_string()
        } else {
            "other-store".to_string()
        };
        let target_alias = if anchor_target {
            "anchor-alias".to_string()
        } else {
            "other".to_string()
        };
        if anchor_target {
            document["store"]["module"] = serde_json::json!(target_alias);
        }
        let base_floor = if anchor_target { "1.4.0" } else { "2.0.0" };
        busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
        let publisher_key = plugins::key(68);
        let publisher_hex = hex::encode(publisher_key.verifying_key().to_bytes());
        app.plugins_cfg
            .trust
            .publishers
            .push(busbar_kernel::config::PluginPublisher {
                name: "acme".into(),
                public_key: publisher_hex.clone(),
            });
        app.plugins_cfg
            .min_versions
            .insert(target_name.clone(), "1.4.0".into());
        manifest.name = target_name.clone();
        manifest.alias = target_alias.clone();
        manifest.publisher = "acme".into();
        manifest.version = "1.4.0".into();
        let target = plugins::signed(&publisher_key, manifest.clone(), &library);
        if anchor_target {
            std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
        }
        std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
        document["plugins"] = serde_json::json!({
            "enabled":true, "dir":directory,
            "trust":{"publishers":[{"name":"acme", "public_key":publisher_hex}]},
            "min_versions":{(target_name.clone()):base_floor},
            "fetch":[{"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}]
        });
        let config_path = directory.join("config.yaml");
        let providers_path = directory.join("providers.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
        std::fs::write(
            &providers_path,
            "{}
",
        )
        .unwrap();
        app.config_path = Some(config_path);
        app.providers_path = Some(providers_path);
        let calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .store_calls()
            .expect("actual Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual rate history boots in its Store");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls)
            .expect("the actual Store opens its overlay");
        app.overlay_path = Some(overlay.clone());
        let prior = std::collections::BTreeMap::from([("prior-plugin".into(), "3.0.0".into())]);
        busbar_kernel::config::overlay::try_persist_plugin_versions(Some(&overlay), &prior)
            .expect("the prior pin persists in the real Store");
        let router = busbar_kernel::build_router(Arc::new(app));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap();
        let response = client
            .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"file":"target.tar.gz"}))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let view: serde_json::Value = response.json().await.unwrap();
        assert_eq!(status, 200, "safe anchor/nonanchor rollback: {view}");
        assert_eq!(view["name"], target_name);
        let persisted = overlay
            .read_required()
            .unwrap()
            .expect("the real Store has the persisted pin merge");
        assert_eq!(persisted.plugin_versions[&target_name], "1.4.0");
        assert_eq!(persisted.plugin_versions["prior-plugin"], "3.0.0");
        server.abort();
    }
}

#[tokio::test]
async fn an_upload_cannot_replace_the_anchor_with_a_target_only_the_running_pin_admits() {
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
        "admin-service-bootstrap-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let target_name = "acme-anchor".to_string();
    let target_alias = "anchor-alias".to_string();
    document["store"]["module"] = serde_json::json!(target_alias);
    let base_floor = "2.0.0";
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let publisher_key = plugins::key(68);
    let publisher_hex = hex::encode(publisher_key.verifying_key().to_bytes());
    app.plugins_cfg
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "acme".into(),
            public_key: publisher_hex.clone(),
        });
    app.plugins_cfg
        .min_versions
        .insert(target_name.clone(), "1.4.0".into());
    manifest.name = target_name.clone();
    manifest.alias = target_alias.clone();
    manifest.publisher = "acme".into();
    manifest.version = "1.4.0".into();
    let target = plugins::signed(&publisher_key, manifest.clone(), &library);
    if target_name == "acme-anchor" {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":{"publishers":[{"name":"acme", "public_key":publisher_hex}]},
        "min_versions":{(target_name.clone()):base_floor},
        "fetch":[{"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}]
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(
        &providers_path,
        "{}
",
    )
    .unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots in its Store");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls)
        .expect("the actual Store opens its overlay");
    app.overlay_path = Some(overlay.clone());
    manifest.version = "2.0.0".into();
    let original = plugins::signed(&publisher_key, manifest, &library);
    std::fs::write(directory.join("target.tar.gz"), &original).unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"target.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&target)})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let error: serde_json::Value = response.json().await.unwrap();
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("bootstrap dependency") && message.contains("install"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(directory.join("target.tar.gz")).unwrap(),
        original,
        "the actual currently installed archive is unchanged"
    );

    server.abort();
}

#[tokio::test]
async fn a_secret_plugin_needed_to_open_the_anchor_cannot_rely_on_its_unread_store_pin() {
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
        "admin-service-bootstrap-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let secret_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_SECRET_PLUGIN").expect(
            "BUSBAR_BOOTSTRAP_TEST_SECRET_PLUGIN names the existing actual secret-env/file cdylib",
        ),
    );
    let secret_statement = busbar_plugin_loader::dispatch::rendering_of_library(&secret_path)
        .expect("the actual secret statement reads")
        .expect("the actual secret exports its statement");
    let library = std::fs::read(secret_path).expect("the actual secret library reads");
    let target_name = "acme-vault".to_string();
    let target_alias = "vault-alias".to_string();
    let base_floor = "2.0.0";
    manifest = plugins::manifest("secret", &target_name, "acme");
    manifest.statement = Some(hex::encode(secret_statement));
    document["store"] = serde_json::json!({"module":busbar_kernel::config::migrated_store_module(), "settings":{"token":{"module":target_alias, "settings":{}}}});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let publisher_key = plugins::key(68);
    let publisher_hex = hex::encode(publisher_key.verifying_key().to_bytes());
    app.plugins_cfg
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "acme".into(),
            public_key: publisher_hex.clone(),
        });
    app.plugins_cfg
        .min_versions
        .insert(target_name.clone(), "1.4.0".into());
    manifest.name = target_name.clone();
    manifest.alias = target_alias.clone();
    manifest.publisher = "acme".into();
    manifest.version = "1.4.0".into();
    let target = plugins::signed(&publisher_key, manifest.clone(), &library);
    if target_name == module {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":{"publishers":[{"name":"acme", "public_key":publisher_hex}]},
        "min_versions":{(target_name.clone()):base_floor},
        "fetch":[{"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}]
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(
        &providers_path,
        "{}
",
    )
    .unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots in its Store");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls)
        .expect("the actual Store opens its overlay");
    app.overlay_path = Some(overlay.clone());
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let prior = overlay
        .read_required()
        .unwrap()
        .map(|doc| doc.plugin_versions);
    let response = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"target.tar.gz"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let error: serde_json::Value = response.json().await.unwrap();
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("bootstrap dependency") && message.contains("acme-vault"),
        "{error}"
    );
    assert_eq!(
        overlay
            .read_required()
            .unwrap()
            .map(|doc| doc.plugin_versions),
        prior,
        "the secret bootstrap dependency never publishes a pin from its unread Store"
    );

    server.abort();
}
