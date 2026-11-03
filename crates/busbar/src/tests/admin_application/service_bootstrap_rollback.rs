// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use base64::Engine as _;
use std::sync::Arc;

fn trust_document(config: &busbar_kernel::config::PluginsCfg) -> serde_json::Value {
    let publishers: Vec<_> = config.trust.publishers.iter().map(|publisher| {
        serde_json::json!({"name": publisher.name, "public_key": publisher.public_key})
    }).collect();
    serde_json::json!({
        "publishers": publishers,
        "allow_unsigned": config.trust.allow_unsigned,
        "allow_third_party": config.trust.allow_third_party,
    })
}

#[tokio::test]
async fn rollback_refuses_the_anchor_below_its_operator_bootstrap_floor_before_any_pin_is_returned()
{
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN")
            .expect("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
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
    let settings =
        serde_json::json!({"db_path":directory.join("bootstrap.sqlite"), "busy_timeout_ms":2000});
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual application Store binds history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let target_name = module.clone();
    let target_version = module_version.clone();
    let major: u64 = target_version.split('.').next().unwrap().parse().unwrap();
    let base_floor = format!("{}.0.0", major.checked_add(1).unwrap());
    assert!(
        busbar_contract::plugin::valid_semver(&target_version),
        "the actual target states its version"
    );
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
        .insert(target_name.clone(), target_version.clone());
    manifest.publisher = "acme".into();
    let target = plugins::signed(&publisher_key, manifest, &library);
    if target_name == module {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    let mut fetch = vec![
        serde_json::json!({"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}),
    ];
    if directory.join("store.tar.gz").exists() {
        fetch.push(serde_json::json!({"url":"https://plugins.example/store.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&archive)}));
    }
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":trust_document(&app.plugins_cfg),
        "min_versions":{(target_name.clone()):base_floor}, "fetch":fetch
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app).expect("the actual root hydrates before admin rollback");
    let router = busbar_kernel::build_router(app);
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
            std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN")
                .expect("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual built store"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let store = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid");
        let module = store.name;
        let module_version = store.version;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.version = module_version.clone();
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
        let settings = serde_json::json!({"db_path":directory.join("bootstrap.sqlite"), "busy_timeout_ms":2000});
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
        let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the actual application Store binds history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let (target_name, target_version, library, manifest) = if anchor_target {
            (module.clone(), module_version.clone(), library, manifest)
        } else {
            let target_path = crate::root::test_plugins::application_store_library();
            let target_statement =
                busbar_plugin_loader::dispatch::rendering_of_library(&target_path)
                    .expect("the actual nonanchor Store Statement reads")
                    .expect("the actual nonanchor Store exports its Statement");
            let read = busbar_contract::abi::mechanism::rendering::read(&target_statement)
                .expect("the nonanchor Statement is valid");
            assert_eq!(
                read.kind,
                busbar_contract::abi::mechanism::KindCode::Store as u32
            );
            assert_ne!(
                read.name, module,
                "anchor and nonanchor are actual distinct Store implementations"
            );
            let mut manifest = plugins::manifest("store", &read.name, "acme");
            manifest.version = read.version.clone();
            manifest.statement = Some(hex::encode(target_statement));
            (
                read.name,
                read.version,
                std::fs::read(target_path).unwrap(),
                manifest,
            )
        };
        let mut manifest = manifest;
        let major: u64 = target_version.split('.').next().unwrap().parse().unwrap();
        let base_floor = if anchor_target {
            target_version.clone()
        } else {
            format!("{}.0.0", major.checked_add(1).unwrap())
        };
        assert!(
            busbar_contract::plugin::valid_semver(&target_version),
            "the actual target states its version"
        );
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
            .insert(target_name.clone(), target_version.clone());
        manifest.publisher = "acme".into();
        let target = plugins::signed(&publisher_key, manifest, &library);
        if target_name == module {
            std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
        }
        std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
        let mut fetch = vec![
            serde_json::json!({"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}),
        ];
        if directory.join("store.tar.gz").exists() {
            fetch.push(serde_json::json!({"url":"https://plugins.example/store.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&archive)}));
        }
        document["plugins"] = serde_json::json!({
            "enabled":true, "dir":directory,
            "trust":trust_document(&app.plugins_cfg),
            "min_versions":{(target_name.clone()):base_floor}, "fetch":fetch
        });
        let config_path = directory.join("config.yaml");
        let providers_path = directory.join("providers.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
        std::fs::write(&providers_path, "{}\n").unwrap();
        app.config_path = Some(config_path);
        app.providers_path = Some(providers_path);
        busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
        let app = Arc::new(app);
        busbar_kernel::boot::hydrate_all(&app)
            .expect("the actual root hydrates before admin rollback");
        let router = busbar_kernel::build_router(app);
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
            .expect("the actual Store has the persisted pin merge");
        assert_eq!(persisted.plugin_versions[&target_name], target_version);
        assert_eq!(persisted.plugin_versions["prior-plugin"], "3.0.0");
        server.abort();
    }
}

#[tokio::test]
async fn an_upload_cannot_replace_the_anchor_with_a_target_only_the_running_pin_admits() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN")
            .expect("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
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
    let settings =
        serde_json::json!({"db_path":directory.join("bootstrap.sqlite"), "busy_timeout_ms":2000});
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual application Store binds history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let target_name = module.clone();
    let target_version = module_version.clone();
    let major: u64 = target_version.split('.').next().unwrap().parse().unwrap();
    let base_floor = format!("{}.0.0", major.checked_add(1).unwrap());
    assert!(
        busbar_contract::plugin::valid_semver(&target_version),
        "the actual target states its version"
    );
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
        .insert(target_name.clone(), target_version.clone());
    manifest.publisher = "acme".into();
    let target = plugins::signed(&publisher_key, manifest, &library);
    if target_name == module {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    let mut fetch = vec![
        serde_json::json!({"url":"https://plugins.example/target.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&target)}),
    ];
    if directory.join("store.tar.gz").exists() {
        fetch.push(serde_json::json!({"url":"https://plugins.example/store.tar.gz", "sha256":busbar_contract::redacted::sha256_hex(&archive)}));
    }
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":trust_document(&app.plugins_cfg),
        "min_versions":{(target_name.clone()):base_floor}, "fetch":fetch
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
    let original = archive;
    assert_ne!(
        original, target,
        "the attempted replacement differs from the installed signed archive"
    );
    std::fs::write(directory.join("target.tar.gz"), &original).unwrap();
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app).expect("the actual root hydrates before admin rollback");
    let router = busbar_kernel::build_router(app);
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
        "the actual installed archive is unchanged"
    );

    server.abort();
}

#[tokio::test]
async fn a_secret_plugin_needed_to_open_the_anchor_cannot_rely_on_its_unread_store_pin() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
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
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual application Store binds history before activation");
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
    let secret = busbar_contract::abi::mechanism::rendering::read(&secret_statement)
        .expect("the actual secret Statement is valid");
    assert_eq!(
        secret.kind,
        busbar_contract::abi::mechanism::KindCode::Secret as u32
    );
    assert!(
        busbar_contract::plugin::valid_semver(&secret.version),
        "the actual secret states its version"
    );
    let target_name = secret.name;
    let target_alias = target_name.clone();
    let target_version = secret.version;
    let major: u64 = target_version.split('.').next().unwrap().parse().unwrap();
    let base_floor = format!("{}.0.0", major.checked_add(1).unwrap());
    let anchor = busbar_kernel::config::migrated_store_module();
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
    assert!(linked.secret_slots(anchor).into_iter().chain(linked.reference_slots(anchor)).any(|path| path == "token"), "the actual memory Store must declare the token credential reference used by this dependency test");
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
        .insert(target_name.clone(), target_version.clone());
    manifest.name = target_name.clone();
    manifest.alias = target_alias.clone();
    manifest.publisher = "acme".into();
    manifest.version = target_version;
    let target = plugins::signed(&publisher_key, manifest.clone(), &library);
    if target_name == module {
        std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    }
    std::fs::write(directory.join("target.tar.gz"), &target).unwrap();
    document["plugins"] = serde_json::json!({
        "enabled":true, "dir":directory,
        "trust":trust_document(&app.plugins_cfg),
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
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app).expect("the actual root hydrates before admin rollback");
    let router = busbar_kernel::build_router(app);
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
        message.contains("bootstrap dependency") && message.contains(&target_name),
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
