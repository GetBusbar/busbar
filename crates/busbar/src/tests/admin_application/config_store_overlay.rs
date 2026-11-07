// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{persistence::*, Secret};
use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::config::transaction::config_transaction;
use busbar_kernel::persistence::scoped::ScopedStore;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn apply_refuses_unrecoverable_store_overlay_before_replacing_security_state() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_FAILURE_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
        for failure in ["read", "corrupt", "newer"] {
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, failure)
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
                        status.success()
                            && output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                        "the actual-root usage witness failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(&format!("{WITNESS} {failure}")),
                        "the exact child did not complete its assertions: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "the actual-root usage witness timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected = std::env::var(CHILD).expect("exact overlay failure scenario");
    assert!(matches!(selected.as_str(), "read" | "corrupt" | "newer"));
    for failure in ["read", "corrupt", "newer"]
        .into_iter()
        .filter(|failure| *failure == selected)
    {
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("admin-store-overlay");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value =
            crate::root::test_plugins::application_store_settings(&directory);
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let mut document = serde_json::json!({
            "providers": {},
            "models": {},
            "groups": {"security_team": {}},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
        document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
        let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
            .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = crate::root::test_plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .await
            .expect("actual native Store opens");
        let faults = OverlayFaults::new(actual);
        let core = crate::root::real_store::core_over(faults.clone()).await;
        let calls = overlay_scope(core.clone());
        let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core.clone()),
            false,
        )
        .await
        .expect("the actual product builds the swap deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .await
            .expect("native rate history boots before activation");
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }

        app.hook_registry.insert(
            "security_gate".into(),
            serde_json::from_value(serde_json::json!({
                "kind": "gate", "module": "test-hook", "global": true,
            }))
            .unwrap(),
        );

        let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
            crate::root::real_store::hydrated(Arc::new(app)).await,
            1 << 20,
            0,
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let client = reqwest::Client::new();
        let before = handle.load();
        match failure {
            "read" => faults.fail_reads.store(true, Ordering::SeqCst),
            "corrupt" => {
                calls
                    .put(
                        "busbar.config.overlay.v1",
                        b"head",
                        Secret::new(b"{ not json".to_vec()),
                    )
                    .await
                    .unwrap();
            }
            "newer" => {
                let doc = busbar_kernel::config::overlay::OverlayDoc {
                    version: busbar_kernel::config::overlay::OVERLAY_VERSION + 1,
                    ..Default::default()
                };
                busbar_kernel::config::overlay::write_async(&overlay, &doc)
                    .await
                    .unwrap();

                use sha2::Digest as _;
                let schema = "busbar.config.overlay.v1";
                let raw = calls.get(schema, b"head").await.unwrap().unwrap();
                let mut head: serde_json::Value =
                    serde_json::from_slice(raw.expose(&busbar_kernel::seal::lend())).unwrap();
                let generation: [u8; 16] =
                    serde_json::from_value(head["generation"].clone()).unwrap();
                let bytes = serde_json::to_vec(&doc).unwrap();
                assert!(bytes.len() <= busbar_contract::MAX_RECORD_BYTES);
                let mut chunk = b"chunk:".to_vec();
                chunk.extend_from_slice(&generation);
                chunk.extend_from_slice(&0_u64.to_be_bytes());
                calls
                    .put(schema, &chunk, Secret::new(bytes.clone()))
                    .await
                    .unwrap();
                head["length"] = serde_json::json!(bytes.len());
                let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
                head["digest"] = serde_json::json!(digest);
                calls
                    .put(
                        schema,
                        b"head",
                        Secret::new(serde_json::to_vec(&head).unwrap()),
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    busbar_kernel::config::overlay::read_state_async(&overlay).await,
                    busbar_kernel::config::overlay::OverlayReadState::VersionTooNew(_)
                ));
            }
            _ => unreachable!(),
        }
        let response = client
            .post(format!("http://{addr}/api/v1/admin/config/apply"))
            .json(&serde_json::json!({"config": document}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400, "{failure}");
        let after = handle.load();
        assert!(Arc::ptr_eq(&after, &before), "{failure} must not swap");
        assert!(after.hook_registry.contains_key("security_gate"));
        assert!(after.groups_registry.contains_key("security_team"));
        assert_eq!(after.config_version, before.config_version);
        server.abort();
    }
    println!("{WITNESS} {selected}");
}
#[tokio::test]
async fn reload_refuses_a_store_read_failure_and_preserves_the_running_generation() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_FAILURE_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {"persisted_team": {}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual native Store opens");
    let faults = OverlayFaults::new(actual);
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("native rate history boots before activation");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);

    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
        crate::root::real_store::hydrated(Arc::new(app)).await,
        1 << 20,
        0,
        false,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let client = reqwest::Client::new();
    let before = handle.load();
    faults.fail_reads.store(true, Ordering::SeqCst);
    let response = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert!(handle.load().groups_registry.contains_key("persisted_team"));
    server.abort();
    let _ = std::fs::remove_dir_all(dir);
    println!("{WITNESS}");
}
#[tokio::test]
async fn group_creation_refuses_store_failure_and_unknown_commit() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_FAILURE_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
        for failure in ["false", "true"] {
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, failure)
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
                        status.success()
                            && output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                        "the actual-root usage witness failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(&format!("{WITNESS} {failure}")),
                        "the exact child did not complete its assertions: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "the actual-root usage witness timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected = std::env::var(CHILD).expect("exact overlay failure scenario");
    assert!(matches!(selected.as_str(), "false" | "true"));
    for unknown in [false, true]
        .into_iter()
        .filter(|unknown| unknown.to_string() == selected)
    {
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("admin-store-overlay");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value =
            crate::root::test_plugins::application_store_settings(&directory);
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let mut document = serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
        document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
        let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
            .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = crate::root::test_plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .await
            .expect("actual native Store opens");
        let faults = OverlayFaults::new(actual);
        let core = crate::root::real_store::core_over(faults.clone()).await;
        let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core.clone()),
            false,
        )
        .await
        .expect("the actual product builds the swap deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .await
            .expect("native rate history boots before activation");
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }

        let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
            crate::root::real_store::hydrated(Arc::new(app)).await,
            1 << 20,
            0,
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let client = reqwest::Client::new();
        let before = handle.load();
        if unknown {
            faults.lose_reply.store(true, Ordering::SeqCst);
        } else {
            faults.fail_writes.store(true, Ordering::SeqCst);
        }
        let response = client
            .post(format!("http://{addr}/api/v1/admin/groups"))
            .json(&serde_json::json!({"name": "candidate_team", "config": {}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400, "unknown={unknown}");
        let body = response.bytes().await.unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("not confirmed"), "{body}");
        assert!(!body.contains("nothing was changed"), "{body}");
        let after = handle.load();
        assert!(Arc::ptr_eq(&after, &before));
        assert!(!after.groups_registry.contains_key("candidate_team"));
        faults.fail_reads.store(false, Ordering::SeqCst);
        let durable = overlay.read_required_async().await.unwrap();
        assert_eq!(
            durable.is_some_and(|doc| doc.groups.contains_key("candidate_team")),
            unknown,
            "only the unknown-outcome case applied the Store write"
        );
        server.abort();
    }
    println!("{WITNESS} {selected}");
}
#[tokio::test]
async fn settings_preserves_a_large_store_overlay_across_reload() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_FAILURE_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual native Store opens");
    let faults = OverlayFaults::new(actual);
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("native rate history boots before activation");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);

    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, _handle) = busbar_kernel::build_split_routers_with_limits(
        crate::root::real_store::hydrated(Arc::new(app)).await,
        1 << 20,
        0,
        false,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let _client = reqwest::Client::new();
    let groups: std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> = (0..32)
        .map(|index| (format!("persisted-team-{index:04}"), Default::default()))
        .collect();
    busbar_kernel::config::overlay::write_async(
        &overlay,
        &busbar_kernel::config::overlay::OverlayDoc {
            groups: groups.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let response = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"per_request_fee": 31}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "{:?}",
        response.text().await
    );
    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &dir.join("config.yaml"),
        Some(&dir.join("providers.yaml")),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        rules.as_ref(),
        Some(overlay.clone()),
    )
    .await
    .unwrap();
    let doc = loaded.overlay_doc.unwrap();
    assert_eq!(doc.root.unwrap().per_request_fee, Some(31));
    assert_eq!(
        serde_json::to_value(doc.groups).unwrap(),
        serde_json::to_value(groups).unwrap()
    );
    assert!(
        overlay
            .read_bytes_async()
            .await
            .unwrap()
            .expect("actual stored overlay bytes")
            .len()
            > busbar_contract::MAX_RECORD_BYTES
    );
    server.abort();
    let _ = std::fs::remove_dir_all(dir);
    println!("{WITNESS}");
}
#[tokio::test]
async fn unknown_settings_receipt_requires_successful_reload_before_new_mutation() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_FAILURE_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual native Store opens");
    let faults = OverlayFaults::new(actual);
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("native rate history boots before activation");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);
    let original_config = std::fs::read(&config_path).unwrap();

    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
        crate::root::real_store::hydrated(Arc::new(app)).await,
        1 << 20,
        0,
        false,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let client = reqwest::Client::new();
    let before = handle.load();
    faults.lose_reply.store(true, Ordering::SeqCst);
    let put = |fee| {
        let client = client.clone();
        async move {
            client
                .put(format!("http://{addr}/api/v1/admin/config/settings"))
                .json(&serde_json::json!({"per_request_fee": fee}))
                .send()
                .await
                .unwrap()
        }
    };
    assert_eq!(put(17).await.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        overlay
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(17),
        "the Store applied the candidate before its reply was lost"
    );

    assert_eq!(put(29).await.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let candidates = faults.requests.lock().unwrap().clone();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].candidate().id.operation,
        candidates[1].candidate().id.operation
    );
    assert_eq!(candidates[0].fingerprint(), candidates[1].fingerprint());

    let mut invalid = document.clone();
    invalid["groups"] = serde_json::json!({"broken": {"parent": "missing"}});
    std::fs::write(&config_path, serde_yaml::to_string(&invalid).unwrap()).unwrap();
    let failed = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let group = client
        .post(format!("http://{addr}/api/v1/admin/groups"))
        .json(&serde_json::json!({"name": "after_failed_reload", "config": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(group.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        faults.requests.lock().unwrap().clone().len(),
        2,
        "quarantine admits no new candidate"
    );

    std::fs::write(&config_path, original_config).unwrap();
    let reset = client
        .delete(format!("http://{addr}/api/v1/admin/overlay/root"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        400,
        "a reset rebuild also retains quarantine"
    );
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(faults.requests.lock().unwrap().clone().len(), 2);

    let reloaded = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    assert_eq!(reloaded.status().as_u16(), 200);
    let recovered = handle.load();
    assert!(!Arc::ptr_eq(&recovered, &before));
    assert_eq!(
        recovered
            .overlay_path
            .as_ref()
            .unwrap()
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(17),
        "reload publishes the recovered Store generation"
    );
    assert_eq!(
        put(41).await.status().as_u16(),
        200,
        "the published fresh carrier can mutate"
    );
    assert_eq!(
        overlay
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(41),
        "the new mutation persists to the same configured Store"
    );
    assert!(
        busbar_kernel::config::overlay::persist_root_async(
            Some(&overlay),
            &busbar_kernel::config::overlay::RootSettings::default(),
        )
        .await
        .is_err(),
        "publishing a new carrier never clears the old generation's quarantine"
    );
    server.abort();
    let _ = std::fs::remove_dir_all(dir);
    println!("{WITNESS}");
}
#[tokio::test]
async fn an_unknown_store_overlay_commit_never_swaps_or_claims_success() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_TRANSACTION_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual native Store opens");
    let faults = OverlayFaults::new(actual);
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("native rate history boots before activation");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(
        crate::root::real_store::hydrated(Arc::new(app)).await,
    ));
    let before = handle.load();
    faults.lose_reply.store(true, Ordering::SeqCst);
    let commit = || {
        let overlay = overlay.clone();
        config_transaction::<_, _, AdminError>(&handle, move |txn| {
            let mut next = (**txn.app()).clone();
            next.config_version = next.config_version.wrapping_add(1);
            Ok(txn.commit_async(
                Arc::new(next),
                async move {
                    busbar_kernel::config::overlay::persist_root_async(
                        Some(&overlay),
                        &busbar_kernel::config::overlay::RootSettings {
                            per_request_fee: Some(17),
                            ..Default::default()
                        },
                    )
                    .await
                },
                (),
            ))
        })
    };
    assert!(
        commit().await.is_err(),
        "a lost receipt cannot report success"
    );
    assert!(
        Arc::ptr_eq(&handle.load(), &before),
        "unknown means no swap"
    );
    assert_eq!(
        overlay
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(17),
        "this exercises an applied write whose reply was lost"
    );
    assert!(
        commit().await.is_err(),
        "resolving a prior receipt requires reload"
    );
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let candidates = faults.requests.lock().unwrap().clone();
    assert_eq!(candidates.len(), 2, "one write and its exact replay");
    assert_eq!(
        candidates[0].candidate().id.operation,
        candidates[1].candidate().id.operation
    );
    assert_eq!(candidates[0].fingerprint(), candidates[1].fingerprint());
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_store_overlay_persist_finishes_before_releasing_the_domain() {
    const CHILD: &str = "BUSBAR_ADMIN_OVERLAY_TRANSACTION_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = plugins::config_document(&plugins::trusted_config(&directory));
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual native Store opens");
    let faults = OverlayFaults::new(actual);
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("native rate history boots before activation");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(
        crate::root::real_store::hydrated(Arc::new(app)).await,
    ));
    let before = handle.load().config_version;
    let barrier = Arc::new(tokio::sync::Notify::new());
    *faults.block_read.lock().unwrap() = Some(barrier.clone());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let victim = {
        let handle = handle.clone();
        let backend = overlay.clone();
        tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, move |txn| {
                let mut next = (**txn.app()).clone();
                next.config_version = next.config_version.wrapping_add(1);
                Ok(txn.commit_async(
                    Arc::new(next),
                    async move {
                        entered_tx.send(()).unwrap();
                        busbar_kernel::config::overlay::persist_root_async(
                            Some(&backend),
                            &busbar_kernel::config::overlay::RootSettings {
                                per_request_fee: Some(23),
                                ..Default::default()
                            },
                        )
                        .await
                    },
                    (),
                ))
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .unwrap()
        .unwrap();
    victim.abort();
    assert!(victim.await.is_err());
    let domain_held = tokio::time::timeout(
        Duration::from_millis(100),
        config_transaction::<_, _, AdminError>(&handle, |txn| Ok(txn.done(()))),
    )
    .await
    .is_err();
    let version_while_blocked = handle.load().config_version;

    barrier.notify_one();
    assert!(
        domain_held,
        "the cancelled caller's Store operation still owns the domain"
    );
    assert_eq!(version_while_blocked, before);
    tokio::time::timeout(
        Duration::from_secs(10),
        config_transaction::<_, _, AdminError>(&handle, |txn| Ok(txn.done(()))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(handle.load().config_version, before + 1);
    assert_eq!(
        overlay
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(23),
        "the Store persistence completed before the generation became live"
    );
    println!("{WITNESS}");
}

fn overlay_scope(core: Arc<busbar_kernel::persistence::facade::CoreStore>) -> ScopedStore {
    ScopedStore::host_private(
        core,
        "busbar.config.overlay",
        ["busbar.config.overlay.v1".to_string()],
    )
    .unwrap()
}

struct OverlayFaults {
    inner: Arc<dyn PersistenceBackend>,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
    lose_reply: AtomicBool,
    block_read: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
    requests: std::sync::Mutex<Vec<PreparedCandidate>>,
}
impl OverlayFaults {
    fn new(inner: Arc<dyn PersistenceBackend>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_reads: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
            lose_reply: AtomicBool::new(false),
            block_read: Default::default(),
            requests: Default::default(),
        })
    }
}
impl PersistenceBackend for OverlayFaults {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let schema = b"busbar.config.overlay.v1";
            let overlay = request.addresses.iter().any(|address| {
                address
                    .key
                    .windows(schema.len())
                    .any(|bytes| bytes == schema)
            });
            if overlay {
                if self.fail_reads.load(Ordering::SeqCst) {
                    return Err(Failure::Unavailable);
                }
                let block = self.block_read.lock().unwrap().take();
                if let Some(block) = block {
                    block.notified().await;
                }
            }
            self.inner.read(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let schema = b"busbar.config.overlay.v1";
            let publication = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { address, .. } if address.key.ends_with(b"head") && address.key.windows(schema.len()).any(|bytes| bytes == schema)));
            if publication {
                self.requests.lock().unwrap().push(candidate.clone());
                if self.fail_writes.load(Ordering::SeqCst) {
                    return Err(Failure::Refused);
                }
            }
            let lose = publication && self.lose_reply.swap(false, Ordering::SeqCst);
            let result = self.inner.commit(candidate).await?;
            if lose {
                Err(Failure::Unknown)
            } else {
                Ok(result)
            }
        })
    }
}
