// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use axum::http::StatusCode;
use busbar_contract::records::*;
use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::config::transaction::{config_transaction, Outcome};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_store_read_does_not_stall_the_executor() {
    const CHILD: &str = "BUSBAR_ADMIN_KEY_TRANSACTION_CHILD";
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
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {"team": {}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    let signing_path = directory.join("transaction-signing.key");
    std::fs::write(&signing_path, [7_u8; 32]).unwrap();
    document["auth"]["signing_key"] = serde_json::json!({"file": signing_path});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let delay = Duration::from_millis(400);
    let probe_store = SlowStore::new(app.governance.as_ref().unwrap().store(), delay);
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    let actual_plugins = app.plugins_cfg.clone();
    drop(app);
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual config resolves");
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        actual_plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: probe_store.clone(),
            calls: Some(calls),
        }),
        false,
    )
    .expect("normal composition with precise actual Store read-delay wrapper");
    limits.stage_boot();
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let g = app.governance.as_ref().expect("actual governance").clone();
    let calls = g.store_calls().expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 97);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    app.overlay_path =
        Some(busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual overlay"));
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let reads_before = probe_store.reads.load(Ordering::SeqCst);
    let (stop, worst, probe) = spawn_liveness_probe();

    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

    let status = tokio::spawn(delete_team(addr)).await.expect("delete joins");
    stop.store(true, Ordering::SeqCst);
    let ticks = probe.await.expect("probe joins");

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "no keys are bound, so the delete succeeds"
    );
    assert!(
        probe_store.reads.load(Ordering::SeqCst) >= 1,
        "the test must actually have gone through the slow `list_keys` it is measuring"
    );
    assert!(ticks > 0, "the probe must have run");
    let worst_gap = worst.load(Ordering::SeqCst);
    assert!(
        worst_gap < delay.as_millis() as u64 / 2,
        "EXECUTOR STALLED: the liveness probe's worst tick gap was {worst_gap}ms while a {}ms store \
         read ran under the config-mutation lock. A blocking store call reached the async thread — \
         it must be deferred through `Txn::read_store` onto spawn_blocking.",
        delay.as_millis()
    );
    assert!(
        probe_store.reads.load(Ordering::SeqCst) > reads_before,
        "the measured delete actually reached the delayed Store"
    );
    server.abort();
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_is_read_from_the_post_lock_snapshot() {
    const CHILD: &str = "BUSBAR_ADMIN_KEY_TRANSACTION_CHILD";
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
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {"team": {}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    let signing_path = directory.join("transaction-signing.key");
    std::fs::write(&signing_path, [7_u8; 32]).unwrap();
    document["auth"]["signing_key"] = serde_json::json!({"file": signing_path});
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
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.max_keys_per_principal = 5;
    let g = app.governance.as_ref().expect("actual governance").clone();
    let calls = g.store_calls().expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 97);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    app.overlay_path =
        Some(busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual overlay"));
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    assert_eq!(mint(addr, "first", Some("team")).await, StatusCode::CREATED);

    let lowering = {
        let handle = handle.clone();
        tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, |txn| {
                let current = txn.app().clone();
                Ok(txn.read_store(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    let mut next = (*current).clone();
                    next.config_version = current.config_version.wrapping_add(1);
                    next.max_keys_per_principal = 1;
                    let installed = Arc::new(next);
                    Ok(Outcome::swap(installed.clone(), installed))
                }))
            })
            .await
        })
    };

    tokio::time::sleep(Duration::from_millis(80)).await;
    let status = mint(addr, "second", Some("team")).await;
    lowering.await.expect("join").expect("cap change commits");

    assert_eq!(
        handle.load().max_keys_per_principal,
        1,
        "the cap change committed"
    );
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "STALE CAP: the mint admitted a key against a `max_keys_per_principal` read from a snapshot \
         older than its own lock acquisition. `txn.app()` is the only config a body can see, so \
         this must enforce the post-lock cap of 1."
    );
    server.abort();
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mints_never_bind_a_deleted_group() {
    const CHILD: &str = "BUSBAR_ADMIN_KEY_TRANSACTION_CHILD";
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
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("admin-store-overlay");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let mut document = serde_json::json!({
            "providers": {},
            "models": {},
            "groups": {"team": {}},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
        let signing_path = directory.join("transaction-signing.key");
        std::fs::write(&signing_path, [7_u8; 32]).unwrap();
        document["auth"]["signing_key"] = serde_json::json!({"file": signing_path});
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
        let boot_calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .store_calls()
            .expect("actual boot Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual rate history boots before rates are committed");
        limits
            .keep()
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let g = app.governance.as_ref().expect("actual governance").clone();
        let calls = g.store_calls().expect("actual Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 97);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("actual rate history boots");
        app.overlay_path =
            Some(busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual overlay"));
        let (_data, admin, _handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        assert_eq!(
            mint(addr, "bound-control", Some("team")).await,
            StatusCode::CREATED
        );
        let keys = g.all_keys().expect("control key readable");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].group.as_deref(), Some("team"));
        server.abort();
    }
    for round in 0..10u32 {
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
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("admin-store-overlay");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let mut document = serde_json::json!({
            "providers": {},
            "models": {},
            "groups": {"team": {}},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
        let signing_path = directory.join("transaction-signing.key");
        std::fs::write(&signing_path, [7_u8; 32]).unwrap();
        document["auth"]["signing_key"] = serde_json::json!({"file": signing_path});
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
        let boot_calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .store_calls()
            .expect("actual boot Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual rate history boots before rates are committed");
        limits
            .keep()
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let g = app.governance.as_ref().expect("actual governance").clone();
        let calls = g.store_calls().expect("actual Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 97);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("actual rate history boots");
        app.overlay_path =
            Some(busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual overlay"));
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let mut minting = Vec::new();
        let mut deleting = None;
        for i in 0..8 {
            minting.push(tokio::spawn(async move {
                mint(addr, &format!("k{round}-{i}"), Some("team")).await
            }));
            if i == 2 {
                deleting = Some(tokio::spawn(delete_team(addr)));
            }
        }
        let deleting = deleting.expect("delete spawned");
        let mut created = 0;
        for m in minting {
            match m.await.expect("mint task joins") {
                StatusCode::CREATED => created += 1,
                StatusCode::BAD_REQUEST => {}
                status => panic!("mint must create or refuse the deleted group, got {status}"),
            }
        }
        let deleted = deleting.await.expect("delete task joins");
        assert_eq!(
            deleted,
            if created == 0 {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CONFLICT
            },
            "deletion succeeds only if no bound mint committed"
        );

        let live = handle.load();
        let keys = g.all_keys().expect("keys readable");
        assert_eq!(keys.len(), created, "every successful mint is durable");
        assert_eq!(
            live.groups_registry.contains_key("team"),
            created != 0,
            "the group remains exactly when a bound mint prevented deletion"
        );
        for key in keys {
            if let Some(bound) = key.group.as_deref() {
                assert!(
                    live.groups_registry.contains_key(bound)
                        && live.cost.group_named(bound).is_some(),
                    "DANGLING BIND: key `{}` is durably bound to group `{bound}`, which no longer \
                     exists. A bind's existence check and its store write must share one \
                     transaction.",
                    key.id
                );
            }
        }
        server.abort();
    }
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rebinds_never_bind_a_deleted_group() {
    const CHILD: &str = "BUSBAR_ADMIN_KEY_TRANSACTION_CHILD";
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
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {"team": {}, "other": {}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    let signing_path = directory.join("transaction-signing.key");
    std::fs::write(&signing_path, [7_u8; 32]).unwrap();
    document["auth"]["signing_key"] = serde_json::json!({"file": signing_path});
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
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let g = app.governance.as_ref().expect("actual governance").clone();
    let calls = g.store_calls().expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 97);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    app.overlay_path =
        Some(busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual overlay"));
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let mut ids = Vec::new();
    for i in 0..6 {
        let (key, _tok) = g
            .mint_signed(
                busbar_kernel::governance::NewKeySpec {
                    name: format!("r{i}"),
                    allowed_pools: None,
                    group: Some("other".to_string()),
                    labels: Default::default(),
                    ..Default::default()
                },
                u64::MAX,
                0,
            )
            .expect("mint");
        ids.push(key.id);
    }
    let mut rebinding = Vec::new();
    for id in ids {
        rebinding.push(tokio::spawn(async move {
            reqwest::Client::new()
                .put(format!("http://{addr}/api/v1/admin/keys/{id}"))
                .json(&serde_json::json!({"group": "team"}))
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let deleting = tokio::spawn(delete_team(addr));
    for r in rebinding {
        r.await.expect("rebind joins");
    }
    deleting.await.expect("delete joins");

    let live = handle.load();
    for key in g.all_keys().expect("keys readable") {
        if let Some(bound) = key.group.as_deref() {
            assert!(
                live.groups_registry.contains_key(bound),
                "DANGLING REBIND: key `{}` points at removed group `{bound}`",
                key.id
            );
        }
    }
    server.abort();
    println!("{WITNESS}");
}
async fn mint(addr: std::net::SocketAddr, name: &str, group: Option<&str>) -> StatusCode {
    let body = match group {
        Some(g) => serde_json::json!({"name": name, "group": g}),
        None => serde_json::json!({"name": name}),
    };
    reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
}
async fn delete_team(addr: std::net::SocketAddr) -> StatusCode {
    reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/admin/groups/team"))
        .send()
        .await
        .unwrap()
        .status()
}
fn spawn_liveness_probe() -> (
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<u64>,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let worst = Arc::new(AtomicU64::new(0));
    let probe = {
        let (stop, worst) = (stop.clone(), worst.clone());
        tokio::spawn(async move {
            let mut last = Instant::now();
            let mut ticks = 0u64;
            while !stop.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
                let now = Instant::now();
                worst.fetch_max(
                    now.duration_since(last).as_millis() as u64,
                    Ordering::SeqCst,
                );
                last = now;
                ticks += 1;
            }
            ticks
        })
    };
    (stop, worst, probe)
}
struct SlowStore {
    inner: Arc<dyn RecordStore>,
    delay: Duration,
    reads: AtomicU64,
}
impl SlowStore {
    fn new(inner: Arc<dyn RecordStore>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner,
            delay,
            reads: AtomicU64::new(0),
        })
    }
}
impl RecordStore for SlowStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys_since(since)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.inner.supports_usage_correction()
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.inner.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.inner.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.inner.add_metering_batch_deduped(op, deltas)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.inner.put_credential(_secret)
    }
    fn rewrap_credential(
        &self,
        _expected: &CredentialSecret,
        _replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(_expected, _replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.inner.list_credentials(_key_id)
    }
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        self.inner.revoke_credential(_id, _reason)
    }
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.inner.list_credentials_since(_since)
    }
    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(_entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        self.inner.add_denylist(_sub, _reason)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.upsert_plane_record(_record)
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(_kind, _id)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.append_plane_record(_record)
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.inner.list_plane_records(_kind, _selector)
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        self.inner.list_plane_record_parents(_kind)
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(_kind, _before)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        self.inner.delete_plane_record(_kind, _id)
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner
            .redeem_plane_token(_kind, _token, _expires_at, _now)
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner
            .plane_token_live(_kind, _token, _expires_at, _now)
    }
}
