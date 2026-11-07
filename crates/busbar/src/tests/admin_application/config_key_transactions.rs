// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use axum::http::StatusCode;
use busbar_contract::persistence::*;
use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::config::transaction::{config_transaction, Outcome};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
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
    let backend = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("configured native backend");
    let delay = Duration::from_millis(400);
    let probe_store = SlowStore::new(backend, delay);
    let core = crate::root::real_store::core_over(probe_store.clone()).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone()).unwrap();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core),
        false,
    )
    .await
    .expect("actual composition over native delayed backend");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("actual rate history boots");
    limits.keep().await.expect("limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
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
         the native Store future must yield while its read is pending.",
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
    let (mut app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("actual rate history boots");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app.max_keys_per_principal = 5;
    let g = app.governance.as_ref().expect("actual governance").clone();
    let calls = g.core_store_handle().unwrap();
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::from_core(calls).expect("actual overlay"),
    );
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
        // Each fresh Store gets one real process-wide rate history owner.
        let name = std::thread::current().name().unwrap().to_string();
        for round in 0..=10u32 {
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, round.to_string())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
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
                        "actual round {round} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "round {round} completion witness absent: {output}"
                    );
                    break;
                }
                assert!(Instant::now() < until, "actual round {round} timed out");
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let round: u32 = std::env::var(CHILD).unwrap().parse().unwrap();

    if round == 0 {
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
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the actual product builds the swap deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .await
            .expect("actual rate history boots");
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        let g = app.governance.as_ref().expect("actual governance").clone();
        let calls = g.core_store_handle().unwrap();
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(calls).expect("actual overlay"),
        );
        let (_data, admin, _handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        assert_eq!(
            mint(addr, "bound-control", Some("team")).await,
            StatusCode::CREATED
        );
        let keys = g.all_keys_async().await.expect("control key readable");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].group.as_deref(), Some("team"));
        server.abort();
        println!("{WITNESS}");
        return;
    }
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
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the actual product builds the swap deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .await
            .expect("actual rate history boots");
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        let g = app.governance.as_ref().expect("actual governance").clone();
        let calls = g.core_store_handle().unwrap();
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(calls).expect("actual overlay"),
        );
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
        let keys = g.all_keys_async().await.expect("keys readable");
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
    let (mut app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("actual rate history boots");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let g = app.governance.as_ref().expect("actual governance").clone();
    let calls = g.core_store_handle().unwrap();
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::from_core(calls).expect("actual overlay"),
    );
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let mut ids = Vec::new();
    for i in 0..6 {
        let (key, _tok) = g
            .mint_signed_async(
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
            .await
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
    for key in g.all_keys_async().await.expect("keys readable") {
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
    inner: Arc<dyn PersistenceBackend>,
    delay: Duration,
    reads: AtomicU64,
}
impl SlowStore {
    fn new(inner: Arc<dyn PersistenceBackend>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner,
            delay,
            reads: AtomicU64::new(0),
        })
    }
}
impl PersistenceBackend for SlowStore {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move { self.inner.read(request).await })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.namespace.0 == *b"busbar.identity1" && request.prefix.first() == Some(&b'K')
            {
                self.reads.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
            }
            self.inner.scan(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move { self.inner.commit(candidate).await })
    }
}
