// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::config::transaction::{config_transaction, Outcome};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn a_txn_that_declares_no_plan_swaps_nothing() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_TXN_CHILD";
    const WITNESS: &str = "actual root config transaction assertions completed";
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
    let directory = plugins::scratch("admin-config-transaction");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
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
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));

    let before = handle.load().config_version;
    let seen: u64 = config_transaction::<_, _, AdminError>(&handle, |txn| {
        Ok(txn.done(txn.app().config_version))
    })
    .await
    .expect("read-only txn succeeds");
    assert_eq!(seen, before, "the body reads the post-lock snapshot");
    assert_eq!(handle.load().config_version, before, "no plan ⇒ no swap");
    println!("{WITNESS}");
}
#[tokio::test]
async fn a_failed_persist_swaps_nothing() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_TXN_CHILD";
    const WITNESS: &str = "actual root config transaction assertions completed";
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
    let directory = plugins::scratch("admin-config-transaction");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
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
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));

    let before = handle.load().config_version;
    let err = config_transaction(&handle, |txn| {
        let mut next = (**txn.app()).clone();
        next.config_version = before.wrapping_add(1);
        Ok(txn.commit(Arc::new(next), || Err("disk said no".to_string()), ()))
    })
    .await
    .expect_err("a failed persist fails the transaction");
    assert!(
        matches!(&err, AdminError::Validation(m) if m == "disk said no"),
        "the persist closure owns the operator-facing message: {err:?}"
    );
    assert_eq!(
        handle.load().config_version,
        before,
        "persist failed ⇒ the live engine is untouched"
    );
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_transactions_never_lose_a_swap() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_TXN_CHILD";
    const WITNESS: &str = "actual root config transaction assertions completed";
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
    let directory = plugins::scratch("admin-config-transaction");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
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
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));

    let before = handle.load().config_version;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, |txn| {
                let current = txn.app();
                let mut next = (**current).clone();
                next.config_version = current.config_version.wrapping_add(1);
                Ok(txn.live_swap(Arc::new(next), ()))
            })
            .await
        }));
    }
    for t in tasks {
        t.await.expect("join").expect("txn commits");
    }
    assert_eq!(
        handle.load().config_version,
        before + 16,
        "every transaction's build read the previous one's swap — no lost update"
    );
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_handler_future_does_not_release_the_mutation_domain() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_TXN_CHILD";
    const WITNESS: &str = "actual root config transaction assertions completed";
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
    let directory = plugins::scratch("admin-config-transaction");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
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
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let finished = Arc::new(AtomicBool::new(false));

    let victim = {
        let (handle, finished) = (handle.clone(), finished.clone());
        tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, move |txn| {
                Ok(txn.store_write(move || {
                    entered_tx.send(()).expect("test still listening");
                    release_rx.recv().expect("test releases the deferred step");
                    finished.store(true, Ordering::SeqCst);
                    Ok(Outcome::Value(()))
                }))
            })
            .await
        })
    };

    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the deferred step must start");
    victim.abort();
    assert!(victim.await.is_err(), "the caller's future was cancelled");

    let contender = config_transaction::<_, _, AdminError>(&handle, |txn| Ok(txn.done(())));
    assert!(
        tokio::time::timeout(Duration::from_millis(500), contender)
            .await
            .is_err(),
        "a cancelled handler must not hand the mutation domain to a concurrent op while its \
         deferred work is still writing"
    );
    assert!(
        !finished.load(Ordering::SeqCst),
        "the deferred step is still in flight - the timeout above was a real lock wait"
    );

    release_tx.send(()).expect("deferred step still parked");
    tokio::time::timeout(
        Duration::from_secs(10),
        config_transaction::<_, _, AdminError>(&handle, |txn| Ok(txn.done(()))),
    )
    .await
    .expect("the domain is released once the deferred work finishes")
    .expect("txn ok");
    assert!(
        finished.load(Ordering::SeqCst),
        "cancellation abandons the RESULT, never the critical section"
    );
    println!("{WITNESS}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugin_install_is_serialized_by_the_mutation_domain() {
    const CHILD: &str = "BUSBAR_ADMIN_PLUGIN_TRANSACTION_CHILD";
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
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
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
    let dir = directory.clone();
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual Store overlay"),
    );
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let hold = Duration::from_millis(300);
    let holder = {
        let handle = handle.clone();
        tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, |txn| {
                Ok(txn.read_store(move || {
                    std::thread::sleep(hold);
                    Ok(Outcome::Value(()))
                }))
            })
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(80)).await;
    let started = Instant::now();

    let _ = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .json(&serde_json::json!({ "file": "x.tar.gz", "tarball_b64": "bm90IGEgdGFyYmFsbA==" }))
        .send()
        .await
        .unwrap();
    let waited = started.elapsed();
    holder.await.expect("join").expect("holder commits");

    assert!(
        waited >= hold / 2,
        "INSTALL OUTSIDE THE DOMAIN: the install returned after only {}ms while a transaction held \
         the section for {}ms. Plugin writes must enter the same `config_transaction` section \
         rollback/reload validate-and-rebuild in, or an install can overwrite the artifact between \
         a rollback's validate and its rebuild.",
        waited.as_millis(),
        hold.as_millis()
    );
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
