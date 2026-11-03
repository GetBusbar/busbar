// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use axum::http::StatusCode;
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use busbar_kernel::config::overlay::OverlayStore;
use busbar_kernel::config::overlay::{persist_root, RootSettings};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
const BASE_FEE: i64 = 0;
const CANDIDATE_BODY_CAP: usize = 5_000_123;
use crate::root::test_plugins as plugins;
async fn put(addr: std::net::SocketAddr, fee: i64) -> reqwest::Response {
    reqwest::Client::new().put(format!("http://{addr}/api/v1/admin/config/settings"))
        .json(&serde_json::json!({"per_request_fee": fee, "limits": {"request_body_max_bytes": CANDIDATE_BODY_CAP}}))
        .send().await.unwrap()
}
async fn reload(addr: std::net::SocketAddr) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap()
}
fn stored_fee(backend: &OverlayStore) -> Option<i64> {
    backend
        .read_required()
        .unwrap()
        .and_then(|doc| doc.root)
        .and_then(|root| root.per_request_fee)
}
#[tokio::test]
async fn an_absent_card_and_unchanged_prices_allow_a_successful_settings_handler() {
    const CHILD: &str = "BUSBAR_ADMIN_PRICE_ACTIVATION_CHILD";
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
    if let Some(rotate) = rotate {
        rotate();
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 103);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let before = handle.load();
    assert_eq!(put(addr, BASE_FEE).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(stored_fee(&overlay), Some(BASE_FEE));
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        Some(CANDIDATE_BODY_CAP)
    );
    let next = handle.load();
    assert_eq!(reload(addr).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &next));
    server.abort();
    println!("{WITNESS}");
}

const REFUSED_CANDIDATE_FEE: i64 = 71_001;
const UNKNOWN_CANDIDATE_FEE: i64 = 71_002;
const REFUSED_ACTIVATION_FEE: i64 = 71_003;
const UNKNOWN_ACTIVATION_FEE: i64 = 71_004;
const PENDING_ACTIVATION_FEE: i64 = 71_005;
const PRE_PUBLICATION_PANIC_FEE: i64 = 71_006;
const POST_PUBLICATION_PANIC_FEE: i64 = 71_007;
const REFUSED_CONFIG_FEE: i64 = 71_008;
const UNKNOWN_CONFIG_FEE: i64 = 71_009;
const NONPRICE_BODY_CAP: usize = CANDIDATE_BODY_CAP + 1;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn settings_refuses_unconfirmed_prices_then_reload_confirms_the_exact_candidate_once() {
    const WITNESS: &str = "actual rate activation assertions completed";
    const CASE: &str = "BUSBAR_ADMIN_PRICE_CASE";
    if std::env::var_os(CASE).is_none() {
        for case in &["0", "1", "2", "3"] {
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let name = std::thread::current()
                .name()
                .expect("exact test name")
                .to_string();
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CASE, case)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start exact actual-root scenario"),
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
                        "actual-root scenario {case} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "scenario {case} did not complete: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "actual-root price scenario {case} timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected_case = std::env::var(CASE).unwrap();
    assert!(
        ["0", "1", "2", "3"].contains(&selected_case.as_str()),
        "unknown exact price case"
    );

    for (case, (fee, activation, unknown)) in [
        (REFUSED_CANDIDATE_FEE, false, false),
        (UNKNOWN_CANDIDATE_FEE, false, true),
        (REFUSED_ACTIVATION_FEE, true, false),
        (UNKNOWN_ACTIVATION_FEE, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        if case.to_string() != selected_case {
            continue;
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
        if let Some(rotate) = rotate {
            rotate();
        }
        let dir = directory.clone();
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
        std::fs::write(&providers_path, "{}\n").unwrap();
        app.config_path = Some(config_path.clone());
        app.providers_path = Some(providers_path);
        let calls = app
            .governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls");
        let price_faults = PriceStoreFaults::new(calls.clone(), false);
        crate::root::kernel::ROOT_CARD.keep_in_store(price_faults.clone(), 103);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("actual rate history boots");
        limits
            .keep()
            .expect("the booted actual rates and limits commit");
        let book = crate::root::kernel::ROOT_CARD
            .card_store()
            .expect("actual loaded card history")
            .clone();
        let opening = book
            .entries()
            .into_iter()
            .find(|entry| entry.card.per_request_fee == BASE_FEE)
            .expect("actual opening card");
        let candidate_tag =
            opening.records().unwrap()[0].0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
        let activation_tag = crate::root::card_store::Activation { effective_from: 0 }
            .records(&opening)
            .unwrap()[0]
            .0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
        price_faults.writes.lock().unwrap().clear();
        let overlay_faults = PriceStoreFaults::new(calls, true);
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(overlay_faults.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });

        let before = handle.load();
        let before_limits = busbar_kernel::config::limits::installed();
        let before_price = live_price(&book);
        let target_tag = if activation {
            activation_tag
        } else {
            candidate_tag
        };
        price_faults.tag.store(target_tag, Ordering::SeqCst);
        price_faults
            .mode
            .store(if unknown { 2 } else { 1 }, Ordering::SeqCst);

        assert_eq!(put(addr, fee).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(handle.load().config_version, before.config_version);
        assert_eq!(live_price(&book), before_price);
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            before_limits
                .as_ref()
                .map(|limits| limits.request_body_max_bytes)
        );
        assert_eq!(
            stored_fee(&overlay),
            Some(fee),
            "config and prices can use different Stores"
        );
        let submitted = price_faults.attempts(target_tag);
        assert!(
            !submitted.is_empty(),
            "an actual rate-card record was submitted"
        );
        let candidate = book
            .pending()
            .expect("the unconfirmed exact candidate retains custody");
        assert!(
            submitted.iter().all(|attempt| attempt == &submitted[0]),
            "retries retain the immutable actual key/body"
        );

        assert!(persist_root(Some(&overlay), &RootSettings::default()).is_err());
        assert_eq!(put(addr, fee).await.status(), StatusCode::BAD_REQUEST);
        let applied = reqwest::Client::new()
            .post(format!("http://{addr}/api/v1/admin/config/apply"))
            .json(&serde_json::json!({"config": document}))
            .send()
            .await
            .unwrap();
        assert_eq!(applied.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            book.pending(),
            Some(candidate),
            "quarantine creates no new candidate"
        );

        let original = std::fs::read(&config_path).unwrap();
        let mut invalid = document.clone();
        invalid["groups"] = serde_json::json!({"broken": {"parent": "missing"}});
        std::fs::write(&config_path, serde_yaml::to_string(&invalid).unwrap()).unwrap();
        assert_eq!(reload(addr).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(live_price(&book), before_price);
        assert_eq!(put(addr, fee).await.status(), StatusCode::BAD_REQUEST);
        std::fs::write(&config_path, original).unwrap();

        price_faults.mode.store(0, Ordering::SeqCst);
        assert_eq!(reload(addr).await.status(), StatusCode::OK);
        assert!(
            book.pending().is_none(),
            "actual reload confirms and publishes the retained candidate"
        );
        assert!(!Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            live_price(&book),
            LivePrice {
                fee,
                epoch: before_price.epoch + 1
            }
        );
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            Some(CANDIDATE_BODY_CAP)
        );
        let confirmed = price_faults.attempts(target_tag);
        assert!(
            confirmed.iter().all(|attempt| attempt == &submitted[0]),
            "every retry uses the same actual key/body"
        );
        assert_eq!(confirmed[0].0, submitted[0].0);
        assert_eq!(confirmed[0].1, submitted[0].1);
        assert_eq!(
            price_faults
                .inner
                .record_get(crate::root::card_store::CARD_SCHEMA, &submitted[0].0)
                .await
                .unwrap(),
            Some(submitted[0].1.clone())
        );
        let entries = book.entries();
        let confirmed_entry = entries
            .iter()
            .find(|entry| entry.card.per_request_fee == fee)
            .expect("actual candidate published");
        assert_eq!(
            confirmed_entry.key, candidate,
            "reload publishes the retained immutable candidate exactly once"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.card.per_request_fee == fee)
                .count(),
            1
        );
        assert_eq!(
            confirmed_entry.actor,
            format!(
                "config/settings by {}",
                busbar_kernel::auth::AuthPrincipal(None).actor_id()
            )
        );
        assert!(persist_root(Some(&overlay), &RootSettings::default()).is_err());

        price_faults
            .refuse_all_card_writes
            .store(true, Ordering::SeqCst);
        assert_eq!(reload(addr).await.status(), StatusCode::OK);
        let nonprice = reqwest::Client::new()
            .put(format!("http://{addr}/api/v1/admin/config/settings"))
            .json(&serde_json::json!({"limits": {"request_body_max_bytes": NONPRICE_BODY_CAP}}))
            .send()
            .await
            .unwrap();
        assert_eq!(nonprice.status(), StatusCode::OK);
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            Some(NONPRICE_BODY_CAP)
        );
        assert_eq!(live_price(&book).epoch, before_price.epoch + 1);
        assert_eq!(price_faults.attempts(target_tag).len(), confirmed.len());
        server.abort();
    }
    println!("{WITNESS}");
}
#[tokio::test]
async fn config_refusal_or_unknown_reply_never_attempts_price_activation() {
    const WITNESS: &str = "actual rate activation assertions completed";
    const CASE: &str = "BUSBAR_ADMIN_PRICE_CASE";
    if std::env::var_os(CASE).is_none() {
        for case in &["false", "true"] {
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let name = std::thread::current()
                .name()
                .expect("exact test name")
                .to_string();
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CASE, case)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start exact actual-root scenario"),
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
                        "actual-root scenario {case} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "scenario {case} did not complete: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "actual-root price scenario {case} timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected_case = std::env::var(CASE).unwrap();
    assert!(
        ["false", "true"].contains(&selected_case.as_str()),
        "unknown exact price case"
    );

    for (fee, unknown) in [(REFUSED_CONFIG_FEE, false), (UNKNOWN_CONFIG_FEE, true)] {
        if unknown.to_string() != selected_case {
            continue;
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
        if let Some(rotate) = rotate {
            rotate();
        }
        let dir = directory.clone();
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
        std::fs::write(&providers_path, "{}\n").unwrap();
        app.config_path = Some(config_path.clone());
        app.providers_path = Some(providers_path);
        let calls = app
            .governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls");
        let price_faults = PriceStoreFaults::new(calls.clone(), false);
        crate::root::kernel::ROOT_CARD.keep_in_store(price_faults.clone(), 103);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("actual rate history boots");
        limits
            .keep()
            .expect("the booted actual rates and limits commit");
        let book = crate::root::kernel::ROOT_CARD
            .card_store()
            .expect("actual loaded card history")
            .clone();
        let opening = book
            .entries()
            .into_iter()
            .find(|entry| entry.card.per_request_fee == BASE_FEE)
            .expect("actual opening card");
        let candidate_tag =
            opening.records().unwrap()[0].0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
        let activation_tag = crate::root::card_store::Activation { effective_from: 0 }
            .records(&opening)
            .unwrap()[0]
            .0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
        price_faults.writes.lock().unwrap().clear();
        let overlay_faults = PriceStoreFaults::new(calls, true);
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(overlay_faults.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let before = handle.load();
        overlay_faults
            .mode
            .store(if unknown { 2 } else { 1 }, Ordering::SeqCst);
        assert_eq!(put(addr, fee).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            live_price(&book),
            LivePrice {
                fee: BASE_FEE,
                epoch: 0
            }
        );
        assert!(price_faults.attempts(candidate_tag).is_empty());
        assert!(price_faults.attempts(activation_tag).is_empty());
        server.abort();
    }
    println!("{WITNESS}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_activation_and_canceled_handler_keep_the_old_generation_until_confirmation() {
    const WITNESS: &str = "actual rate activation assertions completed";
    const CASE: &str = "BUSBAR_ADMIN_PRICE_CASE";
    if std::env::var_os(CASE).is_none() {
        for case in &["only"] {
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let name = std::thread::current()
                .name()
                .expect("exact test name")
                .to_string();
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CASE, case)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start exact actual-root scenario"),
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
                        "actual-root scenario {case} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "scenario {case} did not complete: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "actual-root price scenario {case} timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected_case = std::env::var(CASE).unwrap();
    assert!(
        ["only"].contains(&selected_case.as_str()),
        "unknown exact price case"
    );
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
    if let Some(rotate) = rotate {
        rotate();
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    let price_faults = PriceStoreFaults::new(calls.clone(), false);
    crate::root::kernel::ROOT_CARD.keep_in_store(price_faults.clone(), 103);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    let book = crate::root::kernel::ROOT_CARD
        .card_store()
        .expect("actual loaded card history")
        .clone();
    let opening = book
        .entries()
        .into_iter()
        .find(|entry| entry.card.per_request_fee == BASE_FEE)
        .expect("actual opening card");
    let _candidate_tag = opening.records().unwrap()[0].0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
    let activation_tag = crate::root::card_store::Activation { effective_from: 0 }
        .records(&opening)
        .unwrap()[0]
        .0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
    price_faults.writes.lock().unwrap().clear();
    let overlay_faults = PriceStoreFaults::new(calls, true);
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(overlay_faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let pending_router = admin.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let before = handle.load();
    let before_limits = busbar_kernel::config::limits::installed();
    price_faults.tag.store(activation_tag, Ordering::SeqCst);
    price_faults.mode.store(3, Ordering::SeqCst);
    let pause = price_faults.pause.clone();
    let request = tokio::spawn(async move {
        use tower::ServiceExt as _;
        let request = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/admin/config/settings")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"per_request_fee": PENDING_ACTIVATION_FEE,
                "limits": {"request_body_max_bytes": CANDIDATE_BODY_CAP}})
                .to_string(),
            ))
            .unwrap();
        pending_router.oneshot(request).await
    });
    tokio::time::timeout(COMPLETION_TIMEOUT, async {
        while !pause.entered() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("activation reached an actual Pending Store reply");
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        live_price(&book),
        LivePrice {
            fee: BASE_FEE,
            epoch: 0
        }
    );
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        before_limits
            .as_ref()
            .map(|limits| limits.request_body_max_bytes)
    );
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let queued = {
        let handle = handle.clone();
        tokio::spawn(async move {
            busbar_kernel::config::transaction::config_transaction::<
                _,
                _,
                busbar_core_admin::v1::contract::AdminError,
            >(&handle, |txn| Ok(txn.done(txn.app().config_version)))
            .await
        })
    };
    tokio::task::yield_now().await;
    assert!(
        !queued.is_finished(),
        "the canceled caller does not release its blocking task's guard"
    );
    pause.release();
    let version = tokio::time::timeout(COMPLETION_TIMEOUT, queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(version > before.config_version);
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        live_price(&book),
        LivePrice {
            fee: PENDING_ACTIVATION_FEE,
            epoch: 1
        }
    );
    assert_eq!(price_faults.attempts(activation_tag).len(), 1);
    server.abort();
    println!("{WITNESS}");
}
#[tokio::test]
async fn callback_panics_preserve_one_coherent_published_price_generation() {
    const WITNESS: &str = "actual rate activation assertions completed";
    const CASE: &str = "BUSBAR_ADMIN_PRICE_CASE";
    if std::env::var_os(CASE).is_none() {
        for case in &["before", "after"] {
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let name = std::thread::current()
                .name()
                .expect("exact test name")
                .to_string();
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CASE, case)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start exact actual-root scenario"),
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
                        "actual-root scenario {case} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "scenario {case} did not complete: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "actual-root price scenario {case} timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected_case = std::env::var(CASE).unwrap();
    assert!(
        ["before", "after"].contains(&selected_case.as_str()),
        "unknown exact price case"
    );
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
    if let Some(rotate) = rotate {
        rotate();
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    let price_faults = PriceStoreFaults::new(calls.clone(), false);
    crate::root::kernel::ROOT_CARD.keep_in_store(price_faults.clone(), 103);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    let book = crate::root::kernel::ROOT_CARD
        .card_store()
        .expect("actual loaded card history")
        .clone();
    let opening = book
        .entries()
        .into_iter()
        .find(|entry| entry.card.per_request_fee == BASE_FEE)
        .expect("actual opening card");
    let candidate_tag = opening.records().unwrap()[0].0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
    let _activation_tag = crate::root::card_store::Activation { effective_from: 0 }
        .records(&opening)
        .unwrap()[0]
        .0[busbar_kernel_ledger::cost::ENTRY_KEY_LEN];
    price_faults.writes.lock().unwrap().clear();
    let overlay_faults = PriceStoreFaults::new(calls, true);
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(overlay_faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });

    if selected_case == "before" {
        let before = handle.load();
        let before_limits = busbar_kernel::config::limits::installed();
        overlay_faults.mode.store(4, Ordering::SeqCst);
        assert_eq!(
            put(addr, PRE_PUBLICATION_PANIC_FEE).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            live_price(&book),
            LivePrice {
                fee: BASE_FEE,
                epoch: 0
            }
        );
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            before_limits
                .as_ref()
                .map(|limits| limits.request_body_max_bytes)
        );
        assert!(price_faults.attempts(candidate_tag).is_empty());
        assert!(persist_root(Some(&overlay), &RootSettings::default()).is_err());
        overlay_faults.mode.store(0, Ordering::SeqCst);
        assert_eq!(reload(addr).await.status(), StatusCode::OK);
        assert_eq!(
            live_price(&book),
            LivePrice {
                fee: PRE_PUBLICATION_PANIC_FEE,
                epoch: 1
            }
        );
    } else {
        let before = handle.load();
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        handle.on_apply(Box::new({
            let first = first.clone();
            let book = book.clone();
            let weak = Arc::downgrade(&handle);
            move |next| {
                assert!(Arc::ptr_eq(&weak.upgrade().unwrap().load(), next));
                assert_eq!(live_price(&book).fee, POST_PUBLICATION_PANIC_FEE);
                if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    weak.upgrade().unwrap().on_apply(Box::new(|_| {}));
                    panic!("injected post-publication applier panic");
                }
            }
        }));
        assert_eq!(
            put(addr, POST_PUBLICATION_PANIC_FEE).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            live_price(&book),
            LivePrice {
                fee: POST_PUBLICATION_PANIC_FEE,
                epoch: 1
            }
        );
        assert_eq!(stored_fee(&overlay), Some(POST_PUBLICATION_PANIC_FEE));
        assert_eq!(
            put(addr, POST_PUBLICATION_PANIC_FEE).await.status(),
            StatusCode::OK
        );
        assert_eq!(live_price(&book).epoch, 1);
    }
    server.abort();
    println!("{WITNESS}");
}
// Pure observation of the actual published rate-card history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LivePrice {
    fee: i64,
    epoch: u64,
}
fn live_price(book: &crate::root::card_history::CardStore) -> LivePrice {
    LivePrice {
        fee: book.in_force().expect("actual active card").per_request_fee,
        epoch: book
            .node_history()
            .expect("actual published node history")
            .len()
            .saturating_sub(1) as u64,
    }
}
#[derive(Default)]
struct Pause {
    entered: AtomicBool,
    released: AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}
impl Pause {
    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
    async fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        std::future::poll_fn(|cx| {
            let mut waker = self.waker.lock().unwrap();
            if self.released.load(Ordering::SeqCst) {
                std::task::Poll::Ready(())
            } else {
                *waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        })
        .await
    }
}
// Delegates the exact configured Store, with only explicitly selected causal faults.
struct PriceStoreFaults {
    inner: Arc<dyn StoreCalls>,
    overlay: bool,
    tag: AtomicU8,
    mode: AtomicU8,
    lost: AtomicBool,
    paused: AtomicBool,
    refuse_all_card_writes: AtomicBool,
    writes: std::sync::Mutex<Vec<(Vec<u8>, RecordBytes)>>,
    pause: Arc<Pause>,
}
impl PriceStoreFaults {
    fn new(inner: Arc<dyn StoreCalls>, overlay: bool) -> Arc<Self> {
        Arc::new(Self {
            inner,
            overlay,
            tag: AtomicU8::new(0),
            mode: AtomicU8::new(0),
            lost: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            refuse_all_card_writes: AtomicBool::new(false),
            writes: Default::default(),
            pause: Arc::new(Pause::default()),
        })
    }
    fn card_target(&self, schema: &str, key: &[u8]) -> bool {
        !self.overlay
            && schema == crate::root::card_store::CARD_SCHEMA
            && key.get(busbar_kernel_ledger::cost::ENTRY_KEY_LEN)
                == Some(&self.tag.load(Ordering::SeqCst))
    }
    fn attempts(&self, tag: u8) -> Vec<(Vec<u8>, RecordBytes)> {
        self.writes
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.get(busbar_kernel_ledger::cost::ENTRY_KEY_LEN) == Some(&tag))
            .cloned()
            .collect()
    }
}
impl StoreCalls for PriceStoreFaults {
    fn supports_usage_correction(&self) -> bool {
        self.inner.supports_usage_correction()
    }
    fn apply_usage_correction<'a>(
        &'a self,
        request: &'a busbar_contract::records::correction::Request,
    ) -> StoreCall<'a, busbar_contract::records::correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn supports_record_transaction(&self) -> bool {
        self.inner.supports_record_transaction()
    }
    fn record_transaction<'a>(
        &'a self,
        request: &'a busbar_contract::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, busbar_contract::abi::sdk::store::conditional::Decision> {
        let mode = self.mode.load(Ordering::SeqCst);
        if self.overlay && mode == 1 {
            return Box::pin(async {
                Err(StoreFailure::Refused(
                    "precise actual overlay transaction refusal".into(),
                ))
            });
        }
        let lose = self.overlay && mode == 2 && !self.lost.swap(true, Ordering::SeqCst);
        let panic_after = self.overlay && mode == 4 && !self.lost.swap(true, Ordering::SeqCst);
        Box::pin(async move {
            let result = self.inner.record_transaction(request).await;
            assert!(
                !(panic_after && result.is_ok()),
                "injected pre-publication actual Store completion callback panic"
            );
            if lose && result.is_ok() {
                Err(StoreFailure::Failed(
                    "lost actual overlay commit reply".into(),
                ))
            } else {
                result
            }
        })
    }
    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.inner.add_usage_batch(op, cells)
    }
    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.inner.add_metering_batch(op, deltas)
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        let card = schema == crate::root::card_store::CARD_SCHEMA;
        if card {
            self.writes
                .lock()
                .unwrap()
                .push((key.to_vec(), value.clone()));
        }
        let selected = self.card_target(schema, key);
        let overlay = self.overlay && schema == "busbar.config.overlay.v1";
        let mode = self.mode.load(Ordering::SeqCst);
        if (card && self.refuse_all_card_writes.load(Ordering::SeqCst))
            || ((selected || overlay) && mode == 1)
        {
            return Box::pin(async {
                Err(StoreFailure::Refused(
                    "precise actual Store write refusal".into(),
                ))
            });
        }
        let lose = selected && mode == 2 && !self.lost.swap(true, Ordering::SeqCst);
        let pause = selected && mode == 3 && !self.paused.swap(true, Ordering::SeqCst);
        Box::pin(async move {
            let result = self.inner.record_put(schema, key, value).await;
            if pause {
                self.pause.wait().await;
            }
            if lose && result.is_ok() {
                Err(StoreFailure::Failed(
                    "lost actual immutable card commit reply".into(),
                ))
            } else {
                result
            }
        })
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if self.card_target(schema, key)
            && self.mode.load(Ordering::SeqCst) == 2
            && self.lost.load(Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(StoreFailure::Failed(
                    "actual card commit reply remains unavailable".into(),
                ))
            });
        }
        self.inner.record_get(schema, key)
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.inner.record_scan(schema, prefix, limit)
    }
    fn put_key<'a>(&'a self, key: &'a busbar_contract::records::VirtualKey) -> StoreCall<'a, ()> {
        self.inner.put_key(key)
    }
    fn get_key<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreCall<'a, Option<busbar_contract::records::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreCall<'_, Vec<busbar_contract::records::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        self.inner.delete_key(id)
    }
    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a busbar_contract::records::VirtualKey,
        secret: &'a busbar_contract::records::CredentialSecret,
    ) -> StoreCall<'a, ()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials<'a>(
        &'a self,
        key_id: &'a str,
    ) -> StoreCall<'a, Vec<busbar_contract::records::CredentialMeta>> {
        self.inner.list_credentials(key_id)
    }
    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.inner.revoke_credential(id, reason)
    }
    fn list_credentials_since(
        &self,
        since: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::CredentialSecret>> {
        self.inner.list_credentials_since(since)
    }
    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        self.inner.list_denylist()
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn list_audit(&self) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.inner.list_audit()
    }
    fn list_audit_tail(
        &self,
        limit: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.inner.upsert_plane_record(record)
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.inner.append_plane_record(op, record)
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        self.inner.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        self.inner.purge_usage_before(before)
    }
}
