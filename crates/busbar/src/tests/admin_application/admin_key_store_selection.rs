// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::persistence::*;
use busbar_kernel::governance::NewKeySpec;
use std::collections::HashSet;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

struct CountingStore {
    inner: Arc<dyn PersistenceBackend>,
    list_keys_calls: std::sync::atomic::AtomicUsize,
    get_key_calls: std::sync::atomic::AtomicUsize,
}
impl CountingStore {
    fn new(inner: Arc<dyn PersistenceBackend>) -> Self {
        Self {
            inner,
            list_keys_calls: std::sync::atomic::AtomicUsize::new(0),
            get_key_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn reset(&self) {
        self.list_keys_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.get_key_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }
}
impl PersistenceBackend for CountingStore {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if request.addresses.iter().any(identity_key) {
                self.get_key_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.namespace.0 == *b"busbar.identity1" && request.prefix.first() == Some(&b'K')
            {
                self.list_keys_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.scan(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move { self.inner.commit(candidate).await })
    }
}

#[tokio::test]
async fn test_single_key_reads_use_get_key_not_list_keys() {
    const CHILD: &str = "BUSBAR_ADMIN_COUNT_28EA126B9F42";
    const WITNESS: &str =
        "actual root case test_single_key_reads_use_get_key_not_list_keys completed";
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
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
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
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
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
        plugins::scratch("test_single_key_reads_use_get_key_not_list_keys-actual-store");
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
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let store = Arc::new(CountingStore::new(anchor.clone()));
    let anchor = crate::root::real_store::core_over(store.clone()).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
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
    let gov = app
        .governance
        .as_ref()
        .expect("actual opened Store governance")
        .clone();
    let (key_a, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let (key_b, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let (key_c, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "c".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    store.reset();
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}} must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}} must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/admin/keys/{}/usage",
            key_b.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}}/usage must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}}/usage must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .post(format!(
            "http://{addr}/api/v1/admin/keys/{}/revoke",
            key_c.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "POST /keys/{{id}}/revoke must not scan the whole table to check existence"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "POST /keys/{{id}}/revoke must resolve the key via Store::get_key"
    );
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_single_key_writes_use_get_key_for_their_existence_check() {
    const CHILD: &str = "BUSBAR_ADMIN_COUNT_43A2450EB287";
    const WITNESS: &str =
        "actual root case test_single_key_writes_use_get_key_for_their_existence_check completed";
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
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
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
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
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
        "test_single_key_writes_use_get_key_for_their_existence_check-actual-store",
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
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let store = Arc::new(CountingStore::new(anchor.clone()));
    let anchor = crate::root::real_store::core_over(store.clone()).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
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
    let gov = app
        .governance
        .as_ref()
        .expect("actual opened Store governance")
        .clone();
    let (key_a, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let (key_b, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    store.reset();
    let resp = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "PATCH publishes exact Applied rows without scanning the identity table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "PATCH /keys/{{id}} must resolve the pre-image via Store::get_key"
    );

    store.reset();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key_b.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "DELETE publishes exact Applied rows without scanning the identity table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "DELETE /keys/{{id}} must resolve the pre-image via Store::get_key"
    );
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

fn identity_key(address: &Address) -> bool {
    address.namespace == *b"busbar.identity1" && address.key.first() == Some(&b'K')
}
