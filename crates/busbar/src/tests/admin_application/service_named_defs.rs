// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::{
    abi::store::OpId,
    kinds::RecordBytes,
    records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta},
    store_calls::{StoreCall, StoreCalls, StoreFailure},
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct OverlayReads {
    actual: Arc<dyn StoreCalls>,
    fail: AtomicBool,
    started: AtomicBool,
    gate: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    entered: tokio::sync::Notify,
}
impl StoreCalls for OverlayReads {
    fn supports_usage_correction(&self) -> bool {
        self.actual.supports_usage_correction()
    }
    fn apply_usage_correction<'a>(
        &'a self,
        request: &'a busbar_contract::records::correction::Request,
    ) -> StoreCall<'a, busbar_contract::records::correction::Decision> {
        self.actual.apply_usage_correction(request)
    }
    fn supports_record_transaction(&self) -> bool {
        self.actual.supports_record_transaction()
    }
    fn record_transaction<'a>(
        &'a self,
        request: &'a busbar_contract::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, busbar_contract::abi::sdk::store::conditional::Decision> {
        self.actual.record_transaction(request)
    }
    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.actual.add_usage_batch(op, cells)
    }
    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.actual.add_metering_batch(op, deltas)
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.actual.record_put(schema, key, value)
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if schema == "busbar.config.overlay.v1" {
            if self.fail.load(Ordering::SeqCst) {
                return Box::pin(std::future::ready(Err(StoreFailure::Failed(
                    "overlay read interrupted".into(),
                ))));
            }
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                self.started.store(true, Ordering::SeqCst);
                self.entered.notify_one();
                gate.recv_timeout(std::time::Duration::from_secs(6))
                    .expect("the actual read is released within its bound");
            }
        }
        self.actual.record_get(schema, key)
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.actual.record_scan(schema, prefix, limit)
    }
    fn put_key<'a>(&'a self, key: &'a busbar_contract::records::VirtualKey) -> StoreCall<'a, ()> {
        self.actual.put_key(key)
    }
    fn get_key<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreCall<'a, Option<busbar_contract::records::VirtualKey>> {
        self.actual.get_key(id)
    }
    fn list_keys(&self) -> StoreCall<'_, Vec<busbar_contract::records::VirtualKey>> {
        self.actual.list_keys()
    }
    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        self.actual.delete_key(id)
    }
    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a busbar_contract::records::VirtualKey,
        secret: &'a busbar_contract::records::CredentialSecret,
    ) -> StoreCall<'a, ()> {
        self.actual.put_key_with_credential(key, secret)
    }
    fn list_credentials<'a>(
        &'a self,
        key_id: &'a str,
    ) -> StoreCall<'a, Vec<busbar_contract::records::CredentialMeta>> {
        self.actual.list_credentials(key_id)
    }
    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.actual.revoke_credential(id, reason)
    }
    fn list_credentials_since(
        &self,
        since: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::CredentialSecret>> {
        self.actual.list_credentials_since(since)
    }
    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.actual.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        self.actual.list_denylist()
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::MeteringRow>> {
        self.actual.list_metering(bucket)
    }
    fn list_audit(&self) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.actual.list_audit()
    }
    fn list_audit_tail(
        &self,
        limit: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.actual.list_audit_tail(limit)
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.actual.upsert_plane_record(record)
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.actual.get_plane_record(kind, id)
    }
    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.actual.append_plane_record(op, record)
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.actual.list_plane_records(kind, selector)
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.actual.delete_plane_record(kind, id)
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.actual.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.actual.plane_token_live(kind, token, expires_at, now)
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        self.actual.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        self.actual.purge_plane_records_before(kind, before)
    }
    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        self.actual.purge_usage_before(before)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn list_named_defs_reads_the_overlay_off_the_async_worker() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let faults = Arc::new(OverlayReads {
        actual: calls,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let backend = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    let (release, gate) = std::sync::mpsc::channel::<()>();
    *faults.gate.lock().unwrap() = Some(gate);
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watching = faults.clone();
    let watchdog = std::thread::spawn(move || {
        let free = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        let _ = release.send(());
        free && watching.started.load(Ordering::SeqCst)
    });
    let waiting = faults.clone();
    let sibling = tokio::spawn(async move {
        waiting.entered.notified().await;
        let _ = done.send(());
    });
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let page: serde_json::Value = response.json().await.unwrap();
    assert!(page["items"].as_array().unwrap().is_empty(), "{page}");
    assert!(
        watchdog.join().unwrap(),
        "the overlay read parked the async worker after entering the actual Store call"
    );
    sibling.abort();
    let _ = sibling.await;
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn get_named_def_reads_the_overlay_off_the_async_worker() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let faults = Arc::new(OverlayReads {
        actual: calls,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let backend = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    let (release, gate) = std::sync::mpsc::channel::<()>();
    *faults.gate.lock().unwrap() = Some(gate);
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watching = faults.clone();
    let watchdog = std::thread::spawn(move || {
        let free = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        let _ = release.send(());
        free && watching.started.load(Ordering::SeqCst)
    });
    let waiting = faults.clone();
    let sibling = tokio::spawn(async move {
        waiting.entered.notified().await;
        let _ = done.send(());
    });
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}/absent"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "not_found");
    assert!(
        watchdog.join().unwrap(),
        "the overlay read parked the async worker after entering the actual Store call"
    );
    sibling.abort();
    let _ = sibling.await;
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn named_defs_still_flag_an_unparseable_overlay_entry() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let faults = Arc::new(OverlayReads {
        actual: calls,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let backend = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    busbar_kernel::config::overlay::persist_named_map(
        Some(&backend),
        busbar_kernel::config::named_map::NamedMapSection::Export,
        "broken",
        Some(&serde_json::json!({"no_such_field": true})),
    )
    .expect("the actual Store retains the unparseable definition");
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let page: serde_json::Value = response.json().await.unwrap();
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["broken"], "the unparseable overlay entry is listed");
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}/broken"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let one: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        one, page["items"][0],
        "the list and the single read give the one flagged view"
    );
    server.abort();
}

#[tokio::test]
async fn named_defs_propagate_store_overlay_read_failures() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let faults = Arc::new(OverlayReads {
        actual: calls,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let backend = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    faults.fail.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    for suffix in ["", "/absent"] {
        let response = client
            .get(format!("http://{addr}/api/v1/admin{root}{suffix}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400);
        let error: serde_json::Value = response.json().await.unwrap();
        assert_eq!(error["error"]["code"], "invalid_request");
    }
    server.abort();
}
