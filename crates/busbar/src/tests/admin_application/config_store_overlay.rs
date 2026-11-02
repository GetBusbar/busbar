// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

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

    for failure in ["read", "corrupt", "newer"] {
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
            "groups": {"security_team": {}},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        });
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
        // Only preservation is observed; this inert negative hook metadata never executes.
        app.hook_registry.insert(
            "security_gate".into(),
            serde_json::from_value(serde_json::json!({
                "kind": "gate", "module": "test-hook", "global": true,
            }))
            .unwrap(),
        );
        let calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .store_calls()
            .expect("actual Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual rate history boots in the configured Store");
        let faults = OverlayFaults::new(calls);
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let client = reqwest::Client::new();
        let before = handle.load();
        match failure {
            "read" => faults.fail_reads.store(true, Ordering::SeqCst),
            "corrupt" => {
                faults
                    .inner
                    .record_put(
                        "busbar.config.overlay.v1",
                        b"head",
                        &RecordBytes::new(b"{ not json".to_vec()).unwrap(),
                    )
                    .await
                    .unwrap();
            }
            "newer" => {
                let mut doc = busbar_kernel::config::overlay::OverlayDoc::default();
                doc.version = busbar_kernel::config::overlay::OVERLAY_VERSION + 1;
                busbar_kernel::config::overlay::write(&overlay, &doc).unwrap();
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
    println!("{WITNESS}");
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
        "groups": {"persisted_team": {}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
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
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
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
        .expect("the actual rate history boots in the configured Store");
    let faults = OverlayFaults::new(calls);
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
        .expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
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

    for unknown in [false, true] {
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
        let calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .store_calls()
            .expect("actual Store calls");
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 91);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual rate history boots in the configured Store");
        let faults = OverlayFaults::new(calls);
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(faults.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
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
        let durable = overlay.read_required().unwrap();
        assert_eq!(
            durable.is_some_and(|doc| doc.groups.contains_key("candidate_team")),
            unknown,
            "only the unknown-outcome case applied the Store write"
        );
        server.abort();
    }
    println!("{WITNESS}");
}
// Narrow faults around the actual configured Store. Every unaffected operation delegates.
struct OverlayFaults {
    inner: Arc<dyn StoreCalls>,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
    lose_reply: AtomicBool,
    block_read: std::sync::Mutex<Option<Arc<std::sync::Barrier>>>,
    requests: std::sync::Mutex<Vec<busbar_contract::abi::sdk::store::conditional::Request>>,
}
impl OverlayFaults {
    fn new(inner: Arc<dyn StoreCalls>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_reads: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
            lose_reply: AtomicBool::new(false),
            block_read: std::sync::Mutex::new(None),
            requests: Default::default(),
        })
    }
}
impl StoreCalls for OverlayFaults {
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
        self.requests.lock().unwrap().push(request.clone());
        if self.fail_writes.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StoreFailure::Refused(
                    "planted overlay conditional refusal".into(),
                ))
            });
        }
        let lose = self.lose_reply.swap(false, Ordering::SeqCst);
        Box::pin(async move {
            let result = self.inner.record_transaction(request).await;
            if lose && result.is_ok() {
                Err(StoreFailure::Failed(
                    "planted lost commit reply after actual Store commit".into(),
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
        if self.fail_writes.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StoreFailure::Refused(
                    "planted overlay write refusal".into(),
                ))
            });
        }
        self.inner.record_put(schema, key, value)
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StoreFailure::Failed("planted overlay read outage".into()))
            });
        }
        if let Some(barrier) = self.block_read.lock().unwrap().take() {
            barrier.wait();
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
