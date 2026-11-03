// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::*;
use busbar_kernel::config::groups::{LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

struct RecordReads {
    actual: Arc<dyn RecordStore>,
    started: Arc<tokio::sync::Notify>,
    word: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    heard: Arc<AtomicBool>,
    fail_metering: AtomicBool,
}
impl RecordStore for RecordReads {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.actual.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.actual.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.actual.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.actual.delete_key(id)
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.actual.list_keys_since(since)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        if let Some(word) = self.word.lock().unwrap().take() {
            self.started.notify_one();
            if word.recv_timeout(Duration::from_secs(5)).is_ok() {
                self.heard.store(true, Ordering::SeqCst);
            }
        }
        self.actual.get_usage(bucket_id, window_start)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.actual.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.actual.supports_usage_correction()
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.actual.put_usage(bucket_id, window_start, ledger)
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.actual.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.actual.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.actual.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.actual.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.actual.add_metering_batch_deduped(op, deltas)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.actual.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        if self.fail_metering.load(Ordering::SeqCst) {
            return Err(RecordStoreError("simulated metering store outage".into()));
        }
        self.actual.list_metering(bucket)
    }
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.actual.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.actual.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.actual.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.actual.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.actual.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.actual.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.actual.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.actual.list_audit()
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.actual.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.actual.list_denylist()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.actual.list_audit_tail(limit)
    }
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.actual.upsert_plane_record(record)
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.actual.get_plane_record(kind, id)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.actual.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.actual.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.actual.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.actual.purge_plane_records_before(kind, before)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.actual.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.actual.delete_plane_record(kind, id)
    }
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.actual.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.actual.plane_token_live(kind, token, expires_at, now)
    }
}

fn usage_group_cfg() -> GroupCfg {
    let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: pool.map(busbar_contract::records::ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    GroupCfg {
        limits: vec![
            limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
            limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
            limit(
                LimitMetric::Budget,
                500,
                LimitWindow::Month,
                Some("frontier"),
            ),
        ],
        ..Default::default()
    }
}

fn usage_cost(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
) -> busbar_kernel::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, groups)
}

#[tokio::test(flavor = "current_thread")]
async fn get_group_usage_reads_the_store_off_the_async_worker() {
    const CHILD: &str = "BUSBAR_SERVICE_RECORD_READ_CHILD";
    const WITNESS: &str = "actual Store read observations completed";
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
    let groups = BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
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
    let directory = plugins::scratch(&format!(
        "admin-service-group-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
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
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "rate_card": BTreeMap::from([("m", busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0, output_utok: 10.0, ..Default::default()
        })]),
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
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds the node book and rates");
    limits
        .keep()
        .expect("the product limits commit after the actual book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(usage_cost(&groups));
    app.groups_registry = groups;
    let actual = app.governance.as_ref().unwrap();
    let calls = actual.store_calls().expect("the actual Store calls");
    let started = Arc::new(tokio::sync::Notify::new());
    let heard = Arc::new(AtomicBool::new(false));
    let store = Arc::new(RecordReads {
        actual: actual.store(),
        started: started.clone(),
        word: std::sync::Mutex::new(None),
        heard: heard.clone(),
        fail_metering: AtomicBool::new(false),
    });
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(store.clone(), None, None)
            .expect("governance opens the actual delegated Store"),
    );
    assert!(gov.attach_store_calls(calls));
    app.governance = Some(gov);
    let (tell, word) = std::sync::mpsc::channel();
    *store.word.lock().unwrap() = Some(word);
    let sibling = tokio::spawn(async move {
        started.notified().await;
        let _ = tell.send(());
    });
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/api/v1/admin/groups/acme/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(heard.load(Ordering::SeqCst), "the group usage read held the async worker while the actual Store waited for its sibling task");
    sibling.abort();
    let _ = sibling.await;
    server.abort();
    println!("{WITNESS}");
}

#[tokio::test(flavor = "current_thread")]
async fn usage_read_store_failure_logs_the_real_error() {
    const CHILD: &str = "BUSBAR_SERVICE_RECORD_READ_CHILD";
    const WITNESS: &str = "actual Store read observations completed";
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
    let groups = BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
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
    let directory = plugins::scratch(&format!(
        "admin-service-group-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
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
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "rate_card": BTreeMap::from([("m", busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0, output_utok: 10.0, ..Default::default()
        })]),
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
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds the node book and rates");
    limits
        .keep()
        .expect("the product limits commit after the actual book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(usage_cost(&groups));
    app.groups_registry = groups;
    let actual = app.governance.as_ref().unwrap();
    let calls = actual.store_calls().expect("the actual Store calls");
    let started = Arc::new(tokio::sync::Notify::new());
    let heard = Arc::new(AtomicBool::new(false));
    let store = Arc::new(RecordReads {
        actual: actual.store(),
        started: started.clone(),
        word: std::sync::Mutex::new(None),
        heard: heard.clone(),
        fail_metering: AtomicBool::new(false),
    });
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(store.clone(), None, None)
            .expect("governance opens the actual delegated Store"),
    );
    assert!(gov.attach_store_calls(calls));
    app.governance = Some(gov);
    #[derive(Clone)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Captured(captured.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    store.fail_metering.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/api/v1/admin/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 500);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "internal");
    let messages = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        messages.contains("usage.metering") && messages.contains("simulated metering store outage"),
        "the real Store error and which read failed must be logged: {messages}"
    );
    server.abort();
    println!("{WITNESS}");
}
