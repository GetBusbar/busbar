// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

use busbar_contract::{
    abi::store::OpId,
    kinds::RecordBytes,
    records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta},
    store_calls::{StoreCall, StoreCalls, StoreFailure},
};
use std::sync::atomic::{AtomicBool, Ordering};
struct OverlayWriteOutage {
    actual: Arc<dyn StoreCalls>,
    armed: AtomicBool,
    failures: std::sync::atomic::AtomicUsize,
}
impl StoreCalls for OverlayWriteOutage {
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
        if schema == "busbar.config.overlay.v1" && self.armed.load(Ordering::SeqCst) {
            self.failures.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Err(StoreFailure::Failed(
                "the planted overlay-write outage".into(),
            ))))
        } else {
            self.actual.record_put(schema, key, value)
        }
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
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

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_install_limits() {
    const CHILD: &str = "BUSBAR_ADMIN_PERSIST_8E706DEE46E0";
    const WITNESS: &str =
        "actual root case test_admin_v1_config_settings_persist_failure_does_not_install_limits completed";
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
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
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
        "test_admin_v1_config_settings_persist_failure_does_not_install_limits-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
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
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let outage = Arc::new(OverlayWriteOutage {
        actual: anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the real Store exposes typed calls"),
        armed: AtomicBool::new(false),
        failures: std::sync::atomic::AtomicUsize::new(0),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: anchor.records,
        calls: Some(outage.clone()),
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    outage.armed.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let before = busbar_kernel::config::limits::installed();

    let rejected_cap: usize = 7_654_321;
    let put = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "limits": { "request_body_max_bytes": rejected_cap } }).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    let after = busbar_kernel::config::limits::installed();
    assert_ne!(
        after.as_ref().map(|l| l.request_body_max_bytes),
        Some(rejected_cap),
        "a persist failure must leave the REJECTED config's limits uninstalled — the response just \
         claimed nothing was changed, and these are process-wide values the old (still-serving) App \
         reads through"
    );
    assert_eq!(
        after.map(|l| l.request_body_max_bytes),
        before.map(|l| l.request_body_max_bytes),
        "the limits installed before the rejected apply are the ones still installed after it"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        outage.failures.load(Ordering::SeqCst) > 0,
        "the rejection must cross the planted real Store overlay write failure"
    );
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials() {
    const CHILD: &str = "BUSBAR_ADMIN_PERSIST_5FD5D7D51822";
    const WITNESS: &str =
        "actual root case test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials completed";
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
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
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
        plugins::scratch("test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let token_path = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&token_path, "admintok-v1").expect("write the test operator input");
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
        "module": operator, "token": { "file": token_path },
    });
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let outage = Arc::new(OverlayWriteOutage {
        actual: anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the real Store exposes typed calls"),
        armed: AtomicBool::new(false),
        failures: std::sync::atomic::AtomicUsize::new(0),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: anchor.records,
        calls: Some(outage.clone()),
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    let gov = app
        .governance
        .as_ref()
        .expect("actual root governance")
        .clone();
    let before_hash = gov.admin_token_hash();
    outage.armed.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::fs::write(&token_path, "admintok-v2").unwrap();

    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok-v1")
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    assert_eq!(
        gov.admin_token_hash(),
        before_hash,
        "a persist failure must leave the shared GovState's admin-token digest untouched — the \
         response just claimed nothing was changed, and this is the process-lifetime object the \
         OLD (still-serving) App snapshot also points at"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        outage.failures.load(Ordering::SeqCst) > 0,
        "the rejection must cross the planted real Store overlay write failure"
    );
    let _ = handle.await;
    println!("{WITNESS}");
}
