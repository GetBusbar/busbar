// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use axum::http::StatusCode;
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::*;
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use busbar_kernel::governance::at_rest::{self, AtRestKeys};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[tokio::test]
async fn unchanged_admin_reload_retries_at_rest_maintenance_after_store_recovery() {
    const CHILD: &str = "BUSBAR_ADMIN_REWRAP_CHILD";
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
    for failure in ["listing", "claim"] {
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
        let dir = directory.clone();
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        let old_path = dir.join("old-at-rest.key");
        let new_path = dir.join("new-at-rest.key");
        std::fs::write(&old_path, [3_u8; 32]).unwrap();
        std::fs::write(&new_path, [4_u8; 32]).unwrap();
        let mut disk = document.clone();
        disk["plugins"] = serde_json::json!({"enabled": true, "dir": directory.to_string_lossy()});
        disk["credentials"] = serde_json::json!({"at_rest": {"key": {"file": new_path}, "previous": {"file": old_path}}});
        std::fs::write(&config_path, serde_yaml::to_string(&disk).unwrap()).unwrap();
        std::fs::write(&providers_path, "{}\n").unwrap();
        let calls = app
            .governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("the actual Store calls");
        let store = RewrapStore::new(app.governance.as_ref().unwrap().store());
        store
            .inner
            .put_key(&VirtualKey {
                id: "rewrap-owner".into(),
                generation_hash: "binding:rewrap-owner:0".into(),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let meta = CredentialMeta {
            id: "rewrap-credential".into(),
            key_id: "rewrap-owner".into(),
            kind: "signed-request".into(),
            slot: 0,
            public_id: "rewrap-public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        };
        let old_keys = AtRestKeys::new(&[3_u8; 32], None);
        store
            .inner
            .put_credential(&CredentialSecret {
                secret: old_keys.seal(&meta, b"recoverable-test-secret").unwrap(),
                meta,
            })
            .unwrap();
        let actual_plugins = app.plugins_cfg.clone();
        drop(app);
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual config resolves");
        let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            actual_plugins,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(calls.clone()),
            }),
            false,
        )
        .expect("normal composition uses the precise actual-Store record fault wrapper");
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
        app.config_path = Some(config_path);
        app.providers_path = Some(providers_path);
        let gov = app.governance.as_ref().unwrap().clone();
        crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 93);
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("actual rate history boots");
        let overlay_faults = RewrapOverlayFaults::new(calls);
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(overlay_faults.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) =
            busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let client = reqwest::Client::new();
        store
            .fail_listing
            .store(failure == "listing", Ordering::SeqCst);
        store.deny_claim.store(failure == "claim", Ordering::SeqCst);
        let first = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "{failure}: first reload commits even with maintenance debt"
        );
        let pending = store.inner.list_credentials_since(0).unwrap().remove(0);
        assert_eq!(at_rest::sealed_kid(&pending.secret), Some(old_keys.kid()));
        let current_keys = AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32]));
        assert_eq!(
            at_rest::open(Some(&current_keys), &pending.meta, &pending.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );
        let calls = store.listings.load(Ordering::SeqCst);
        store.fail_listing.store(false, Ordering::SeqCst);
        store.deny_claim.store(false, Ordering::SeqCst);
        let second = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK, "{failure}: retry reload");
        assert!(
            store.listings.load(Ordering::SeqCst) > calls,
            "{failure}: unchanged kids must still retry the Store"
        );
        let sealed = store.inner.list_credentials_since(0).unwrap().remove(0);
        assert_eq!(
            at_rest::sealed_kid(&sealed.secret),
            Some(current_keys.kid())
        );
        assert_eq!(
            at_rest::open(Some(&current_keys), &sealed.meta, &sealed.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );

        std::fs::write(&new_path, [5_u8; 32]).unwrap();
        overlay_faults.fail_writes.store(true, Ordering::SeqCst);
        let before = handle.load();
        let calls = store.listings.load(Ordering::SeqCst);
        let rejected = client
            .put(format!("http://{addr}/api/v1/admin/config/settings"))
            .json(&serde_json::json!({"limits": {"request_body_max_bytes": 5000123}}))
            .send()
            .await
            .unwrap();
        assert!(!rejected.status().is_success());
        let rejected_body = rejected.bytes().await.unwrap();
        let rejected_text = std::str::from_utf8(&rejected_body).unwrap();
        assert!(
            rejected_text.contains("persistence to the overlay was not confirmed"),
            "{rejected_text}"
        );
        assert!(Arc::ptr_eq(&before, &handle.load()));

        assert!(!gov.set_at_rest_keys(Some(AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32])))));
        assert_eq!(
            store.listings.load(Ordering::SeqCst),
            calls,
            "rejected commit does not run credential maintenance"
        );
        server.abort();
        let _ = std::fs::remove_dir_all(dir);
    }
    println!("{WITNESS}");
}
struct RewrapStore {
    inner: Arc<dyn RecordStore>,
    fail_listing: AtomicBool,
    deny_claim: AtomicBool,
    listings: AtomicUsize,
}
impl RewrapStore {
    fn new(inner: Arc<dyn RecordStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_listing: AtomicBool::new(false),
            deny_claim: AtomicBool::new(false),
            listings: AtomicUsize::new(0),
        })
    }
}
impl RecordStore for RewrapStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
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
        self.listings.fetch_add(1, Ordering::SeqCst);
        if self.fail_listing.load(Ordering::SeqCst) {
            return Err(RecordStoreError("planted credential listing outage".into()));
        }
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
        if self.deny_claim.load(Ordering::SeqCst) {
            return Ok(false);
        }
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
// Narrow faults around the actual configured Store. Every unaffected operation delegates.
struct RewrapOverlayFaults {
    inner: Arc<dyn StoreCalls>,
    fail_writes: AtomicBool,
}
impl RewrapOverlayFaults {
    fn new(inner: Arc<dyn StoreCalls>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_writes: AtomicBool::new(false),
        })
    }
}
impl StoreCalls for RewrapOverlayFaults {
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
        if self.fail_writes.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StoreFailure::Refused(
                    "planted overlay conditional refusal".into(),
                ))
            });
        }
        self.inner.record_transaction(request)
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
