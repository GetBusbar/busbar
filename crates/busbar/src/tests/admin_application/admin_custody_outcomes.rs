// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use busbar_contract::records::*;
use busbar_kernel::state::AppHandle;
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::test_common as common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[derive(Default)]
struct Pause {
    entered: Notify,
    released: Mutex<bool>,
    resume: Condvar,
}

impl Pause {
    fn wait(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.resume.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.resume.notify_all();
    }
}

struct ReleaseOnDrop(Arc<Pause>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Store {
    inner: Arc<dyn RecordStore>,
    pause_write: AtomicBool,
    write: Arc<Pause>,
    claimed: Notify,
    settled: Notify,
    fail_read: AtomicBool,
    fail_delete: AtomicBool,
    lose_write_reply: AtomicBool,
    fail_refresh_after_write: AtomicBool,
    fail_list: AtomicBool,
    refuse_write_with_applied_text: AtomicBool,
}

impl Store {
    fn new(inner: Arc<dyn RecordStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            pause_write: AtomicBool::new(false),
            write: Arc::new(Pause::default()),
            claimed: Notify::new(),
            settled: Notify::new(),
            fail_read: AtomicBool::new(false),
            fail_delete: AtomicBool::new(false),
            lose_write_reply: AtomicBool::new(false),
            fail_refresh_after_write: AtomicBool::new(false),
            fail_list: AtomicBool::new(false),
            refuse_write_with_applied_text: AtomicBool::new(false),
        })
    }
}

impl RecordStore for Store {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        if self.refuse_write_with_applied_text.load(Ordering::SeqCst) {
            return Err(RecordStoreError(
                "MINT APPLIED (new secret not returned): untrusted Store error text".into(),
            ));
        }
        if self.pause_write.swap(false, Ordering::SeqCst) {
            self.write.wait();
        }
        self.inner.put_key(key)?;
        if self.fail_refresh_after_write.load(Ordering::SeqCst) {
            self.fail_list.store(true, Ordering::SeqCst);
        }
        if self.lose_write_reply.load(Ordering::SeqCst) {
            return Err(RecordStoreError(
                "reply lost after committed key write".into(),
            ));
        }
        Ok(())
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        if self.fail_read.load(Ordering::SeqCst) {
            return Err(RecordStoreError("key read unavailable".into()));
        }
        self.inner.get_key(id)
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        if self.fail_list.load(Ordering::SeqCst) {
            return Err(RecordStoreError("private refresh failure detail".into()));
        }
        self.inner.list_keys()
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(RecordStoreError("delete unavailable".into()));
        }
        self.inner.delete_key(id)
    }

    fn get_usage(&self, id: &str, start: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, start)
    }

    fn put_usage(&self, id: &str, start: u64, ledger: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, start, ledger)
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        let result = self.inner.redeem_plane_token(kind, token, expires_at, now);
        if kind == busbar_core_admin::idempotency::durable::REPLAY_KIND {
            self.claimed.notify_one();
        }
        result
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let replay = record.kind == busbar_core_admin::idempotency::durable::REPLAY_KIND;
        self.inner.upsert_plane_record(record)?;
        if replay {
            self.settled.notify_one();
        }
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys_since(since)
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
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.inner.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.inner.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.inner.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.inner.list_plane_record_parents(kind)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

// Each ordinary case runs one production root in its own process because the
// node book and rate-card authority are process-owned.
fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_CUSTODY_OUTCOME_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current().name().unwrap().to_string();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let until = std::time::Instant::now() + Duration::from_secs(120);
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
                "actual custody child failed: {status}: {output}"
            );
            assert!(
                output.contains("custody assertions completed"),
                "missing actual custody completion witness: {output}"
            );
            return true;
        }
        assert!(
            std::time::Instant::now() < until,
            "actual custody child timed out"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn app() -> (
    Arc<Store>,
    Arc<AppHandle>,
    axum::Router,
    crate::root::durability::NodeBook,
) {
    busbar_kernel::snapshot::init_for_test(Duration::from_secs(3600));
    crate::dist_root_install::install();
    let library = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("actual built Store artifact"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .unwrap()
        .unwrap();
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .unwrap()
        .name;
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("admin-custody-outcomes");
    let archive = plugins::signed(
        &plugins::key(0x33),
        manifest,
        &std::fs::read(library).unwrap(),
    );
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let settings: Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .unwrap();
    assert!(settings.is_object());
    let oidc_path = common::plugins::token_verifier_cdylib_path().expect("actual OIDC artifact");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .unwrap()
        .unwrap();
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .unwrap()
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "custody-auth", false);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32])).unwrap();
    let deploy=busbar_kernel::config::deploy_from_deserializer(json!({
        "providers":{},"models":{},
        "identity-providers":{"custody-auth":{"module":oidc_module,"max_admin_scope":"full","settings":common::credentials::settings("api://admin-custody")}},
        "auth":{"chain":[],"admin_auth":["custody-auth"],"signing_key":{"file":signing},"role_bindings":{"custody-auth":{"custodians":{"admin_scope":"full"}}}},
        "store":{"module":module,"settings":settings},"advanced":{"allow_destinations":["127.0.0.1"]}
    })).unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "http://127.0.0.1:9/store.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
        });
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config).unwrap();
    let store = Store::new(anchor.records);
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: anchor.calls,
    };
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(anchor.calls.as_ref().unwrap().clone())
            .unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .unwrap();
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module).unwrap();
    limits.keep().unwrap();
    if let Some(rotate) = rotate {
        rotate();
    }
    let (router, handle) =
        busbar_kernel::build_router_with_limits(Arc::new(app), 1 << 20, 0, false);
    (store, handle, router, book)
}

async fn request(
    router: axum::Router,
    method: &'static str,
    path: String,
    actor: &'static str,
    token: Option<&'static str>,
    value: Value,
) -> axum::response::Response {
    let credential = common::credentials::token_for(actor, &["custodians"], "api://admin-custody");
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(format!("/api/v1/admin/keys{path}"))
        .header("authorization", format!("Bearer {credential}"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("idempotency-key", token);
    }
    tower::ServiceExt::oneshot(
        router,
        request
            .body(axum::body::Body::from(value.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn mint(
    router: axum::Router,
    actor: &'static str,
    token: &'static str,
) -> axum::response::Response {
    request(
        router,
        "POST",
        String::new(),
        actor,
        Some(token),
        json!({"name":actor}),
    )
    .await
}

// Same production create-key framing, retained here as an explicit boundary
// assertion without widening the crate-private convenience function.
fn create_replay_key(header: &str) -> String {
    format!("create:{}:{}", header.len(), header)
}

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn signal(notify: &Notify) {
    tokio::time::timeout(Duration::from_secs(10), notify.notified())
        .await
        .expect("the operation must finish after its blocked store is released");
}

fn audit_rows(actor: &str, action: &str, outcome: &str) -> usize {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(
            0,
            busbar_kernel::audit_ring::MAX_AUDIT_ENTRIES,
            Some(action),
            None,
        )
        .iter()
        .filter(|entry| entry.principal == format!("oidc:{actor}") && entry.outcome == outcome)
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_mint_finishes_replay_and_durable_settlement() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(mint(router.clone(), "custody:mint", "mint"));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;

    let response = mint(router.clone(), "custody:mint", "mint").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let answer = body(response).await;
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    assert_eq!(store.inner.list_keys().unwrap()[0].id, answer["id"]);
    assert_eq!(audit_rows("custody:mint", "key.create", "applied"), 1);
    assert!(matches!(
        busbar_core_admin::idempotency::durable::claim(
            &*store,
            &("oidc:custody:mint".into(), create_replay_key("mint")),
            busbar_kernel::store::now(),
        ),
        Err(busbar_core_admin::idempotency::durable::Refused::Applied(_))
    ));
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_mint_queued_behind_config_write_still_settles() {
    if isolated() {
        return;
    }
    use busbar_kernel::config::transaction::{config_transaction, Outcome};
    let (store, handle, router, _book) = app();
    let pause = Arc::new(Pause::default());
    let release = ReleaseOnDrop(pause.clone());
    let transaction_handle = handle.clone();
    let blocked = pause.clone();
    let holder = tokio::spawn(async move {
        config_transaction::<_, _, busbar_core_admin::v1::contract::AdminError>(
            &transaction_handle,
            move |txn| {
                Ok(txn.store_write(move || {
                    blocked.wait();
                    Ok(Outcome::Value(()))
                }))
            },
        )
        .await
    });
    signal(&pause.entered).await;
    let caller = tokio::spawn(mint(router.clone(), "custody:queued", "queued"));
    signal(&store.claimed).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    holder.await.unwrap().unwrap();
    signal(&store.settled).await;
    let response = mint(router.clone(), "custody:queued", "queued").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    assert_eq!(audit_rows("custody:queued", "key.create", "applied"), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_rotate_finishes_replay_without_a_second_generation() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    let seeded = body(mint(router.clone(), "custody:rotate-seed", "seed").await).await;
    signal(&store.settled).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate",
        Some("rotate"),
        Value::Null,
    ));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;
    let generation = store.inner.get_key(&id).unwrap().unwrap().generation_hash;
    let response = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate",
        Some("rotate"),
        Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(body(response).await["token"], seeded["token"]);
    assert_eq!(
        store.inner.get_key(&id).unwrap().unwrap().generation_hash,
        generation
    );
    assert_eq!(audit_rows("custody:rotate", "key.rotate", "applied"), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_mutation_store_failures_each_record_a_refusal() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    let seeded = body(mint(router.clone(), "custody:errors-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_read.store(true, Ordering::SeqCst);
    let update = request(
        router.clone(),
        "PATCH",
        format!("/{id}"),
        "custody:patch-error",
        None,
        json!({"enabled":false}),
    )
    .await;
    let rotate = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate-error",
        None,
        Value::Null,
    )
    .await;
    let revoke = request(
        router.clone(),
        "POST",
        format!("/{id}/revoke"),
        "custody:revoke-error",
        None,
        Value::Null,
    )
    .await;
    let delete = request(
        router.clone(),
        "DELETE",
        format!("/{id}"),
        "custody:delete-error",
        None,
        Value::Null,
    )
    .await;
    for (actor, action, response) in [
        ("custody:patch-error", "key.patch", update),
        ("custody:rotate-error", "key.rotate", rotate),
        ("custody:revoke-error", "key.revoke", revoke),
        ("custody:delete-error", "key.delete", delete),
    ] {
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(audit_rows(actor, action, "rejected"), 1);
        assert_eq!(audit_rows(actor, action, "applied"), 0);
    }
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_delete_records_the_revocation_that_already_applied() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    let seeded = body(mint(router.clone(), "custody:delete-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_delete.store(true, Ordering::SeqCst);
    let response = request(
        router.clone(),
        "DELETE",
        format!("/{id}"),
        "custody:partial-delete",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let key = store.inner.get_key(&id).unwrap().unwrap();
    assert!(!key.enabled);
    assert!(key.deleted_at.is_none());
    assert!(store.inner.list_denylist().unwrap().contains(&id));
    assert_eq!(
        audit_rows("custody:partial-delete", "key.revoke", "applied"),
        1
    );
    assert_eq!(
        audit_rows("custody:partial-delete", "key.delete", "rejected"),
        1
    );
    assert_eq!(
        audit_rows("custody:partial-delete", "key.delete", "applied"),
        0
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_mint_reply_does_not_release_a_committed_claim() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = mint(router.clone(), "custody:lost-mint", "lost").await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    store.lose_write_reply.store(false, Ordering::SeqCst);
    let retry = mint(router.clone(), "custody:lost-mint", "lost").await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_rotate_reply_does_not_release_a_committed_claim() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    let seeded = body(mint(router.clone(), "custody:lost-rotate-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:lost-rotate",
        Some("lost"),
        Value::Null,
    )
    .await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let generation = store.inner.get_key(&id).unwrap().unwrap().generation_hash;
    store.lose_write_reply.store(false, Ordering::SeqCst);
    let retry = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:lost-rotate",
        Some("lost"),
        Value::Null,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.inner.get_key(&id).unwrap().unwrap().generation_hash,
        generation
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_mint_refresh_failure_is_truthful_and_same_idempotency_cannot_mint_again() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    store.fail_refresh_after_write.store(true, Ordering::SeqCst);
    let response = mint(router.clone(), "custody:applied-refresh", "applied-refresh").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let answer = body(response).await;
    let rows = store.inner.list_keys().unwrap();
    assert_eq!(rows.len(), 1);
    let id = &rows[0].id;
    let text = answer.to_string();
    assert!(
        text.contains("MINT APPLIED (new secret not returned)"),
        "{text}"
    );
    assert!(text.contains(id));
    assert!(!text.contains("private refresh failure detail"));
    assert!(answer.get("token").is_none());
    assert!(answer.get("aws_secret_access_key").is_none());
    assert_eq!(
        audit_rows("custody:applied-refresh", "key.create", "applied"),
        1
    );
    assert_eq!(
        audit_rows("custody:applied-refresh", "key.create", "rejected"),
        0
    );
    assert!(matches!(busbar_core_admin::idempotency::durable::claim(
        &*store,
        &("oidc:custody:applied-refresh".into(), create_replay_key("applied-refresh")),
        busbar_kernel::store::now(),
    ), Err(busbar_core_admin::idempotency::durable::Refused::Applied(what)) if what == format!("key:{id}")));
    store.fail_list.store(false, Ordering::SeqCst);
    store
        .fail_refresh_after_write
        .store(false, Ordering::SeqCst);
    // A new response cache forces this retry to consult the actual Store's durable
    // receipt. The previous process-local response must not mask a missing settlement.
    let fresh_cache = Arc::new(busbar_core_admin::keys::KeyReplayCache::new());
    let retry = mint(
        router.clone().layer(axum::Extension(fresh_cache)),
        "custody:applied-refresh",
        "applied-refresh",
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(body(retry).await.to_string().contains("already ran"));
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_store_error_cannot_spoof_the_typed_committed_mint_outcome() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app();
    store
        .refuse_write_with_applied_text
        .store(true, Ordering::SeqCst);
    let response = mint(router.clone(), "custody:spoofed-applied", "spoofed-applied").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let answer = body(response).await;
    assert!(!answer.to_string().contains("MINT APPLIED"));
    assert!(store.inner.list_keys().unwrap().is_empty());
    assert_eq!(
        audit_rows("custody:spoofed-applied", "key.create", "applied"),
        0
    );
    assert!(matches!(
        busbar_core_admin::idempotency::durable::claim(
            &*store,
            &(
                "oidc:custody:spoofed-applied".into(),
                create_replay_key("spoofed-applied")
            ),
            busbar_kernel::store::now(),
        ),
        Err(busbar_core_admin::idempotency::durable::Refused::InFlight)
    ));
    println!("custody assertions completed");
}
