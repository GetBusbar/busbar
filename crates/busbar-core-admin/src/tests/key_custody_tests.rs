use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Extension;
use busbar_contract::records::*;
use busbar_kernel::auth::AuthPrincipal;
use busbar_kernel::governance::GovState;
use busbar_kernel::state::{AppHandle, CurrentApp};
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use serde_json::{json, Value};
use tokio::sync::Notify;

use super::{create_key, delete_key, revoke_key, rotate_key, update_key, KeyReplayCache};

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
    inner: MemoryStore,
    pause_write: AtomicBool,
    write: Arc<Pause>,
    claimed: Notify,
    settled: Notify,
    fail_read: AtomicBool,
    fail_delete: AtomicBool,
    lose_write_reply: AtomicBool,
}

impl Store {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStore::new(),
            pause_write: AtomicBool::new(false),
            write: Arc::new(Pause::default()),
            claimed: Notify::new(),
            settled: Notify::new(),
            fail_read: AtomicBool::new(false),
            fail_delete: AtomicBool::new(false),
            lose_write_reply: AtomicBool::new(false),
        })
    }
}

impl RecordStore for Store {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        if self.pause_write.swap(false, Ordering::SeqCst) {
            self.write.wait();
        }
        self.inner.put_key(key)?;
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
        self.claimed.notify_one();
        result
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)?;
        self.settled.notify_one();
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
}

fn app(store: Arc<Store>) -> Arc<AppHandle> {
    busbar_kernel_testkit::test_support::metrics::init();
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[7; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(GovState::new_with_signer(store, None, Some(signer)).unwrap());
    Arc::new(AppHandle::new(
        crate::new_test_app().governance(gov).build(),
    ))
}

fn principal(actor: &str) -> AuthPrincipal {
    AuthPrincipal(Some(busbar_contract::auth::Principal::from_id(actor)))
}

fn headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", token.parse().unwrap());
    headers
}

async fn mint(
    handle: Arc<AppHandle>,
    cache: Arc<KeyReplayCache>,
    actor: &'static str,
    token: &'static str,
) -> axum::response::Response {
    create_key(
        State(handle),
        Extension(principal(actor)),
        headers(token),
        Extension(cache),
        Bytes::from(json!({"name": actor}).to_string()),
    )
    .await
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
        .filter(|entry| entry.principal == actor && entry.outcome == outcome)
        .count()
}

#[tokio::test]
async fn abandoned_mint_finishes_replay_and_durable_settlement() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(mint(handle.clone(), cache.clone(), "custody:mint", "mint"));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;

    let response = mint(handle, cache, "custody:mint", "mint").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let answer = body(response).await;
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    assert_eq!(store.inner.list_keys().unwrap()[0].id, answer["id"]);
    assert_eq!(audit_rows("custody:mint", "key.create", "applied"), 1);
    assert!(matches!(
        crate::idempotency::durable::claim(
            &*store,
            &(
                "custody:mint".into(),
                crate::idempotency::create_replay_key("mint")
            ),
            busbar_kernel::store::now(),
        ),
        Err(crate::idempotency::durable::Refused::Applied(_))
    ));
}

#[tokio::test]
async fn abandoned_mint_queued_behind_config_write_still_settles() {
    use busbar_kernel::config::transaction::{config_transaction, Outcome};
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    let pause = Arc::new(Pause::default());
    let release = ReleaseOnDrop(pause.clone());
    let transaction_handle = handle.clone();
    let blocked = pause.clone();
    let holder = tokio::spawn(async move {
        config_transaction::<_, _, crate::v1::contract::AdminError>(
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
    let caller = tokio::spawn(mint(
        handle.clone(),
        cache.clone(),
        "custody:queued",
        "queued",
    ));
    signal(&store.claimed).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    holder.await.unwrap().unwrap();
    signal(&store.settled).await;
    let response = mint(handle, cache, "custody:queued", "queued").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    assert_eq!(audit_rows("custody:queued", "key.create", "applied"), 1);
}

#[tokio::test]
async fn abandoned_rotate_finishes_replay_without_a_second_generation() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    let seeded =
        body(mint(handle.clone(), cache.clone(), "custody:rotate-seed", "seed").await).await;
    signal(&store.settled).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(rotate_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:rotate")),
        Path(id.clone()),
        headers("rotate"),
        Extension(cache.clone()),
    ));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;
    let generation = store.inner.get_key(&id).unwrap().unwrap().generation_hash;
    let response = rotate_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:rotate")),
        Path(id.clone()),
        headers("rotate"),
        Extension(cache),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(body(response).await["token"], seeded["token"]);
    assert_eq!(
        store.inner.get_key(&id).unwrap().unwrap().generation_hash,
        generation
    );
    assert_eq!(audit_rows("custody:rotate", "key.rotate", "applied"), 1);
}

#[tokio::test]
async fn key_mutation_store_failures_each_record_a_refusal() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    let seeded =
        body(mint(handle.clone(), cache.clone(), "custody:errors-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_read.store(true, Ordering::SeqCst);
    let update = update_key(
        State(handle.clone()),
        Extension(principal("custody:patch-error")),
        Path(id.clone()),
        HeaderMap::new(),
        Bytes::from_static(b"{\"enabled\":false}"),
    )
    .await;
    let rotate = rotate_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:rotate-error")),
        Path(id.clone()),
        HeaderMap::new(),
        Extension(cache),
    )
    .await;
    let revoke = revoke_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:revoke-error")),
        Path(id.clone()),
    )
    .await;
    let delete = delete_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:delete-error")),
        Path(id),
        HeaderMap::new(),
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
}

#[tokio::test]
async fn failed_delete_records_the_revocation_that_already_applied() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    let seeded = body(mint(handle.clone(), cache, "custody:delete-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_delete.store(true, Ordering::SeqCst);
    let response = delete_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:partial-delete")),
        Path(id.clone()),
        HeaderMap::new(),
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
}

#[tokio::test]
async fn lost_mint_reply_does_not_release_a_committed_claim() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = mint(handle.clone(), cache.clone(), "custody:lost-mint", "lost").await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
    store.lose_write_reply.store(false, Ordering::SeqCst);
    let retry = mint(handle, cache, "custody:lost-mint", "lost").await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(store.inner.list_keys().unwrap().len(), 1);
}

#[tokio::test]
async fn lost_rotate_reply_does_not_release_a_committed_claim() {
    let store = Store::new();
    let handle = app(store.clone());
    let cache = Arc::new(KeyReplayCache::new());
    let seeded = body(
        mint(
            handle.clone(),
            cache.clone(),
            "custody:lost-rotate-seed",
            "seed",
        )
        .await,
    )
    .await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = rotate_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:lost-rotate")),
        Path(id.clone()),
        headers("lost"),
        Extension(cache.clone()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let generation = store.inner.get_key(&id).unwrap().unwrap().generation_hash;
    store.lose_write_reply.store(false, Ordering::SeqCst);
    let retry = rotate_key(
        CurrentApp(handle.load()),
        Extension(principal("custody:lost-rotate")),
        Path(id.clone()),
        headers("lost"),
        Extension(cache),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.inner.get_key(&id).unwrap().unwrap().generation_hash,
        generation
    );
}
