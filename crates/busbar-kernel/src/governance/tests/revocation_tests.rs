// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::MemoryStore;
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::time::Duration;

struct HungDenylistStore {
    inner: MemoryStore,

    entered: mpsc::Sender<()>,

    entries: Arc<AtomicUsize>,
}
impl RecordStore for HungDenylistStore {
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(());

        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    fn put_key(&self, k: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(k)
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
    fn get_usage(&self, id: &str, w: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_usage(&self, id: &str, w: u64, d: &UsageDelta) -> RecordStoreResult<()> {
        self.inner.add_usage(id, w, d)
    }
    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, b: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(b)
    }
    fn append_audit(&self, e: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(e)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
}

struct BrokenDenylistStore {
    inner: MemoryStore,
    calls: Arc<AtomicUsize>,
}
impl RecordStore for BrokenDenylistStore {
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(busbar_contract::records::RecordStoreError(
            "connection refused".into(),
        ))
    }
    fn put_key(&self, k: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(k)
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
    fn get_usage(&self, id: &str, w: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_usage(&self, id: &str, w: u64, d: &UsageDelta) -> RecordStoreResult<()> {
        self.inner.add_usage(id, w, d)
    }
    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, b: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(b)
    }
    fn append_audit(&self, e: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(e)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
}

#[test]
fn a_hung_store_does_not_park_the_reactor() {
    let (tx, entered) = mpsc::channel();
    let entries = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(HungDenylistStore {
        inner: MemoryStore::new(),
        entered: tx,
        entries: entries.clone(),
    });

    let rev = RevocationSync::new(store, HashSet::new(), 0);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    let rt = {
        let handle = rt.handle().clone();
        std::mem::forget(rt);
        handle
    };

    {
        let rev = rev.clone();
        rt.spawn(async move {
            rev.refresh_if_stale(REVOCATION_SYNC_TTL_SECS * 100);

            let _ = rev.contains("vk_whoever");
        });
    }
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the store read must actually have been started");

    let (ptx, probe) = mpsc::channel();
    rt.spawn(async move {
        let _ = ptx.send("healthz ok");
    });
    let served = probe.recv_timeout(Duration::from_secs(5));
    assert!(
        matches!(served, Ok("healthz ok")),
        "the runtime must keep serving while a store read is outstanding; a worker is parked \
             inside the store (got {served:?})"
    );

    for window in 200..210u64 {
        rev.refresh_if_stale(REVOCATION_SYNC_TTL_SECS * window);

        rev.refresh_if_stale_at(0, REVOCATION_SYNC_TTL_SECS * 1_000 * window);
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        entries.load(Ordering::SeqCst),
        1,
        "at most ONE store read may ever be outstanding: a store that never answers must cost \
             exactly one blocking-pool thread, not one per staleness window"
    );
}

#[test]
fn a_failed_read_does_not_close_the_staleness_window() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(BrokenDenylistStore {
        inner: MemoryStore::new(),
        calls: calls.clone(),
    });
    let rev = RevocationSync::new(store, HashSet::new(), 0);

    let t = REVOCATION_SYNC_TTL_SECS * 10;
    rev.refresh_if_stale(t);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the window's one attempt ran"
    );
    assert_eq!(
        rev.synced_at(),
        0,
        "a failed read must leave the LAST SUCCESSFUL sync stamp alone — otherwise a \
             permanently broken store reports itself as freshly synced forever"
    );

    for _ in 0..50 {
        rev.refresh_if_stale(t + 1);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a broken store must be retried once per window, not once per request"
    );

    rev.refresh_if_stale(t + REVOCATION_SYNC_TTL_SECS + 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry per window");
}

#[test]
fn a_successful_read_unions_and_closes_the_window() {
    let store = Arc::new(MemoryStore::new());
    store.add_denylist("vk_peer", "revoked by a peer").unwrap();
    let mut local = HashSet::new();
    local.insert("vk_local".to_string());
    let rev = RevocationSync::new(store, local, 0);

    let t = REVOCATION_SYNC_TTL_SECS * 10;
    rev.refresh_if_stale(t);
    assert!(rev.contains("vk_peer"), "the peer's revoke was merged in");
    assert!(
        rev.contains("vk_local"),
        "a union must never erase this node's live revocations"
    );
    assert_eq!(rev.synced_at(), t, "success closes the staleness window");
}

#[test]
fn a_key_another_node_minted_rotated_or_deleted_is_seen_within_one_window() {
    use crate::governance::signing::{TokenSigner, DEFAULT_KID};
    use crate::governance::{GovState, NewKeySpec};

    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let node = || {
        GovState::new_with_signer(
            Arc::clone(&store),
            None,
            Some(TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID)),
        )
        .expect("a node over the store")
    };
    let (a, b) = (node(), node());
    let t0 = busbar_kernel::store::now();
    let exp = t0 + REVOCATION_SYNC_TTL_SECS * 1_000;
    let window = |n: u64| t0 + REVOCATION_SYNC_TTL_SECS * 2 * n;

    let (key, first) = a
        .mint_signed(
            NewKeySpec {
                name: "fleet".into(),
                ..Default::default()
            },
            exp,
            t0,
        )
        .expect("node a mints");
    let first = first.expose(&crate::seal::lend()).to_string();
    assert!(
        b.verify_token(&first, window(1), None).is_some(),
        "node b admits the key node a minted"
    );

    let rotated = a
        .rotate_key(&key.id, exp)
        .expect("node a rotates")
        .expect("the key exists");
    let second = rotated.token.expose(&crate::seal::lend()).to_string();
    assert!(
        b.verify_token(&first, window(2), None).is_none(),
        "node b retires the token node a's rotation replaced"
    );
    assert!(
        b.verify_token(&second, window(2), None).is_some(),
        "node b admits the rotated token"
    );

    a.delete_key(&key.id).expect("node a deletes");
    assert!(
        b.verify_token(&second, window(3), None).is_none(),
        "node b stops admitting a key node a deleted"
    );
}

#[test]
fn a_backwards_wall_clock_still_observes_shared_store_rotation_and_revocation() {
    use crate::governance::signing::{TokenSigner, DEFAULT_KID};
    use crate::governance::{GovState, NewKeySpec};

    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let node = || {
        GovState::new_with_signer(
            store.clone(),
            None,
            Some(TokenSigner::from_secret_bytes(&[19; 32], DEFAULT_KID)),
        )
        .unwrap()
    };
    let (a, b) = (node(), node());
    let t0 = crate::store::now();
    let exp = t0 + 7_200;
    let rolled_back = t0 - 3_600;
    let (key, first) = a
        .mint_signed(
            NewKeySpec {
                name: "clock-regression".into(),
                ..Default::default()
            },
            exp,
            t0,
        )
        .unwrap();
    b.refresh().unwrap();
    assert!(b
        .verify_token(first.expose(&crate::seal::lend()), t0, None)
        .is_some());

    let second = a.rotate_key(&key.id, exp).unwrap().unwrap().token;

    assert!(b
        .verify_token(first.expose(&crate::seal::lend()), rolled_back, None)
        .is_some());
    let window_ms = REVOCATION_SYNC_TTL_SECS * 1_000;
    b.denylist.refresh_if_stale_at(rolled_back, window_ms);
    assert!(b
        .verify_token(first.expose(&crate::seal::lend()), rolled_back, None)
        .is_none());
    assert!(b
        .verify_token(second.expose(&crate::seal::lend()), rolled_back, None)
        .is_some());
    assert_eq!(
        b.denylist.synced_at(),
        rolled_back,
        "the successful wall stamp is reset"
    );

    a.revoke(&key.id, "peer revoke after clock correction")
        .unwrap();

    b.denylist.refresh_if_stale_at(rolled_back, window_ms * 2);
    assert!(b
        .verify_token(second.expose(&crate::seal::lend()), rolled_back, None)
        .is_none());
    assert!(b.denylist.contains(&key.id));
}

#[test]
fn failed_refreshes_under_a_regressing_clock_are_rate_limited_by_monotonic_age() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rev = RevocationSync::new(
        Arc::new(BrokenDenylistStore {
            inner: MemoryStore::new(),
            calls: calls.clone(),
        }),
        HashSet::new(),
        10_000,
    );
    let window_ms = REVOCATION_SYNC_TTL_SECS * 1_000;
    rev.refresh_if_stale_at(6_400, window_ms);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for n in 1..100 {
        rev.refresh_if_stale_at(6_400 - n, window_ms + n);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "regression never creates a retry storm"
    );
    rev.refresh_if_stale_at(6_000, window_ms * 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        rev.synced_at(),
        10_000,
        "a failure never closes the stale window"
    );
}
