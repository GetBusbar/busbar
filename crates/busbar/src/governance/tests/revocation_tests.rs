// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/governance/revocation.rs`.

use super::*;
use busbar_api::{
    AuditRecord, MeteringDelta, MeteringRow, StoreResult, UsageDelta, UsageLedger, VirtualKey,
};
use busbar_store_memory::MemoryStore;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::time::Duration;

/// A `Store` whose `list_denylist` behaves as the operator's worst day does: it announces that
/// it has been entered and then NEVER RETURNS. That is not a contrived shape — `store-postgres`
/// has no reconnect and no statement timeout by design, so a black-holed TCP connection is
/// exactly this. Every other method delegates to a real `MemoryStore`.
struct HungDenylistStore {
    inner: MemoryStore,
    /// Signalled the instant `list_denylist` is entered, so a test can prove the read STARTED
    /// without having to guess at timing.
    entered: mpsc::Sender<()>,
    /// How many reads have been started — the bound check.
    entries: Arc<AtomicUsize>,
}
impl Store for HungDenylistStore {
    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(());
        // Park forever. A test thread parked here is the whole point; the runtime is dropped at
        // the end of the test and the process moves on.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(k)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_usage(&self, id: &str, w: u64, d: &UsageDelta) -> StoreResult<()> {
        self.inner.add_usage(id, w, d)
    }
    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, b: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(b)
    }
    fn append_audit(&self, e: &AuditRecord) -> StoreResult<()> {
        self.inner.append_audit(e)
    }
    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
}

/// A `Store` whose `list_denylist` always fails — for the stamping rules.
struct BrokenDenylistStore {
    inner: MemoryStore,
    calls: Arc<AtomicUsize>,
}
impl Store for BrokenDenylistStore {
    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(busbar_api::StoreError("connection refused".into()))
    }
    fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(k)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_usage(&self, id: &str, w: u64, d: &UsageDelta) -> StoreResult<()> {
        self.inner.add_usage(id, w, d)
    }
    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, b: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(b)
    }
    fn append_audit(&self, e: &AuditRecord) -> StoreResult<()> {
        self.inner.append_audit(e)
    }
    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
}

/// THE PROPERTY UNDER TEST.
///
/// The property is not "the denylist is eventually correct" — that held on the broken version
/// too. The property is **the async runtime keeps running while the store does not answer**.
/// A single-worker runtime makes that measurable and deterministic: the auth path's revocation
/// check runs on the one worker thread, and the moment it performs a store read inline, nothing
/// else in the process can be scheduled — not another request, not `/healthz` (which is exempt
/// from the auth chain but still needs a worker to be polled at all), not the admin plane.
///
/// With the read performed inline (`self.store.list_denylist()` on the auth path) the probe
/// task below is never scheduled and the `timeout` elapses; with the read scheduled onto the
/// blocking pool the worker stays free and the probe completes.
#[test]
fn a_hung_store_does_not_park_the_reactor() {
    let (tx, entered) = mpsc::channel();
    let entries = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(HungDenylistStore {
        inner: MemoryStore::new(),
        entered: tx,
        entries: entries.clone(),
    });
    // Stamped well in the past so the very first check is stale and triggers a refresh.
    let rev = RevocationSync::new(store, HashSet::new(), 0);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    // The runtime is deliberately LEAKED, not dropped: this test parks a thread inside a store
    // call that never returns, and `Runtime::drop` waits for in-flight work. Dropping it — on
    // the assertion-failure path especially — would turn a clean test failure into a hung test
    // run. In production the process outlives the hung read the same way.
    let rt = {
        let handle = rt.handle().clone();
        std::mem::forget(rt);
        handle
    };

    // A "request" reaching the revocation check on the single worker.
    {
        let rev = rev.clone();
        rt.spawn(async move {
            rev.refresh_if_stale(REVOCATION_SYNC_TTL_SECS * 100);
            // The check must also still ANSWER while the store is hung — fail-closed against
            // the last-known set, not blocked on the store.
            let _ = rev.contains("vk_whoever");
        });
    }
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the store read must actually have been started");

    // With the store read outstanding, can the runtime still schedule anything at all? The
    // probe deliberately signals over a STD channel and is waited on with a std timeout: when
    // the reactor is dead its timer driver is dead too, so a `tokio::time::timeout` would never
    // fire and the failure would surface as a hang instead of an assertion.
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

    // THE BOUND: further stale windows must NOT start further reads while one is outstanding.
    // Without it, `spawn_blocking` alone would trade a dead reactor for a drained blocking pool.
    for window in 200..210u64 {
        rev.refresh_if_stale(REVOCATION_SYNC_TTL_SECS * window);
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        entries.load(Ordering::SeqCst),
        1,
        "at most ONE store read may ever be outstanding: a store that never answers must cost \
             exactly one blocking-pool thread, not one per staleness window"
    );
}

/// A FAILED read must not close the staleness window. The old code stamped `now` BEFORE the
/// read, so a store that never once succeeded still looked freshly synced every window: the
/// denylist could stay stale for the life of the process while every window "succeeded".
///
/// With a single stamp advanced before the read, `synced_at` jumps to the attempt time; here
/// `synced_at` is untouched by failure, and the failure is still rate-limited to one attempt
/// per window.
#[test]
fn a_failed_read_does_not_close_the_staleness_window() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(BrokenDenylistStore {
        inner: MemoryStore::new(),
        calls: calls.clone(),
    });
    let rev = RevocationSync::new(store, HashSet::new(), 0);

    // No Tokio runtime here, so the refresh runs inline — deterministic, and the semantics
    // non-async callers were always written against.
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

    // ..and the failure is nonetheless rate-limited: same window ⇒ no second attempt.
    for _ in 0..50 {
        rev.refresh_if_stale(t + 1);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a broken store must be retried once per window, not once per request"
    );

    // Next window: exactly one more attempt.
    rev.refresh_if_stale(t + REVOCATION_SYNC_TTL_SECS + 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry per window");
}

/// A SUCCESSFUL read closes the window, unions (never replaces), and keeps a locally-revoked
/// subject that the store has not yet been asked about.
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
