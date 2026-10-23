// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/governance/revocation.rs`.

use super::*;
use crate::governance::MemoryStore;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, Retention, UsageDelta, UsageLedger,
    VirtualKey,
};
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
impl RecordStore for HungDenylistStore {
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(());
        // Park forever. A test thread parked here is the whole point; the runtime is dropped at
        // the end of the test and the process moves on.
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
    fn scrub_key(&self, _id: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support scrub_key".to_string(),
        ))
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(RecordStore::list_keys(self)?
            .into_iter()
            .filter(|k| k.revision == 0 || k.revision > since)
            .collect())
    }
    fn purge_windows_before(&self, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_metering_before(&self, _bucket: &str) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        RecordStore::put_key(self, key)?;
        RecordStore::put_credential(self, secret)?;
        Ok(())
    }
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }
    fn lookup_credential_secret(
        &self,
        _kind: &str,
        _public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(None)
    }
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut all = RecordStore::list_audit(self)?;
        let limit = limit as usize;
        if all.len() > limit {
            all.drain(0..all.len() - limit);
        }
        Ok(all)
    }
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        match retention {
            Retention::Age => RecordStore::purge_plane_records_before(self, kind, before),
            Retention::TerminalOnly => Ok(0),
        }
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

/// A `Store` whose `list_denylist` always fails — for the stamping rules.
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
    fn scrub_key(&self, _id: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support scrub_key".to_string(),
        ))
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(RecordStore::list_keys(self)?
            .into_iter()
            .filter(|k| k.revision == 0 || k.revision > since)
            .collect())
    }
    fn purge_windows_before(&self, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_metering_before(&self, _bucket: &str) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        RecordStore::put_key(self, key)?;
        RecordStore::put_credential(self, secret)?;
        Ok(())
    }
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }
    fn lookup_credential_secret(
        &self,
        _kind: &str,
        _public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(None)
    }
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut all = RecordStore::list_audit(self)?;
        let limit = limit as usize;
        if all.len() > limit {
            all.drain(0..all.len() - limit);
        }
        Ok(all)
    }
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        match retention {
            Retention::Age => RecordStore::purge_plane_records_before(self, kind, before),
            Retention::TerminalOnly => Ok(0),
        }
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
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
