// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/plane_host/scope.rs`.

use super::*;
use crate::plane::handle_engine::{HandleMeta, SealedEvent};
use busbar_api::{PlaneDisposition, PlaneRecord};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A test RAII guard whose `Drop` bumps a shared counter — stands in for the real admission guard.
struct DropCounter(Arc<AtomicUsize>);
impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn arena_reclaims_a_registered_guard_on_drop() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    {
        let scope = DispatchScope::new();
        let id = scope.register_admission(Box::new(DropCounter(reclaimed.clone())));
        assert_eq!(id, AdmissionId(1));
        assert_eq!(scope.registered(), 1);
        // Not yet reclaimed while the scope is live.
        assert_eq!(reclaimed.load(Ordering::SeqCst), 0);
    }
    // Scope dropped: the real guard `Drop` ran.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

#[test]
fn arena_reclaims_every_kind_and_runs_closers() {
    let count = Arc::new(AtomicUsize::new(0));
    let scope = DispatchScope::new();
    let c = count.clone();
    scope.register_admission(Box::new(DropCounter(count.clone())));
    let cc = c.clone();
    scope.register_egress(Box::new(move || {
        cc.fetch_add(1, Ordering::SeqCst);
    }));
    let ccc = c.clone();
    scope.register_pipe(Box::new(move || {
        ccc.fetch_add(1, Ordering::SeqCst);
    }));
    let cccc = c.clone();
    scope.register_lease(Box::new(move || {
        cccc.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(scope.registered(), 4);
    // Explicit reclaim (the abort-path hardening assertion): synchronous, reclaims all four.
    scope.reclaim_all();
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(scope.registered(), 0);
    // Idempotent: a second reclaim (e.g. the Drop after an explicit reclaim) is a no-op.
    scope.reclaim_all();
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[test]
fn durable_scope_reclaims_a_handed_off_guard_on_its_own_drop() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    {
        let dur = DurableScope::with_handoff(Box::new(DropCounter(reclaimed.clone())));
        assert_eq!(dur.registered(), 1, "the handoff took ownership");
        // The durable handle does NOT reclaim while the scope is live — the whole point of the
        // handoff is that it outlives the request future.
        assert_eq!(reclaimed.load(Ordering::SeqCst), 0);
    }
    // The durable scope dropped (task end): the moved-in guard's real `Drop` ran exactly once.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_scope_handoff_is_lazy_and_reclaims_lifo() {
    let count = Arc::new(AtomicUsize::new(0));
    let dur = DurableScope::new();
    assert_eq!(dur.registered(), 0, "an empty durable scope owns nothing");
    dur.handoff(Box::new(DropCounter(count.clone())));
    dur.handoff(Box::new(DropCounter(count.clone())));
    assert_eq!(dur.registered(), 2);
    dur.reclaim_all();
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "both durable handles reclaimed"
    );
    assert_eq!(dur.registered(), 0);
    // Idempotent: the Drop after an explicit reclaim is a no-op.
    dur.reclaim_all();
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

/// A test settling admission: its `Drop` bumps `released` (the probe-release path), and `settle`
/// bumps `settled` and then makes the drop a no-op — the exact shape the real `BreakerAdmission`
/// has (record-once, release-if-unsettled).
struct TestSettling {
    settled: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
    done: bool,
}
impl SettleAdmission for TestSettling {
    fn settle(&mut self, _signal: &Signal) -> StatusClass {
        self.settled.fetch_add(1, Ordering::SeqCst);
        self.done = true;
        StatusClass::Ok
    }
}
impl Drop for TestSettling {
    fn drop(&mut self) {
        if !self.done {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn ok_signal() -> Signal {
    Signal {
        size: core::mem::size_of::<Signal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        class: StatusClass::Ok,
        _reserved: 0,
        latency_nanos: 0,
        bytes: 0,
        fault_class: busbar_plugin::hot::FaultClass::Unspecified,
        fault_flags: 0,
        _reserved2: 0,
        _reserved3: 0,
        retry_after_secs: 0,
        provider_signal_ptr: core::ptr::null(),
        provider_signal_len: 0,
    }
}

/// A settling admission handed to a durable scope RELEASES its probe on scope drop when never
/// settled — the leak-safety keystone re-homed to task lifetime.
#[test]
fn durable_scope_releases_an_unsettled_admission_on_drop() {
    let settled = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    {
        let dur = DurableScope::new();
        let id = dur.register_settling(Box::new(TestSettling {
            settled: settled.clone(),
            released: released.clone(),
            done: false,
        }));
        assert!(!id.is_none(), "a settling registration yields a live id");
        assert_eq!(dur.registered(), 1);
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "not released while the scope is live"
        );
    }
    assert_eq!(settled.load(Ordering::SeqCst), 0, "never settled");
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "the unsettled probe released on drop"
    );
}

/// `DurableScope::settle` records the outcome exactly once and makes the drop a no-op; a replay is
/// `None` (the entry was consumed).
#[test]
fn durable_scope_settle_records_once_and_is_gone_on_replay() {
    let settled = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let sig = ok_signal();
    {
        let dur = DurableScope::new();
        let id = dur.register_settling(Box::new(TestSettling {
            settled: settled.clone(),
            released: released.clone(),
            done: false,
        }));
        assert_eq!(dur.settle(id, &sig), Some(StatusClass::Ok));
        assert_eq!(settled.load(Ordering::SeqCst), 1);
        assert_eq!(dur.registered(), 0, "a settled admission leaves the arena");
        // Replay: the id was consumed → Gone (None).
        assert_eq!(dur.settle(id, &sig), None);
    }
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "a settled probe does not also release"
    );
}

/// The handoff PRIMITIVE: a settling admission registered in a per-request `DispatchScope`
/// moves into a `DurableScope` preserving its id, and no longer reclaims at the dispatch arena's
/// drop — only at the durable scope's.
#[test]
fn dispatch_to_durable_handoff_preserves_id_and_relifetimes() {
    let settled = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let dur = DurableScope::new();
    let id = {
        let disp = DispatchScope::new();
        let id = disp.register_settling_admission(Box::new(TestSettling {
            settled: settled.clone(),
            released: released.clone(),
            done: false,
        }));
        assert_eq!(disp.registered(), 1);
        let moved = disp
            .handoff_settling_to(id, &dur)
            .expect("the admission hands off");
        assert_eq!(moved, id, "the id is preserved across the arena move");
        assert_eq!(disp.registered(), 0, "the dispatch arena no longer owns it");
        assert_eq!(dur.registered(), 1, "the durable scope now owns it");
        // The dispatch arena drops HERE (end of block) — the probe must NOT release, it is durable.
        id
    };
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "the dispatch-drop did not release the moved probe"
    );
    // A stale handoff of the same id is None.
    assert!(DispatchScope::new().handoff_settling_to(id, &dur).is_none());
    drop(dur);
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "the durable scope's drop released it"
    );
    assert_eq!(settled.load(Ordering::SeqCst), 0);
}

#[test]
fn handle_ids_are_nonzero_and_monotonic() {
    let scope = DispatchScope::new();
    let a = scope.register_egress(Box::new(|| {}));
    let b = scope.register_egress(Box::new(|| {}));
    assert!(!a.is_none());
    assert_eq!(a, EgressId(1));
    assert_eq!(b, EgressId(2));
}

// ── SessionScope over the durable-handle engine ─────────────────────────────────────────────────

/// A stand-in session row the engine holds opaquely and never names — a local demo type, so these
/// tests name no plane record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessRow {
    id: String,
    owner: String,
    updated_at: u64,
    terminal: bool,
    cursor: u64,
}

impl SessRow {
    fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: "sess".to_string(),
            id: self.id.clone(),
            parent: None,
            seq: 0,
            ts: self.updated_at,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            body: Vec::new(),
        }
    }
    fn meta(&self) -> HandleMeta {
        HandleMeta {
            owner: self.owner.clone(),
            updated_at: self.updated_at,
            terminal: self.terminal,
            cursor: self.cursor,
        }
    }
    fn arc(self) -> Arc<dyn std::any::Any + Send + Sync> {
        Arc::new(self)
    }
}

fn sess_bounds() -> SweepBounds {
    SweepBounds {
        abandon_secs: 1_000,
        terminal_ttl_secs: 1_000,
        max_retained: 64,
    }
}

fn sess_abandon(
    _id: &str,
    _row: &(dyn std::any::Any + Send + Sync),
    _pos: &ChainPosition,
    _now: u64,
) -> Option<Mutation> {
    None
}

fn sess_no_report(_id: &str, _e: &busbar_api::StoreError) {}

/// Open the session's handle at genesis, stamping the `SubmitRecord` with the session's own
/// `(owner, id)` — the binding contract [`SessionScope::open`] documents.
fn open_session(session: &SessionScope, cursor: u64, now: u64) {
    let row = SessRow {
        id: session.id().to_string(),
        owner: session.owner().to_string(),
        updated_at: now,
        terminal: false,
        cursor,
    };
    session
        .open(
            now,
            sess_bounds(),
            |_pos| {
                let record = row.record();
                let meta = row.meta();
                Ok(SubmitRecord {
                    id: row.id.clone(),
                    row: row.clone().arc(),
                    meta,
                    row_record: record.clone(),
                    event: Some(SealedEvent {
                        record,
                        tail_hash: format!("h-{}", row.id),
                    }),
                })
            },
            sess_abandon,
            sess_no_report,
        )
        .expect("open");
}

/// A plan mutation that overwrites the row with `next` — the session mutation shape reused below.
fn set_row(next: SessRow) -> Mutation {
    let record = next.record();
    let meta = next.meta();
    Mutation {
        row: Some(next.arc()),
        meta: Some(meta),
        row_record: Some(record),
        event: None,
    }
}

#[test]
fn a_session_opens_mutates_and_reads_its_handle() {
    let engine = Arc::new(DurableHandleEngine::new());
    let session = SessionScope::new(Arc::clone(&engine), "alice", "s1");
    assert_eq!(session.owner(), "alice");
    assert_eq!(session.id(), "s1");
    open_session(&session, 0, 1);

    // The session reads its own row through the scoped path.
    let row = session.get().expect("owner sees its handle");
    assert_eq!(row.downcast_ref::<SessRow>().unwrap().cursor, 0);

    // A mutation goes through scoped_mutate under the session's owner.
    let out = session
        .mutate(|row, _pos| {
            let row = row.downcast_ref::<SessRow>().unwrap();
            let mut next = row.clone();
            next.cursor = 7;
            Ok(Some(set_row(next)))
        })
        .expect("owner mutate");
    assert_eq!(out.downcast_ref::<SessRow>().unwrap().cursor, 7);
    assert_eq!(
        session
            .get()
            .unwrap()
            .downcast_ref::<SessRow>()
            .unwrap()
            .cursor,
        7
    );
}

#[test]
fn a_foreign_owner_session_is_refused_read_write_and_close() {
    let engine = Arc::new(DurableHandleEngine::new());
    let alice = SessionScope::new(Arc::clone(&engine), "alice", "s1");
    open_session(&alice, 3, 1);

    // A second session bound to the SAME id under a DIFFERENT owner.
    let mallory = SessionScope::new(Arc::clone(&engine), "mallory", "s1");

    assert!(
        matches!(mallory.get(), Err(HandleDenied::NotYours)),
        "a foreign owner cannot read"
    );
    assert!(
        matches!(
            mallory.mutate(|row, _pos| {
                let row = row.downcast_ref::<SessRow>().unwrap();
                let mut next = row.clone();
                next.cursor = 99;
                Ok(Some(set_row(next)))
            }),
            Err(ScopedMutateError::NotYours)
        ),
        "a foreign owner cannot resume/mutate"
    );
    assert!(!mallory.close(), "a foreign owner evicts nothing");

    // The rightful owner's row is untouched and still present.
    assert_eq!(
        alice
            .get()
            .unwrap()
            .downcast_ref::<SessRow>()
            .unwrap()
            .cursor,
        3
    );
    assert!(engine.get_unscoped("s1").is_some());
}

#[test]
fn close_evicts_only_once_the_handle_is_terminal() {
    let engine = Arc::new(DurableHandleEngine::new());
    let session = SessionScope::new(Arc::clone(&engine), "alice", "s1");
    open_session(&session, 0, 1);

    // An ACTIVE handle refuses eviction.
    assert!(!session.close(), "an active handle is not evicted");
    assert!(engine.get_unscoped("s1").is_some());

    // Drive it terminal through the session's own scoped mutate.
    session
        .mutate(|row, _pos| {
            let row = row.downcast_ref::<SessRow>().unwrap();
            let mut next = row.clone();
            next.terminal = true;
            Ok(Some(set_row(next)))
        })
        .expect("settle");

    // Now close evicts the terminal handle from the working set, leaving durable rows behind.
    assert!(session.close(), "a terminal handle is evicted");
    assert!(engine.get_unscoped("s1").is_none());
    assert!(engine.is_empty());
    // A second close is a no-op — the handle is gone, so the owner now sees NotYours too.
    assert!(!session.close());
}
