// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane/taskstore.rs`.
//!
//! ## What "durable" is allowed to mean in a test
//!
//! A durability test that has never been run against a store that DROPS on restart has proven
//! nothing — it would pass just as happily against a registry that never wrote anything, because a
//! second registry reading zero tasks and a second registry reading two tasks are only
//! distinguishable if the assertion is on the READ-BACK. So every claim here is asserted on what
//! comes back out, and the negative twin
//! (`the_ram_default_loses_every_in_flight_task_and_the_registry_says_so`) runs the SAME sequence
//! against the shipped RAM default and requires it to lose everything. If durability ever silently
//! stops working, the positive test goes red; if the test ever stops actually testing durability,
//! the negative one goes red.

use super::*;
use crate::a2a::task::{Direction, Task, TaskState};
use crate::plane::store::StoreNamedTestExt;
use busbar_api::{TaskEventRow, TaskRow};
use std::collections::BTreeMap;
use std::sync::Arc;

const NOW: u64 = 1_770_000_000;

// ── the two stores under test ────────────────────────────────────────────────────────────────

/// TEST-ONLY durable-task double, and the reason it exists is the same one
/// `admin/tests/audit_tests.rs::DurableTestStore` gives for its own: `busbar_store_memory` is
/// DOCUMENTED as genuinely ephemeral (`main.rs`'s boot-restore path and `docs/configuration.md` both
/// rely on it), so teaching it to persist tasks just to suit a test would silently change a product
/// contract. This wraps the real `MemoryStore` for every other `Store` method and backs ONLY the
/// task methods with its own ledger — "durable" for exactly as long as this test process lives,
/// which is what lets a second `TaskRegistry` over the SAME handle stand in for "process 2".
struct DurableTaskStore {
    inner: busbar_store_memory::MemoryStore,
    tasks: std::sync::Mutex<BTreeMap<String, TaskRow>>,
    /// The chained events as the OPAQUE stored BODIES a durable backend holds — the neutral
    /// `{seq,prev_hash,hash,content}` the P5-C9 seam persists — keyed by `(task_id, seq)`. A typed view
    /// is reconstructed on read via [`crate::plane::store::task_event_row_from_body`] (which also reads
    /// legacy serde bodies), so "durable" here is byte-for-byte what a real store keeps.
    events: std::sync::Mutex<BTreeMap<(String, u64), Vec<u8>>>,
}

impl DurableTaskStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            tasks: std::sync::Mutex::new(BTreeMap::new()),
            events: std::sync::Mutex::new(BTreeMap::new()),
        }
    }
    /// Reach past the engine and mutate a persisted event directly — an operator with database
    /// access, or an attacker who got there. The only way to stage the tamper the chain exists to
    /// detect.
    ///
    /// The stored body is opaque (the neutral seam envelope), so the edit is staged by reconstructing
    /// the typed row, applying the caller's mutation, and re-persisting the body with its `hash` LEFT
    /// STALE — a rewritten payload under an unchanged digest, which is exactly the tamper `verify_chain`
    /// recomputes and catches.
    fn tamper_event(&self, task_id: &str, seq: u64, edit: impl Fn(&mut TaskEventRow)) {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let body = events
            .get_mut(&(task_id.to_string(), seq))
            .expect("the event to tamper with must exist");
        let mut row = crate::plane::store::task_event_row_from_body(task_id, body)
            .expect("the event to tamper with decodes");
        edit(&mut row);
        // Rebuild the neutral body from the edited fields, KEEPING the original (now stale) `hash`.
        let content = format!(
            "|{}|{}|{}|{}|{}|{}",
            row.ts, row.kind, row.context_id, row.principal, row.agent_id, row.state
        )
        .into_bytes();
        let tampered = crate::audit::journal::NeutralBody {
            seq: row.seq,
            prev_hash: row.prev_hash,
            hash: row.hash,
            content,
        };
        *body = crate::plane::store::encode(&tampered).expect("neutral body re-encodes");
    }
}

impl busbar_api::Store for DurableTaskStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    // ── The neutral kind-tagged verbs, delegating to the named task methods above ────────────────
    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        match record.kind.as_str() {
            crate::plane::store::KIND_TASK => {
                self.put_task(&crate::plane::store::decode(&record.body)?)
            }
            _ => Ok(()),
        }
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> busbar_api::StoreResult<Option<Vec<u8>>> {
        match kind {
            crate::plane::store::KIND_TASK => self
                .get_task(id)?
                .map(|r| crate::plane::store::encode(&r))
                .transpose(),
            _ => Ok(None),
        }
    }
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        match record.kind.as_str() {
            crate::plane::store::KIND_TASK_EVENT => self.append_event_body(record),
            _ => Ok(()),
        }
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (crate::plane::store::KIND_TASK, busbar_api::PlaneSelector::All) => self
                .list_tasks()?
                .iter()
                .map(crate::plane::store::encode)
                .collect(),
            (crate::plane::store::KIND_TASK_EVENT, busbar_api::PlaneSelector::Parent(p)) => Ok(self
                .events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|((id, _), _)| id == p)
                .map(|(_, body)| body.clone())
                .collect()),
            _ => Ok(Vec::new()),
        }
    }
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> busbar_api::StoreResult<u64> {
        match kind {
            crate::plane::store::KIND_TASK => self.purge_tasks_before(before),
            _ => Ok(0),
        }
    }
}

impl DurableTaskStore {
    fn put_task(&self, task: &TaskRow) -> busbar_api::StoreResult<()> {
        self.tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(task.task_id.clone(), task.clone());
        Ok(())
    }

    fn get_task(&self, task_id: &str) -> busbar_api::StoreResult<Option<TaskRow>> {
        Ok(self
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(task_id)
            .cloned())
    }

    fn list_tasks(&self) -> busbar_api::StoreResult<Vec<TaskRow>> {
        Ok(self
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    fn purge_tasks_before(&self, before: u64) -> busbar_api::StoreResult<u64> {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        let before_count = tasks.len();
        // The contract: TERMINAL rows only. An interrupt waiting on a human is exactly the row that
        // legitimately sits still for a long time, and collecting it is losing the work.
        tasks.retain(|_, t| {
            let terminal = matches!(
                t.state.as_str(),
                "completed" | "failed" | "canceled" | "rejected"
            );
            !(terminal && t.updated_at < before)
        });
        Ok((before_count - tasks.len()) as u64)
    }

    /// Persist ONE task-event body VERBATIM, keyed by `(task_id, seq)` from the record's `parent`/`seq`
    /// — the opaque neutral envelope a real backend keeps, no decode on the write path.
    fn append_event_body(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        let task_id = record.parent.clone().unwrap_or_else(|| record.id.clone());
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((task_id, record.seq), record.body.clone());
        Ok(())
    }
}

fn durable() -> Arc<DurableTaskStore> {
    Arc::new(DurableTaskStore::new())
}

/// The SHIPPED RAM default, which implements none of the task methods and therefore drops
/// everything. Used to prove the durability assertions are not vacuous.
fn ram_default() -> Arc<dyn busbar_api::Store> {
    Arc::new(busbar_store_memory::MemoryStore::new())
}

// ── the sequence both durability tests run ───────────────────────────────────────────────────

/// "Process 1": submit two tasks, take one to `working`, interrupt the other on `auth-required`
/// with a real artifact cursor. Returns the registry so a caller can inspect it before dropping it.
fn process_one(store: Arc<dyn busbar_api::Store>) -> TaskRegistry {
    let reg = TaskRegistry::new();
    reg.set_sink(crate::plane::store::PlaneStoreView::narrow(store));

    reg.submit(
        &Task::submitted("t-work", "ctx-a", "key-1", Direction::Inbound, NOW).unwrap(),
        "req-1",
    )
    .expect("submit t-work");
    reg.transition("t-work", TaskState::Working, NOW + 1, "req-1")
        .expect("t-work -> working");

    reg.submit(
        &Task::submitted("t-paused", "ctx-b", "key-2", Direction::Outbound, NOW).unwrap(),
        "req-2",
    )
    .expect("submit t-paused");
    reg.record_dispatch("t-paused", "planner", NOW + 1, "req-2")
        .expect("dispatch");
    reg.transition("t-paused", TaskState::Working, NOW + 2, "req-2")
        .expect("t-paused -> working");
    reg.advance_cursor("t-paused", 7, NOW + 3, "req-2")
        .expect("cursor");
    reg.transition("t-paused", TaskState::AuthRequired, NOW + 4, "req-2")
        .expect("t-paused -> auth-required");
    reg
}

// ── ITEM 19: the durable task store ──────────────────────────────────────────────────────────

/// THE DURABILITY PROOF. Process 1 writes; the registry is DROPPED; process 2 rehydrates from the
/// same durable backend and the in-flight tasks are all still there, with every field that decides
/// how they resume.
#[test]
fn in_flight_tasks_survive_a_restart_over_a_durable_backend() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();

    {
        let reg1 = process_one(handle.clone());
        assert_eq!(reg1.len(), 2, "process 1 holds both tasks");
        drop(reg1); // THE RESTART. Every byte of in-memory state is gone from here on.
    }

    let reg2 = TaskRegistry::new();
    reg2.set_sink(crate::plane::store::PlaneStoreView::narrow(handle.clone()));
    let rehydrated = reg2
        .restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .expect("rehydrate must succeed");

    assert_eq!(rehydrated.active, 2, "both in-flight tasks came back");
    assert_eq!(rehydrated.terminal, 0);
    assert_eq!(rehydrated.unreadable, 0, "no row failed to read back");
    assert!(
        rehydrated.chain_breaks.is_empty(),
        "every restored task's provenance chain verified: {:?}",
        rehydrated.chain_breaks
    );
    assert_eq!(reg2.len(), 2);

    // ASSERT ON THE OUTPUT, field by field. A task we believe we persisted is not a task we read
    // back, and a rehydrate that returned the right COUNT with the wrong contents resumes wrongly.
    let work = reg2.get_scoped("key-1", "t-work").expect("scoped read");
    assert_eq!(work.state, TaskState::Working);
    assert_eq!(work.context_id, "ctx-a");
    assert_eq!(work.direction, Direction::Inbound);

    let paused = reg2.get_scoped("key-2", "t-paused").expect("scoped read");
    assert_eq!(
        paused.state,
        TaskState::AuthRequired,
        "THE INTERRUPT SURVIVED — this is what makes suspend/resume real rather than nominal"
    );
    assert_eq!(paused.agent_id, "planner", "the chosen agent survived");
    assert_eq!(
        paused.artifact_cursor, 7,
        "the resubscribe resume point survived; without it the relay replays from zero"
    );
    assert_eq!(paused.direction, Direction::Outbound);
}

/// THE NEGATIVE TWIN, and the reason the test above is not vacuous. The SAME sequence against the
/// shipped RAM default loses everything, and the registry REPORTS that rather than pretending.
///
/// This is a product contract, not a defect: `store: memory` is documented as ephemeral. What would
/// be a defect is the engine papering over it, so the assertion is that the read-back is empty.
#[test]
fn the_ram_default_loses_every_in_flight_task_and_the_registry_says_so() {
    let store = ram_default();
    {
        let reg1 = process_one(store.clone());
        assert_eq!(reg1.len(), 2, "process 1 holds both tasks IN RAM");
        drop(reg1);
    }
    let reg2 = TaskRegistry::new();
    reg2.set_sink(crate::plane::store::PlaneStoreView::narrow(store.clone()));
    let rehydrated = reg2
        .restore_from_store(crate::plane::store::PlaneStoreView::narrow(store.clone()).as_ref())
        .unwrap();
    assert_eq!(
        rehydrated,
        Rehydrated::default(),
        "the RAM default restores NOTHING — durability is a property of the configured backend"
    );
    assert_eq!(reg2.len(), 0);
    assert_eq!(
        reg2.get_scoped("key-2", "t-paused"),
        Err(Denied::NotYours),
        "the interrupted task is genuinely gone"
    );
}

/// A RESUME after the restart works: the rehydrated interrupt accepts the input and returns to
/// `working`, and the provenance chain CONTINUES from where it left off rather than starting again.
#[test]
fn an_interrupt_resumes_after_a_restart_and_its_chain_continues() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    drop(process_one(handle.clone()));

    let seq_before = handle.list_task_events("t-paused").unwrap().len() as u64;
    assert!(seq_before >= 4, "process 1 wrote a real chain");

    let reg2 = TaskRegistry::new();
    reg2.set_sink(crate::plane::store::PlaneStoreView::narrow(handle.clone()));
    reg2.restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .unwrap();

    let resumed = reg2
        .transition("t-paused", TaskState::Working, NOW + 100, "req-resume")
        .expect("the caller supplied the required auth on the same contextId");
    assert_eq!(resumed.state, TaskState::Working);

    let events = handle.list_task_events("t-paused").unwrap();
    assert_eq!(
        events.len() as u64,
        seq_before + 1,
        "exactly one event was appended across the restart"
    );
    let last = events.last().unwrap();
    assert_eq!(last.seq, seq_before + 1, "the sequence CONTINUED");
    assert_eq!(
        last.kind, "task.resumed",
        "resuming from an interrupt is its own event kind, not a plain `working`"
    );
    assert_eq!(
        crate::audit::verify_chain(&events),
        Ok(()),
        "the chain verifies across the restart boundary"
    );
}

// ── ITEM 21: the per-task hash chain, over the real store ────────────────────────────────────

/// The engine-side verifier, run against the store, DETECTS a tampered link. This is the assertion
/// that turns the chain from decoration into a control: somebody with database access edits one
/// persisted event, and `verify_task_chain` names it.
#[test]
fn the_verifier_detects_a_tampered_link_in_the_persisted_chain() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle.clone());

    // GREEN first: the untouched chain verifies, and it verified over a chain with real length.
    let n = reg
        .verify_task_chain(
            crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref(),
            "t-paused",
        )
        .unwrap()
        .expect("an untouched chain verifies");
    assert!(n >= 4, "the chain that verified is not empty: {n} events");

    // Now reach past the engine and rewrite history: claim the dispatch went to a different agent.
    store.tamper_event("t-paused", 2, |e| {
        e.agent_id = "attacker-agent".to_string();
    });

    let brk = reg
        .verify_task_chain(
            crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref(),
            "t-paused",
        )
        .unwrap()
        .expect_err("a tampered event MUST be detected");
    assert_eq!(brk.seq, 2, "the verifier names WHICH event was altered");
    assert!(
        matches!(
            brk.kind,
            crate::audit::ChainBreakKind::DigestMismatch { .. }
        ),
        "an in-place edit is a digest mismatch, got {:?}",
        brk.kind
    );
    assert!(brk.to_string().contains("EDITED"), "{brk}");
}

/// A tampered chain found at BOOT is reported as tamper evidence, and the task is still restored.
/// Refusing to restore would let anyone who can write to the store DELETE a task by corrupting one
/// of its events, which turns a detection control into a destruction primitive.
#[test]
fn a_tampered_chain_is_reported_on_restore_and_the_task_is_still_restored() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    drop(process_one(handle.clone()));
    store.tamper_event("t-paused", 1, |e| e.principal = "someone-else".to_string());

    let reg2 = TaskRegistry::new();
    reg2.set_sink(crate::plane::store::PlaneStoreView::narrow(handle.clone()));
    let out = reg2
        .restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .unwrap();

    assert_eq!(out.active, 2, "both tasks are still restored");
    assert_eq!(out.chain_breaks.len(), 1, "exactly one chain failed");
    assert_eq!(out.chain_breaks[0].scope, "t-paused");
    assert_eq!(out.chain_breaks[0].seq, 1);
    assert!(
        reg2.get_scoped("key-2", "t-paused").is_ok(),
        "the task survived; the BREAK is what is reported, not a deletion"
    );
}

// ── cross-tenant scoping ─────────────────────────────────────────────────────────────────────

/// A caller may never name or read another tenant's task, and CANNOT TELL a foreign id from a
/// nonexistent one — a distinguishable not-found is an id-space enumeration oracle.
#[test]
fn a_caller_can_never_read_another_tenants_task_and_cannot_probe_for_it() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle);

    assert!(reg.get_scoped("key-1", "t-work").is_ok());
    assert_eq!(
        reg.get_scoped("key-1", "t-paused"),
        Err(Denied::NotYours),
        "key-1 does not own t-paused"
    );
    assert_eq!(
        reg.get_scoped("key-1", "t-does-not-exist"),
        Err(Denied::NotYours),
        "and a nonexistent id is INDISTINGUISHABLE from a foreign one"
    );
    // An unauthenticated (empty) principal owns nothing, rather than owning everything unattributed.
    assert_eq!(reg.get_scoped("", "t-work"), Err(Denied::NotYours));
    assert!(reg.list_scoped("").is_empty());

    // The listing is scoped too, and it is SET EQUALITY, not a floor: a listing that leaked one
    // extra task would pass a "contains my task" assertion.
    let mine: Vec<String> = reg
        .list_scoped("key-2")
        .into_iter()
        .map(|t| t.task_id)
        .collect();
    assert_eq!(mine, vec!["t-paused".to_string()]);
    let theirs: Vec<String> = reg
        .list_scoped("key-1")
        .into_iter()
        .map(|t| t.task_id)
        .collect();
    assert_eq!(theirs, vec!["t-work".to_string()]);
    // The unscoped read exists and is deliberately different — it is the operator/sweep path.
    assert!(reg.get_unscoped("t-paused").is_some());
}

// ── retention and compaction ─────────────────────────────────────────────────────────────────

/// Retention drops TERMINAL rows past the window and NEVER an interrupted one, however old. The
/// interrupt waiting on a human is the row that legitimately sits still longest; collecting it is
/// losing the work, not reclaiming space.
#[test]
fn compaction_collects_terminal_tasks_and_never_an_interrupt() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle.clone());
    reg.transition("t-work", TaskState::Completed, NOW + 10, "req-1")
        .expect("t-work completes");
    assert!(
        reg.evict_terminal("t-work"),
        "a terminal task may be evicted"
    );
    assert!(
        !reg.evict_terminal("t-paused"),
        "an ACTIVE task may NOT be evicted — evicting it loses its chain position and the next \
         event would open a SECOND chain at seq 1 under the same task id"
    );

    let removed = reg.compact(NOW + 1_000).expect("compact");
    assert_eq!(removed, 1, "exactly the completed task was collected");
    assert!(
        handle.get_task("t-work").unwrap().is_none(),
        "the terminal row is gone from the store"
    );
    let survivor = handle
        .get_task("t-paused")
        .unwrap()
        .expect("the interrupt is NEVER collected by age");
    assert_eq!(survivor.state, "auth-required");
}

/// A TERMINAL task is counted, not loaded, on rehydrate: it is not in flight and nothing resumes it,
/// and loading every terminal task would grow the working set without bound over a deployment's
/// life.
#[test]
fn a_terminal_task_is_counted_on_restore_and_deliberately_not_loaded() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    {
        let reg1 = process_one(handle.clone());
        reg1.transition("t-work", TaskState::Completed, NOW + 10, "req-1")
            .unwrap();
    }
    let reg2 = TaskRegistry::new();
    reg2.set_sink(crate::plane::store::PlaneStoreView::narrow(handle.clone()));
    let out = reg2
        .restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .unwrap();
    assert_eq!(out.active, 1);
    assert_eq!(out.terminal, 1);
    assert_eq!(
        reg2.len(),
        1,
        "only the in-flight task is in the working set"
    );
    assert!(
        handle.get_task("t-work").unwrap().is_some(),
        "but its durable row is retained for the provenance window"
    );
}

/// A row that will not PARSE is counted and reported, never silently skipped. A skipped row is an
/// in-flight task that quietly ceased to exist across a deploy — the exact failure this store was
/// built to prevent.
#[test]
fn an_unreadable_row_is_counted_rather_than_silently_dropped() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    drop(process_one(handle.clone()));
    // A row written by a hypothetical newer engine carrying a state this binary does not know.
    let mut row = handle.get_task("t-work").unwrap().unwrap();
    row.state = "nearly-done".to_string();
    handle.put_task(&row).unwrap();

    let reg2 = TaskRegistry::new();
    let out = reg2
        .restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .unwrap();
    assert_eq!(out.unreadable, 1, "the row is COUNTED");
    assert_eq!(out.active, 1, "and the readable one still came back");
}

// ── write-through ordering ───────────────────────────────────────────────────────────────────

/// A FAILED durable write does not leave the working set ahead of the store. Being ahead is the
/// worse of the two failures: the process believes a transition happened that a restart will
/// un-happen.
#[test]
fn a_failed_durable_write_leaves_the_working_set_agreeing_with_the_store() {
    /// A store whose task writes always fail (a full disk, a dead connection).
    struct RefusingStore(busbar_store_memory::MemoryStore);
    impl busbar_api::Store for RefusingStore {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.0.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.0.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.0.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.0.delete_key(id)
        }
        fn get_usage(&self, b: &str, w: u64) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.0.get_usage(b, w)
        }
        fn put_usage(
            &self,
            b: &str,
            w: u64,
            l: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.0.put_usage(b, w, l)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.0.add_metering(d)
        }
        fn list_metering(&self, b: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.0.list_metering(b)
        }
        fn upsert_plane_record(
            &self,
            record: &busbar_api::PlaneRecord,
        ) -> busbar_api::StoreResult<()> {
            self.put_task(&crate::plane::store::decode(&record.body)?)
        }
    }

    impl RefusingStore {
        fn put_task(&self, _t: &TaskRow) -> busbar_api::StoreResult<()> {
            Err(busbar_api::StoreError("disk is full".to_string()))
        }
    }

    let store: Arc<dyn busbar_api::Store> =
        Arc::new(RefusingStore(busbar_store_memory::MemoryStore::new()));
    let reg = TaskRegistry::new();
    reg.set_sink(crate::plane::store::PlaneStoreView::narrow(store));
    let task = Task::submitted("t-1", "ctx", "key-1", Direction::Inbound, NOW).unwrap();
    let err = reg
        .submit(&task, "req-1")
        .expect_err("a submit that cannot be persisted must not report success");
    assert!(err.to_string().contains("disk is full"), "{err}");
    assert_eq!(
        reg.len(),
        0,
        "and it is NOT in the working set: an acknowledged-but-unpersisted task is the one a crash \
         loses while the caller believes it is running"
    );
}

/// The artifact cursor is MONOTONIC. Rewinding it re-delivers chunks the caller already has, and on
/// a chunked assembly that is corruption rather than duplication.
#[test]
fn the_artifact_cursor_never_moves_backwards() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle.clone());
    let before = handle.list_task_events("t-paused").unwrap().len();

    let same = reg
        .advance_cursor("t-paused", 3, NOW + 50, "req-2")
        .unwrap();
    assert_eq!(same.artifact_cursor, 7, "a rewind is refused, not applied");
    assert_eq!(
        handle.list_task_events("t-paused").unwrap().len(),
        before,
        "and it emits no provenance event, because nothing happened"
    );

    let forward = reg
        .advance_cursor("t-paused", 9, NOW + 51, "req-2")
        .unwrap();
    assert_eq!(forward.artifact_cursor, 9);
}

/// A push callback is persisted with the task, because a completion that lands after a restart still
/// has to be delivered.
#[test]
fn a_push_callback_survives_the_restart_with_its_task() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    {
        let reg1 = process_one(handle.clone());
        reg1.set_push_callback(
            "t-paused",
            Some("https://caller.example/done".to_string()),
            NOW + 6,
        )
        .unwrap();
    }
    let reg2 = TaskRegistry::new();
    reg2.restore_from_store(crate::plane::store::PlaneStoreView::narrow(handle.clone()).as_ref())
        .unwrap();
    assert_eq!(
        reg2.get_scoped("key-2", "t-paused").unwrap().push_callback,
        Some("https://caller.example/done".to_string())
    );
}

/// An unknown task id is refused loudly on every mutation rather than silently creating one.
#[test]
fn a_mutation_against_an_unknown_task_is_refused() {
    let reg = TaskRegistry::new();
    for e in [
        reg.transition("nope", TaskState::Working, NOW, "r")
            .map(|_| ()),
        reg.record_dispatch("nope", "a", NOW, "r").map(|_| ()),
        reg.advance_cursor("nope", 1, NOW, "r").map(|_| ()),
        reg.set_push_callback("nope", None, NOW).map(|_| ()),
    ] {
        let err = e.expect_err("an unknown task id must be refused");
        assert!(err.to_string().contains("no such task"), "{err}");
    }
    assert_eq!(reg.len(), 0, "and nothing was created");
}

/// An ILLEGAL transition is refused and NOTHING is written: no store row, no provenance event.
/// A rejected move that still emitted an event would put a state in the chain the task never had.
#[test]
fn an_illegal_transition_writes_neither_a_row_nor_an_event() {
    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle.clone());
    reg.transition("t-work", TaskState::Completed, NOW + 10, "r")
        .unwrap();
    let events_before = handle.list_task_events("t-work").unwrap();
    let row_before = handle.get_task("t-work").unwrap().unwrap();

    let err = reg
        .transition("t-work", TaskState::Working, NOW + 11, "r")
        .expect_err("terminal is terminal");
    assert!(err.to_string().contains("illegal task transition"), "{err}");
    assert_eq!(handle.list_task_events("t-work").unwrap(), events_before);
    assert_eq!(handle.get_task("t-work").unwrap().unwrap(), row_before);
}

// TEMPORARY RED DEMONSTRATION — deleted in the same change that fixes it. It exists to make the
// defect visible in a test run rather than in prose: today the store takes a bare `Option<String>`,
// so a URL the SSRF guard refuses outright is accepted and read back off the task row.
#[test]
fn red_demo_the_store_accepts_a_url_the_guard_refuses() {
    use crate::a2a::pushnotify;
    let hostile = "https://169.254.169.254/hook";
    let refusal = pushnotify::validate(hostile, &[]).expect_err("the guard refuses it");

    let store = durable();
    let handle: Arc<dyn busbar_api::Store> = store.clone();
    let reg = process_one(handle);
    let task = reg
        .set_push_callback("t-paused", Some(hostile.to_string()), NOW + 6)
        .expect("stored");

    assert_eq!(
        task.push_callback,
        None,
        "THE STORE PERSISTED A CALLBACK THE SSRF GUARD REFUSES.\n  guard said: {refusal}\n  \
         stored on the task row: {:?}\n  read back from the registry: {:?}",
        task.push_callback,
        reg.get_scoped("key-2", "t-paused").unwrap().push_callback
    );
}
