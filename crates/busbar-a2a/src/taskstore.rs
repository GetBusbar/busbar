// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE TASK STORE — the A2A plane's registry of in-flight tasks, its write-through to the
//! configured governance store, and the rehydrate that makes a restart a pause rather than a loss.
//!
//! Relocated from `busbar-core/src/plane/taskstore.rs` in the 1.7.0 plane extraction: a task is a
//! SINGLE-plane mechanism (A2A only), so the whole subsystem lives on the plane that owns it. The
//! durable journal is backed by the GENERIC neutral `PlaneRecord` store
//! ([`busbar_substrate::plane::store::PlaneStore`]) — the same opaque envelope every plane persists
//! through — so nothing A2A-specific crosses the store ABI. The per-task provenance CHAIN is computed
//! here, plane-side, over the plane's own [`TaskEventRow`]. The DIGEST is VERSIONED on the row
//! ([`TaskEventRow::digest_version`]): a new event is sealed under the INJECTIVE length-prefixed framing
//! v2 ([`DIGEST_VERSION_LEN_PREFIXED`]), while a chain persisted before the field-injection fix carries
//! no version, defaults to the legacy pipe-join framing v1, and still verifies byte-identically. The
//! legacy framing (`{prev_hash}|{task_id}|{seq}|{ts}|{kind}|{context_id}|{principal}|{agent_id}|
//! {state}`, sha256) is the one the former core host-side journal produced verbatim; it is RETAINED for
//! read-back only because its unframed free-text fields let a `|` shift field boundaries and collide two
//! distinct tuples — the reason v2 exists.
//!
//! ## The property this file exists to hold
//!
//! A2A is asynchronous by design. A task can be interrupted waiting on a human and resume hours later.
//! If the task table lives only in RAM, a deploy silently destroys every in-flight task and every
//! interrupt. So: every state change is written through to the store as it happens, and boot reads
//! them back. `store: memory` implements none of the plane-record methods, so their `Store` defaults
//! apply and nothing persists — that is the documented `store: memory` posture, not a bug.
//!
//! ## Reads are scoped, and a foreign id is indistinguishable from a missing one
//!
//! A caller may enumerate and inspect ONLY its own tasks. [`TaskRegistry::get_scoped`] returns the same
//! `Denied` for "no such task" and "that task is not yours", because a distinguishable not-found is an
//! enumeration oracle.

// PARTLY UNMOUNTED in this crate's own default build: the plane tests that drive the store run under
// `test-support`, and a bare unit build reads some helpers as unused.
#![cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]

use std::any::Any;
use std::sync::Arc;

use crate::record::{DIGEST_VERSION_LEN_PREFIXED, KIND_TASK, KIND_TASK_EVENT};
use crate::{TaskEventRow, TaskRow};
use busbar_api::{PlaneSelector, StoreError, StoreResult};
use busbar_substrate::plane::handle_engine::{
    ChainPosition, DurableHandleEngine, HandleEngineError, HandleMeta, Mutation, MutateError,
    RehydrateOutcome, SealedEvent, SubmitRecord, SweepBounds,
};
use busbar_substrate::plane::store::PlaneStore;

// ---------------------------------------------------------------------------------------------------
// The per-task provenance chain — computed plane-side, byte-identical digest.
// ---------------------------------------------------------------------------------------------------

/// Recompute one task event's tamper-evidence digest under the framing `version` selects. `request_id`
/// is deliberately excluded from every framing (a join key, absent on the boot/sweep paths, must not be
/// able to break an intact chain).
///
/// - [`DIGEST_VERSION_LEN_PREFIXED`] (v2): the INJECTIVE framing every new event is sealed under. See
///   [`digest_event_v2`].
/// - [`crate::record::DIGEST_VERSION_LEGACY_PIPE`] (v1) — a pre-fix row whose `digest_version` defaulted there:
///   the legacy ambiguous pipe-join, retained ONLY so a chain persisted before the field-injection fix
///   still verifies byte-identically. See [`digest_event_v1`].
#[allow(clippy::too_many_arguments)]
fn digest_event(
    version: u8,
    prev_hash: &str,
    task_id: &str,
    seq: u64,
    ts: u64,
    kind: &str,
    context_id: &str,
    principal: &str,
    agent_id: &str,
    state: &str,
) -> String {
    match version {
        DIGEST_VERSION_LEN_PREFIXED => digest_event_v2(
            prev_hash, task_id, seq, ts, kind, context_id, principal, agent_id, state,
        ),
        // v1 and any unrecognized/defaulted version fall to the legacy framing: a pre-fix row carries
        // no `digest_version` and serde defaults it to v1, and an unknown version can only have been
        // written by a build that does not exist, so treating it as legacy is the safe read.
        _ => digest_event_v1(
            prev_hash, task_id, seq, ts, kind, context_id, principal, agent_id, state,
        ),
    }
}

/// FRAMING V1 — the LEGACY ambiguous pipe-join `{prev_hash}|{task_id}|{seq}|{ts}|{kind}|{context_id}|
/// {principal}|{agent_id}|{state}`, which the former core host-side journal produced verbatim. The
/// free-text fields are not length-framed, so a `|` inside one shifts field boundaries and two distinct
/// tuples can collide — the reason v2 exists. Kept ONLY to verify chains persisted before the fix.
#[allow(clippy::too_many_arguments)]
fn digest_event_v1(
    prev_hash: &str,
    task_id: &str,
    seq: u64,
    ts: u64,
    kind: &str,
    context_id: &str,
    principal: &str,
    agent_id: &str,
    state: &str,
) -> String {
    let input = format!(
        "{prev_hash}|{task_id}|{seq}|{ts}|{kind}|{context_id}|{principal}|{agent_id}|{state}"
    );
    busbar_api::sha256_hex(input.as_bytes())
}

/// FRAMING V2 — the INJECTIVE length-prefixed encoding: a fixed domain tag, then each STRING field as
/// `<u64-le len><bytes>` and each INTEGER field as its fixed 8-byte little-endian encoding, hashed with
/// sha256. Because every field's length precedes its bytes, the boundary between fields is unambiguous:
/// no attacker-influenced value (`context_id` / `agent_id` / `principal`) can shift a boundary to make
/// two distinct tuples share a preimage. The field ORDER matches v1 so the mapping stays legible.
#[allow(clippy::too_many_arguments)]
fn digest_event_v2(
    prev_hash: &str,
    task_id: &str,
    seq: u64,
    ts: u64,
    kind: &str,
    context_id: &str,
    principal: &str,
    agent_id: &str,
    state: &str,
) -> String {
    // A fixed-length constant prefix that domain-separates this preimage space from any other sha256
    // use (and, trivially, from every v1 preimage, which begins with a hex hash or a bare `|`).
    let mut buf: Vec<u8> = b"busbar.a2a.taskchain.v2\0".to_vec();
    let push_str = |buf: &mut Vec<u8>, field: &str| {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field.as_bytes());
    };
    push_str(&mut buf, prev_hash);
    push_str(&mut buf, task_id);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&ts.to_le_bytes());
    push_str(&mut buf, kind);
    push_str(&mut buf, context_id);
    push_str(&mut buf, principal);
    push_str(&mut buf, agent_id);
    push_str(&mut buf, state);
    busbar_api::sha256_hex(&buf)
}

/// The digest of an already-built event row, from its own fields AND its stored framing version — the
/// verification primitive. Reading the version off the row is what lets a pre-fix (v1) chain and a
/// post-fix (v2) chain both verify against their own bytes.
fn digest_of(row: &TaskEventRow) -> String {
    digest_event(
        row.digest_version,
        &row.prev_hash,
        &row.task_id,
        row.seq,
        row.ts,
        &row.kind,
        &row.context_id,
        &row.principal,
        &row.agent_id,
        &row.state,
    )
}

/// WHY a task's provenance chain failed to verify. Four distinguishable causes, because the operator's
/// response to each differs — a `bool` verifier is run once and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreakKind {
    /// This event's stored `hash` is not the digest of its own fields: a field was edited in place.
    DigestMismatch { stored: String, recomputed: String },
    /// This event's `prev_hash` is not the previous event's `hash`: something was inserted, removed or
    /// reordered.
    LinkMismatch { expected: String, found: String },
    /// The sequence is not contiguous: a gap or a duplicate/regression.
    SequenceBreak { expected: u64, found: u64 },
    /// An event from a different task appears in this task's chain.
    ForeignScope { expected: String, found: String },
}

/// A verification failure on one task's chain: WHERE it is and WHAT it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The 1-based index into the event slice at which the break was found.
    pub at_index: usize,
    /// The event's claimed sequence number.
    pub seq: u64,
    /// The task id this chain is scoped to.
    pub scope: String,
    /// What broke.
    pub kind: ChainBreakKind,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the A2A per-task provenance chain for task `{}` BROKEN at index {} (seq {}): ",
            self.scope, self.at_index, self.seq
        )?;
        match &self.kind {
            ChainBreakKind::DigestMismatch { stored, recomputed } => write!(
                f,
                "the event's own fields do not hash to its stored digest (stored {stored}, \
                 recomputed {recomputed}) — this event was EDITED"
            ),
            ChainBreakKind::LinkMismatch { expected, found } => write!(
                f,
                "prev_hash does not match the preceding event's hash (expected {expected}, found \
                 {found}) — an event was INSERTED, REMOVED or REORDERED here"
            ),
            ChainBreakKind::SequenceBreak { expected, found } => write!(
                f,
                "sequence is not contiguous (expected {expected}, found {found}) — events were \
                 REMOVED or DUPLICATED"
            ),
            ChainBreakKind::ForeignScope { expected, found } => write!(
                f,
                "an event belonging to task `{found}` appears in task `{expected}`'s chain"
            ),
        }
    }
}

/// VERIFY ONE TASK'S CHAIN — `events` is the store's oldest-first list for ONE task, starting at the
/// chain's genesis, so `seq` starts at 1 and the first `prev_hash` is empty. An EMPTY list verifies
/// (indistinguishable from "every event deleted" using the events alone).
pub fn verify_chain(events: &[TaskEventRow]) -> Result<(), ChainBreak> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    let scope = first.task_id.clone();
    let mut expected_prev = String::new();
    let mut expected_seq = 1u64;
    for (i, ev) in events.iter().enumerate() {
        let at_index = i + 1;
        let brk = |kind| ChainBreak {
            at_index,
            seq: ev.seq,
            scope: scope.clone(),
            kind,
        };
        if ev.task_id != scope {
            return Err(brk(ChainBreakKind::ForeignScope {
                expected: scope.clone(),
                found: ev.task_id.clone(),
            }));
        }
        if ev.seq != expected_seq {
            return Err(brk(ChainBreakKind::SequenceBreak {
                expected: expected_seq,
                found: ev.seq,
            }));
        }
        if ev.prev_hash != expected_prev {
            return Err(brk(ChainBreakKind::LinkMismatch {
                expected: expected_prev.clone(),
                found: ev.prev_hash.clone(),
            }));
        }
        let recomputed = digest_of(ev);
        if recomputed != ev.hash {
            return Err(brk(ChainBreakKind::DigestMismatch {
                stored: ev.hash.clone(),
                recomputed,
            }));
        }
        expected_prev = ev.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// The event input a caller supplies, and the retention constants.
// ---------------------------------------------------------------------------------------------------

/// The fields a caller supplies for one event. `seq`, `prev_hash` and `hash` are NOT here: they are the
/// chain's own business, sealed by [`seal_task_event`] into the substrate engine's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventInput {
    kind: &'static str,
    context_id: String,
    principal: String,
    agent_id: String,
    state: String,
    request_id: String,
    ts: u64,
}

/// Is this canonical A2A task-state token TERMINAL? Matched as strings so the store names no
/// `TaskState`; the four tokens are fixed by the wire protocol.
fn is_terminal_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "canceled" | "rejected")
}

/// RETENTION: how long a TERMINAL task stays in the WORKING SET (readable through the scoped reads,
/// per the A2A contract that a task is pollable after it settles) after its terminal transition. In
/// SECONDS — every `TaskRow` timestamp is epoch seconds.
const TERMINAL_TASK_TTL_SECS: u64 = 300;

/// RETENTION: the hard ceiling on working-set entries, enforced by the submit-time sweep. The oldest
/// TERMINAL tasks are dropped first; an ACTIVE task is NEVER dropped to make room.
const MAX_RETAINED_TASKS: usize = 4096;

/// RETENTION: the ABANDONMENT ceiling on an ACTIVE task. One whose last update is older than this
/// transitions to `canceled` through the normal write path. In SECONDS.
const ACTIVE_TASK_ABANDON_SECS: u64 = 86_400;

/// Why a scoped read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// The task does not exist, OR it belongs to somebody else. ONE variant, on purpose.
    NotYours,
}

/// What a boot rehydrate actually found. Every number is reported rather than summed, because they mean
/// different things to an operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rehydrated {
    /// Active or interrupted tasks brought back and resumable.
    pub active: usize,
    /// Terminal tasks seen and deliberately not loaded into the working set.
    pub terminal: usize,
    /// Rows that would not parse — an in-flight task that ceased to exist across a deploy, counted
    /// rather than silently dropped.
    pub unreadable: usize,
    /// Tasks whose persisted provenance chain FAILED to verify. Tamper evidence; the task is still
    /// restored and the chain continues from the broken tail.
    pub chain_breaks: Vec<ChainBreak>,
}

/// What went wrong servicing a task mutation.
#[derive(Debug)]
pub enum TaskStoreError {
    /// The task id is not in the working set.
    NoSuchTask(String),
    /// The A2A codec refused the row or the move — carried as its already-rendered message.
    Domain(String),
    /// The durable write failed.
    Store(StoreError),
}

impl std::fmt::Display for TaskStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStoreError::NoSuchTask(id) => write!(f, "no such task `{id}`"),
            TaskStoreError::Domain(e) => write!(f, "{e}"),
            TaskStoreError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// The neutral projection helper: build the substrate engine's [`HandleMeta`] from a [`TaskRow`]. The
/// engine reads only this projection (owner / age / terminal / cursor) to run its mechanics; the row
/// itself it holds opaquely.
fn meta_of(row: &TaskRow) -> HandleMeta {
    HandleMeta {
        owner: row.principal.clone(),
        updated_at: row.updated_at,
        terminal: is_terminal_state(&row.state),
        cursor: row.artifact_cursor,
    }
}

/// Recover, by REFERENCE, the [`TaskRow`] the engine is holding opaquely for this plane. Always a
/// `TaskRow`: the A2A registry only ever hands the engine a `TaskRow`, and the downcast is within this
/// crate (same `TypeId`), so the row's byte-identity survives with no re-encode round-trip.
fn as_task_ref(row: &(dyn Any + Send + Sync)) -> &TaskRow {
    row.downcast_ref::<TaskRow>()
        .expect("an A2A durable handle always carries a TaskRow")
}

/// Recover an OWNED clone of the engine's opaque row.
fn as_task(row: &Arc<dyn Any + Send + Sync>) -> TaskRow {
    as_task_ref(row.as_ref()).clone()
}

/// SEAL one A2A provenance event at `pos` into the [`SealedEvent`] the substrate engine appends:
/// compute the A2A digest (framing v2) over the event's fields — byte-identical to the former
/// plane-side `seal_event` — build the typed [`TaskEventRow`], and frame it into the opaque plane
/// record. The plane owns the digest here; the engine owns the append and the chain-position advance.
fn seal_task_event(
    pos: &ChainPosition,
    task_id: &str,
    ev: &EventInput,
) -> StoreResult<SealedEvent> {
    let seq = pos.next_seq;
    // Every NEW event is sealed under the injective framing v2; v1 is only ever read, never written.
    let digest_version = DIGEST_VERSION_LEN_PREFIXED;
    let hash = digest_event(
        digest_version,
        &pos.tail_hash,
        task_id,
        seq,
        ev.ts,
        ev.kind,
        &ev.context_id,
        &ev.principal,
        &ev.agent_id,
        &ev.state,
    );
    let event_row = TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        ts: ev.ts,
        kind: ev.kind.to_string(),
        context_id: ev.context_id.clone(),
        principal: ev.principal.clone(),
        agent_id: ev.agent_id.clone(),
        state: ev.state.clone(),
        request_id: ev.request_id.clone(),
        prev_hash: pos.tail_hash.clone(),
        hash: hash.clone(),
        digest_version,
    };
    Ok(SealedEvent {
        record: event_row.to_plane_record()?,
        tail_hash: hash,
    })
}

/// THE ABANDON TRANSITION the retention sweep applies to an A2A task idle past the ceiling: move it to
/// `canceled` through the normal chained write path (a `task.terminal` event on its provenance chain).
/// A2A-specific — the `canceled` token and the event vocab are the plane's — so it is handed to the
/// engine's neutral sweep as its abandon callback. A seal/encode failure here (impossible in practice
/// for a `TaskRow`) skips the abandon; the task stays active and the next sweep retries, exactly as a
/// durable-write failure does.
fn plan_abandon(
    _id: &str,
    row: &(dyn Any + Send + Sync),
    pos: &ChainPosition,
    now: u64,
) -> Option<Mutation> {
    let row = row.downcast_ref::<TaskRow>()?;
    let mut candidate = row.clone();
    candidate.state = "canceled".to_string();
    candidate.updated_at = now;
    let ev = EventInput {
        kind: busbar_substrate::audit::vocab::EV_TERMINAL,
        context_id: candidate.context_id.clone(),
        principal: candidate.principal.clone(),
        agent_id: candidate.agent_id.clone(),
        state: candidate.state.clone(),
        request_id: String::new(),
        ts: now,
    };
    let event = seal_task_event(pos, &candidate.task_id, &ev).ok()?;
    let row_record = candidate.to_plane_record().ok()?;
    let meta = meta_of(&candidate);
    Some(Mutation {
        row: Some(Arc::new(candidate)),
        meta: Some(meta),
        row_record: Some(row_record),
        event: Some(event),
    })
}

/// Report an abandon that could not be durably recorded: the task stays active and the next sweep
/// retries. Warned at most once (the durable sink is down; a per-task log would flood). Handed to the
/// engine's sweep as its neutral failure reporter.
fn report_abandon_fail(id: &str, e: &StoreError) {
    static ABANDON_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if !ABANDON_UNRECORDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        busbar_substrate::diag_error!(
            crate::diagnostics::A2A_FAILURE_UNRECORDED,
            task_id = %id,
            error = %e,
            "an abandoned A2A task could not be transitioned to canceled; it stays \
             active and the next sweep retries"
        );
    }
}

/// Map a neutral engine error back to the A2A task-store taxonomy (byte-identical `Display`).
fn map_engine_err(e: HandleEngineError) -> TaskStoreError {
    match e {
        HandleEngineError::NoSuchHandle(id) => TaskStoreError::NoSuchTask(id),
        HandleEngineError::Rejected(msg) => TaskStoreError::Domain(msg),
        HandleEngineError::Store(e) => TaskStoreError::Store(e),
    }
}

/// The A2A retention knobs, handed to the engine's submit-time sweep.
const SWEEP_BOUNDS: SweepBounds = SweepBounds {
    abandon_secs: ACTIVE_TASK_ABANDON_SECS,
    terminal_ttl_secs: TERMINAL_TASK_TTL_SECS,
    max_retained: MAX_RETAINED_TASKS,
};

/// The in-flight A2A task registry — now a THIN CONSUMER of the neutral
/// [`busbar_substrate::plane::handle_engine::DurableHandleEngine`]. The engine owns the mechanics (the
/// working set, the durable write-through, the retention sweep, the boot rehydrate, the push cursor,
/// the scoped anti-enumeration read); this type layers the A2A TASK SHAPE, STATUSES, VOCAB and DIGEST
/// over it. No `Debug`: the engine holds a `dyn PlaneStore`.
pub struct TaskRegistry {
    engine: DurableHandleEngine,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            engine: DurableHandleEngine::new(),
        }
    }
}

/// THE PROCESS-WIDE REGISTRY. Process state, not config-derived state, so it lives as a global rather
/// than on the swappable `App` snapshot: a config apply must not destroy in-flight tasks.
pub static TASKS: std::sync::LazyLock<TaskRegistry> = std::sync::LazyLock::new(TaskRegistry::new);

/// TEST ONLY: the one lock every test that attaches a sink to the process-wide [`TASKS`] takes. The
/// registry is process state, so two tests attaching different sinks concurrently would interleave.
/// Async mutex because the guard is held across `.await` points in the front-door batteries.
#[cfg(any(test, feature = "test-support"))]
pub static TASKS_SINK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the configured governance store as the DURABLE SINK. Called once at boot. With no sink
    /// the registry is a RAM cache — the `store: memory` posture.
    pub fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        self.engine.set_sink(store);
    }

    /// TEST ONLY: drop the sink again, so a test that attached one to the process-wide [`TASKS`] leaves
    /// the registry as it found it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn clear_sink_for_test(&self) {
        self.engine.clear_sink_for_test();
    }

    /// BOOT REHYDRATE. Reads every persisted task, loads the ACTIVE ones into the working set, and
    /// resumes each one's provenance chain from its persisted events. Terminal tasks are counted and
    /// left in the store. The engine drives the orchestration + tolerance; this closure supplies the
    /// A2A decode, the read-back check, the terminal-token test, and the chain verify (accumulating the
    /// plane-typed [`ChainBreak`]s), and emits the A2A diagnostics.
    pub fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
        readable: impl Fn(&TaskRow) -> Result<(), String>,
    ) -> StoreResult<Rehydrated> {
        let mut chain_breaks: Vec<ChainBreak> = Vec::new();
        let counts = self.engine.rehydrate(store, KIND_TASK, |store, body| {
            // Decode per-row: a single row this build cannot parse is COUNTED as unreadable and
            // SKIPPED, never allowed to `?`-abort the whole rehydrate (which would drop every OTHER
            // task's working set). This is the same tolerance a chain break already gets below.
            let row = match TaskRow::from_body(body) {
                Ok(r) => r,
                Err(e) => {
                    busbar_substrate::diag_error!(
                        crate::diagnostics::A2A_TASK_ROWS_UNREADABLE,
                        error = %e,
                        "a persisted A2A task row could not be DECODED on restore; it is being \
                         skipped and counted rather than aborting the whole rehydrate"
                    );
                    return Ok(RehydrateOutcome::Unreadable);
                }
            };
            if let Err(e) = readable(&row) {
                busbar_substrate::diag_error!(
                    crate::diagnostics::A2A_TASK_ROWS_UNREADABLE,
                    task_id = %row.task_id,
                    error = %e,
                    "a persisted A2A task row could not be read back; it is NOT resumable and is \
                     being reported rather than skipped silently"
                );
                return Ok(RehydrateOutcome::Unreadable);
            }
            if is_terminal_state(&row.state) {
                return Ok(RehydrateOutcome::Terminal);
            }
            // Decode each event per-record: an undecodable event is counted and skipped, not
            // `?`-aborted. A gap in the chain that a skip leaves is caught by `verify_chain` below and
            // reported as a chain break — the same tamper-evidence path — rather than losing the whole
            // working set to one bad row.
            let mut events: Vec<TaskEventRow> = Vec::new();
            let mut event_unreadable = 0usize;
            for b in store
                .list_plane_records(KIND_TASK_EVENT, &PlaneSelector::Parent(row.task_id.clone()))?
                .iter()
            {
                match TaskEventRow::from_body(b) {
                    Ok(ev) => events.push(ev),
                    Err(e) => {
                        busbar_substrate::diag_error!(
                            crate::diagnostics::A2A_TASK_ROWS_UNREADABLE,
                            task_id = %row.task_id,
                            error = %e,
                            "a persisted A2A task EVENT could not be DECODED on restore; it is being \
                             skipped and counted rather than aborting the whole rehydrate"
                        );
                        event_unreadable += 1;
                    }
                }
            }
            if let Err(brk) = verify_chain(&events) {
                busbar_substrate::diag_error!(
                    crate::diagnostics::A2A_TASK_CHAIN_VERIFY_FAILED,
                    task_id = %row.task_id,
                    break_detail = %brk,
                    "A2A per-task provenance CHAIN VERIFICATION FAILED on restore — the persisted \
                     events do not verify against their own hash chain"
                );
                chain_breaks.push(brk);
            }
            let pos = match events.last() {
                None => ChainPosition::genesis(),
                Some(last) => ChainPosition::from_tail(last.hash.clone(), last.seq.saturating_add(1)),
            };
            let meta = meta_of(&row);
            let id = row.task_id.clone();
            Ok(RehydrateOutcome::Active {
                id,
                row: Arc::new(row),
                meta,
                pos,
                event_unreadable,
            })
        })?;
        Ok(Rehydrated {
            active: counts.active,
            terminal: counts.terminal,
            unreadable: counts.unreadable,
            chain_breaks,
        })
    }

    /// SUBMIT a new task: record it, write it through, and open its provenance chain. The durable write
    /// happens BEFORE the task is announced as accepted; the retention sweep runs before the insert.
    pub fn submit(&self, row: &TaskRow, request_id: &str) -> Result<TaskRow, TaskStoreError> {
        let row = row.clone();
        let request_id = request_id.to_string();
        self.engine
            .submit(
                row.created_at,
                SWEEP_BOUNDS,
                |pos| {
                    let ev = EventInput {
                        kind: busbar_substrate::audit::vocab::EV_SUBMITTED,
                        context_id: row.context_id.clone(),
                        principal: row.principal.clone(),
                        agent_id: row.agent_id.clone(),
                        state: row.state.clone(),
                        request_id: request_id.clone(),
                        ts: row.created_at,
                    };
                    let event = seal_task_event(pos, &row.task_id, &ev)?;
                    Ok(SubmitRecord {
                        id: row.task_id.clone(),
                        meta: meta_of(&row),
                        row_record: row.to_plane_record()?,
                        row: Arc::new(row.clone()),
                        event,
                    })
                },
                plan_abandon,
                report_abandon_fail,
            )
            .map(|arc| as_task(&arc))
            .map_err(map_engine_err)
    }

    /// TRANSITION a task, emitting the matching chained provenance event and writing both through. The
    /// in-memory entry is updated only after the durable write succeeds.
    pub fn transition<F>(
        &self,
        task_id: &str,
        request_id: &str,
        plan: F,
    ) -> Result<TaskRow, TaskStoreError>
    where
        F: FnOnce(&TaskRow) -> Result<(TaskRow, &'static str), String>,
    {
        let request_id = request_id.to_string();
        self.engine
            .mutate(task_id, |row, pos| {
                let (candidate, kind) = plan(as_task_ref(row)).map_err(MutateError::Rejected)?;
                let ev = EventInput {
                    kind,
                    context_id: candidate.context_id.clone(),
                    principal: candidate.principal.clone(),
                    agent_id: candidate.agent_id.clone(),
                    state: candidate.state.clone(),
                    request_id: request_id.clone(),
                    ts: candidate.updated_at,
                };
                let event =
                    seal_task_event(pos, &candidate.task_id, &ev).map_err(MutateError::Store)?;
                let row_record = candidate.to_plane_record().map_err(MutateError::Store)?;
                let meta = meta_of(&candidate);
                Ok(Some(Mutation {
                    row: Some(Arc::new(candidate)),
                    meta: Some(meta),
                    row_record: Some(row_record),
                    event: Some(event),
                }))
            })
            .map(|arc| as_task(&arc))
            .map_err(map_engine_err)
    }

    /// DISPATCH: record which agent this task was routed to, and chain a `task.delegated` event.
    pub fn record_dispatch(
        &self,
        task_id: &str,
        agent_id: &str,
        now: u64,
        request_id: &str,
    ) -> Result<TaskRow, TaskStoreError> {
        let agent_id = agent_id.to_string();
        let request_id = request_id.to_string();
        self.engine
            .mutate(task_id, |row, pos| {
                let mut candidate = as_task_ref(row).clone();
                candidate.agent_id = agent_id.clone();
                candidate.updated_at = now;
                let ev = EventInput {
                    kind: busbar_substrate::audit::vocab::EV_DELEGATED,
                    context_id: candidate.context_id.clone(),
                    principal: candidate.principal.clone(),
                    agent_id: candidate.agent_id.clone(),
                    state: candidate.state.clone(),
                    request_id: request_id.clone(),
                    ts: now,
                };
                let event =
                    seal_task_event(pos, &candidate.task_id, &ev).map_err(MutateError::Store)?;
                let row_record = candidate.to_plane_record().map_err(MutateError::Store)?;
                let meta = meta_of(&candidate);
                Ok(Some(Mutation {
                    row: Some(Arc::new(candidate)),
                    meta: Some(meta),
                    row_record: Some(row_record),
                    event: Some(event),
                }))
            })
            .map(|arc| as_task(&arc))
            .map_err(map_engine_err)
    }

    /// RECORD ONE PUSH-NOTIFICATION DELIVERY OUTCOME on the task's own chain. Not a transition and not
    /// a dispatch — appends an event and touches nothing else on the row.
    pub fn record_push_delivery(
        &self,
        task_id: &str,
        kind: &'static str,
        now: u64,
        request_id: &str,
    ) -> Result<(), TaskStoreError> {
        let request_id = request_id.to_string();
        self.engine
            .mutate(task_id, |row, pos| {
                let row = as_task_ref(row);
                let ev = EventInput {
                    kind,
                    context_id: row.context_id.clone(),
                    principal: row.principal.clone(),
                    agent_id: row.agent_id.clone(),
                    state: row.state.clone(),
                    request_id: request_id.clone(),
                    ts: now,
                };
                let event = seal_task_event(pos, task_id, &ev).map_err(MutateError::Store)?;
                Ok(Some(Mutation {
                    row: None,
                    meta: None,
                    row_record: None,
                    event: Some(event),
                }))
            })
            .map(|_| ())
            .map_err(map_engine_err)
    }

    /// ADVANCE THE ARTIFACT CURSOR — how many artifact chunks have been durably relayed. MONOTONIC.
    pub fn advance_cursor(
        &self,
        task_id: &str,
        cursor: u64,
        now: u64,
        request_id: &str,
    ) -> Result<TaskRow, TaskStoreError> {
        let request_id = request_id.to_string();
        self.engine
            .mutate(task_id, |row, pos| {
                let row = as_task_ref(row);
                if cursor <= row.artifact_cursor {
                    return Ok(None);
                }
                let mut candidate = row.clone();
                candidate.artifact_cursor = cursor;
                candidate.updated_at = now;
                let ev = EventInput {
                    kind: busbar_substrate::audit::vocab::EV_ARTIFACT,
                    context_id: candidate.context_id.clone(),
                    principal: candidate.principal.clone(),
                    agent_id: candidate.agent_id.clone(),
                    state: candidate.state.clone(),
                    request_id: request_id.clone(),
                    ts: now,
                };
                let event =
                    seal_task_event(pos, &candidate.task_id, &ev).map_err(MutateError::Store)?;
                let row_record = candidate.to_plane_record().map_err(MutateError::Store)?;
                let meta = meta_of(&candidate);
                Ok(Some(Mutation {
                    row: Some(Arc::new(candidate)),
                    meta: Some(meta),
                    row_record: Some(row_record),
                    event: Some(event),
                }))
            })
            .map(|arc| as_task(&arc))
            .map_err(map_engine_err)
    }

    /// Register (or clear) this task's push-notification callback. The SSRF FLOOR is applied by the A2A
    /// caller BEFORE this method; a refused URL reaches here as `None`. No provenance event: it changes
    /// no task state, only the delivery target on the row.
    pub fn set_push_callback(
        &self,
        task_id: &str,
        callback: Option<String>,
        now: u64,
    ) -> Result<TaskRow, TaskStoreError> {
        self.engine
            .mutate(task_id, |row, _pos| {
                let mut candidate = as_task_ref(row).clone();
                candidate.push_callback = callback.clone().unwrap_or_default();
                candidate.updated_at = now;
                let row_record = candidate.to_plane_record().map_err(MutateError::Store)?;
                let meta = meta_of(&candidate);
                Ok(Some(Mutation {
                    row: Some(Arc::new(candidate)),
                    meta: Some(meta),
                    row_record: Some(row_record),
                    event: None,
                }))
            })
            .map(|arc| as_task(&arc))
            .map_err(map_engine_err)
    }

    /// SCOPED READ. The authorization gate for `GetTask`: a caller sees its own tasks and nothing else,
    /// and cannot tell a foreign id from a nonexistent one.
    pub fn get_scoped(&self, principal: &str, task_id: &str) -> Result<TaskRow, Denied> {
        self.engine
            .scoped_get(principal, task_id)
            .map(|arc| as_task(&arc))
            .map_err(|_| Denied::NotYours)
    }

    /// SCOPED LIST. The authorization gate for `ListTasks`, sorted by task id so the result is
    /// deterministic (the engine sorts by handle id, which is the task id).
    pub fn list_scoped(&self, principal: &str) -> Vec<TaskRow> {
        self.engine.scoped_list(principal).iter().map(as_task).collect()
    }

    /// UNSCOPED read — for the retention sweep and the operator surface, never for a caller.
    pub fn get_unscoped(&self, task_id: &str) -> Option<TaskRow> {
        self.engine.get_unscoped(task_id).map(|arc| as_task(&arc))
    }

    /// How many tasks are in the working set. Active + interrupted only.
    pub fn len(&self) -> usize {
        self.engine.len()
    }

    /// Whether the working set holds no tasks.
    pub fn is_empty(&self) -> bool {
        self.engine.is_empty()
    }

    /// Drop a task from the WORKING SET once it is terminal, leaving its durable rows and its
    /// provenance chain in the store for the retention window. Refuses to evict an ACTIVE task.
    pub fn evict_terminal(&self, task_id: &str) -> bool {
        self.engine.evict_if_terminal(task_id)
    }

    /// RETENTION: ask the store to drop terminal task rows older than `before`, and drop any matching
    /// working-set entries. Returns how many durable rows went.
    pub fn compact(&self, before: u64) -> StoreResult<u64> {
        self.engine.compact(before, KIND_TASK)
    }

    /// TEST ONLY: how many working-set entries hold a chain position — trivially the working-set size,
    /// kept as the diagnostic the retention tests read.
    #[cfg(any(test, feature = "test-support"))]
    pub fn chain_positions(&self) -> usize {
        self.engine.len()
    }

    /// TEST ONLY: the retention constants, so the cross-crate retention tests assert against the
    /// shipped values rather than restating them.
    #[cfg(any(test, feature = "test-support"))]
    pub fn retention_bounds() -> (u64, usize) {
        (TERMINAL_TASK_TTL_SECS, MAX_RETAINED_TASKS)
    }

    /// TEST ONLY: the abandonment ceiling.
    #[cfg(any(test, feature = "test-support"))]
    pub fn abandon_ceiling_secs() -> u64 {
        ACTIVE_TASK_ABANDON_SECS
    }

    /// VERIFY one task's persisted provenance chain, end to end, against the store.
    pub fn verify_task_chain(
        &self,
        store: &dyn PlaneStore,
        task_id: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        let events: Vec<TaskEventRow> = store
            .list_plane_records(KIND_TASK_EVENT, &PlaneSelector::Parent(task_id.to_string()))?
            .iter()
            .map(|b| TaskEventRow::from_body(b))
            .collect::<StoreResult<_>>()?;
        match verify_chain(&events) {
            Ok(()) => Ok(Ok(events.len())),
            Err(brk) => Ok(Err(brk)),
        }
    }
}

/// TEST ONLY: a registry over `store` (used as its durable sink), for the durable/restart batteries.
/// The A2A twin of the former `TaskTestHarness`, minus the host-side journal scaffolding the plane no
/// longer uses — the chain is computed plane-side now, so a test needs only a registry with a sink.
#[cfg(any(test, feature = "test-support"))]
pub struct TaskTestHarness {
    pub reg: TaskRegistry,
}

#[cfg(any(test, feature = "test-support"))]
impl TaskTestHarness {
    /// Fresh isolated harness over `store` (the durable sink).
    pub fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        let reg = TaskRegistry::new();
        reg.set_sink(busbar_substrate::plane::store::PlaneStoreView::narrow(
            store,
        ));
        Self { reg }
    }

    /// Re-open a harness over `store` — a RESTART: the durable store is unchanged and a new registry
    /// (empty working set) is returned for the rehydrate to fill.
    pub fn restart(store: Arc<dyn busbar_api::Store>) -> Self {
        Self::over(store)
    }
}

/// TEST-ONLY NAMED-VOCABULARY STORE EXTENSION — the plane-side twin of the former neutral
/// `busbar_core::plane::store::StoreNamedTestExt`, relocated here with the task subsystem. It exists
/// only so the plane's own batteries read/write the `task`/`task_event` streams through terse named
/// methods (`put_task`/`get_task`/`list_task_events`) rather than restating the generic
/// `PlaneRecord`-kind calls at every site, byte-identically to the neutral path. A test double that
/// keeps its own typed map provides INHERENT methods of the same names, which win method resolution
/// over this blanket impl, while a bare `dyn Store` resolves here.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)] // a complete named-vocabulary surface; not every method is exercised by every suite
pub trait TaskStoreTestExt: busbar_api::Store {
    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.upsert_plane_record(&task.to_plane_record()?)
    }
    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        self.get_plane_record(KIND_TASK, task_id)?
            .map(|b| TaskRow::from_body(&b))
            .transpose()
    }
    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        self.list_plane_records(KIND_TASK, &PlaneSelector::All)?
            .iter()
            .map(|b| TaskRow::from_body(b))
            .collect()
    }
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        self.purge_plane_records_before(KIND_TASK, before)
    }
    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.append_plane_record(&event.to_plane_record()?)
    }
    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        self.list_plane_records(KIND_TASK_EVENT, &TaskEventRow::parent_selector(task_id))?
            .iter()
            .map(|b| TaskEventRow::from_body(b))
            .collect()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<T: busbar_api::Store + ?Sized> TaskStoreTestExt for T {}

/// THE READ-BACK HALF, shared by every battery that asserts on this chain — the durable-sink test
/// double, relocated here with the task subsystem so the batteries that attach it to the process-wide
/// [`TASKS`] name one home.
#[cfg(any(test, feature = "test-support"))]
#[path = "a2a/tests/event_ledger.rs"]
pub mod event_ledger;

#[cfg(all(test, feature = "test-support"))]
#[path = "a2a/tests/taskstore_tests.rs"]
mod taskstore_tests;

/// THE FROZEN BYTE-LAYOUT GOLDEN for the A2A per-task provenance chain — relocated from
/// `busbar-core`'s `audit/tests/boot_verify_golden.rs` with the task subsystem. It pins the durable
/// digest and the typed `TaskEventRow` body encoding against frozen bytes: a change to either would
/// report every persisted chain in every deployment as TAMPERED, so it fails LOUDLY on drift. It pins
/// BOTH framings — the legacy v1 pipe-join (a chain persisted before the field-injection fix, whose rows
/// carry no `digest_version` and default to v1) AND the injective v2 length-prefixed framing every new
/// event is sealed under — so a change to EITHER is caught. Runs in the plain unit build (no
/// `test-support`, no `busbar-core`), so it guards the wire contract on every `cargo test -p busbar-a2a`.
#[cfg(test)]
#[path = "a2a/tests/chain_golden.rs"]
mod chain_golden;
