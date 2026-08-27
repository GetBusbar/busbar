// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE TASK STORE: the registry of in-flight tasks, its write-through to the configured
//! governance store, and the rehydrate that makes a restart a pause rather than a loss.
//!
//! ## The property this file exists to hold
//!
//! A2A is asynchronous by design. A task can be interrupted waiting on a human and resume hours
//! later. If the task table lives only in RAM, a deploy silently destroys every in-flight task and
//! every interrupt, and `suspend`/resume is a word rather than a behaviour. So: every state change
//! is written through to the store as it happens, and boot reads them back.
//!
//! ## The shape is the audit log's, deliberately
//!
//! [`crate::admin::audit::AuditLog`] already solved this exact problem for admin mutations: an
//! in-memory working set, an optional durable SINK attached at boot, write-through on every append,
//! and a `restore_from_store` that reconstitutes the state and VERIFIES the hash chain before
//! trusting it. Inventing a second shape for the same problem would mean two restore paths with two
//! sets of edge cases. This is that shape, with a per-task chain instead of one global one.
//!
//! ## The RAM default really is ephemeral, and that is a product contract, not an oversight
//!
//! `store: memory` implements none of the task methods, so their `Store` defaults apply and nothing
//! persists. That is documented behaviour for every other stateful thing busbar keeps, and the
//! engine must never paper over it: durability is a property of the CONFIGURED BACKEND, and the only
//! honest way to know whether a deployment has it is to READ A TASK BACK. `restore_from_store`
//! returning zero on the RAM default is the truth being reported, not a bug.
//!
//! ## Reads are scoped, and a foreign id is indistinguishable from a missing one
//!
//! A caller may enumerate and inspect ONLY its own tasks. [`TaskRegistry::get_scoped`] returns the
//! same `Denied` for "no such task" and "that task is not yours", because a distinguishable
//! not-found is an enumeration oracle: a caller that can tell the two apart can probe the id space
//! and learn which task ids exist in other tenants.

// PARTLY UNMOUNTED. `set_sink`, `restore_from_store`, `submit`, `record_dispatch`, `transition`,
// `advance_cursor` and `set_push_callback` are all driven — boot rehydrates, the ingress opens a
// task per call, the relay moves its state, and a state change is now also what DELIVERS the
// caller's push notification. The scoped reads and `compact` await the task-read surface.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::audit::journal::NeutralBody;
use crate::audit::{verify_chain, ChainBreak, Framing};

use crate::plane::store::{decode, task_record, PlaneStore, KIND_TASK, KIND_TASK_EVENT};
use crate::plane_host::journal::PlaneJournalRecord;
use crate::provenance::{self, EventInput};
use busbar_api::{PlaneSelector, StoreError, StoreResult, TaskEventRow, TaskRow};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    Framing as AbiFraming, JournalStreamDesc, ReframeOut, Seq, StatusClass, POD_VERSION,
};
use core::mem::MaybeUninit;

/// The host-assigned `kind_id` the A2A `task_event` durable stream is registered under and addressed
/// by on every scoped op. Process-global (the host's stream registry is), distinct from every other
/// stream's id (the MCP `call` stream takes its own).
pub(crate) const KIND_ID_TASK_EVENT: u32 = 1;

/// The A2A `task_event` stream's FFI reframe slot: the [`JournalReframeFn`](busbar_plugin::hot::host::JournalReframeFn)
/// the host calls to reconstruct a record's chain fields from a stored body. Delegates the raw-buffer
/// work to the audited [`crate::plane_host::journal::reframe_bridge`] (so this file stays `deny(unsafe)`)
/// over the native [`reframe_task_event`] decode, which handles BOTH the neutral body and a legacy row.
extern "C-unwind" fn reframe_task_event_ffi(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    crate::plane_host::journal::reframe_bridge(
        body_ptr,
        body_len,
        out,
        prev_buf,
        prev_cap,
        hash_buf,
        hash_cap,
        suffix_buf,
        suffix_cap,
        reframe_task_event,
    )
}

/// REGISTER the A2A `task_event` durable stream with the host (once, at boot, before the rehydrate):
/// its neutral `kind`, `PipeSeparated` framing with the scope in the digest, and the reframe slot,
/// under [`KIND_ID_TASK_EVENT`]. The host attaches the durable sink from `app.governance` at register
/// time — the same plane-narrowed store the task-row upserts write through — so the host-side journal
/// and the row upserts reach one backend. Idempotent per `kind_id`.
pub(crate) fn register_task_event_stream(app: &std::sync::Arc<crate::state::App>) {
    register_task_event_stream_as(KIND_ID_TASK_EVENT, app);
}

/// Register the `task_event` stream under an ARBITRARY `kind_id` — the parameterized form production's
/// [`register_task_event_stream`] pins to [`KIND_ID_TASK_EVENT`], and a TEST drives over a FRESH id so
/// parallel tests never share one process-global chain (the host stream registry is a singleton per id).
pub(crate) fn register_task_event_stream_as(kind_id: u32, app: &std::sync::Arc<crate::state::App>) {
    let kind = KIND_TASK_EVENT.as_bytes();
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing: AbiFraming::PipeSeparated,
        digests_scope: 1,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    crate::plane_host::with_dispatch_scope(app, |host, vt| {
        (vt.journal_register
            .expect("journal_register is a wired host slot"))(
            host,
            &desc as *const JournalStreamDesc,
            reframe_task_event_ffi,
        );
    });
}

/// Pack a set of stored bodies into the [`journal_seed`](crate::plane_host::journal) wire shape:
/// `u32` count LE, then per body a `u32` length LE + its bytes. The inverse of the host's
/// `unpack_bodies` — the durable seam takes the raw bodies packed and reframes each host-side.
fn pack_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bodies.len() as u32).to_le_bytes());
    for b in bodies {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// The A2A `task_event` stream's framing facts, held PLANE-SIDE (this file moves to `busbar-a2a` in
/// commit 10). Core's chain mechanism carries NONE of them — they ride each record/input across the
/// neutral seam. `PipeSeparated`, and the scope (the task id) participates in the digest.
const TASK_EVENT_FRAMING: Framing = Framing::PipeSeparated;
const TASK_EVENT_DIGESTS_SCOPE: bool = true;

/// The A2A event's pre-framed content SUFFIX (Option A leading `|`): `|ts|kind|context_id|principal|
/// agent_id|state`. `frame_prelude(prev_hash, task_id, seq) ⧺ suffix` reproduces the legacy
/// [`TaskEventRow`] digest byte stream EXACTLY, so a chain appended through the seam verifies
/// byte-identically against events written before the cleave. `request_id` is excluded, matching the
/// digest (a join key that is absent on the boot/sweep paths must not be able to break an intact chain).
fn task_event_suffix(
    ts: u64,
    kind: &str,
    context_id: &str,
    principal: &str,
    agent_id: &str,
    state: &str,
) -> Vec<u8> {
    format!("|{ts}|{kind}|{context_id}|{principal}|{agent_id}|{state}").into_bytes()
}

/// THE DECODE BRIDGE (plane-side reframe): turn one stored `task_event` body back into a chain record.
///
/// Handles BOTH the NEW neutral `{seq, prev_hash, hash, content}` body the seam persists AND an OLD
/// `serde(TaskEventRow)` body a store held before the cleave — so a deployed store spanning the upgrade
/// both VERIFIES and READS BACK, not merely verifies. The neutral body is tried first (the shape every
/// post-cleave append writes); a legacy row is missing `content` and falls through to the typed decode,
/// whose fields rebuild the identical suffix. `scope` is the task id (the store parent), supplied by the
/// caller and never read from the body.
fn reframe_task_event(scope: &str, body: &[u8]) -> StoreResult<PlaneJournalRecord> {
    if let Ok(nb) = decode::<NeutralBody>(body) {
        return Ok(PlaneJournalRecord::from_parts(
            scope.to_string(),
            nb.seq,
            nb.prev_hash,
            nb.hash,
            nb.content,
            TASK_EVENT_FRAMING,
            TASK_EVENT_DIGESTS_SCOPE,
        ));
    }
    let row: TaskEventRow = decode(body)?;
    let content = task_event_suffix(
        row.ts,
        &row.kind,
        &row.context_id,
        &row.principal,
        &row.agent_id,
        &row.state,
    );
    Ok(PlaneJournalRecord::from_parts(
        scope.to_string(),
        row.seq,
        row.prev_hash,
        row.hash,
        content,
        TASK_EVENT_FRAMING,
        TASK_EVENT_DIGESTS_SCOPE,
    ))
}

/// TEST ONLY: verify a chain presented as TYPED [`TaskEventRow`]s by reframing each into the neutral
/// journal record the seam persists and running the ONE verifier. The typed `ChainedRecord` impl is
/// gone (the row moves to `busbar-a2a`), so a test that holds typed rows — read back through a store
/// test-ext — verifies them through the SAME reframe/digest production reads a persisted chain with.
/// The scope, and the digest's inclusion of it, come from each row's own `task_id`, exactly as the
/// deleted `TaskEventRow::scope_of`/`digest_fields` did.
#[cfg(any(test, feature = "test-support"))]
pub fn verify_task_event_rows(rows: &[TaskEventRow]) -> Result<(), crate::audit::ChainBreak> {
    let records: Vec<PlaneJournalRecord> = rows
        .iter()
        .map(|r| {
            let content = task_event_suffix(
                r.ts,
                &r.kind,
                &r.context_id,
                &r.principal,
                &r.agent_id,
                &r.state,
            );
            PlaneJournalRecord::from_parts(
                r.task_id.clone(),
                r.seq,
                r.prev_hash.clone(),
                r.hash.clone(),
                content,
                TASK_EVENT_FRAMING,
                TASK_EVENT_DIGESTS_SCOPE,
            )
        })
        .collect();
    verify_chain(&records)
}

/// One task in the working set. Its provenance chain POSITION is no longer held here — that moved to
/// the generic [`Journal`], keyed by task id — and the events themselves were never in RAM: the store
/// owns them, and holding every event of every long-running task would defeat a durable store.
#[derive(Debug, Clone)]
struct Entry {
    row: TaskRow,
}

/// Is this canonical A2A task-state token TERMINAL? The engine needs the terminal/active split for
/// the rehydrate skip, eviction and compaction, but it must not name the a2a `TaskState` — the four
/// terminal tokens are part of [`TaskRow::state`]'s canonical closed domain, matched here as strings.
/// Kept byte-identical with `crate::a2a::task::TaskState::is_terminal`, which owns the same set on the
/// codec side; the tokens are fixed by the wire protocol, so the two agree by construction.
fn is_terminal_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "canceled" | "rejected")
}

/// Why a scoped read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// The task does not exist, OR it exists and belongs to somebody else. ONE variant, on purpose:
    /// see the module doc. The caller renders 403 either way, before any task data is assembled.
    NotYours,
}

/// What a boot rehydrate actually found. Every number is reported rather than summed into one
/// "restored" count, because they mean different things to an operator and a single number hides the
/// two that are bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rehydrated {
    /// Active or interrupted tasks brought back and resumable.
    pub active: usize,
    /// Terminal tasks seen and deliberately not loaded into the working set. They stay in the store
    /// for the provenance window; they are not in-flight and nothing resumes them.
    pub terminal: usize,
    /// Rows that would not parse (an unknown state or direction, a missing identity). NOT silently
    /// dropped: a skipped row is an in-flight task that ceased to exist across a deploy, which is
    /// the exact failure this store exists to prevent, so it is counted and logged.
    pub unreadable: usize,
    /// Tasks whose persisted provenance chain FAILED to verify. Tamper evidence. The task is still
    /// restored — refusing to restore it would let anyone who can write to the store delete a task
    /// by corrupting one of its events — but the break is reported and the chain continues from the
    /// broken tail rather than being silently re-based onto it.
    pub chain_breaks: Vec<ChainBreak>,
}

/// The in-flight task registry. No `Debug`: the journal holds a `dyn PlaneStore` (not `Debug` — a
/// backend must not be obliged to render itself, where a credential could surface in a log).
///
/// The WORKING SET (`tasks`) is keyed by task id. The per-task provenance CHAIN's position cache no
/// longer lives here: it moved host-side into the durable-seam DurableStream registered under
/// [`KIND_ID_TASK_EVENT`], reached over the vtable `journal_*_scoped` fns with a threaded [`HostCtx`].
/// This registry keeps only the working set and the durable sink for the `task` ROW upserts (which are
/// NOT chained — the chain is the `task_event` stream's, host-side). The two stay in lockstep: a task
/// is seeded into the working set and its host-side chain at submit/restore and forgotten from both at
/// terminal eviction/compaction. The host-side journal is uncapped (`usize::MAX`) — a task table is
/// bounded by its own lifecycle (terminal eviction + retention), not by an LRU.
pub struct TaskRegistry {
    tasks: Mutex<HashMap<String, Entry>>,
    /// The durable sink for the `task` ROW upserts (see [`task_record`]). NOT the event chain — that
    /// chain's seq-authority + position cache is the host-side DurableStream's now. Attached at boot
    /// beside the stream registration; `None` is the documented `store: memory` RAM-cache posture.
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
    /// The host-side durable stream this registry's `task_event` chain is addressed by. Production is
    /// always [`KIND_ID_TASK_EVENT`] (one process, one A2A task stream); a TEST constructs a registry
    /// over a FRESH id (see [`TaskRegistry::with_kind_id`]) so parallel tests never share one
    /// process-global chain.
    kind_id: u32,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            sink: Mutex::new(None),
            kind_id: KIND_ID_TASK_EVENT,
        }
    }
}

/// THE PROCESS-WIDE REGISTRY. Process state, not config-derived state, so it lives as a global
/// rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`], and for
/// the same reason: a config apply must not destroy in-flight tasks. An operator editing a pool
/// weight and applying it would otherwise take every running task with it, which is a far larger
/// blast radius than the change they made.
pub static TASKS: std::sync::LazyLock<TaskRegistry> = std::sync::LazyLock::new(TaskRegistry::new);

/// TEST ONLY: the one lock every test that attaches a sink to the process-wide [`TASKS`] takes.
///
/// The registry is process state (see [`TASKS`]), so two tests attaching different sinks to it
/// concurrently would interleave and each would read the other's writes. This is the same measure,
/// for the same reason, as `mcp/tests/calllog_dispatch_tests.rs`'s `CALLS_GLOBAL`, and it is an
/// ASYNC mutex for the reason that file states: the guard is held across `.await` points (a real
/// listener is served and a real request is driven), and a blocking guard held across an await parks
/// a runtime worker on a lock another task must run to release. `tokio::sync::Mutex` also has no
/// poisoning, so a panicking test cannot wedge the ones after it.
///
/// It lives here rather than in either test file because the two batteries that need it — the A2A
/// front door's and the push-delivery path's — are mounted from different modules, and two locks
/// over one global is the same thing as no lock.
#[cfg(any(test, feature = "test-support"))]
pub static TASKS_SINK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// TEST ONLY: a fresh, process-unique `task_event` stream id, well above the production ids (1/2) and
/// the `plane_host::journal` test range (base 10_000) and the MCP `call` test range (base 200_000), so
/// a test's local chain never shares the process-global host stream registry with another test's.
#[cfg(any(test, feature = "test-support"))]
pub fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(100_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// TEST ONLY: a registry + an app whose governance store is `store`, with the `task_event` stream
/// registered against it under a FRESH host-side id so parallel tests are isolated. The registry's
/// row-upsert sink is attached too. Every chain write is driven inside [`TaskTestHarness::host`].
#[cfg(any(test, feature = "test-support"))]
pub struct TaskTestHarness {
    pub reg: TaskRegistry,
    pub(crate) app: Arc<crate::state::App>,
    kind_id: u32,
}

#[cfg(any(test, feature = "test-support"))]
impl TaskTestHarness {
    /// Fresh isolated harness over `store` (used as BOTH the chain sink, via registration against an
    /// app whose governance wraps it, AND the row-upsert sink).
    pub fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        let kind_id = fresh_test_kind_id();
        Self::install(kind_id, store)
    }

    /// Re-open a harness over `store` under the SAME `kind_id` — a RESTART: the host-side stream is
    /// re-registered (fresh positions), the durable store is unchanged, and a new registry (empty
    /// working set) is returned for the rehydrate to fill.
    pub fn restart(kind_id: u32, store: Arc<dyn busbar_api::Store>) -> Self {
        Self::install(kind_id, store)
    }

    fn install(kind_id: u32, store: Arc<dyn busbar_api::Store>) -> Self {
        let app = test_app_over(store.clone());
        register_task_event_stream_as(kind_id, &app);
        let reg = TaskRegistry::with_kind_id(kind_id);
        reg.set_sink(crate::plane::store::PlaneStoreView::narrow(store));
        Self { reg, app, kind_id }
    }

    /// This harness's stream id, so a paired [`TaskTestHarness::restart`] addresses the same store.
    pub fn kind_id(&self) -> u32 {
        self.kind_id
    }

    /// Drive one synchronous chain op with a live `HostCtx` over this harness's app.
    pub fn host<R>(&self, f: impl FnOnce(busbar_plugin::hot::host::HostCtx) -> R) -> R {
        crate::plane_host::with_dispatch_scope(&self.app, |h, _| f(h))
    }
}

/// TEST ONLY: a TestApp whose governance store is `store` — the seam a chain test registers its
/// `task_event` stream against so the chain persists to `store`.
#[cfg(any(test, feature = "test-support"))]
pub fn test_app_over(store: Arc<dyn busbar_api::Store>) -> Arc<crate::state::App> {
    let gov =
        Arc::new(crate::governance::GovState::new(store, None).expect("gov store constructs"));
    crate::test_support::TestApp::new().governance(gov).build()
}

/// TEST ONLY: the PRODUCTION `task_event` stream ([`KIND_ID_TASK_EVENT`]), registered ONCE against a
/// shared no-sink app so the many working-set tests over the process-wide [`TASKS`] mint sequences
/// without each racing to re-register (a re-register resets every chain position). A chain-asserting
/// test aims this same stream at its own ledger with [`aim_global_task_sink`] while it holds
/// [`TASKS_SINK_LOCK`] — a sink swap, never a re-register, so positions are left intact.
#[cfg(any(test, feature = "test-support"))]
fn global_task_host_app() -> &'static Arc<crate::state::App> {
    static APP: std::sync::OnceLock<Arc<crate::state::App>> = std::sync::OnceLock::new();
    APP.get_or_init(|| {
        let app = crate::test_support::TestApp::new().build();
        register_task_event_stream(&app);
        app
    })
}

/// TEST ONLY: ensure the process-wide `task_event` stream ([`KIND_ID_TASK_EVENT`]) is registered
/// ONCE (no-sink) — for a front-door INTEGRATION harness whose app is not booted through the real
/// `a2a_hydrate`, so the relay's `TASKS.submit`/`transition` mint sequences. Idempotent (never
/// re-registers, so it never resets a chain position a concurrent test is mid-write on).
#[cfg(any(test, feature = "test-support"))]
pub fn ensure_global_task_stream_registered() {
    let _ = global_task_host_app();
}

/// TEST ONLY: run `f` with a host over the shared global-[`TASKS`] app (registration ensured). The
/// chain append addresses the process-wide [`KIND_ID_TASK_EVENT`] stream; a working-set test leaves it
/// no-sink and only needs a minted `Seq`, a chain test has aimed it at its ledger.
#[cfg(any(test, feature = "test-support"))]
pub fn with_global_task_host<R>(f: impl FnOnce(busbar_plugin::hot::host::HostCtx) -> R) -> R {
    crate::plane_host::with_dispatch_scope(global_task_host_app(), |h, _| f(h))
}

/// TEST ONLY: aim (or detach, with `None`) the process-wide `task_event` stream's durable sink — for a
/// chain-asserting global-[`TASKS`] test holding [`TASKS_SINK_LOCK`].
#[cfg(any(test, feature = "test-support"))]
pub fn aim_global_task_sink(store: Option<Arc<dyn PlaneStore>>) {
    let _ = global_task_host_app();
    crate::plane_host::journal::set_stream_sink_for_test(KIND_ID_TASK_EVENT, store);
}

/// What went wrong servicing a task mutation.
#[derive(Debug)]
pub enum TaskStoreError {
    /// The task id is not in the working set.
    NoSuchTask(String),
    /// The A2A CODEC refused the row or the move — carried as its already-rendered message so the
    /// neutral engine never names the a2a `TaskError`. The caller (which owns the codec) produced the
    /// string via the same `Display` the old `TaskStoreError::Task(TaskError)` printed, so the surface
    /// a caller sees (`illegal task transition ...`, `unknown task state ...`, `task is missing ...`)
    /// is byte-identical.
    Domain(String),
    /// The durable write failed. Surfaced rather than swallowed: a transition that is not durable is
    /// a transition that a restart will lose, and the caller has to be able to decide.
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

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// TEST ONLY: a registry whose `task_event` chain is addressed by a specific host-side stream id,
    /// so parallel tests never share one process-global chain. Production always uses the default
    /// [`KIND_ID_TASK_EVENT`] via [`TaskRegistry::new`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_kind_id(kind_id: u32) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            sink: Mutex::new(None),
            kind_id,
        }
    }

    /// Poison-recovering lock. The data behind it is always still consistent after a panic (the
    /// critical sections only mutate a map), and cascading a poison would make every subsequent task
    /// operation panic too — a task plane that wedges permanently because one request panicked.
    fn tasks(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The durable sink for the `task` ROW upserts. `None` is the documented `store: memory`
    /// RAM-cache posture. The `task_event` chain reaches its OWN sink host-side (attached to the
    /// registered DurableStream), pointing at the same backend.
    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// Attach the configured governance store as the DURABLE SINK for the `task` row upserts. Called
    /// once at boot, beside the `task_event` stream registration (which attaches its own sink from the
    /// same `app.governance`). With no sink the registry is a RAM cache — the `store: memory` posture.
    pub fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// TEST ONLY: drop the row-upsert sink again, so a test that attached one to the process-wide
    /// [`TASKS`] leaves the registry as it found it. There is no production caller and there must not
    /// be: detaching a live deployment's durable sink mid-run would silently stop persisting task
    /// evidence, which is the failure this whole module exists to prevent.
    #[cfg(any(test, feature = "test-support"))]
    pub fn clear_sink_for_test(&self) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// BOOT REHYDRATE. Reads every persisted task, loads the ACTIVE ones into the working set, and
    /// resumes each one's provenance chain from its persisted events.
    ///
    /// Terminal tasks are counted and left in the store: they are not in flight, and loading them
    /// would grow the working set without bound over a deployment's life for no resume value.
    pub fn restore_from_store(
        &self,
        host: HostCtx,
        store: &dyn PlaneStore,
        readable: impl Fn(&TaskRow) -> Result<(), String>,
    ) -> StoreResult<Rehydrated> {
        let rows: Vec<TaskRow> = store
            .list_plane_records(KIND_TASK, &PlaneSelector::All)?
            .iter()
            .map(|body| decode(body))
            .collect::<StoreResult<_>>()?;
        let mut out = Rehydrated::default();
        let mut tasks = self.tasks();
        for row in &rows {
            // Whether the row PARSES is an A2A-codec judgement, so the caller hands the engine a
            // neutral predicate (`Task::from_row` on the a2a side) that answers `Err(msg)` for an
            // unknown state/direction or a missing identity — the exact set the pre-cleave
            // `Task::from_row` refused. The engine never names the codec; it only classifies rows.
            if let Err(e) = readable(row) {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_TASK_ROW_UNREADABLE,
                    task_id = %row.task_id,
                    error = %e,
                    "a persisted A2A task row could not be read back; it is NOT resumable and \
                     is being reported rather than skipped silently"
                );
                out.unreadable += 1;
                continue;
            }
            // The row parsed, so its `state` token is one this binary knows; the terminal/active
            // split is on the canonical token (see [`is_terminal_state`]), byte-identical to the old
            // `task.state.is_terminal()`.
            if is_terminal_state(&row.state) {
                out.terminal += 1;
                continue;
            }
            // The chain is resumed host-side from what is persisted, and VERIFIED first — the durable
            // seam SEEDS this one task's position from the RAW event bodies THIS loop read (it drives
            // the row walk, not the whole-store enumeration, so terminal tasks' chains are never
            // cached). A break is reported and the chain continues from the broken tail: refusing to
            // continue would mean anybody who can corrupt one event can silently stop all further
            // provenance for that task.
            let bodies = store
                .list_plane_records(KIND_TASK_EVENT, &PlaneSelector::Parent(row.task_id.clone()))?;
            if let Some(brk) = self.seed_chain(host, &row.task_id, &bodies)? {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_TASK_CHAIN_VERIFY_FAILED,
                    task_id = %row.task_id,
                    break_detail = %brk,
                    "A2A per-task provenance CHAIN VERIFICATION FAILED on restore — the \
                     persisted events do not verify against their own hash chain"
                );
                out.chain_breaks.push(brk);
            }
            tasks.insert(row.task_id.clone(), Entry { row: row.clone() });
            out.active += 1;
        }
        Ok(out)
    }

    /// SEED one task's HOST-SIDE chain position from its raw stored event bodies, through the durable
    /// seam. The host reframes each body (via [`reframe_task_event_ffi`]), resumes the chain from its
    /// tail and reports whether it verified. On a break the RICH [`ChainBreak`] is recomputed locally
    /// (read-only, touching no position, so it changes no byte) so the operator diagnostic still names
    /// WHICH break and WHERE — the seam header carries only broke/at_index/seq, and the boot log wants
    /// the full vocabulary. A clean verify returns `None`.
    fn seed_chain(
        &self,
        host: HostCtx,
        task_id: &str,
        bodies: &[Vec<u8>],
    ) -> StoreResult<Option<ChainBreak>> {
        let packed = pack_bodies(bodies);
        let hdr =
            crate::plane_host::journal::seed_scoped_via_seam(host, self.kind_id, task_id, &packed)
                .map_err(|()| {
                    StoreError("A2A task-event chain seed failed at the durable seam".to_string())
                })?;
        if hdr.broke == 0 {
            return Ok(None);
        }
        let records: Vec<PlaneJournalRecord> = bodies
            .iter()
            .map(|b| reframe_task_event(task_id, b))
            .collect::<StoreResult<_>>()?;
        Ok(verify_chain(&records).err())
    }

    /// SUBMIT a new task: record it, write it through, and open its provenance chain.
    ///
    /// The durable write happens BEFORE the task is announced as accepted. A task acknowledged to a
    /// caller but not yet persisted is precisely the task a crash loses while the caller believes it
    /// is running.
    pub fn submit(
        &self,
        host: HostCtx,
        row: &TaskRow,
        request_id: &str,
    ) -> Result<TaskRow, TaskStoreError> {
        // The task ROW is upserted first, then the genesis event is minted+appended+committed by the
        // host-side journal (the write-ordering invariant is the journal's) — the same order as
        // before: row durable before the event, working set updated only after both succeed. The
        // caller handed a `TaskRow` it built from the canonical `Task` via the a2a-side codec, so the
        // engine stores it as-is and names no a2a type.
        if let Some(store) = self.sink() {
            store
                .upsert_plane_record(&task_record(row).map_err(TaskStoreError::Store)?)
                .map_err(TaskStoreError::Store)?;
        }
        self.append_event(
            host,
            &row.task_id,
            EventInput {
                kind: provenance::EV_SUBMITTED,
                context_id: row.context_id.clone(),
                principal: row.principal.clone(),
                agent_id: row.agent_id.clone(),
                state: row.state.clone(),
                request_id: request_id.to_string(),
                ts: row.created_at,
            },
        )?;
        self.tasks()
            .insert(row.task_id.clone(), Entry { row: row.clone() });
        Ok(row.clone())
    }

    /// TRANSITION a task, emitting the matching chained provenance event and writing both through.
    ///
    /// The in-memory entry is updated only after the durable write succeeds, so a failed write
    /// leaves the working set agreeing with the store rather than ahead of it. Being ahead is the
    /// worse of the two: it makes the process believe a transition happened that a restart will
    /// then un-happen.
    pub fn transition<F>(
        &self,
        host: HostCtx,
        task_id: &str,
        request_id: &str,
        plan: F,
    ) -> Result<TaskRow, TaskStoreError>
    where
        F: FnOnce(&TaskRow) -> Result<(TaskRow, &'static str), String>,
    {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;

        // THE STATE-MACHINE DECISION IS THE CALLER'S, made HERE under the working-set lock so it is
        // still ATOMIC with the write. `plan` is handed the CURRENT persisted row and returns the new
        // row plus the provenance event `kind` it chose from the transition — both A2A domain logic
        // (validate the move, classify resumed/working/interrupted/terminal) that must not live in
        // core. A rejected move (`Err`) writes NOTHING: nothing below runs until `plan` returns `Ok`,
        // and the rendered message rides the neutral `Domain` variant byte-identically to the old
        // `TaskStoreError::Task(TaskError::IllegalTransition{..})`. The new row's `updated_at` is the
        // move's timestamp (the caller set it), which is also the event `ts` — the same value the old
        // `now` argument carried, so no separate clock reaches the engine.
        let (candidate, kind) = plan(&entry.row).map_err(TaskStoreError::Domain)?;

        self.write_through(
            host,
            &candidate,
            EventInput {
                kind,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.clone(),
                request_id: request_id.to_string(),
                ts: candidate.updated_at,
            },
        )?;
        entry.row = candidate.clone();
        Ok(candidate)
    }

    /// The SHARED write-through for a mutation that changes the task row AND appends a provenance
    /// event: upsert the row durably FIRST, then let the journal mint+append+commit the event under
    /// its write-ordering invariant. Row-before-event and working-set-after-both, the order every
    /// mutator kept before the cleave — extracted here so each one delegates instead of re-deriving it.
    /// The in-memory working set is NOT touched (the caller updates it only after this returns `Ok`).
    fn write_through(
        &self,
        host: HostCtx,
        row: &TaskRow,
        event: EventInput,
    ) -> Result<(), TaskStoreError> {
        if let Some(store) = self.sink() {
            store
                .upsert_plane_record(&task_record(row).map_err(TaskStoreError::Store)?)
                .map_err(TaskStoreError::Store)?;
        }
        self.append_event(host, &row.task_id, event)?;
        Ok(())
    }

    /// APPEND one provenance event to a task's chain through the DURABLE JOURNAL SEAM: build the plane's
    /// pre-framed content suffix, hand the neutral journal the scope (the task id, a durable `String`
    /// key) plus the framing input, and let the ONE core chain mint the seq/prev_hash/hash and persist
    /// the neutral `{seq, prev_hash, hash, content}` body under its write-ordering invariant. The
    /// reframe bridge is consulted only on a cache-miss resume — which never happens here, since the
    /// task journal opts out of position eviction (`usize::MAX`) — but the seam requires it, so the
    /// same [`reframe_task_event`] that boot rehydrate uses is threaded through.
    fn append_event(
        &self,
        host: HostCtx,
        scope: &str,
        event: EventInput,
    ) -> Result<(), TaskStoreError> {
        let content = task_event_suffix(
            event.ts,
            event.kind,
            &event.context_id,
            &event.principal,
            &event.agent_id,
            &event.state,
        );
        // The ONE core chain (host-side, under [`KIND_ID_TASK_EVENT`]) mints the seq/prev_hash/hash,
        // frames the `PipeSeparated` prelude in the stream's registered framing, joins this pre-framed
        // suffix and persists the neutral body under the journal's write-ordering invariant. The stream
        // was registered with the SAME framing/digests_scope this suffix was built for, so the appended
        // chain verifies byte-identically against events written before the seam.
        let seq = crate::plane_host::journal::journal_append_scoped(
            host,
            self.kind_id,
            scope.as_ptr(),
            scope.len(),
            content.as_ptr(),
            content.len(),
        );
        if seq == Seq::NONE {
            return Err(TaskStoreError::Store(StoreError(
                "A2A task-event chain append failed at the durable seam".to_string(),
            )));
        }
        Ok(())
    }

    /// DISPATCH: record which agent this task was routed to, and chain a `task.delegated` event.
    /// Separate from [`TaskRegistry::transition`] because choosing a target is not a state change —
    /// the task is `working` before and after — but it IS the single most important fact the
    /// delegating side's provenance has to carry: who delegated, to which registered agent.
    pub fn record_dispatch(
        &self,
        host: HostCtx,
        task_id: &str,
        agent_id: &str,
        now: u64,
        request_id: &str,
    ) -> Result<TaskRow, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        let mut candidate = entry.row.clone();
        candidate.agent_id = agent_id.to_string();
        candidate.updated_at = now;
        self.write_through(
            host,
            &candidate,
            EventInput {
                kind: provenance::EV_DELEGATED,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.clone(),
                request_id: request_id.to_string(),
                ts: now,
            },
        )?;
        entry.row = candidate.clone();
        Ok(candidate)
    }

    /// RECORD ONE PUSH-NOTIFICATION DELIVERY OUTCOME on the task's own chain.
    ///
    /// Not a transition and not a dispatch: the task's state and its agent are both unchanged by a
    /// webhook attempt, so this appends an event and touches nothing else on the row. It exists
    /// because the delivery path — including its delivery-time SSRF guard, the strongest check on
    /// that path — disposed of every outcome with a log line, so **a refused delivery left no record
    /// an auditor could ever find**. See `provenance::EV_PUSH_REFUSED`.
    ///
    /// A task the working set does not hold gets no event and says so: the caller (`pushdeliver`) is
    /// already on a best-effort path and must not be given a reason to fail a caller's task over
    /// bookkeeping. That is the same posture the rest of this path takes, and the error is returned
    /// rather than swallowed here so the decision stays with the caller.
    pub(crate) fn record_push_delivery(
        &self,
        host: HostCtx,
        task_id: &str,
        kind: &'static str,
        now: u64,
        request_id: &str,
    ) -> Result<(), TaskStoreError> {
        let tasks = self.tasks();
        let entry = tasks
            .get(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        // A delivery attempt changes neither the state nor the agent, so this appends an event and
        // touches nothing else on the row — straight to the journal, no task-row upsert.
        let event = EventInput {
            kind,
            context_id: entry.row.context_id.clone(),
            principal: entry.row.principal.clone(),
            agent_id: entry.row.agent_id.clone(),
            // The state the task was in when the notification carrying it was attempted — the
            // notification body is built from exactly this, so the record says what the receiver
            // was told, not merely that it was told something.
            state: entry.row.state.clone(),
            request_id: request_id.to_string(),
            ts: now,
        };
        self.append_event(host, task_id, event)?;
        Ok(())
    }

    /// ADVANCE THE ARTIFACT CURSOR — how many artifact chunks have been durably relayed.
    ///
    /// MONOTONIC, and a request to move it backwards is refused rather than applied. The cursor is
    /// the resubscribe resume point; rewinding it re-delivers artifact chunks the caller already
    /// has, and on a chunked assembly that is corruption rather than duplication.
    pub fn advance_cursor(
        &self,
        host: HostCtx,
        task_id: &str,
        cursor: u64,
        now: u64,
        request_id: &str,
    ) -> Result<TaskRow, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        if cursor <= entry.row.artifact_cursor {
            return Ok(entry.row.clone());
        }
        let mut candidate = entry.row.clone();
        candidate.artifact_cursor = cursor;
        candidate.updated_at = now;
        self.write_through(
            host,
            &candidate,
            EventInput {
                kind: provenance::EV_ARTIFACT,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.clone(),
                request_id: request_id.to_string(),
                ts: now,
            },
        )?;
        entry.row = candidate.clone();
        Ok(candidate)
    }

    /// Register (or clear) this task's push-notification callback.
    ///
    /// THE FULL SSRF DECISION IS STILL MADE ELSEWHERE — twice, and both are load-bearing:
    /// `ingress::invoke` runs [`crate::a2a::pushnotify::validate`] against a live resolution before the
    /// caller's registration is accepted at all, and [`crate::a2a::pushdeliver`] runs it AGAIN against a
    /// fresh resolution before every single delivery, because a durable row outlives the DNS answer
    /// that was checked when it was written.
    ///
    /// What the SSRF FLOOR adds — a defence-in-depth structural refusal for a URL that reaches the
    /// store without having been validated — is A2A domain logic and now runs at the A2A CALLER
    /// (`crate::a2a::pushnotify::floor_callback`, invoked by the `EngineHost` seam BEFORE this
    /// method), so the neutral engine persists an already-cleared callback and makes no security
    /// decision of its own. The refusal semantics are byte-identical: a refused URL is DROPPED
    /// (`None` reaches here) and logged loudly a2a-side, never surfaced as an error that would fail a
    /// task the caller is owed. The registration path still answers `400` at the ingress.
    pub fn set_push_callback(
        &self,
        task_id: &str,
        callback: Option<String>,
        now: u64,
    ) -> Result<TaskRow, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        let mut candidate = entry.row.clone();
        // `TaskRow.push_callback` is a `String`; `None` is the empty string, matching the old
        // `Task.push_callback: Option<String>` projection through `Task::to_row`.
        candidate.push_callback = callback.unwrap_or_default();
        candidate.updated_at = now;
        if let Some(store) = self.sink() {
            store
                .upsert_plane_record(&task_record(&candidate).map_err(TaskStoreError::Store)?)
                .map_err(TaskStoreError::Store)?;
        }
        entry.row = candidate.clone();
        Ok(candidate)
    }

    /// SCOPED READ. The authorization gate for `GetTask`: a caller sees its own tasks and nothing
    /// else, and cannot tell a foreign id from a nonexistent one.
    pub fn get_scoped(&self, principal: &str, task_id: &str) -> Result<TaskRow, Denied> {
        // An EMPTY principal never matches, even against a row that somehow carried one. The a2a codec
        // refuses to construct a `Task` with an empty principal, so this is belt-and-braces against a
        // future caller that reaches here with an unauthenticated identity: an empty-equals-empty
        // match would turn "not authenticated" into "owns every unattributed task".
        if principal.is_empty() {
            return Err(Denied::NotYours);
        }
        match self.tasks().get(task_id) {
            Some(e) if e.row.principal == principal => Ok(e.row.clone()),
            _ => Err(Denied::NotYours),
        }
    }

    /// SCOPED LIST. The authorization gate for `ListTasks`, sorted by task id so the result is
    /// deterministic (a listing whose order varies makes a diff between two calls unreadable).
    pub fn list_scoped(&self, principal: &str) -> Vec<TaskRow> {
        if principal.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<TaskRow> = self
            .tasks()
            .values()
            .filter(|e| e.row.principal == principal)
            .map(|e| e.row.clone())
            .collect();
        out.sort_by(|a, b| a.task_id.cmp(&b.task_id));
        out
    }

    /// UNSCOPED read — for the retention sweep and the operator surface, never for a caller.
    /// Named so that a call site using it for a caller read is visible in review.
    pub fn get_unscoped(&self, task_id: &str) -> Option<TaskRow> {
        self.tasks().get(task_id).map(|e| e.row.clone())
    }

    /// How many tasks are in the working set. Active + interrupted only — terminal tasks are not
    /// loaded (see [`TaskRegistry::restore_from_store`]).
    pub fn len(&self) -> usize {
        self.tasks().len()
    }

    /// Whether the working set holds no tasks — the `is_empty` twin of [`TaskRegistry::len`].
    pub fn is_empty(&self) -> bool {
        self.tasks().is_empty()
    }

    /// Drop a task from the WORKING SET once it is terminal, leaving its durable rows and its
    /// provenance chain in the store for the retention window.
    ///
    /// Refusing to evict an ACTIVE task is the guard that matters: evicting one loses its chain
    /// position, and the next event for it would open a SECOND chain at seq 1 under the same task
    /// id — two chains that each verify and together describe nothing.
    pub fn evict_terminal(&self, host: HostCtx, task_id: &str) -> bool {
        let mut tasks = self.tasks();
        match tasks.get(task_id) {
            Some(e) if is_terminal_state(&e.row.state) => {
                tasks.remove(task_id);
                // Release the host-side chain position too, in lockstep with the working set — the
                // durable events stay in the store, but a terminal task takes no more appends, so its
                // RAM position is dropped rather than kept for the life of the process.
                crate::plane_host::journal::journal_forget(
                    host,
                    self.kind_id,
                    task_id.as_ptr(),
                    task_id.len(),
                );
                true
            }
            _ => false,
        }
    }

    /// RETENTION: ask the store to drop terminal task rows older than `before`, and drop any
    /// matching working-set entries. Returns how many durable rows went.
    ///
    /// The policy lives at the call site, not here: retention is a setting on the store, not a
    /// subsystem of its own, so this file owns the mechanism and nothing about the window.
    pub fn compact(&self, host: HostCtx, before: u64) -> StoreResult<u64> {
        let removed = match self.sink() {
            Some(store) => store.purge_plane_records_before(KIND_TASK, before)?,
            None => 0,
        };
        let mut tasks = self.tasks();
        let dropped: Vec<String> = tasks
            .iter()
            .filter(|(_, e)| is_terminal_state(&e.row.state) && e.row.updated_at < before)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &dropped {
            tasks.remove(id);
            // Release each dropped task's host-side chain position in lockstep with the working set.
            crate::plane_host::journal::journal_forget(host, self.kind_id, id.as_ptr(), id.len());
        }
        Ok(removed)
    }

    /// VERIFY one task's persisted provenance chain, end to end, against the store.
    ///
    /// This is the operator-facing half of the hash chain, and its existence is the difference
    /// between provenance and decoration: a chain nothing ever recomputes proves nothing, because
    /// nobody ever finds out that it does not.
    pub fn verify_task_chain(
        &self,
        store: &dyn PlaneStore,
        task_id: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        // Reads the store directly and reframes locally — the operator-facing verify wants the rich
        // break (which log, which index) and the record count, both of which the neutral seam header
        // does not carry. It touches no chain position, so it needs no host.
        let events: Vec<PlaneJournalRecord> = store
            .list_plane_records(KIND_TASK_EVENT, &PlaneSelector::Parent(task_id.to_string()))?
            .iter()
            .map(|b| reframe_task_event(task_id, b))
            .collect::<StoreResult<_>>()?;
        match verify_chain(&events) {
            Ok(()) => Ok(Ok(events.len())),
            Err(brk) => Ok(Err(brk)),
        }
    }
}

/// THE CORE-BACKED task reader — the one production implementation of the neutral
/// [`busbar_substrate::plane_host::TaskReader`] seam, installed at boot by the composition root. Each
/// method funnels straight into the SAME `TASKS.{get_scoped, get_unscoped, list_scoped}` a plane used
/// to name directly, so a plane that reads through `task_reader()` runs byte-identical to the in-core
/// callers. A ZST unit struct, so `&CoreTaskReader` promotes to `'static`.
pub struct CoreTaskReader;

impl busbar_substrate::plane_host::TaskReader for CoreTaskReader {
    fn get_scoped(&self, principal: &str, task_id: &str) -> Option<TaskRow> {
        TASKS.get_scoped(principal, task_id).ok()
    }

    fn get_unscoped(&self, task_id: &str) -> Option<TaskRow> {
        TASKS.get_unscoped(task_id)
    }

    fn list_scoped(&self, principal: &str) -> Vec<TaskRow> {
        TASKS.list_scoped(principal)
    }
}

// THE READ-BACK HALF, shared by every battery that asserts on this chain. Mounted here, beside the
// registry whose sink it stands in for, so the two batteries that attach it to the process-wide
// `TASKS` (the front door's and the push-delivery path's) use ONE double — a second double is a
// second thing that can stop matching what a real backend does.
#[cfg(any(test, feature = "test-support"))]
#[path = "tests/event_ledger.rs"]
pub mod event_ledger;
