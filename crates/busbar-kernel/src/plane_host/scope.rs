// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lifecycle SCOPES a plane's host handles live at.
//!
//! The scope types ([`DispatchScope`], [`DurableScope`], [`SessionScope`]) and the settle vocabulary
//! they carry ([`AdmissionId`], [`Settle`], [`Settled`], [`SettleAdmission`]) are the kernel's own
//! plain Rust types: no plugin is on the other side of them, so none is an ABI shape (BUSBAR-1.6.0.md
//! THE DESIGN §11.5 l.1338-1349; the old HOT lane they were borrowed from is retired, §11.11
//! l.1444-1446).

use crate::breaker::CanonicalSignal;
use crate::host_work::handle_engine::{
    ChainPosition, DurableHandleEngine, HandleDenied, HandleEngineError, MutateError, Mutation,
    ScopedMutateError, SubmitRecord, SweepBounds,
};
use busbar_contract::records::RecordStoreError;
use std::any::Any;
use std::sync::{Arc, Mutex};

/// A breaker admission the arena holds, by the id a settle leg names it with. The arena's `Drop`
/// reclaims it (runs the real `Admission::drop`) when the work item's future ends or is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdmissionId(pub u64);

impl AdmissionId {
    /// The reserved "no admission" id: ids the arena hands out start at `1`.
    pub const NONE: AdmissionId = AdmissionId(0);

    /// True iff this is the reserved [`NONE`](Self::NONE) id.
    #[inline]
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// What a settle leg reports against the breaker admission it holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Settle {
    /// The guarded operation succeeded: close the half-open probe, dilute the error window.
    Success,
    /// A failure to fold, carried as the breaker's own canonical signal.
    Failure(CanonicalSignal),
    /// Not an upstream health signal (a busbar-side refusal, a leg never transmitted): release the
    /// probe and record nothing.
    RecordNothing,
}

/// The answer to a settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// The live admission was found, its outcome recorded and its probe consumed.
    Ok,
    /// No live admission carries the id: stale, or already settled.
    Gone,
    /// The settle panicked; nothing is claimed about the cell.
    Fault,
}

/// A settle-capable breaker admission held in the arena — the leak-safety-critical resource of the
/// BREAKER family. Its `Drop` (run by [`DispatchScope::reclaim_all`]) releases the real single-flight
/// half-open probe, so a dropped/cancelled dispatch that never settled cannot wedge the cell in
/// `HalfOpen`; [`settle`](Self::settle) instead records the observed outcome against the breaker,
/// after which the guard's release `Drop` is a no-op.
///
/// The concrete implementor (`plane_host::breaker::BreakerAdmission`) owns the real
/// `store::planes::Admission` RAII token; this trait lets the arena hold it behind a boxed object and
/// still drive its one settle, WITHOUT `scope` depending on the private breaker types.
pub trait SettleAdmission: Send {
    /// Record the observed `signal` against the breaker exactly once. Invoked at most once via
    /// [`DispatchScope::settle_admission`]; after it, the guard's probe-release `Drop` becomes a no-op
    /// (the recorded outcome already consumed HalfOpen).
    fn settle(&mut self, signal: &Settle);
}

/// Which kind of host handle an [`Entry`] carries; named in the reclaim boundary's warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    /// A breaker/failover admission grant.
    Admission,
}

/// One registered, reclaimable resource: an RAII guard whose `Drop` reclaims it (boxed as `dyn Send`
/// so the arena does not reach a private type), or a settle-capable breaker admission.
enum Resource {
    /// An RAII guard: dropping the box runs the guard's `Drop` (the governance admission grant).
    Guard(Box<dyn Send>),
    /// A breaker admission: dropping it releases the single-flight half-open probe (the leak-safety
    /// reclaim), and it can be SETTLED once — recording the outcome — before the scope ends. Boxed
    /// behind [`SettleAdmission`] so the arena never names the private breaker types.
    Admission(Box<dyn SettleAdmission>),
}

/// A registered handle: its kind, its raw id (what the plane holds), and the resource to reclaim.
struct Entry {
    /// What the entry holds, named in the reclaim boundary's warning.
    kind: HandleKind,
    /// The id a settle names it by.
    raw: u64,
    res: Resource,
}

/// The mutable interior of a [`DispatchScope`]. Guarded by a `Mutex` because every host call holds
/// only a shared `&DispatchScope` (through its `HostState`) yet must register/reclaim.
#[derive(Default)]
struct Registry {
    entries: Vec<Entry>,
    /// Monotonic id source; `0` is the reserved `NONE` sentinel of every handle newtype, so ids start
    /// at `1`.
    next: u64,
}

/// The per-dispatch-invocation arena of acquired host handles — the leak-safety keystone.
///
/// Core opens ONE of these per dispatch, and the host calls made for it register every handle they
/// acquire here (through a `HostState` referencing it). On
/// `Drop` — whenever the dispatch future ends OR is dropped — [`reclaim_all`](Self::reclaim_all)
/// reclaims every registered handle, so a cancelled/dropped dispatch can never leak a bare host handle.
pub struct DispatchScope {
    reg: Mutex<Registry>,
}

impl Default for DispatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchScope {
    /// Open an empty dispatch arena.
    #[must_use]
    pub fn new() -> Self {
        DispatchScope {
            reg: Mutex::new(Registry::default()),
        }
    }

    /// Poison-recovering lock: a panic mid-register must not wedge the arena for the reclaim path, so
    /// recover the guard rather than cascade the poison (same discipline as `store::*_recover`).
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.reg.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Allocate the next non-zero raw handle id.
    fn next_raw(reg: &mut Registry) -> u64 {
        reg.next += 1;
        reg.next
    }

    /// Register an admission as an RAII `guard` (the governance admission grant; a test guard in the
    /// arena's own tests). Its `Drop` runs the actual release when the scope drops.
    pub fn register_admission(&self, guard: Box<dyn Send>) -> AdmissionId {
        let mut reg = self.lock();
        let raw = Self::next_raw(&mut reg);
        reg.entries.push(Entry {
            kind: HandleKind::Admission,
            raw,
            res: Resource::Guard(guard),
        });
        AdmissionId(raw)
    }

    /// Register a settle-capable breaker admission (the real `store::planes::Admission` RAII token,
    /// wrapped so it can also be settled) — the BREAKER family's leak-safety keystone. Returns the
    /// arena's [`AdmissionId`]; the plane never holds the bare probe. On scope drop the guard's `Drop`
    /// releases the probe; a prior [`settle_admission`](Self::settle_admission) makes that a no-op.
    pub fn register_settling_admission(&self, guard: Box<dyn SettleAdmission>) -> AdmissionId {
        let mut reg = self.lock();
        let raw = Self::next_raw(&mut reg);
        reg.entries.push(Entry {
            kind: HandleKind::Admission,
            raw,
            res: Resource::Admission(guard),
        });
        AdmissionId(raw)
    }

    /// Settle the breaker admission `id`: record the observed `signal` against the breaker, REMOVING
    /// the entry (so the guard's probe-release `Drop` runs now, a no-op after the record), and answer
    /// [`Settled::Ok`]. Returns `None` when no live admission carries `id` — a stale or
    /// already-settled handle the caller maps to [`Settled::Gone`]. Recording runs with the lock
    /// released, matching [`reclaim_all`](Self::reclaim_all)'s discipline.
    pub fn settle_admission(&self, id: AdmissionId, signal: &Settle) -> Option<Settled> {
        if id.is_none() {
            return None;
        }
        let entry = {
            let mut reg = self.lock();
            let pos = reg
                .entries
                .iter()
                .position(|e| e.raw == id.0 && matches!(e.res, Resource::Admission(_)))?;
            reg.entries.remove(pos)
        };
        match entry.res {
            Resource::Admission(mut guard) => {
                guard.settle(signal);
                drop(guard); // release the probe (a no-op now the outcome is recorded)
                Some(Settled::Ok)
            }
            // Unreachable: the `matches!` above selected an `Admission` entry.
            _ => None,
        }
    }

    /// How many handles are currently registered (test/observability hook).
    #[must_use]
    pub fn registered(&self) -> usize {
        self.lock().entries.len()
    }

    /// Reclaim EVERY registered handle NOW, in reverse (LIFO) acquisition order: drop each guard
    /// (running its real `Drop`). Idempotent — a second call finds an
    /// empty registry. Called by `Drop`; exposed so a test can assert synchronous reclaim on abort.
    ///
    /// EVERY ENTRY GETS ITS OWN BOUNDARY. Reclaiming runs code this loop does not own — a guard's
    /// real `Drop` — and one of those panicking must not cost the
    /// others. Unbounded, a single panic here skips every remaining entry, leaking exactly what this
    /// arena exists to reclaim; and because the loop is reached from `Drop`, that panic unwinding out
    /// of a drop already running during an unwind aborts the process. The boundary contains it to the
    /// entry that raised it, and the loop carries on.
    pub fn reclaim_all(&self) {
        // Take the entries OUT under the lock, then reclaim with the lock released so a reclaim that
        // re-enters the arena cannot deadlock.
        let drained: Vec<Entry> = {
            let mut reg = self.lock();
            std::mem::take(&mut reg.entries)
        };
        for entry in drained.into_iter().rev() {
            let kind = entry.kind;
            // `AssertUnwindSafe`: nothing observable survives a panicking reclaim. The entry is
            // already out of the registry and is consumed here whichever way it ends, so there is no
            // half-updated state left for a later reader to see.
            let reclaimed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match entry.res {
                    Resource::Guard(g) => drop(g),
                    Resource::Admission(g) => drop(g), // Drop releases the single-flight probe.
                }
            }));
            if reclaimed.is_err() {
                tracing::warn!(
                    handle_kind = ?kind,
                    "a host-handle reclaim panicked; the remaining handles were reclaimed anyway"
                );
            }
        }
    }
}

impl Drop for DispatchScope {
    fn drop(&mut self) {
        self.reclaim_all();
    }
}

/// The CONNECTION-lifetime scope (DESIGN-v5-taxonomy Axis 2): ONE live stateful session that owns a
/// single durable handle in the [`DurableHandleEngine`] for longer than one exchange (a duplex/session
/// plane; a DB-wire plane). It is a thin, NEUTRAL binding — an `Arc` on the process-wide engine plus
/// the session's `(owner, id)` coordinates — and nothing about any one plane's record. It NAMES no
/// engine mechanic of its own; every method delegates to the engine the substrate already owns.
///
/// The owner is load-bearing, not decorative: the session's whole lifecycle keys on it. [`get`] reads
/// through the engine's SCOPED anti-enumeration lookup and [`mutate`]/[`close`] gate on ownership, so a
/// SECOND session bound to the same `id` under a DIFFERENT owner collapses to the exact same
/// indistinguishable refusal ([`HandleDenied::NotYours`] / [`ScopedMutateError::NotYours`]) the engine
/// enforces — a foreign owner can neither read, resume, nor evict the handle, and cannot even tell it
/// exists. That is the anti-enumeration contract carried up to the session surface unchanged.
///
/// [`get`]: SessionScope::get
/// [`mutate`]: SessionScope::mutate
/// [`close`]: SessionScope::close
pub struct SessionScope {
    /// The process-wide durable-handle engine this session's handle lives in.
    engine: Arc<DurableHandleEngine>,
    /// The principal the handle is attributed to — the ONLY key the engine's scoped read/write match
    /// on. Every [`get`](Self::get)/[`mutate`](Self::mutate)/[`close`](Self::close) passes this owner,
    /// so a session under the wrong owner is refused identically to a missing handle.
    owner: String,
    /// The opaque handle id this session is bound to (the engine's working-set key).
    id: String,
}

impl SessionScope {
    /// Bind a session to the durable handle keyed by `id`, attributed to `owner`, living in `engine`.
    /// Pure binding — it touches the engine only on the later [`open`](Self::open) /
    /// [`get`](Self::get) / [`mutate`](Self::mutate) / [`close`](Self::close). Use this to attach to a
    /// handle the engine already holds (a boot-rehydrated one, or a second live view), or as the first
    /// step before [`open`](Self::open) submits a fresh one.
    #[must_use]
    pub fn new(
        engine: Arc<DurableHandleEngine>,
        owner: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        SessionScope {
            engine,
            owner: owner.into(),
            id: id.into(),
        }
    }

    /// The principal this session's handle is attributed to.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The opaque handle id this session is bound to.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// OPEN this session's handle: submit a fresh durable handle to the engine at the genesis position.
    /// Delegates straight to [`DurableHandleEngine::submit`]; `plan` builds the row + records + optional
    /// genesis event (the plane computes any digest), and `report_fail` receives the failure to take
    /// back a row whose genesis append failed. Returns the installed opaque row. The retention sweep
    /// this submit may claim touches only settled handles; a live session stays until it is settled.
    ///
    /// The caller's `plan` MUST stamp the returned [`SubmitRecord`] with THIS session's [`id`](Self::id)
    /// and a [`HandleMeta`](crate::host_work::handle_engine::HandleMeta) owner equal to this session's
    /// [`owner`](Self::owner): the session keys every later scoped call on that pair, so a genesis under
    /// a diverging owner/id would leave this session unable to read or resume what it just opened.
    pub fn open<P, R>(
        &self,
        now: u64,
        bounds: SweepBounds,
        plan: P,
        report_fail: R,
    ) -> Result<Arc<dyn Any + Send + Sync>, HandleEngineError>
    where
        P: FnOnce(&ChainPosition) -> Result<SubmitRecord, RecordStoreError>,
        R: Fn(&str, &RecordStoreError),
    {
        self.engine.submit(now, bounds, plan, report_fail)
    }

    /// GET this session's current opaque row through the engine's SCOPED read — a session bound under a
    /// foreign owner (or to a since-evicted id) is refused with the one indistinguishable
    /// [`HandleDenied::NotYours`], never learning whether the handle exists.
    pub fn get(&self) -> Result<Arc<dyn Any + Send + Sync>, HandleDenied> {
        self.engine.scoped_get(&self.owner, &self.id)
    }

    /// MUTATE this session's handle through [`DurableHandleEngine::scoped_mutate`], always under THIS
    /// session's owner: the engine runs its owner gate FIRST, so a foreign-owner session is refused with
    /// [`ScopedMutateError::NotYours`] BEFORE `plan` ever runs — identically to a missing handle, leaking
    /// nothing. Only an owner match runs `plan` (which sees the current row + chain position) and the
    /// engine's persist-then-update path. Returns the resulting opaque row.
    pub fn mutate<F>(&self, plan: F) -> Result<Arc<dyn Any + Send + Sync>, ScopedMutateError>
    where
        F: FnOnce(
            &(dyn Any + Send + Sync),
            &ChainPosition,
        ) -> Result<Option<Mutation>, MutateError>,
    {
        self.engine.scoped_mutate(&self.owner, &self.id, plan)
    }

    /// CLOSE this session: evict its handle from the working set once it has reached a TERMINAL state,
    /// leaving its durable rows in the store. Ownership-gated the same way as [`mutate`](Self::mutate) —
    /// a foreign-owner session evicts nothing and returns `false`, indistinguishable from a missing
    /// handle. Returns `true` only when this session owns the handle AND it was terminal (so it was
    /// evicted); a still-ACTIVE handle is refused eviction and returns `false`.
    pub fn close(&self) -> bool {
        // Prove ownership through the same scoped read the engine gates on: a foreign owner sees
        // NotYours and evicts nothing, so close cannot become an enumeration oracle either.
        if self.engine.scoped_get(&self.owner, &self.id).is_err() {
            return false;
        }
        self.engine.evict_if_terminal(&self.id)
    }
}

/// The DURABLE unit-of-work scope (DESIGN-v5-taxonomy Axis 2). Reclaims on explicit complete/expire
/// and SURVIVES the process; holds durable work-handles and deferred-callback context. Critically a
/// durable work-handle is NOT reclaimed at dispatch-future drop (that was the v4 arena bug) — the async
/// plane parks a handle at a `202` and resumes it later by nested lookup.
///
/// The DURABLE HANDOFF (the `create_task` gap): a breaker probe-hold that `into_task_dispatch`
/// moves out of the per-request [`DispatchScope`] into the detached runner must NOT reclaim when the
/// REQUEST future drops (that would release the probe mid-task and wedge the cell). Handing it to a
/// `DurableScope` the RUNNER owns re-homes its reclaim to TASK end: this scope drops with the runner —
/// on the task's normal completion AND on a `tasks/cancel` abort — running the moved-in guard's `Drop`
/// (the owner-checked probe release) exactly then, not a moment earlier.
///
/// SETTLE-CAPABLE, not merely drop-only (the create_task gap): a breaker probe-hold handed here
/// can be RECORDED against the breaker exactly once via [`settle`](Self::settle) before the scope
/// drops — so a detached runner leg can fold its observed outcome into the same `(key, lane)` cell
/// the admission consulted, and only the UNSETTLED probe releases on drop. A settle before the drop
/// makes the drop a no-op, exactly as it does in the per-request [`DispatchScope`].
///
/// Lazily allocated: the inner arena is empty (no heap) until a handle is actually handed off, so a
/// durable scope that parks nothing costs nothing.
#[derive(Default)]
#[non_exhaustive]
pub struct DurableScope {
    /// The durable arena. Reuses the [`DispatchScope`] machinery (register / settle / reclaim) so the
    /// handoff, the one settle, and the owner-checked release are byte-for-byte the per-request
    /// arena's — the ONLY difference is WHO owns this scope (the detached runner, so it drops at TASK
    /// end) rather than any change in mechanics. A settle over this arena therefore drives the exact
    /// same `breaker_settle` path the per-request one does.
    arena: DispatchScope,
}

impl DurableScope {
    /// Open an empty durable scope.
    #[must_use]
    pub fn new() -> Self {
        DurableScope {
            arena: DispatchScope::new(),
        }
    }

    /// Take DROP-ONLY durable ownership of `guard`: its `Drop` now reclaims when this scope drops
    /// (task end), NOT at dispatch-future drop.
    pub fn handoff(&self, guard: Box<dyn Send>) {
        self.arena.register_admission(guard);
    }

    /// SETTLE the durable breaker admission `id`: record `signal` against the breaker exactly once,
    /// releasing the probe (a no-op after the record). `None` when no live admission carries `id`
    /// here (stale / already settled). This is the detached-leg settle the runner reaches for on the
    /// create_task path.
    pub fn settle(&self, id: AdmissionId, signal: &Settle) -> Option<Settled> {
        self.arena.settle_admission(id, signal)
    }

    /// Borrow the durable arena as a [`DispatchScope`], so the host's `breaker_settle` settles a
    /// durable admission with no change to the breaker path.
    #[must_use]
    pub fn arena(&self) -> &DispatchScope {
        &self.arena
    }

    /// How many durable handles this scope owns (test/observability hook).
    #[must_use]
    pub fn registered(&self) -> usize {
        self.arena.registered()
    }

    /// Reclaim EVERY handed-off handle NOW, in reverse (LIFO) handoff order. Idempotent; the inner
    /// arena's own `Drop` runs it when this scope drops, so an explicit call is only for a task-complete
    /// path that reclaims synchronously.
    pub fn reclaim_all(&self) {
        self.arena.reclaim_all();
    }
}

#[cfg(test)]
#[path = "tests/scope_tests.rs"]
mod tests;
