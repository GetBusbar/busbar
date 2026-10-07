// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lifecycle SCOPES that outlive one dispatch: [`SessionScope`] (one live session's durable
//! handle) and [`DurableScope`] (handles handed off past the request future). The per-dispatch
//! arena they build on, [`DispatchScope`], is `crate::plane::dispatch_scope`'s, re-exported here.

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
pub use crate::plane::dispatch_scope::{DispatchScope, EgressFaultDetail, SettleAdmission};
use crate::plane::handle_engine::{
    ChainPosition, DurableHandleEngine, HandleDenied, HandleEngineError, MutateError, Mutation,
    ScopedMutateError, SubmitRecord, SweepBounds,
};
use busbar_contract::abi::hot::{AdmissionId, Signal, StatusClass};
use busbar_contract::records::RecordStoreError;
use std::any::Any;
use std::sync::Arc;

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
    /// genesis event (the plane computes any digest), `abandon` is the retention-sweep transition, and
    /// `report_fail` receives a sweep-time durable failure. Returns the installed opaque row.
    ///
    /// The caller's `plan` MUST stamp the returned [`SubmitRecord`] with THIS session's [`id`](Self::id)
    /// and a [`HandleMeta`](crate::plane::handle_engine::HandleMeta) owner equal to this session's
    /// [`owner`](Self::owner): the session keys every later scoped call on that pair, so a genesis under
    /// a diverging owner/id would leave this session unable to read or resume what it just opened.
    pub fn open<P, A, R>(
        &self,
        now: u64,
        bounds: SweepBounds,
        plan: P,
        abandon: A,
        report_fail: R,
    ) -> Result<Arc<dyn Any + Send + Sync>, HandleEngineError>
    where
        P: FnOnce(&ChainPosition) -> Result<SubmitRecord, RecordStoreError>,
        A: Fn(&str, &(dyn Any + Send + Sync), &ChainPosition, u64) -> Option<Mutation>,
        R: Fn(&str, &RecordStoreError),
    {
        self.engine.submit(now, bounds, plan, abandon, report_fail)
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
    /// end) rather than any change in mechanics. A `HostState` materialized over this arena
    /// therefore drives the exact same `breaker_settle` seam the per-request path does.
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

    /// SETTLE the durable breaker admission `id`: record `signal` against the breaker exactly once and
    /// return the resulting ABI [`StatusClass`], releasing the probe (a no-op after the record).
    /// `None` when no live admission carries `id` here (stale / already settled). This is the
    /// detached-leg settle the runner reaches for on the create_task path.
    pub fn settle(&self, id: AdmissionId, signal: &Signal) -> Option<StatusClass> {
        self.arena.settle_admission(id, signal)
    }

    /// Borrow the durable arena as a [`DispatchScope`] so a `HostState` can be materialized
    /// over it — the seam that lets the host `breaker_settle` vtable slot settle a durable admission
    /// with no change to the breaker path.
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
