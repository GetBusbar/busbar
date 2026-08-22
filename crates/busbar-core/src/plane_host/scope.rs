// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lifecycle SCOPES a plane's host handles live at (DESIGN-LOCKED §4, DESIGN-v5-taxonomy Axis 2).
//!
//! Every host handle a plane acquires is acquired AT a scope, and the host reclaims it when that
//! scope ends or is dropped. The taxonomy names three:
//!
//! | Scope | reclaim trigger | holds |
//! |---|---|---|
//! | [`DispatchScope`] | the work-item future ends/drops (disconnect / cancel / panic / parked-at-await) | admission, one-shot egress, subprocess pipe, verify-leadership lease |
//! | [`SessionScope`] | the connection closes | per-connection state, pooled backend conn, in-flight leases |
//! | [`DurableScope`] | explicit complete / expire (SURVIVES the process) | durable work-handles, deferred-callback context |
//!
//! Only [`DispatchScope`] is built out here — it is the leak-safety KEYSTONE. [`SessionScope`] and
//! [`DurableScope`] are documented minimal stubs the riders wire later.
//!
//! ## Why the dispatch arena exists (the leak fix)
//!
//! A plane never holds a live `Admission` / egress / subprocess; it holds an OPAQUE handle-id and the
//! host owns the real resource. If a plane took a bare handle and its dispatch future were then
//! dropped (client disconnect, cancel, panic, or a future parked at an `.await` that never resumes),
//! the real resource would leak — and a leaked breaker `Admission` wedges the circuit in `HalfOpen`
//! forever (nothing runs its release `Drop`). The [`DispatchScope`] closes that hole: EVERY handle the
//! plane takes during one dispatch invocation is registered in this per-invocation arena, and the
//! arena's own `Drop` reclaims ALL of them — running the real `Admission::drop`, closing egress,
//! killing subprocesses — no matter how the dispatch future ends. RAII across the FFI seam, scoped to
//! exactly what core controls.

use busbar_plugin::hot::{AdmissionId, EgressId, PipeId, Signal, StatusClass, VerifyLease};
use std::sync::Mutex;

/// A reclaim action for a handle whose release is an explicit host call (close an egress, kill a
/// subprocess, drop a leadership lease). Phase 2 fills these with the real host-side calls; each runs
/// exactly once, when the [`DispatchScope`] drops.
type Reclaim = Box<dyn FnOnce() + Send + 'static>;

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
    /// Record the observed `signal` against the breaker exactly once and return the resulting ABI
    /// [`StatusClass`]. Invoked at most once via [`DispatchScope::settle_admission`]; after it, the
    /// guard's probe-release `Drop` becomes a no-op (the recorded outcome already consumed HalfOpen).
    fn settle(&mut self, signal: &Signal) -> StatusClass;
}

/// Which kind of host handle an [`Entry`] carries. Kept alongside the raw id so the Phase-2 fan-out
/// can resolve a plane-held handle-id back to its registered resource (e.g. `egress_write(id)`), and
/// so the same raw `u64` under two kinds never collides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    /// A breaker/failover admission grant.
    Admission,
    /// A one-shot / duplex governed egress.
    Egress,
    /// A subprocess (or raw-connection) duplex byte pipe.
    Pipe,
    /// A single-flight counterparty-verification leadership lease.
    VerifyLease,
}

/// One registered, reclaimable resource. Either an RAII guard whose `Drop` reclaims it (the shape the
/// real breaker `store::planes::Admission` takes in Phase 2 — boxed as `dyn Send` so this scaffold does
/// not reach a private type), or an explicit [`Reclaim`] closure the arena runs once on drop.
enum Resource {
    /// An RAII guard: dropping the box runs the guard's `Drop`. Used for the real admission guard in
    /// Phase 2 and by the arena's own unit test.
    Guard(Box<dyn Send>),
    /// An explicit reclaim call, taken and run once on scope drop.
    Closer(Option<Reclaim>),
    /// A breaker admission: dropping it releases the single-flight half-open probe (the leak-safety
    /// reclaim), and it can be SETTLED once — recording the outcome — before the scope ends. Boxed
    /// behind [`SettleAdmission`] so the arena never names the private breaker types.
    Admission(Box<dyn SettleAdmission>),
}

/// A registered handle: its kind, its raw id (what the plane holds), and the resource to reclaim.
struct Entry {
    // `kind` + `raw` are the Phase-2 lookup key: the fan-out resolves a plane-held handle-id back to
    // its registered resource (e.g. `egress_write(EgressId)` → this entry). The scaffold only RECLAIMS
    // (which needs `res` alone), so they are write-only until that fan-out lands.
    #[allow(dead_code)]
    kind: HandleKind,
    #[allow(dead_code)]
    raw: u64,
    res: Resource,
}

/// The mutable interior of a [`DispatchScope`]. Guarded by a `Mutex` because every vtable fn holds
/// only a shared `&DispatchScope` (via the recovered `HostState`) yet must register/reclaim.
#[derive(Default)]
struct Registry {
    entries: Vec<Entry>,
    /// Monotonic id source; `0` is the reserved `NONE` sentinel of every handle newtype, so ids start
    /// at `1`.
    next: u64,
}

/// The per-dispatch-invocation arena of acquired host handles — the leak-safety keystone (§4).
///
/// Core opens ONE of these per dispatch, hands the plane a [`HostCtx`](super::HostCtx) that recovers a
/// `HostState` referencing it, and the plane's host calls register every handle they acquire here. On
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

    /// Register a breaker admission as an RAII `guard` (the real `store::planes::Admission` in Phase 2;
    /// a test guard here). Its `Drop` runs the actual release when the scope drops.
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

    /// Settle the breaker admission `id`: record the observed `signal` against the breaker and return
    /// the resulting ABI [`StatusClass`], REMOVING the entry (so the guard's probe-release `Drop` runs
    /// now, a no-op after the record). Returns `None` when no live admission carries `id` — a stale or
    /// already-settled handle the caller maps to `Gone`. Recording runs with the lock released, matching
    /// [`reclaim_all`](Self::reclaim_all)'s discipline.
    pub fn settle_admission(&self, id: AdmissionId, signal: &Signal) -> Option<StatusClass> {
        if id.is_none() {
            return None;
        }
        let entry = {
            let mut reg = self.lock();
            let pos = reg.entries.iter().position(|e| {
                e.raw == id.0 && matches!(e.res, Resource::Admission(_))
            })?;
            reg.entries.remove(pos)
        };
        match entry.res {
            Resource::Admission(mut guard) => {
                let class = guard.settle(signal);
                drop(guard); // release the probe (a no-op now the outcome is recorded)
                Some(class)
            }
            // Unreachable: the `matches!` above selected an `Admission` entry.
            _ => None,
        }
    }

    /// Register an open governed egress with the `reclaim` that closes it (Phase 2: `egress_close`).
    pub fn register_egress(&self, reclaim: Reclaim) -> EgressId {
        let mut reg = self.lock();
        let raw = Self::next_raw(&mut reg);
        reg.entries.push(Entry {
            kind: HandleKind::Egress,
            raw,
            res: Resource::Closer(Some(reclaim)),
        });
        EgressId(raw)
    }

    /// Register a subprocess/raw-connection pipe with the `reclaim` that kills/closes it (Phase 2).
    pub fn register_pipe(&self, reclaim: Reclaim) -> PipeId {
        let mut reg = self.lock();
        let raw = Self::next_raw(&mut reg);
        reg.entries.push(Entry {
            kind: HandleKind::Pipe,
            raw,
            res: Resource::Closer(Some(reclaim)),
        });
        PipeId(raw)
    }

    /// Register a verification leadership lease with the `reclaim` that releases it (Phase 2).
    pub fn register_lease(&self, reclaim: Reclaim) -> VerifyLease {
        let mut reg = self.lock();
        let raw = Self::next_raw(&mut reg);
        reg.entries.push(Entry {
            kind: HandleKind::VerifyLease,
            raw,
            res: Resource::Closer(Some(reclaim)),
        });
        VerifyLease(raw)
    }

    /// How many handles are currently registered (test/observability hook).
    #[must_use]
    pub fn registered(&self) -> usize {
        self.lock().entries.len()
    }

    /// Reclaim EVERY registered handle NOW, in reverse (LIFO) acquisition order: drop each guard
    /// (running its real `Drop`) and run each closer exactly once. Idempotent — a second call finds an
    /// empty registry. Called by `Drop`; exposed so a test can assert synchronous reclaim on abort.
    pub fn reclaim_all(&self) {
        // Take the entries OUT under the lock, then reclaim with the lock released so a reclaim that
        // re-enters the arena cannot deadlock.
        let drained: Vec<Entry> = {
            let mut reg = self.lock();
            std::mem::take(&mut reg.entries)
        };
        for entry in drained.into_iter().rev() {
            match entry.res {
                Resource::Guard(g) => drop(g),
                Resource::Admission(g) => drop(g), // Drop releases the single-flight probe.
                Resource::Closer(Some(reclaim)) => reclaim(),
                Resource::Closer(None) => {}
            }
        }
    }
}

impl Drop for DispatchScope {
    fn drop(&mut self) {
        self.reclaim_all();
    }
}

/// The CONNECTION-lifetime scope (DESIGN-v5-taxonomy Axis 2). Reclaims on connection close; holds
/// per-connection state, a pooled backend connection, and in-flight leases (a2a session; DB-wire).
///
/// STUB: minimal by design. The riders that add a duplex/session plane wire this out (a per-connection
/// opaque-state slot joins the per-plane one, §6); until then it exists only to NAME the scope in the
/// hierarchy so a future add is append-only, never a reshape.
#[derive(Default)]
#[non_exhaustive]
pub struct SessionScope {}

impl SessionScope {
    /// Open an empty session scope.
    #[must_use]
    pub fn new() -> Self {
        SessionScope {}
    }
}

/// The DURABLE unit-of-work scope (DESIGN-v5-taxonomy Axis 2). Reclaims on explicit complete/expire
/// and SURVIVES the process; holds durable work-handles and deferred-callback context. Critically a
/// durable work-handle is NOT reclaimed at dispatch-future drop (that was the v4 arena bug) — the async
/// plane parks a handle at a `202` and resumes it later by nested lookup.
///
/// The DURABLE HANDOFF (§4, the `create_task` gap): a breaker probe-hold that `into_task_dispatch`
/// moves out of the per-request [`DispatchScope`] into the detached runner must NOT reclaim when the
/// REQUEST future drops (that would release the probe mid-task and wedge the cell). Handing it to a
/// `DurableScope` the RUNNER owns re-homes its reclaim to TASK end: this scope drops with the runner —
/// on the task's normal completion AND on a `tasks/cancel` abort — running the moved-in guard's `Drop`
/// (the owner-checked probe release) exactly then, not a moment earlier.
///
/// Lazily allocated: the handle vector is empty (no heap) until a handle is actually handed off, so a
/// durable scope that parks nothing costs nothing.
#[derive(Default)]
#[non_exhaustive]
pub struct DurableScope {
    /// Handles handed to durable (unit-of-work) ownership. Each is an RAII guard whose `Drop`
    /// reclaims it when THIS scope drops (task complete/expire/abort) — never at dispatch-future
    /// drop. Boxed `dyn Send` so the runner can hold it behind the scope without naming the concrete
    /// resource type (e.g. `store::planes::Admission`).
    handles: Vec<Box<dyn Send>>,
}

impl DurableScope {
    /// Open an empty durable scope.
    #[must_use]
    pub fn new() -> Self {
        DurableScope {
            handles: Vec::new(),
        }
    }

    /// Open a durable scope that already owns `guard` — the `into_task_dispatch` handoff in one step:
    /// the breaker probe-hold moves from the per-request dispatch arena into a runner-owned durable
    /// scope, so its `Drop` reclaim runs at TASK end rather than request end.
    #[must_use]
    pub fn with_handoff(guard: Box<dyn Send>) -> Self {
        DurableScope {
            handles: vec![guard],
        }
    }

    /// Take durable ownership of `guard`: its `Drop` now reclaims when this scope drops (task end),
    /// NOT at dispatch-future drop. This is the durable HANDOFF — the resource leaves the per-request
    /// arena's lifetime and joins the unit-of-work's.
    pub fn handoff(&mut self, guard: Box<dyn Send>) {
        self.handles.push(guard);
    }

    /// How many durable handles this scope owns (test/observability hook).
    #[must_use]
    pub fn registered(&self) -> usize {
        self.handles.len()
    }

    /// Reclaim EVERY handed-off handle NOW, in reverse (LIFO) handoff order — dropping each guard runs
    /// its real `Drop` (the owner-checked release). Idempotent; called by `Drop`, exposed so an
    /// explicit task-complete path can reclaim synchronously.
    pub fn reclaim_all(&mut self) {
        while let Some(guard) = self.handles.pop() {
            drop(guard);
        }
    }
}

impl Drop for DurableScope {
    fn drop(&mut self) {
        self.reclaim_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut dur = DurableScope::new();
        assert_eq!(dur.registered(), 0, "an empty durable scope owns nothing");
        dur.handoff(Box::new(DropCounter(count.clone())));
        dur.handoff(Box::new(DropCounter(count.clone())));
        assert_eq!(dur.registered(), 2);
        dur.reclaim_all();
        assert_eq!(count.load(Ordering::SeqCst), 2, "both durable handles reclaimed");
        assert_eq!(dur.registered(), 0);
        // Idempotent: the Drop after an explicit reclaim is a no-op.
        dur.reclaim_all();
        assert_eq!(count.load(Ordering::SeqCst), 2);
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
}
