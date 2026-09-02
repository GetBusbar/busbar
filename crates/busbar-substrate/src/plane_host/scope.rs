// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lifecycle SCOPES a plane's host handles live at.
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

use busbar_plugin::hot::{
    AdmissionId, EgressFailClass, EgressId, PipeId, Signal, StatusClass, VerifyLease,
};
use std::sync::Mutex;

/// The neutral FAILURE detail the host stashes when an `egress_open` fails, so the plane can read it
/// back through `egress_fault` and compose its OWN operator string. Held in the [`DispatchScope`] (not
/// a process global) so the bytes live exactly for the dispatch that produced them and are reclaimed
/// with it; the CAUSE (the flattened transport-error chain) and the URL are kept SEPARATE so each
/// plane chooses to include or strip the url.
#[derive(Clone, Debug)]
pub struct EgressFaultDetail {
    /// The neutral failure class the plane maps to its own failover/refusal taxonomy.
    pub class: EgressFailClass,
    /// The observed status (0 when the failure was before a response head).
    pub status: u16,
    /// The flattened cause-message bytes (the transport-error chain), url-free.
    pub cause: String,
    /// The target url bytes, kept separate from the cause.
    pub url: String,
}

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

/// The per-dispatch-invocation arena of acquired host handles — the leak-safety keystone.
///
/// Core opens ONE of these per dispatch, hands the plane a `HostCtx` that recovers a
/// `HostState` referencing it, and the plane's host calls register every handle they acquire here. On
/// `Drop` — whenever the dispatch future ends OR is dropped — [`reclaim_all`](Self::reclaim_all)
/// reclaims every registered handle, so a cancelled/dropped dispatch can never leak a bare host handle.
pub struct DispatchScope {
    reg: Mutex<Registry>,
    /// The last failed `egress_open`'s neutral fault detail, stashed here so the plane reads it back
    /// through `egress_fault` after a non-`Ok` open. Lives with the dispatch (reclaimed on drop); holds
    /// only the LAST fault (the "read it immediately after the failing open" contract, like the govern
    /// refusal reason).
    egress_fault: Mutex<Option<EgressFaultDetail>>,
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
            egress_fault: Mutex::new(None),
        }
    }

    /// STASH the neutral fault detail of a just-failed `egress_open`, so a following `egress_fault`
    /// hands it to the plane. Overwrites any prior unread fault (the last-fault contract).
    pub fn stash_egress_fault(&self, detail: EgressFaultDetail) {
        *self.egress_fault.lock().unwrap_or_else(|e| e.into_inner()) = Some(detail);
    }

    /// TAKE (and clear) the stashed egress fault, or `None` when none is pending. Consuming so a stale
    /// fault cannot be re-read against a later, unrelated open.
    pub fn take_egress_fault(&self) -> Option<EgressFaultDetail> {
        self.egress_fault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
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
            let pos = reg
                .entries
                .iter()
                .position(|e| e.raw == id.0 && matches!(e.res, Resource::Admission(_)))?;
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

    /// Register a settle-capable breaker admission under a CALLER-SUPPLIED raw id rather than a
    /// freshly-minted one — the receiving half of the [`DurableScope`] handoff (see
    /// [`handoff_settling_to`](Self::handoff_settling_to)). The monotonic `next` counter is advanced
    /// past `raw` so a later mint in this arena cannot collide with the adopted id. Returns the
    /// [`AdmissionId`] the entry now answers to (== `AdmissionId(raw)`).
    pub fn adopt_settling_admission(
        &self,
        raw: u64,
        guard: Box<dyn SettleAdmission>,
    ) -> AdmissionId {
        let mut reg = self.lock();
        if raw > reg.next {
            reg.next = raw;
        }
        reg.entries.push(Entry {
            kind: HandleKind::Admission,
            raw,
            res: Resource::Admission(guard),
        });
        AdmissionId(raw)
    }

    /// HAND OFF the settling admission `id` from THIS (per-request) arena into `dst`, a
    /// [`DurableScope`] whose lifetime is the unit of work's — WITHOUT losing settle-ability. The
    /// `Box<dyn SettleAdmission>` (its real single-flight probe hold) is REMOVED from this arena so
    /// the per-request future's drop no longer reclaims it, and re-homed into `dst` under the SAME
    /// [`AdmissionId`] so a later [`DurableScope::settle`] still resolves it. Returns the preserved
    /// id on success, `None` when `id` names no live settling admission here (stale / already handed).
    ///
    /// This is the durable handoff at the arena level: the breaker probe-hold leaves request scope
    /// and joins the durable scope, so its owner-checked release fires at TASK end, not request end.
    pub fn handoff_settling_to(&self, id: AdmissionId, dst: &DurableScope) -> Option<AdmissionId> {
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
            Resource::Admission(guard) => Some(dst.adopt_settling(id, guard)),
            // Unreachable: the `position` above selected an `Admission` entry.
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
/// per-connection state, a pooled backend connection, and in-flight leases — for any plane that owns a
/// connection for longer than one exchange (a duplex/session plane; a DB-wire plane).
///
/// STUB: minimal by design. The riders that add a duplex/session plane wire this out (a per-connection
/// opaque-state slot joins the per-plane one); until then it exists only to NAME the scope in the
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

    /// Open a durable scope that already owns a DROP-ONLY `guard` in one step (the guard's `Drop`
    /// reclaims at TASK end). Prefer [`register_settling`](Self::register_settling) when the moved
    /// resource is a breaker admission that a detached leg may still want to settle.
    #[must_use]
    pub fn with_handoff(guard: Box<dyn Send>) -> Self {
        let dur = DurableScope::new();
        dur.handoff(guard);
        dur
    }

    /// Take DROP-ONLY durable ownership of `guard`: its `Drop` now reclaims when this scope drops
    /// (task end), NOT at dispatch-future drop.
    pub fn handoff(&self, guard: Box<dyn Send>) {
        self.arena.register_admission(guard);
    }

    /// Take SETTLE-CAPABLE durable ownership of `guard` and return the [`AdmissionId`] it answers to.
    /// Its probe-release `Drop` runs at scope drop unless [`settle`](Self::settle) records an outcome
    /// first; this is the reroute path's handoff, which owns a bare probe hold rather than one already
    /// registered in a [`DispatchScope`].
    pub fn register_settling(&self, guard: Box<dyn SettleAdmission>) -> AdmissionId {
        self.arena.register_settling_admission(guard)
    }

    /// Adopt a settling admission under a caller-supplied `id` — the receiving half of
    /// [`DispatchScope::handoff_settling_to`], preserving the id across the arena move.
    pub(super) fn adopt_settling(
        &self,
        id: AdmissionId,
        guard: Box<dyn SettleAdmission>,
    ) -> AdmissionId {
        self.arena.adopt_settling_admission(id.0, guard)
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
