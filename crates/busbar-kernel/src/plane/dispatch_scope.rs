// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-DISPATCH ARENA a plane's host handles live in ([`DispatchScope`]) and its supporting
//! vocabulary (`SettleAdmission`, `EgressFaultDetail`). It stands beside the host capability
//! vocabulary ([`super::host`]), whose breaker, metering and govern slices take it (spec Part 3,
//! the HostSlots paragraph: "DispatchScope stands"). It names only [`busbar_contract::abi::hot`] and
//! `std`.

use busbar_contract::abi::hot::{
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
    ///
    /// EVERY ENTRY GETS ITS OWN BOUNDARY. Reclaiming runs code this loop does not own — a closer that
    /// kills a subprocess, a guard's real `Drop` — and one of those panicking must not cost the
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
                    Resource::Closer(Some(reclaim)) => reclaim(),
                    Resource::Closer(None) => {}
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

#[cfg(test)]
#[path = "tests/dispatch_scope_tests.rs"]
mod tests;
