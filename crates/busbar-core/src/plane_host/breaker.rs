// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The BREAKER family of the plane host-vtable — `breaker_admit` + `breaker_settle` — wired over
//! busbar-core's REAL single-flight breaker (`store::planes`, the non-LLM planes' handle on the one
//! cell store).
//!
//! ## Why this pair is the leak-safety-critical one
//!
//! The real breaker admits a dispatch by winning the cell's single-flight half-open probe and hands
//! back a [`store::planes::Admission`](crate::store::PlaneAdmission) — an RAII token whose `Drop`
//! releases that probe. If a plane took a BARE probe handle across the FFI seam and its dispatch
//! future were then dropped (disconnect / cancel / panic / parked-at-await), nothing would run the
//! release and the cell would wedge in `HalfOpen` FOREVER — every caller of that target fast-failing
//! with no recovery. So [`breaker_admit`] never returns the bare token: it REGISTERS the RAII
//! `Admission` in the per-dispatch [`DispatchScope`](super::DispatchScope) arena and returns the
//! arena's opaque [`AdmissionId`]. However the dispatch ends, the arena's `Drop` runs the real
//! `Admission::drop` and the probe is released — no wedge. (Proven in this module's tests.)
//!
//! [`breaker_settle`] looks the admission up in that arena, records the reported [`Signal`] against
//! the breaker (mapped to the real [`CanonicalSignal`](crate::breaker::CanonicalSignal) /
//! [`StatusClass`](crate::breaker::StatusClass) disposition pipeline), and releases the guard.
//!
//! Both fns follow the boundary discipline of the wired slots (`vtable.rs`): recover the
//! [`HostState`] FIRST, run the body inside a MANDATORY `catch_unwind`, and FAIL CLOSED on any error
//! (a refused admit is [`AdmissionId::NONE`]; a faulted settle is the distinct fault class).
//!
//! ## Key → (pool, lane)
//!
//! The breaker cell is `(pool, lane)`-keyed (`store::planes` module header). This slot reads the
//! plane-qualified pool string from the [`Key`]'s borrowed `key_ptr`/`key_len` bytes (e.g.
//! `"tool:fs"` / `"agent:planner"`, already qualified by the caller) and the member LANE from the
//! `Key.scope` field. A lane past the fixed [`MAX_POOL_MEMBERS`] table, a null/empty key, or
//! non-UTF-8 key bytes all fail closed to a refusal rather than risk indexing the lane table.

use super::scope::SettleAdmission;
use super::{recover, HostState};
use crate::breaker::{CanonicalSignal, StatusClass as BreakerClass};
use crate::store::{PlaneAdmission, PlaneBreakers, MAX_POOL_MEMBERS};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{AdmissionId, Key, Signal, StatusClass};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// The arena-held, settle-capable breaker admission. It OWNS the real single-flight probe token
/// (`_admission`), whose `Drop` releases the probe when the [`DispatchScope`](super::DispatchScope)
/// reclaims this guard — the leak-safety guarantee. [`SettleAdmission::settle`] records the reported
/// outcome against the same `(key, lane)` cell before that release, making the release a no-op.
struct BreakerAdmission {
    breakers: Arc<PlaneBreakers>,
    key: String,
    lane: usize,
    /// The RAII probe hold. Read only through its `Drop` (probe release); the leading underscore
    /// keeps it a held-for-drop field without tripping the never-read lint.
    _admission: PlaneAdmission,
}

impl SettleAdmission for BreakerAdmission {
    fn settle(&mut self, signal: &Signal) -> StatusClass {
        match classify(signal.class) {
            Outcome::Success => self.breakers.record_success(&self.key, self.lane),
            Outcome::Failure(sig) => {
                self.breakers.record_signal(&self.key, self.lane, &sig);
            }
            // A refusal is not an upstream health signal — record nothing (the ADR-0002
            // `ClientFault` "relay verbatim, penalize nothing" disposition).
            Outcome::RecordNothing => {}
        }
        // The host-call succeeded: the outcome is recorded and the probe consumed. The distinct
        // `Gone`/`Fault`/`Refused` classes are decided by the vtable wrapper, not here.
        StatusClass::Ok
    }
}

/// What a reported ABI [`StatusClass`] means to the breaker's disposition pipeline.
enum Outcome {
    /// The guarded operation succeeded — close the half-open probe, dilute the error window.
    Success,
    /// A failure to fold, carried as the breaker's own canonical signal.
    Failure(CanonicalSignal),
    /// Not an upstream health signal (a policy refusal) — record nothing.
    RecordNothing,
}

/// Map the neutral ABI outcome class a plane reports to the breaker's canonical disposition. The ABI
/// [`StatusClass`] is the coarse `Ok/Refused/Gone/Unsupported/Fault` seam class; the breaker's own
/// [`StatusClass`](crate::breaker::StatusClass) is the fine dialect-normalized class its classifier
/// folds. `Gone`/`Fault` are transient upstream trouble (a vanished target / an internal fault);
/// `Unsupported` is the caller's fault for this target; `Refused` penalizes nothing.
fn classify(class: StatusClass) -> Outcome {
    let signal = |c: BreakerClass| {
        Outcome::Failure(CanonicalSignal {
            class: c,
            provider_signal: None,
            retry_after: None,
        })
    };
    match class {
        StatusClass::Ok => Outcome::Success,
        StatusClass::Refused => Outcome::RecordNothing,
        StatusClass::Gone => signal(BreakerClass::Network),
        StatusClass::Unsupported => signal(BreakerClass::ClientError),
        StatusClass::Fault => signal(BreakerClass::ServerError),
    }
}

/// Resolve the `(pool, lane)` cell key from a borrowed [`Key`] POD. `None` (→ refuse) on a null/empty
/// key, non-UTF-8 key bytes, or a lane past the fixed [`MAX_POOL_MEMBERS`] table.
///
/// # Safety
/// `key` must be a live, initialized `Key` for the call (ABI discipline).
unsafe fn resolve_key(key: *const Key) -> Option<(String, usize)> {
    if key.is_null() {
        return None;
    }
    // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
    let k = unsafe { &*key };
    let lane = k.scope as usize;
    if lane >= MAX_POOL_MEMBERS {
        return None;
    }
    if k.key_ptr.is_null() || k.key_len == 0 {
        return None;
    }
    // SAFETY: `(key_ptr, key_len)` is a live borrowed range for the call (ABI discipline).
    let bytes = unsafe { std::slice::from_raw_parts(k.key_ptr, k.key_len) };
    match std::str::from_utf8(bytes) {
        Ok(pool) if !pool.is_empty() => Some((pool.to_string(), lane)),
        _ => None,
    }
}

/// WIRED `breaker_admit` → [`PlaneBreakers::admit`]. Admits one dispatch against the `(pool, lane)`
/// cell the [`Key`] names; on success REGISTERS the resulting RAII `Admission` in the dispatch arena
/// and returns the arena's [`AdmissionId`], so a dropped dispatch future releases the probe rather
/// than wedging the cell. Fail-closed: a refusal, a bad key, or a caught panic all return
/// [`AdmissionId::NONE`].
pub(super) extern "C-unwind" fn breaker_admit(host: HostCtx, key: *const Key) -> AdmissionId {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        // SAFETY: ABI key discipline (see `resolve_key`).
        let Some((pool, lane)) = (unsafe { resolve_key(key) }) else {
            return AdmissionId::NONE;
        };
        let breakers = Arc::clone(&state.app.plane_breakers);
        match breakers.admit(&pool, lane) {
            Ok(admission) => state.scope.register_settling_admission(Box::new(BreakerAdmission {
                breakers: Arc::clone(&breakers),
                key: pool,
                lane,
                _admission: admission,
            })),
            // Unavailable (Open / probe-in-flight / dead / budget) → refuse with the NONE sentinel.
            Err(_unavailable) => AdmissionId::NONE,
        }
    }))
    .unwrap_or(AdmissionId::NONE) // fail-closed: a panicked admit refuses.
}

/// WIRED `breaker_settle`. Looks the admission up in the dispatch arena, records the reported
/// [`Signal`] against the breaker (mapped to the canonical disposition), and releases the guard.
/// Returns [`StatusClass::Ok`] when the admission was found and settled, [`StatusClass::Gone`] when
/// `admission` names no live grant (stale / already settled), [`StatusClass::Refused`] on a null
/// signal, and [`StatusClass::Fault`] on a caught panic.
pub(super) extern "C-unwind" fn breaker_settle(
    host: HostCtx,
    admission: AdmissionId,
    signal: *const Signal,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if signal.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `signal` is a live, initialized `Signal` for the call (ABI discipline).
        let sig = unsafe { &*signal };
        state
            .scope
            .settle_admission(admission, sig)
            .unwrap_or(StatusClass::Gone) // no live admission with this id → stale handle.
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane_host::{recover, with_dispatch_scope, HostState};
    use crate::store::BreakerState;
    use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_plugin::hot::{POD_VERSION, Signal};

    const POOL: &[u8] = b"tool:fs";
    const POOL_STR: &str = "tool:fs";

    /// A `Key` naming `POOL` at lane `scope`.
    fn key(scope: u32) -> Key {
        Key {
            size: core::mem::size_of::<Key>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            _reserved2: 0,
            key_ptr: POOL.as_ptr(),
            key_len: POOL.len(),
        }
    }

    /// A `Signal` reporting `class` (health scalars are unused by the wiring).
    fn signal(class: StatusClass) -> Signal {
        Signal {
            size: core::mem::size_of::<Signal>() as u32,
            version: POD_VERSION,
            class,
            _reserved: 0,
            latency_nanos: 0,
            bytes: 0,
        }
    }

    fn with_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable, &crate::state::App) -> R) -> R {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, vt| f(host, vt, &app))
    }

    /// THE LEAK-SAFETY PROOF: admit wins the single-flight probe, then the dispatch scope ends
    /// WITHOUT a settle — and the real `Admission::drop` must release the probe, so the cell is NOT
    /// wedged `HalfOpen`. Verified by a fresh admit winning the probe again after the drop (a leaked
    /// bare handle would leave `probe_in_flight` true forever and refuse it).
    #[test]
    fn admit_then_drop_scope_without_settle_releases_the_real_probe() {
        let app = crate::test_support::TestApp::new().build();
        // Park the cell Open with an already-elapsed cooldown → the next admit wins the half-open probe.
        app.plane_breakers.force_open(POOL_STR, 0, 1);

        // Scope 1: admit, then let the scope DROP without settling.
        with_dispatch_scope(&app, |host, vt| {
            let k = key(0);
            let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
            assert!(!id.is_none(), "admit must win the probe and return a live id");
            assert_eq!(
                app.plane_breakers.state(POOL_STR),
                BreakerState::HalfOpen,
                "the won probe holds the cell HalfOpen while the dispatch is live"
            );
            // While the probe is held, a concurrent admit is refused (single-flight).
            with_dispatch_scope(&app, |h2, vt2| {
                let k2 = key(0);
                assert!(
                    (vt2.breaker_admit.unwrap())(h2, &k2 as *const Key).is_none(),
                    "a second admit while the probe is in flight is refused"
                );
            });
        });

        // Scope 1 dropped WITHOUT a settle → the real `Admission::drop` released the probe.
        // If it had leaked, this admit would be refused (ProbeInFlight); that it wins proves no wedge.
        with_dispatch_scope(&app, |host, vt| {
            let k = key(0);
            let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
            assert!(
                !id.is_none(),
                "after the unsettled scope dropped, the probe is winnable again — no HalfOpen wedge"
            );
        });
    }

    /// A settle records the outcome and returns `Ok`; a second settle of the same id is `Gone`
    /// (the entry was released), and a success drives the HalfOpen probe to a recovered `Closed`.
    #[test]
    fn settle_records_success_and_is_gone_on_replay() {
        let app = crate::test_support::TestApp::new().build();
        app.plane_breakers.force_open(POOL_STR, 0, 1);
        with_dispatch_scope(&app, |host, vt| {
            let k = key(0);
            let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
            assert!(!id.is_none());

            let ok = signal(StatusClass::Ok);
            assert_eq!(
                (vt.breaker_settle.unwrap())(host, id, &ok as *const Signal),
                StatusClass::Ok,
                "settling a live admission records the outcome and returns Ok"
            );
            assert_eq!(
                app.plane_breakers.state(POOL_STR),
                BreakerState::Closed,
                "a recorded success recovers the HalfOpen probe to Closed"
            );
            // Replayed settle: the id was released → Gone.
            assert_eq!(
                (vt.breaker_settle.unwrap())(host, id, &ok as *const Signal),
                StatusClass::Gone,
                "a second settle of the released id is a stale handle"
            );
        });
    }

    /// Fail-closed inputs: a null/empty/oversized-lane key refuses to `NONE`; a null signal and an
    /// unknown admission id settle to `Refused`/`Gone` — never a permissive value.
    #[test]
    fn breaker_slots_fail_closed_on_bad_input() {
        with_state(|host, vt, _app| {
            assert!(
                (vt.breaker_admit.unwrap())(host, core::ptr::null()).is_none(),
                "null key → refuse"
            );
            // Lane past the fixed member table → refuse rather than index out of bounds.
            let far = key(MAX_POOL_MEMBERS as u32);
            assert!(
                (vt.breaker_admit.unwrap())(host, &far as *const Key).is_none(),
                "lane >= MAX_POOL_MEMBERS → refuse"
            );
            let ok = signal(StatusClass::Ok);
            assert_eq!(
                (vt.breaker_settle.unwrap())(host, AdmissionId::NONE, &ok as *const Signal),
                StatusClass::Gone,
                "settling the NONE sentinel is a stale handle"
            );
            assert_eq!(
                (vt.breaker_settle.unwrap())(host, AdmissionId(999), core::ptr::null()),
                StatusClass::Refused,
                "a null signal is refused, not faulted"
            );
        });
    }

    /// A failure settle folds through the real disposition pipeline (records a transient upstream
    /// signal) and still returns `Ok` for the host call.
    #[test]
    fn settle_failure_folds_a_transient_signal() {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, vt| {
            // Closed-ready cell: admit wins trivially.
            let k = key(0);
            let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
            assert!(!id.is_none());
            // SAFETY: live HostState from `with_dispatch_scope`.
            let _state: &HostState = unsafe { recover(host) };
            let fault = signal(StatusClass::Fault);
            assert_eq!(
                (vt.breaker_settle.unwrap())(host, id, &fault as *const Signal),
                StatusClass::Ok,
                "a fault settle records a transient upstream signal and returns Ok"
            );
        });
    }
}
