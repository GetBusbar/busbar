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
use busbar_plugin::hot::{AdmissionId, FaultClass, Key, Signal, StatusClass};
use busbar_plugin::read_sized_field;
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
        // SAFETY: `signal` is a live, initialized `Signal` for this call (settle's ABI discipline);
        // its `provider_signal` borrowed range, when present, is valid for the duration of the call.
        match unsafe { classify(signal) } {
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

/// Build a settle-capable breaker admission from an ALREADY-WON probe hold — the seam the failover
/// reroute path (`mcp::reroute::into_task_dispatch`) uses to re-home a `PlaneAdmission` it won through
/// [`crate::failover::walk`] into a [`DurableScope`](super::DurableScope) as a `Box<dyn SettleAdmission>`,
/// so the detached runner can settle its observed outcome against the SAME `(key, lane)` cell (or let
/// the durable scope release the unsettled probe on task-end drop). The reroute path owns a bare
/// `PlaneAdmission` rather than one registered in a [`DispatchScope`](super::DispatchScope), so this
/// wraps it exactly as [`breaker_admit`] wraps the token it registers.
pub(crate) fn settling_admission(
    breakers: Arc<PlaneBreakers>,
    key: String,
    lane: usize,
    admission: PlaneAdmission,
) -> Box<dyn SettleAdmission> {
    Box::new(BreakerAdmission {
        breakers,
        key,
        lane,
        _admission: admission,
    })
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

/// Reproduce the plane's `normalize_raw_error` disposition from a reported [`Signal`], building the
/// FULL [`CanonicalSignal`] the store's `record_signal` folds — so routing a settle through the host
/// is byte-for-byte the same disposition as the plane recording directly.
///
/// The coarse ABI [`StatusClass`] decides the top-level shape: `Ok` is a success, `Refused` records
/// nothing (a policy refusal is not an upstream health signal), and `Gone`/`Unsupported`/`Fault` are
/// failures to fold. On a failure, the FINE breaker class rides in the append-only [`Signal`] tail:
/// when the sender wrote a real [`FaultClass`] (its `size` proves the field and it is not
/// [`FaultClass::Unspecified`]), it maps 1:1 to the breaker's own [`StatusClass`](BreakerClass) and
/// carries the upstream `Retry-After` floor and the borrowed provider error-code — the exact three
/// inputs `record_signal` reads (the RateLimit cooldown floor, the transient/hard-down reason code).
/// A sender that predates the tail (or leaves `Unspecified`) falls back to the coarse mapping the
/// pre-enrichment host used: `Gone → Network`, `Unsupported → ClientError`, `Fault → ServerError`.
///
/// # Safety
/// `signal.provider_signal_ptr`/`provider_signal_len`, when the tail is present and non-null/non-zero,
/// MUST describe a live, initialized byte range for the duration of the call (settle's ABI discipline).
unsafe fn classify(signal: &Signal) -> Outcome {
    match signal.class {
        StatusClass::Ok => return Outcome::Success,
        // A policy refusal is not an upstream health signal — record nothing (ADR-0002).
        StatusClass::Refused => return Outcome::RecordNothing,
        // A failure to fold — fall through to the fine/coarse classification below.
        StatusClass::Gone | StatusClass::Unsupported | StatusClass::Fault => {}
    }

    // Prefer the FINE breaker class when the sender wrote it (append-only sized read); an older
    // sender, a truncated tail, or an explicit `Unspecified` all fall back to the coarse map.
    let fine = read_sized_field!(signal, Signal, fault_class).unwrap_or(FaultClass::Unspecified);
    let class = match fine {
        FaultClass::Unspecified => return Outcome::Failure(coarse_signal(signal.class)),
        FaultClass::RateLimit => BreakerClass::RateLimit,
        FaultClass::Overloaded => BreakerClass::Overloaded,
        FaultClass::UpstreamError => BreakerClass::ServerError,
        FaultClass::Timeout => BreakerClass::Timeout,
        FaultClass::Network => BreakerClass::Network,
        FaultClass::Auth => BreakerClass::Auth,
        FaultClass::Billing => BreakerClass::Billing,
        FaultClass::ClientError => BreakerClass::ClientError,
        FaultClass::ContextLength => BreakerClass::ContextLength,
    };

    // The `Retry-After` floor: present only when the tail was written AND bit 0 of `fault_flags` is
    // set (so a header value of `0` is distinct from "no header").
    let retry_after = match read_sized_field!(signal, Signal, fault_flags) {
        Some(flags) if flags & 0x01 != 0 => read_sized_field!(signal, Signal, retry_after_secs),
        _ => None,
    };

    // The borrowed provider error-code (into the transient/hard-down reason), when present & UTF-8.
    let provider_signal = provider_code(signal);

    Outcome::Failure(CanonicalSignal {
        class,
        provider_signal,
        retry_after,
    })
}

/// The pre-enrichment coarse mapping, used as the forward-compat fallback for a sender that did not
/// write the fine [`FaultClass`] tail. Preserves the exact legacy disposition (no `provider_signal`,
/// no `retry_after`).
fn coarse_signal(class: StatusClass) -> CanonicalSignal {
    let class = match class {
        StatusClass::Gone => BreakerClass::Network,
        StatusClass::Unsupported => BreakerClass::ClientError,
        // `Ok`/`Refused` never reach here (handled before the fallback); `Fault` is the only other.
        StatusClass::Fault | StatusClass::Ok | StatusClass::Refused => BreakerClass::ServerError,
    };
    CanonicalSignal {
        class,
        provider_signal: None,
        retry_after: None,
    }
}

/// The borrowed provider error-CODE from a [`Signal`] tail, as an owned `String` for the canonical
/// signal's reason field. `None` when the tail is absent, the range is null/empty, or non-UTF-8.
///
/// # Safety
/// See [`classify`]: the borrowed range, when present, must be live for the call.
unsafe fn provider_code(signal: &Signal) -> Option<String> {
    let ptr = read_sized_field!(signal, Signal, provider_signal_ptr)?;
    let len = read_sized_field!(signal, Signal, provider_signal_len)?;
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller guarantees `(ptr, len)` is a live, initialized range for the call.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).ok().map(str::to_string)
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

    /// A `Signal` reporting `class` with NO fine refinement (`FaultClass::Unspecified`) — exercises
    /// the coarse fallback exactly as a pre-enrichment sender would.
    fn signal(class: StatusClass) -> Signal {
        Signal {
            size: core::mem::size_of::<Signal>() as u32,
            version: POD_VERSION,
            class,
            _reserved: 0,
            latency_nanos: 0,
            bytes: 0,
            fault_class: FaultClass::Unspecified,
            fault_flags: 0,
            _reserved2: 0,
            _reserved3: 0,
            retry_after_secs: 0,
            provider_signal_ptr: core::ptr::null(),
            provider_signal_len: 0,
        }
    }

    /// A failure `Signal` carrying a FINE [`FaultClass`], an optional `Retry-After` floor, and an
    /// optional borrowed provider error-code — the enriched shape a real plane reports.
    fn fine_signal(fault: FaultClass, retry_after: Option<u64>, code: Option<&[u8]>) -> Signal {
        let (flags, secs) = match retry_after {
            Some(s) => (0x01u8, s),
            None => (0, 0),
        };
        let (ptr, len) = match code {
            Some(c) => (c.as_ptr(), c.len()),
            None => (core::ptr::null(), 0),
        };
        Signal {
            size: core::mem::size_of::<Signal>() as u32,
            version: POD_VERSION,
            class: StatusClass::Fault,
            _reserved: 0,
            latency_nanos: 0,
            bytes: 0,
            fault_class: fault,
            fault_flags: flags,
            _reserved2: 0,
            _reserved3: 0,
            retry_after_secs: secs,
            provider_signal_ptr: ptr,
            provider_signal_len: len,
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

    /// THE DURABLE SETTLE ROUTE IS REACHABLE (create_task site). Win a probe in a per-request
    /// `DispatchScope`, hand the settling admission off into a `DurableScope` a `DurableHostDispatch`
    /// owns, and settle it THROUGH the host `breaker_settle` seam over that durable arena — proving a
    /// settle-capable host route reaches the detached-runner site with no change to the breaker path.
    /// The recorded success recovers the HalfOpen cell to Closed, exactly as the per-request path does.
    #[test]
    fn durable_host_route_settles_through_breaker_settle() {
        use crate::plane_host::{DispatchScope, DurableHostDispatch, DurableScope};
        let app = std::sync::Arc::new(crate::test_support::TestApp::new().build());
        app.plane_breakers.force_open(POOL_STR, 0, 1);

        // Win the probe in the per-request arena, then hand it off to a runner-owned durable scope.
        let disp = DispatchScope::new();
        let id = {
            let state = HostState {
                app: &app,
                scope: &disp,
            };
            let host: HostCtx =
                (&state as *const HostState).cast_mut().cast::<std::os::raw::c_void>();
            let k = key(0);
            let id = breaker_admit(host, &k as *const Key);
            assert!(!id.is_none(), "admit wins the half-open probe");
            id
        };
        let durable = DurableScope::new();
        let moved = disp
            .handoff_settling_to(id, &durable)
            .expect("the admission hands off to the durable scope");
        assert_eq!(
            app.plane_breakers.state(POOL_STR),
            BreakerState::HalfOpen,
            "the handed-off probe still holds the cell HalfOpen"
        );

        // The detached runner's host route: settle through the vtable over the DURABLE arena.
        let route = DurableHostDispatch::new(std::sync::Arc::clone(&app), durable, moved);
        let ok = signal(StatusClass::Ok);
        let class = route.with_host(|host, vt| {
            (vt.breaker_settle.unwrap())(host, route.admission(), &ok as *const Signal)
        });
        assert_eq!(class, StatusClass::Ok, "the durable admission settles through the host seam");
        assert_eq!(
            app.plane_breakers.state(POOL_STR),
            BreakerState::Closed,
            "the recorded success recovered the HalfOpen probe to Closed"
        );
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

    /// FAITHFULNESS PROOF (classify level): the host's `classify` reproduces the EXACT
    /// [`CanonicalSignal`] that `normalize_raw_error` produces for a 429-with-`Retry-After` and for a
    /// 401 — the same class, provider code, and retry-after floor `record_signal` folds. Before the
    /// enrichment the host lost the Retry-After floor and mapped 401 to a transient bleed; this asserts
    /// it no longer does.
    #[test]
    fn classify_reproduces_normalize_raw_error() {
        use crate::breaker::{normalize_raw_error, RawUpstreamError};
        use std::collections::HashMap;
        let no_map: HashMap<String, String> = HashMap::new();

        // 429 + Retry-After: 30 + provider code → RateLimit, Some(code), Some(30).
        let raw_429 = RawUpstreamError {
            http_status: 429,
            provider_code: Some("slow_down".to_string()),
            structured_type: None,
            retry_after_secs: Some(30),
        };
        let expect_429 = normalize_raw_error(&raw_429, &no_map);
        let code = b"slow_down";
        let sig_429 = fine_signal(FaultClass::RateLimit, Some(30), Some(code));
        // SAFETY: `code` outlives this call; the tail is fully written.
        match unsafe { classify(&sig_429) } {
            Outcome::Failure(cs) => assert_eq!(
                cs, expect_429,
                "429 host classify must equal normalize_raw_error (class + code + retry_after)"
            ),
            _ => panic!("a 429 must classify as a failure to fold"),
        }

        // 401 auth → HardDown class, no code, no retry_after.
        let raw_401 = RawUpstreamError {
            http_status: 401,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        };
        let expect_401 = normalize_raw_error(&raw_401, &no_map);
        let sig_401 = fine_signal(FaultClass::Auth, None, None);
        // SAFETY: no borrowed range; the tail is fully written.
        match unsafe { classify(&sig_401) } {
            Outcome::Failure(cs) => {
                assert_eq!(cs, expect_401, "401 host classify must equal normalize_raw_error");
                assert_eq!(
                    crate::breaker::classify(&cs),
                    crate::breaker::Disposition::HardDown,
                    "401 must fold to a sticky HardDown, not a transient bleed"
                );
            }
            _ => panic!("a 401 must classify as a failure to fold"),
        }
    }

    /// FAITHFULNESS PROOF (end-to-end): driving the enriched 401 and 429 signals THROUGH
    /// `breaker_admit` + `breaker_settle` leaves the target cell in the SAME state as recording the
    /// `normalize_raw_error` `CanonicalSignal` directly onto an identical cell. This is the guarantee
    /// CLUSTER-1 needs: the host settle path IS the plane's own `record_signal` disposition.
    #[test]
    fn settle_through_host_matches_direct_record_signal() {
        use crate::breaker::{normalize_raw_error, RawUpstreamError};
        use std::collections::HashMap;
        let no_map: HashMap<String, String> = HashMap::new();

        for (raw, fault, retry, code) in [
            (
                RawUpstreamError {
                    http_status: 401,
                    provider_code: None,
                    structured_type: None,
                    retry_after_secs: None,
                },
                FaultClass::Auth,
                None,
                None::<&[u8]>,
            ),
            (
                RawUpstreamError {
                    http_status: 429,
                    provider_code: Some("slow_down".to_string()),
                    structured_type: None,
                    retry_after_secs: Some(30),
                },
                FaultClass::RateLimit,
                Some(30u64),
                Some(b"slow_down".as_slice()),
            ),
        ] {
            // Direct path: normalize + record straight onto a fresh cell.
            let direct = crate::test_support::TestApp::new().build();
            let cs = normalize_raw_error(&raw, &no_map);
            direct.plane_breakers.record_signal(POOL_STR, 0, &cs);
            let direct_state = direct.plane_breakers.state_at(POOL_STR, 0);

            // Host path: admit + settle the enriched Signal on an identical fresh cell.
            let hosted = crate::test_support::TestApp::new().build();
            with_dispatch_scope(&hosted, |host, vt| {
                let k = key(0);
                let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
                assert!(!id.is_none());
                let sig = fine_signal(fault, retry, code);
                assert_eq!(
                    (vt.breaker_settle.unwrap())(host, id, &sig as *const Signal),
                    StatusClass::Ok,
                );
            });
            let hosted_state = hosted.plane_breakers.state_at(POOL_STR, 0);

            assert_eq!(
                direct_state, hosted_state,
                "host settle must leave the cell in the same state as a direct record_signal \
                 for http {}",
                raw.http_status
            );
        }
    }
}
