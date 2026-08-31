// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/breaker.rs`.

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, HostState};
use crate::store::BreakerState;
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::{Signal, POD_VERSION};

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
        drift_state: 0,
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
        assert!(
            !id.is_none(),
            "admit must win the probe and return a live id"
        );
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
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
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
    assert_eq!(
        class,
        StatusClass::Ok,
        "the durable admission settles through the host seam"
    );
    assert_eq!(
        app.plane_breakers.state(POOL_STR),
        BreakerState::Closed,
        "the recorded success recovered the HalfOpen probe to Closed"
    );
}

/// THE CREATE_TASK ADMIT PATH: the runner's durable scope is opened UP FRONT and the task admit
/// runs through the host `breaker_admit` seam OVER ITS ARENA — so the probe is BORN durable (no
/// per-request win + re-home). It holds the cell HalfOpen until the detached runner settles it
/// through the same host seam over that durable arena, recovering it to Closed — mirroring
/// `durable_host_route_settles_through_breaker_settle` but entered via the durable-arena admit.
#[test]
fn task_admit_bears_the_probe_in_the_durable_scope_and_settles() {
    use crate::plane_host::{DurableHostDispatch, DurableScope, HostState};
    let app = std::sync::Arc::new(crate::test_support::TestApp::new().build());
    app.plane_breakers.force_open(POOL_STR, 0, 1);

    // Admit DIRECTLY into the runner-owned durable arena (what `create_task` now does via the
    // pooled walk): the won probe is registered in the DurableScope, never a per-request one.
    let durable = DurableScope::new();
    let id = {
        let state = HostState {
            app: &app,
            scope: durable.arena(),
        };
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
        let k = key(0);
        let id = breaker_admit(host, &k as *const Key);
        assert!(!id.is_none(), "the task admit wins the half-open probe");
        id
    };
    assert_eq!(
        durable.registered(),
        1,
        "the probe is BORN in the runner's durable scope — no re-home"
    );
    assert_eq!(
        app.plane_breakers.state(POOL_STR),
        BreakerState::HalfOpen,
        "the durable-born probe holds the cell HalfOpen until the runner settles"
    );

    // The detached runner settles through the vtable over the DURABLE arena.
    let route = DurableHostDispatch::new(std::sync::Arc::clone(&app), durable, id);
    let ok = signal(StatusClass::Ok);
    let class = route.with_host(|host, vt| {
        (vt.breaker_settle.unwrap())(host, route.admission(), &ok as *const Signal)
    });
    assert_eq!(
        class,
        StatusClass::Ok,
        "the durable-born admission settles through the host seam"
    );
    assert_eq!(
        app.plane_breakers.state(POOL_STR),
        BreakerState::Closed,
        "the recorded success recovered the HalfOpen probe to Closed"
    );
}

/// BUDGET REFUSES AFTER THE ADMIT: `create_task` charges the budget once the breaker already
/// admitted, and a refusal there drops the runner's durable scope WITHOUT a settle. The probe the
/// task admit won into that scope must release on the drop (RAII), so the cell is NOT wedged
/// HalfOpen — a fresh admit wins it again.
#[test]
fn task_admit_releases_the_probe_when_the_durable_scope_drops_unsettled() {
    use crate::plane_host::{DurableScope, HostState};
    let app = crate::test_support::TestApp::new().build();
    app.plane_breakers.force_open(POOL_STR, 0, 1);

    {
        let durable = DurableScope::new();
        let state = HostState {
            app: &app,
            scope: durable.arena(),
        };
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
        let k = key(0);
        let id = breaker_admit(host, &k as *const Key);
        assert!(
            !id.is_none(),
            "the task admit wins the probe into the durable scope"
        );
        assert_eq!(
            app.plane_breakers.state(POOL_STR),
            BreakerState::HalfOpen,
            "the durable-born probe holds the cell HalfOpen"
        );
        // The budget refuses here: the durable scope drops WITHOUT a settle (end of block).
    }

    // The drop released the unsettled probe — the cell is winnable again, no HalfOpen wedge.
    with_dispatch_scope(&app, |host, vt| {
        let k = key(0);
        let id = (vt.breaker_admit.unwrap())(host, &k as *const Key);
        assert!(
            !id.is_none(),
            "after the budget-refused durable scope dropped, the probe is winnable again"
        );
    });
}

/// REFUSAL FIDELITY: `breaker_admit_reason` carries the SPECIFIC reason out on a refusal instead
/// of collapsing to `NONE`. An Open cell refuses with [`Unavailability::Open`] + a recovery floor;
/// a live admit returns an id and leaves the reason at `Unspecified`; a null key is `Unspecified`.
#[test]
fn breaker_admit_reason_carries_the_refusal_reason() {
    let app = crate::test_support::TestApp::new().build();
    // Park the cell Open with a FUTURE cooldown (absolute epoch) so the next admit is refused
    // BreakerOpen rather than winning a half-open probe.
    app.plane_breakers
        .force_open(POOL_STR, 0, crate::store::now().saturating_add(3600));
    with_dispatch_scope(&app, |host, vt| {
        let admit_reason = vt.breaker_admit_reason.unwrap();
        let k = key(0);
        let mut out = MaybeUninit::<AdmitRefusal>::uninit();
        let id = admit_reason(host, &k as *const Key, std::ptr::from_mut(&mut out));
        assert!(id.is_none(), "an Open cell refuses");
        // SAFETY: the host always initializes `out`.
        let refusal = unsafe { out.assume_init() };
        assert_eq!(
            refusal.reason,
            Unavailability::Open,
            "the fine reason survives the boundary"
        );
        assert!(
            refusal.retry_after_secs > 0,
            "an Open cell carries its known recovery floor"
        );

        // A null key is not an availability fact → Unspecified, still refused.
        let mut out2 = MaybeUninit::<AdmitRefusal>::uninit();
        let id2 = admit_reason(host, core::ptr::null(), std::ptr::from_mut(&mut out2));
        assert!(id2.is_none());
        // SAFETY: initialized up front.
        assert_eq!(
            unsafe { out2.assume_init() }.reason,
            Unavailability::Unspecified
        );
    });
}

/// A live admit through `breaker_admit_reason` returns an id and leaves the reason `Unspecified`;
/// the settle-capable admission is registered in the arena exactly as `breaker_admit`'s is.
#[test]
fn breaker_admit_reason_admits_and_leaves_reason_unspecified() {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let k = key(0);
        let mut out = MaybeUninit::<AdmitRefusal>::uninit();
        let id = (vt.breaker_admit_reason.unwrap())(
            host,
            &k as *const Key,
            std::ptr::from_mut(&mut out),
        );
        assert!(!id.is_none(), "a Closed-ready cell admits");
        // SAFETY: initialized up front; a live id leaves it Unspecified.
        assert_eq!(
            unsafe { out.assume_init() }.reason,
            Unavailability::Unspecified
        );
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) };
        assert_eq!(
            state.scope.registered(),
            1,
            "the settle-capable admission is registered"
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

/// INVERSE-BUILDER FAITHFULNESS: [`failure_signal`] is the exact inverse of [`classify`] — a
/// `CanonicalSignal` built into a `Signal` and classified back yields the SAME canonical signal
/// (class + provider code + retry-after floor), across every `BreakerClass` and with/without the
/// optional tail fields. This is what lets a settle folded through the host equal a direct
/// `record_signal`; the a2a/mcp CLUSTER-1 settle sites rely on it.
#[test]
fn failure_signal_round_trips_through_classify() {
    use crate::breaker::StatusClass as BC;
    let cases = [
        CanonicalSignal {
            class: BC::RateLimit,
            provider_signal: Some("slow_down".to_string()),
            retry_after: Some(30),
        },
        CanonicalSignal {
            class: BC::Overloaded,
            provider_signal: None,
            retry_after: Some(0),
        },
        CanonicalSignal {
            class: BC::ServerError,
            provider_signal: None,
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::Timeout,
            provider_signal: None,
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::Network,
            provider_signal: None,
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::Auth,
            provider_signal: Some("invalid_key".to_string()),
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::Billing,
            provider_signal: None,
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::ClientError,
            provider_signal: None,
            retry_after: None,
        },
        CanonicalSignal {
            class: BC::ContextLength,
            provider_signal: None,
            retry_after: None,
        },
    ];
    for cs in cases {
        let sig = failure_signal(&cs);
        // SAFETY: `sig` borrows `cs`, which is live for this iteration; the tail is fully written.
        match unsafe { classify(&sig) } {
            Outcome::Failure(back) => assert_eq!(
                back, cs,
                "failure_signal must be the inverse of classify for {:?}",
                cs.class
            ),
            _ => panic!(
                "a failure_signal must classify as a failure for {:?}",
                cs.class
            ),
        }
    }
    // The success builder maps straight to the Success outcome.
    // SAFETY: no borrowed range; the tail is fully written.
    assert!(matches!(
        unsafe { classify(&success_signal()) },
        Outcome::Success
    ));
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
            assert_eq!(
                cs, expect_401,
                "401 host classify must equal normalize_raw_error"
            );
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
