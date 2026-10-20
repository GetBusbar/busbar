// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane_host/breaker.rs`.

use super::*;
use crate::plane_host::{BreakerHost, DispatchScope, DurableScope, EngineHostImpl, Settled};
use busbar_kernel::store::{BreakerState, Unavailable};

const POOL: &[u8] = b"tool:fs";
const POOL_STR: &str = "tool:fs";

/// The kernel's host over a fresh test `App`.
fn host() -> EngineHostImpl {
    EngineHostImpl::new(Arc::new(crate::test_support::TestApp::new().build()))
}

/// THE LEAK-SAFETY PROOF: admit wins the single-flight probe, then the dispatch scope ends
/// WITHOUT a settle — and the real `Admission::drop` must release the probe, so the cell is NOT
/// wedged `HalfOpen`. Verified by a fresh admit winning the probe again after the drop (a leaked
/// bare handle would leave `probe_in_flight` true forever and refuse it).
#[test]
fn admit_then_drop_scope_without_settle_releases_the_real_probe() {
    let host = host();
    // Park the cell Open with an already-elapsed cooldown → the next admit wins the half-open probe.
    host.breaker_store().force_open(POOL_STR, 0, 1);

    // Scope 1: admit, then let the scope DROP without settling.
    {
        let scope = DispatchScope::new();
        let id = admit(&host, &scope, POOL, 0).expect("admit must win the probe");
        assert!(!id.is_none(), "a won probe has a live id");
        assert_eq!(
            host.breaker_store().state(POOL_STR),
            BreakerState::HalfOpen,
            "the won probe holds the cell HalfOpen while the dispatch is live"
        );
        // While the probe is held, a concurrent admit is refused (single-flight).
        let scope2 = DispatchScope::new();
        assert!(
            admit(&host, &scope2, POOL, 0).is_err(),
            "a second admit while the probe is in flight is refused"
        );
    }

    // Scope 1 dropped WITHOUT a settle → the real `Admission::drop` released the probe.
    // If it had leaked, this admit would be refused (ProbeInFlight); that it wins proves no wedge.
    let scope = DispatchScope::new();
    assert!(
        admit(&host, &scope, POOL, 0).is_ok(),
        "after the unsettled scope dropped, the probe is winnable again — no HalfOpen wedge"
    );
}

/// A settle records the outcome and answers `Ok`; a second settle of the same id is `Gone`
/// (the entry was released), and a success drives the HalfOpen probe to a recovered `Closed`.
#[test]
fn settle_records_success_and_is_gone_on_replay() {
    let host = host();
    host.breaker_store().force_open(POOL_STR, 0, 1);
    let scope = DispatchScope::new();
    let id = admit(&host, &scope, POOL, 0).expect("admit wins the probe");
    assert_eq!(
        host.breaker_settle(&scope, id, &success_signal()),
        Settled::Ok,
        "settling a live admission records the outcome and answers Ok"
    );
    assert_eq!(
        host.breaker_store().state(POOL_STR),
        BreakerState::Closed,
        "a recorded success recovers the HalfOpen probe to Closed"
    );
    // Replayed settle: the id was released → Gone.
    assert_eq!(
        host.breaker_settle(&scope, id, &success_signal()),
        Settled::Gone,
        "a second settle of the released id is a stale handle"
    );
}

/// THE CREATE_TASK ADMIT PATH: the runner's durable scope is opened UP FRONT and the task admit
/// runs OVER ITS ARENA — so the probe is BORN durable (no per-request win + re-home). It holds the
/// cell HalfOpen until the detached runner settles it over that durable arena, recovering it to
/// Closed.
#[test]
fn task_admit_bears_the_probe_in_the_durable_scope_and_settles() {
    let host = host();
    host.breaker_store().force_open(POOL_STR, 0, 1);

    let durable = DurableScope::new();
    let id =
        admit(&host, durable.arena(), POOL, 0).expect("the task admit wins the half-open probe");
    assert_eq!(
        durable.registered(),
        1,
        "the probe is BORN in the runner's durable scope — no re-home"
    );
    assert_eq!(
        host.breaker_store().state(POOL_STR),
        BreakerState::HalfOpen,
        "the durable-born probe holds the cell HalfOpen until the runner settles"
    );

    // The detached runner settles over the DURABLE arena.
    assert_eq!(
        host.breaker_settle(durable.arena(), id, &success_signal()),
        Settled::Ok,
        "the durable-born admission settles through the host"
    );
    assert_eq!(
        host.breaker_store().state(POOL_STR),
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
    let host = host();
    host.breaker_store().force_open(POOL_STR, 0, 1);

    {
        let durable = DurableScope::new();
        assert!(
            admit(&host, durable.arena(), POOL, 0).is_ok(),
            "the task admit wins the probe into the durable scope"
        );
        assert_eq!(
            host.breaker_store().state(POOL_STR),
            BreakerState::HalfOpen,
            "the durable-born probe holds the cell HalfOpen"
        );
        // The budget refuses here: the durable scope drops WITHOUT a settle (end of block).
    }

    // The drop released the unsettled probe — the cell is winnable again, no HalfOpen wedge.
    let scope = DispatchScope::new();
    assert!(
        admit(&host, &scope, POOL, 0).is_ok(),
        "after the budget-refused durable scope dropped, the probe is winnable again"
    );
}

/// REFUSAL FIDELITY: a refused admit carries the SPECIFIC reason out instead of collapsing to one
/// shape. An Open cell refuses `BreakerOpen` with a recovery deadline in the future; a bad key is
/// not an availability fact and refuses as the unspecified `ProbeInFlight`.
#[test]
fn a_refused_admit_carries_the_refusal_reason() {
    let host = host();
    // Park the cell Open with a FUTURE cooldown (absolute epoch) so the next admit is refused
    // BreakerOpen rather than winning a half-open probe.
    let now = busbar_kernel::store::now();
    host.breaker_store()
        .force_open(POOL_STR, 0, now.saturating_add(3600));
    let scope = DispatchScope::new();
    match admit(&host, &scope, POOL, 0) {
        Err(Unavailable::BreakerOpen { until }) => {
            assert!(until > now, "an Open cell carries its known recovery floor")
        }
        other => panic!("an Open cell refuses BreakerOpen, got {other:?}"),
    }
    assert_eq!(
        admit(&host, &scope, b"", 0),
        Err(Unavailable::ProbeInFlight),
        "an empty pool is not an availability fact"
    );
    assert_eq!(scope.registered(), 0, "a refusal registers nothing");
}

/// A live admit returns an id and registers the settle-capable admission in the arena.
#[test]
fn a_live_admit_registers_its_settle_capable_admission() {
    let host = host();
    let scope = DispatchScope::new();
    let id = admit(&host, &scope, POOL, 0).expect("a Closed-ready cell admits");
    assert!(!id.is_none());
    assert_eq!(
        scope.registered(),
        1,
        "the settle-capable admission is registered"
    );
}

/// Fail-closed inputs: a non-UTF-8 pool or a lane past the member table refuses; settling the NONE
/// sentinel or an unknown id is `Gone` — never a permissive value.
#[test]
fn breaker_fails_closed_on_bad_input() {
    let host = host();
    let scope = DispatchScope::new();
    assert!(
        admit(&host, &scope, &[0xff, 0xfe], 0).is_err(),
        "non-UTF-8 pool → refuse"
    );
    // Lane past the fixed member table → refuse rather than index out of bounds.
    assert!(
        admit(&host, &scope, POOL, MAX_POOL_MEMBERS as u32).is_err(),
        "lane >= MAX_POOL_MEMBERS → refuse"
    );
    assert_eq!(
        host.breaker_settle(&scope, AdmissionId::NONE, &success_signal()),
        Settled::Gone,
        "settling the NONE sentinel is a stale handle"
    );
    assert_eq!(
        host.breaker_settle(&scope, AdmissionId(999), &refused_signal()),
        Settled::Gone,
        "settling an id the arena never issued is a stale handle"
    );
}

/// A failure settle folds through the real disposition pipeline (records a transient upstream
/// signal) and answers `Ok`.
#[test]
fn settle_failure_folds_a_transient_signal() {
    let host = host();
    let scope = DispatchScope::new();
    let id = admit(&host, &scope, POOL, 0).expect("a Closed-ready cell admits");
    let fault = CanonicalSignal {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        host.breaker_settle(&scope, id, &failure_signal(&fault)),
        Settled::Ok,
        "a fault settle records a transient upstream signal and answers Ok"
    );
}

/// A refused leg RELEASES the probe and records nothing: the cell is back to winnable and stays
/// Closed.
#[test]
fn a_refused_settle_releases_the_probe_and_records_nothing() {
    let host = host();
    host.breaker_store().force_open(POOL_STR, 0, 1);
    let scope = DispatchScope::new();
    let id = admit(&host, &scope, POOL, 0).expect("admit wins the probe");
    assert_eq!(
        host.breaker_settle(&scope, id, &refused_signal()),
        Settled::Ok
    );
    assert_eq!(
        scope.registered(),
        0,
        "the settled admission left the arena"
    );
    let again = DispatchScope::new();
    assert!(
        admit(&host, &again, POOL, 0).is_ok(),
        "the released probe is winnable again"
    );
}

/// The settle builders carry exactly the plane's outcome: a failure carries its canonical signal
/// unchanged (class, provider code and retry-after floor), across every breaker class.
#[test]
fn failure_signal_carries_the_canonical_signal_unchanged() {
    use crate::breaker::StatusClass as BC;
    for class in [
        BC::RateLimit,
        BC::Overloaded,
        BC::ServerError,
        BC::Timeout,
        BC::Network,
        BC::Auth,
        BC::Billing,
        BC::ClientError,
        BC::ContextLength,
    ] {
        let cs = CanonicalSignal {
            class,
            provider_signal: Some("code".to_string()),
            retry_after: Some(30),
        };
        assert_eq!(failure_signal(&cs), Settle::Failure(cs.clone()));
    }
    assert_eq!(success_signal(), Settle::Success);
    assert_eq!(refused_signal(), Settle::RecordNothing);
}

/// FAITHFULNESS PROOF (end-to-end): settling the 401 and 429 signals THROUGH [`admit`] + the host's
/// `breaker_settle` leaves the target cell in the SAME state as recording the `normalize_raw_error`
/// `CanonicalSignal` directly onto an identical cell. This is the guarantee
/// CLUSTER-1 needs: the host settle path IS the plane's own `record_signal` disposition.
#[test]
fn settle_through_host_matches_direct_record_signal() {
    use crate::breaker::{normalize_raw_error, RawUpstreamError};
    use std::collections::HashMap;
    let no_map: HashMap<String, String> = HashMap::new();

    for raw in [
        RawUpstreamError {
            http_status: 401,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        },
        RawUpstreamError {
            http_status: 429,
            provider_code: Some("slow_down".to_string()),
            structured_type: None,
            retry_after_secs: Some(30),
        },
    ] {
        // BOTH cells stamp an Open cooldown as `now() + cooldown` off the WALL CLOCK, one recording
        // after the other, and the clock reads WHOLE SECONDS. So when the second happens to tick
        // between the two recordings the two deadlines differ by exactly that tick — `until: N` vs
        // `until: N+1` — over no difference in disposition at all, which is the one thing this proof
        // is about. Take the reading again when the clock moved under it (bounded, and a clock that
        // never holds still for one pair of recordings is itself the failure), so the comparison
        // only ever sees two recordings made inside the same tick. Nothing about what is compared is
        // relaxed: the states must still be EQUAL, deadline included.
        let mut sample = None;
        for _ in 0..16 {
            let started = busbar_kernel::store::now();

            // Direct path: normalize + record straight onto a fresh cell.
            let direct = crate::test_support::TestApp::new().build();
            let cs = normalize_raw_error(&raw, &no_map);
            direct.plane_breakers.record_signal(POOL_STR, 0, &cs);
            let direct_state = direct.plane_breakers.state_at(POOL_STR, 0);

            // Host path: admit + settle the same signal on an identical fresh cell.
            let hosted = host();
            {
                let scope = DispatchScope::new();
                let id = admit(&hosted, &scope, POOL, 0).expect("a Closed-ready cell admits");
                assert_eq!(
                    hosted.breaker_settle(&scope, id, &failure_signal(&cs)),
                    Settled::Ok,
                );
            }
            let hosted_state = hosted.breaker_store().state_at(POOL_STR, 0);

            if busbar_kernel::store::now() == started {
                sample = Some((direct_state, hosted_state));
                break;
            }
        }
        let (direct_state, hosted_state) = sample.unwrap_or_else(|| {
            panic!(
                "the wall clock ticked through 16 consecutive attempts at http {}: the two \
                 recordings can never be compared within one second",
                raw.http_status
            )
        });

        assert_eq!(
            direct_state, hosted_state,
            "host settle must leave the cell in the same state as a direct record_signal \
             for http {}",
            raw.http_status
        );
    }
}
