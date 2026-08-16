// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The degenerate-cell semantics of [`PlaneBreakers`], on the mocked clock: trip on the core
//! thresholds, per-cell hard-down isolation, single-flight half-open recovery, owner-checked
//! probe release. The PLANES' call sites are proven in their own batteries
//! (`mcp/tests/breaker_fastfail_tests.rs`, `a2a/tests/breaker_fastfail_tests.rs`); this file pins
//! the store-side contract those batteries stand on.

use super::super::planes::PlaneBreakers;
use super::super::{set_now_for_test, BreakerState, Unavailable};
use crate::breaker::{CanonicalSignal, StatusClass};

fn signal(class: StatusClass) -> CanonicalSignal {
    CanonicalSignal {
        class,
        provider_signal: None,
        retry_after: None,
    }
}

/// Five transient failures inside the window trip the cell — the ADR-0002 error-rate default —
/// and the SIXTH admission is refused `BreakerOpen` with an EXACT recovery deadline.
#[test]
fn transient_failures_trip_and_fast_fail() {
    set_now_for_test(1_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::tool_key("fs");
    assert!(b.try_admit(&key, 0).is_ok(), "a fresh cell admits");
    // Recorded without interleaved admissions. The cell stays ADMITTING throughout the first four:
    // on this plane a sub-threshold transient does not bench the member (see
    // `BreakerCfg::bench_below_trip_threshold` — the benching cooldown is the "prefer a sibling"
    // half of a rule whose other half is a failover an UNPOOLED target does not have). The FIFTH
    // failure crosses the error-rate threshold and TRIPS, which is the first thing that refuses
    // anybody.
    for _ in 0..5 {
        b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    }
    assert!(matches!(b.state(&key), BreakerState::Open { .. }));
    match b.try_admit(&key, 0) {
        Err(Unavailable::BreakerOpen { until }) => assert!(until > 1_000),
        other => panic!("a tripped cell must refuse admission, got {other:?}"),
    }
    assert!(b.retry_after_secs(&key, 0) >= 1);
}

/// An Auth signal (401/403) is a HARD DOWN: the cell trips on the FIRST failure — and ONLY that
/// cell. The isolation half is the whole reason `record_signal` uses the per-cell hard-down: every
/// plane target shares lane 0, so an all-cells write would trip every other server and agent.
#[test]
fn hard_down_trips_immediately_and_only_its_own_cell() {
    set_now_for_test(2_000);
    let b = PlaneBreakers::new();
    let fs = PlaneBreakers::tool_key("fs");
    let other_tool = PlaneBreakers::tool_key("search");
    let agent = PlaneBreakers::agent_key("planner");

    let epoch = b.try_admit(&fs, 0).expect("closed cell admits");
    b.record_signal(&fs, 0, &signal(StatusClass::Auth));
    b.release(&fs, 0, epoch);

    assert!(matches!(b.state(&fs), BreakerState::Open { .. }));
    assert!(b.try_admit(&fs, 0).is_err(), "tripped target must refuse");
    // The neighbours are untouched — the keyspace isolation the plane-qualified keys exist for.
    assert!(b.try_admit(&other_tool, 0).is_ok());
    assert!(b.try_admit(&agent, 0).is_ok());
}

/// The two plane prefixes cannot collide: a tool server and an agent that happen to share a bare
/// name have DISTINCT cells.
#[test]
fn tool_and_agent_keys_never_collide() {
    set_now_for_test(3_000);
    let b = PlaneBreakers::new();
    let tool = PlaneBreakers::tool_key("planner");
    let agent = PlaneBreakers::agent_key("planner");
    assert_ne!(tool, agent);
    let epoch = b.try_admit(&tool, 0).expect("admits");
    b.record_signal(&tool, 0, &signal(StatusClass::Auth));
    b.release(&tool, 0, epoch);
    assert!(b.try_admit(&tool, 0).is_err());
    assert!(b.try_admit(&agent, 0).is_ok(), "the agent cell is its own");
}

/// RECOVERY IS A SINGLE-FLIGHT PROBE: once the cooldown expires exactly ONE caller is admitted
/// (HalfOpen), a concurrent caller loses the race, and the probe's success closes the cell for
/// everyone — once, not per queued caller.
#[test]
fn half_open_probe_is_single_flight_and_success_closes() {
    set_now_for_test(10_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::agent_key("planner");
    for _ in 0..5 {
        b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    }
    assert!(matches!(b.state(&key), BreakerState::Open { .. }));

    // Past every cooldown this cfg can compute (max_cooldown_secs = 120).
    set_now_for_test(10_000 + 3_600);
    let probe = b
        .try_admit(&key, 0)
        .expect("the expired-Open cell admits ONE probe");
    assert!(matches!(b.state(&key), BreakerState::HalfOpen));
    assert!(
        matches!(b.try_admit(&key, 0), Err(Unavailable::ProbeInFlight)),
        "a second caller must lose the single-flight race"
    );
    b.record_success(&key, 0);
    b.release(&key, 0, probe);
    assert!(matches!(b.state(&key), BreakerState::Closed));
    assert!(
        b.try_admit(&key, 0).is_ok(),
        "a recovered cell serves everyone"
    );
}

/// A FAILED probe re-opens the cell rather than closing it or wedging it HalfOpen.
#[test]
fn failed_probe_reopens() {
    set_now_for_test(20_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::tool_key("fs");
    for _ in 0..5 {
        b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    }
    set_now_for_test(20_000 + 3_600);
    let probe = b.try_admit(&key, 0).expect("probe admitted");
    b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    b.release(&key, 0, probe);
    assert!(matches!(b.state(&key), BreakerState::Open { .. }));
    assert!(b.try_admit(&key, 0).is_err());
}

/// An ABANDONED probe — admitted, then the dispatch refused before any leg went out, so nothing was
/// recorded — is handed back by the owner-checked release, and the NEXT caller can win it. Without
/// this the cell wedges HalfOpen forever.
#[test]
fn abandoned_probe_release_unwedges_the_cell() {
    set_now_for_test(30_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::tool_key("fs");
    for _ in 0..5 {
        b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    }
    set_now_for_test(30_000 + 3_600);
    let probe = b.try_admit(&key, 0).expect("probe admitted");
    // Nothing recorded: the dispatch was refused between admission and the wire.
    b.release(&key, 0, probe);
    assert!(
        b.try_admit(&key, 0).is_ok(),
        "the released probe must be re-winnable by the next caller"
    );
}

/// A ClientFault-shaped signal records NOTHING against the cell — the caller's bad input is never a
/// lane penalty, on any plane.
#[test]
fn client_fault_never_penalizes() {
    set_now_for_test(40_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::tool_key("fs");
    for _ in 0..20 {
        b.record_signal(&key, 0, &signal(StatusClass::ClientError));
    }
    assert!(matches!(b.state(&key), BreakerState::Closed));
    assert!(b.try_admit(&key, 0).is_ok());
}

/// `retry_after_secs` is the cell's own remaining cooldown, exact, not a guess.
#[test]
fn retry_after_is_the_exact_cooldown() {
    set_now_for_test(50_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::agent_key("planner");
    b.record_signal(&key, 0, &signal(StatusClass::Auth));
    // Hard-down parks the cell with the sticky cooldown (default 1800s).
    let ra = b.retry_after_secs(&key, 0);
    assert!(
        ra > 1_000,
        "hard-down cooldown must be the sticky one, got {ra}"
    );
}

/// THE SUB-THRESHOLD RULE, AT THE CELL. A transient failure that did NOT breach the trip predicate
/// leaves the cell Closed AND ADMITTING — the tightest statement of the defect that had the
/// in-house MCP conformance battery red for five commits.
///
/// The LLM plane's identical FSM benches a lane here on purpose, because the walk then prefers a
/// sibling and the caller is still served. This plane has no walk (`docs/circuit-breaker.md`: "a
/// tripped target is refused, never rerouted"), so benching the only member is a 15-120s outage
/// for every caller, bought with one blip and announced as "open after repeated failures".
#[test]
fn one_sub_threshold_transient_leaves_the_cell_admitting() {
    set_now_for_test(2_000);
    let b = PlaneBreakers::new();
    let key = PlaneBreakers::tool_key("fs");
    b.record_signal(&key, &signal(StatusClass::ServerError));
    assert!(
        matches!(b.state(&key), BreakerState::Closed),
        "one transient cannot satisfy min_requests, so the cell must still read Closed"
    );
    assert!(
        b.try_admit(&key).is_ok(),
        "a cell that did not trip must not refuse the next caller"
    );
}
