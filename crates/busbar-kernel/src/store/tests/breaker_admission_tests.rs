// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The degenerate-cell semantics of [`PlaneBreakers`], on the mocked clock: trip on the core
//! thresholds, per-cell hard-down isolation, single-flight half-open recovery, owner-checked
//! probe release. The dispatch call sites are proven in their own batteries; this file pins the
//! store-side contract those batteries stand on.

use super::super::breaker_admission::PlaneBreakers;
use super::super::{set_now_for_test, BreakerState, Unavailable};
use busbar_contract::upstream::{CanonicalSignal, StatusClass};

/// Opaque cell keys. The kernel's store never reads a key's spelling (a plane qualifies its own
/// keys and proves its own non-collision), so these name no plane's keyspace (BUSBAR-1.6.0.md THE
/// DESIGN §1: "Kernel tests use kind-neutral doubles").
const KEY_A: &str = "k:a";
const KEY_B: &str = "k:b";
const KEY_C: &str = "k:c";

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
    let key = KEY_A.to_string();
    assert!(b.try_admit(&key, 0).is_ok(), "a fresh cell admits");
    // Recorded without interleaved admissions. The cell stays ADMITTING throughout the first four:
    // a sub-threshold transient does not bench the member (see
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
/// target shares lane 0, so an all-cells write would trip every other target.
#[test]
fn hard_down_trips_immediately_and_only_its_own_cell() {
    set_now_for_test(2_000);
    let b = PlaneBreakers::new();
    let fs = KEY_A.to_string();
    let other = KEY_B.to_string();
    let third = KEY_C.to_string();

    let epoch = b.try_admit(&fs, 0).expect("closed cell admits");
    b.record_signal(&fs, 0, &signal(StatusClass::Auth));
    b.release(&fs, 0, epoch);

    assert!(matches!(b.state(&fs), BreakerState::Open { .. }));
    assert!(b.try_admit(&fs, 0).is_err(), "tripped target must refuse");
    // The neighbours are untouched — every key is its own cell.
    assert!(b.try_admit(&other, 0).is_ok());
    assert!(b.try_admit(&third, 0).is_ok());
}

/// RECOVERY IS A SINGLE-FLIGHT PROBE: once the cooldown expires exactly ONE caller is admitted
/// (HalfOpen), a concurrent caller loses the race, and the probe's success closes the cell for
/// everyone — once, not per queued caller.
#[test]
fn half_open_probe_is_single_flight_and_success_closes() {
    set_now_for_test(10_000);
    let b = PlaneBreakers::new();
    let key = KEY_B.to_string();
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
    let key = KEY_A.to_string();
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
    let key = KEY_A.to_string();
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
/// lane penalty.
#[test]
fn client_fault_never_penalizes() {
    set_now_for_test(40_000);
    let b = PlaneBreakers::new();
    let key = KEY_A.to_string();
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
    let key = KEY_B.to_string();
    b.record_signal(&key, 0, &signal(StatusClass::Auth));
    // Hard-down parks the cell with the sticky cooldown (default 1800s).
    let ra = b.retry_after_secs(&key, 0);
    assert!(
        ra > 1_000,
        "hard-down cooldown must be the sticky one, got {ra}"
    );
}

/// THE SUB-THRESHOLD RULE, AT THE CELL. A transient failure that did NOT breach the trip predicate
/// leaves the cell Closed AND ADMITTING — the tightest statement of the defect that had an
/// out-of-tree plugin's conformance battery red for five commits.
///
/// A pooled walk could prefer a sibling here and still serve the caller, but the walk only has
/// somewhere to go when the operator declared a pool, and the UNPOOLED single registration is the
/// canonical case — so benching the only member is a 15-120s outage for every caller, bought
/// with one blip and announced as "open after repeated failures". `bench_below_trip_threshold` is
/// a per-breaker setting, so a pooled cell inherits the conservative answer and is routed around on
/// a TRIP instead.
#[test]
fn one_sub_threshold_transient_leaves_the_cell_admitting() {
    set_now_for_test(2_000);
    let b = PlaneBreakers::new();
    let key = KEY_A.to_string();
    b.record_signal(&key, 0, &signal(StatusClass::ServerError));
    assert!(
        matches!(b.state(&key), BreakerState::Closed),
        "one transient cannot satisfy min_requests, so the cell must still read Closed"
    );
    assert!(
        b.try_admit(&key, 0).is_ok(),
        "a cell that did not trip must not refuse the next caller"
    );
}

/// THE OPERATOR'S LIMITS REACH THESE CELLS (BUSBAR-1.6.0.md THE DESIGN §1: "Any plugin gets all
/// functionality"): a handle built under `limits.hard_down_cooldown_secs` arms that sticky
/// cooldown, and a handle already in service takes a subsequent generation's value through
/// `set_limits` without losing the cell it learned. The end-to-end RED arm (the build and the
/// swap) is `tests::the_operator_breaker_limits_reach_every_planes_cells`.
#[test]
fn the_operator_hard_down_cooldown_reaches_the_cells_and_follows_a_new_generation() {
    set_now_for_test(60_000);
    let b = PlaneBreakers::new_with_limits(60, 86_400);
    b.record_signal(KEY_A, 0, &signal(StatusClass::Auth));
    assert_eq!(
        b.retry_after_secs(KEY_A, 0),
        60,
        "the operator's sticky cooldown"
    );

    b.set_limits(300, 86_400);
    assert_eq!(
        b.retry_after_secs(KEY_A, 0),
        60,
        "an armed cooldown keeps the `until` it was armed with"
    );
    b.record_signal(KEY_B, 0, &signal(StatusClass::Auth));
    assert_eq!(
        b.retry_after_secs(KEY_B, 0),
        300,
        "the next hard-down arms the new value"
    );
}

/// The honoured-wait CEILING reaches these cells too: an upstream asking for a day is clamped to
/// the operator's `limits.max_honored_retry_after_secs`, not to the 24h default.
#[test]
fn the_operator_retry_after_ceiling_reaches_the_cells() {
    set_now_for_test(70_000);
    let b = PlaneBreakers::new_with_limits(1_800, 90);
    // One sub-threshold failure: this cell benches nothing of its own, so the only wait armed is
    // the upstream's own request — clamped to the ceiling.
    b.record_signal(
        KEY_A,
        0,
        &CanonicalSignal {
            class: StatusClass::Overloaded,
            provider_signal: None,
            retry_after: Some(86_400),
        },
    );
    assert_eq!(
        b.retry_after_secs(KEY_A, 0),
        90,
        "an honoured wait is clamped to the operator's ceiling, not the 24h default"
    );
}
