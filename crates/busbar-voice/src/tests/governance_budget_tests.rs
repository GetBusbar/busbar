// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GOVERNANCE-BUDGET capability cells (voice-client + voice-server) — GATE-VALID location.
//!
//! The D2 session lease's reserve → settle → exhaust → hard-close contract already lives and passes
//! in `runtime/tests.rs` (`settle_past_cap_hard_closes_the_carrier` +
//! `host_lease_reserves_settles_and_hard_closes_at_the_real_cap`), but that path clears neither the
//! equality gate's `/tests/` directory rule nor its `_tests.rs` suffix. These are the SAME
//! assertions, re-homed under `src/tests/` so the capability-equality gate's location rule is met.
//! The lease runs over the production money hop (the kernel's `HostMeteringPort` over
//! `plane_host::MeteringHost`) — a turn that settles past the cap answers `MustClose` (a hard close)
//! and every further turn stays closed. Runtime-gated so the lease compiles.

use crate::runtime::metering::{
    HostMeteringPort, MockMeteringHost, SessionBudget, SessionLease, SessionMeter, TurnVerdict,
};
use busbar_kernel::plane_host::MeteringHost;
use std::sync::Arc;

/// A session on the kernel's host meter over `host` with the given money terms (nanodollars).
fn lease_on(host: Arc<dyn MeteringHost>, estimate: u64, fee: u64, cap: u64) -> SessionLease {
    let meter = Arc::new(HostMeteringPort::new(host)) as Arc<dyn SessionMeter>;
    let budget = SessionBudget {
        estimate_nanos: estimate,
        fee_nanos: fee,
        cap_nanos: Some(cap),
    };
    SessionLease::open(&meter, &budget).expect("a real cap opens the lease")
}

/// One turn of `n` reported units (the mock host prices each at one nano).
fn units(n: u64) -> busbar_substrate_values::billing::Usage {
    let mut usage = busbar_substrate_values::billing::Usage::default();
    usage.usage_units.insert("output_tokens".into(), n);
    usage
}

/// voice-client cell: a session lease settled PAST its cap hard-closes and refuses further spend —
/// the marquee D2 hard-close-on-exhaustion guarantee.
#[test]
fn a_session_lease_settled_past_its_cap_hard_closes_and_refuses_further_spend() {
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    // Cap of 5 nanodollars; each turn reports 3 units (3 nanos).
    let lease = lease_on(host, 0, 0, 5);

    // Turn 1: 3 < 5 → still live, no close.
    assert_eq!(
        lease.report_turn("m", &units(3)),
        TurnVerdict::Live,
        "3 < 5 → live, no close"
    );
    assert_eq!(
        lease.report_turn("m", &units(0)),
        TurnVerdict::Live,
        "a live lease demands no close"
    );

    // Turn 2: 3 + 3 = 6 ≥ cap 5 → EXHAUSTED → hard close.
    assert_eq!(
        lease.report_turn("m", &units(3)),
        TurnVerdict::MustClose,
        "6 ≥ cap 5 → exhausted: exhaustion demands a carrier hard close"
    );

    // Further spend past the cap stays closed — the lease refuses to go back live.
    assert_eq!(
        lease.report_turn("m", &units(3)),
        TurnVerdict::MustClose,
        "a lease past its cap refuses further spend and stays hard-closed"
    );
    assert_eq!(lease.settled(), 9, "exact accrual, no drift");
}

/// voice-server cell: the session lease bills the presenting key and refuses past the cap with a hard
/// close — reserve = estimate + flat fee charged once, exhaustion judged against the TRUE cap only,
/// and dropping the handle closes the lease host-side (no registry leak).
#[test]
fn the_session_lease_bills_the_presenting_key_and_refuses_past_the_cap_with_a_hard_close() {
    let host = Arc::new(MockMeteringHost::default());

    // Reserve estimate 100 + flat fee 10, TRUE cap 50 (the flat fee folds into `reserved`, NOT the
    // cap — exhaustion is judged against the cap only, so the fee is never double-counted on settle).
    let lease = lease_on(Arc::clone(&host) as Arc<dyn MeteringHost>, 100, 10, 50);
    assert_eq!(
        host.reserved_of(1),
        Some(110),
        "reserve = estimate + flat fee, billed to the presenting key once"
    );

    assert_eq!(
        lease.report_turn("m", &units(20)),
        TurnVerdict::Live,
        "20 < 50 → live"
    );
    assert_eq!(
        lease.report_turn("m", &units(20)),
        TurnVerdict::Live,
        "40 < 50 → live"
    );
    assert_eq!(lease.settled(), 40, "settled tap reads through the host");
    assert_eq!(
        lease.report_turn("m", &units(20)),
        TurnVerdict::MustClose,
        "60 ≥ cap 50 → exhausted (hard close)"
    );
    assert_eq!(
        lease.report_turn("m", &units(20)),
        TurnVerdict::MustClose,
        "past the cap the lease refuses further spend with a hard close"
    );
    assert_eq!(lease.settled(), 80, "exact accrual, no drift");

    // Dropping the handle closes the lease host-side (no registry leak).
    drop(lease);
    assert!(
        host.closed_ids().contains(&1),
        "the dropped lease closed its session host-side"
    );
}
