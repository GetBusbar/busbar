// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GOVERNANCE-BUDGET capability cells (voice-client + voice-server) — GATE-VALID location.
//!
//! The D2 session lease's reserve → settle → exhaust → hard-close contract already lives and passes
//! in `runtime/tests.rs` (`settle_past_cap_hard_closes_the_carrier` +
//! `host_lease_reserves_settles_and_hard_closes_at_the_real_cap`), but that path clears neither the
//! equality gate's `/tests/` directory rule nor its `_tests.rs` suffix. These are the SAME
//! assertions, re-homed under `src/tests/` so the capability-equality gate's location rule is met.
//! The lease runs over the production money hop (`plane_host::MeteringHost`) — a settle past the cap
//! returns `Exhausted` (a hard close) and refuses further spend. Runtime-gated so the lease compiles.

use crate::runtime::metering::{HostMeteringPort, LeaseState, MeteringPort, MockMeteringHost};
use busbar_substrate::plane_host::MeteringHost;
use std::sync::Arc;

/// voice-client cell: a session lease settled PAST its cap hard-closes and refuses further spend —
/// the marquee D2 hard-close-on-exhaustion guarantee.
#[test]
fn a_session_lease_settled_past_its_cap_hard_closes_and_refuses_further_spend() {
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    let port = HostMeteringPort::new(host);
    // Cap of 5 nanodollars; each settle bills 3.
    let lease = port
        .reserve(0, 0, Some(5))
        .expect("a real cap opens the lease");

    // Settle 1: 3 < 5 → still live, no close.
    assert_eq!(lease.settle(3), LeaseState::Live, "3 < 5 → live, no close");
    assert!(
        !lease.settle(0).must_close(),
        "a live lease demands no close"
    );

    // Settle 2: 3 + 3 = 6 ≥ cap 5 → EXHAUSTED → hard close.
    let state = lease.settle(3);
    assert_eq!(state, LeaseState::Exhausted, "6 ≥ cap 5 → exhausted");
    assert!(
        state.must_close(),
        "exhaustion demands a carrier hard close"
    );

    // Further spend past the cap stays closed — the lease refuses to go back live.
    assert!(
        lease.settle(3).must_close(),
        "a lease past its cap refuses further spend and stays hard-closed"
    );
    assert_eq!(lease.settled_nanos(), 9, "exact accrual, no drift");
}

/// voice-server cell: the session lease bills the presenting key and refuses past the cap with a hard
/// close — reserve = estimate + flat fee charged once, exhaustion judged against the TRUE cap only,
/// and dropping the handle closes the lease host-side (no registry leak).
#[test]
fn the_session_lease_bills_the_presenting_key_and_refuses_past_the_cap_with_a_hard_close() {
    let host = Arc::new(MockMeteringHost::default());
    let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);

    // Reserve estimate 100 + flat fee 10, TRUE cap 50 (the flat fee folds into `reserved`, NOT the
    // cap — exhaustion is judged against the cap only, so the fee is never double-counted on settle).
    let lease = port
        .reserve(100, 10, Some(50))
        .expect("a real cap opens the lease for the presenting key");
    assert_eq!(
        host.reserved_of(1),
        Some(110),
        "reserve = estimate + flat fee, billed to the presenting key once"
    );

    assert_eq!(lease.settle(20), LeaseState::Live, "20 < 50 → live");
    assert_eq!(lease.settle(20), LeaseState::Live, "40 < 50 → live");
    assert_eq!(
        lease.settled_nanos(),
        40,
        "settled tap reads through the host"
    );
    assert_eq!(
        lease.settle(20),
        LeaseState::Exhausted,
        "60 ≥ cap 50 → exhausted (hard close)"
    );
    assert!(
        lease.settle(20).must_close(),
        "past the cap the lease refuses further spend with a hard close"
    );
    assert_eq!(lease.settled_nanos(), 80, "exact accrual, no drift");

    // Dropping the handle closes the lease host-side (no registry leak).
    drop(lease);
    assert!(
        host.closed_ids().contains(&1),
        "the dropped HostLease closed its lease host-side"
    );
}
