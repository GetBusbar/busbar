// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's own surface: the lifetime budget, the probe a caller gives back, and the wait the
//! at-capacity terminal advertises.
//!
//! Each of these is a value some other unit reads and acts on — a budget that answered "unlimited"
//! for a capped destination would let a walk spend past its cap, and a wait computed from nothing
//! would send every shed client back at the same instant. They are asserted here directly, on the
//! unit rather than through a walk, because that is where each of them is decided.

use std::sync::{Arc, Mutex};

use busbar_caps::{KernelSeal, Route, UnitToken};

use crate::cfg::{BreakerCfg, TripConfig, TripMode};
use crate::journal::{JournalSink, ProbeEvent};
use crate::{
    Breaker, BreakerUnit, DestinationId, LaneState, Outcome, AT_CAPACITY_RETRY_AFTER_SECS,
};

/// A fresh `UnitToken<Route>` for one call — test-only, minted through the kernel seal exactly as a
/// real deployment would.
fn route_token() -> UnitToken<Route> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// A journal that keeps every event it is handed, in order. Shared by handle so a test can hold one
/// end while the unit owns the other.
#[derive(Clone, Default)]
struct RecordingJournal {
    events: Arc<Mutex<Vec<ProbeEvent>>>,
}

impl RecordingJournal {
    fn events(&self) -> Vec<ProbeEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl JournalSink for RecordingJournal {
    fn record(&self, event: ProbeEvent) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}

/// A configuration that never trips on its own, so a test that is about something else is not
/// tripping a cell by accident.
fn never_trips() -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 2,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 300,
            threshold: 1.0,
            min_requests: usize::MAX,
            consecutive_n: u32::MAX,
        },
        bench_below_trip_threshold: false,
    }
}

// ── the lifetime budget ─────────────────────────────────────────────────────────────────────────

/// A declared cap is a cap: the remaining figure is the number the operator set, and it comes down
/// one unit per spend until it is spent out.
#[test]
fn a_declared_budget_counts_down_and_then_refuses() {
    let unit: BreakerUnit = BreakerUnit::new();
    let destination = DestinationId::new(1);
    unit.set_budget(destination, 3);

    assert_eq!(
        unit.budget_remaining(destination),
        Some(3),
        "the cap is the number the operator declared"
    );

    assert!(unit.spend_budget(destination));
    assert_eq!(unit.budget_remaining(destination), Some(2));
    assert!(unit.spend_budget(destination));
    assert_eq!(unit.budget_remaining(destination), Some(1));
    assert!(unit.spend_budget(destination));
    assert_eq!(unit.budget_remaining(destination), Some(0));

    assert!(
        !unit.spend_budget(destination),
        "the spend that would drive the counter negative is refused instead"
    );
    assert_eq!(
        unit.budget_remaining(destination),
        Some(0),
        "and it is a no-op: the counter is never driven negative"
    );
}

/// A cap of zero is spent from the moment it is declared.
#[test]
fn a_budget_of_zero_is_already_spent() {
    let unit: BreakerUnit = BreakerUnit::new();
    let destination = DestinationId::new(1);
    unit.set_budget(destination, 0);
    assert_eq!(unit.budget_remaining(destination), Some(0));
    assert!(!unit.spend_budget(destination));
}

/// A negative cap means unlimited, and so does never declaring one: neither reports a remaining
/// figure, and every spend against them succeeds.
#[test]
fn an_unlimited_or_undeclared_destination_reports_no_figure_and_always_spends() {
    let unit: BreakerUnit = BreakerUnit::new();
    let unlimited = DestinationId::new(1);
    let undeclared = DestinationId::new(2);
    unit.set_budget(unlimited, -1);

    assert_eq!(unit.budget_remaining(unlimited), None);
    assert_eq!(unit.budget_remaining(undeclared), None);
    for _ in 0..64 {
        assert!(unit.spend_budget(unlimited));
        assert!(unit.spend_budget(undeclared));
    }
    assert_eq!(unit.budget_remaining(unlimited), None);
}

/// The refund is a compensating give-back of one unit, and it reaches the counter.
#[test]
fn a_refund_gives_back_exactly_the_unit_that_was_spent() {
    let unit: BreakerUnit = BreakerUnit::new();
    let destination = DestinationId::new(1);
    unit.set_budget(destination, 2);

    assert!(unit.spend_budget(destination));
    assert!(unit.spend_budget(destination));
    assert_eq!(unit.budget_remaining(destination), Some(0));

    unit.refund_budget(destination);
    assert_eq!(
        unit.budget_remaining(destination),
        Some(1),
        "the refund is what lets the destination be spent from again"
    );
    assert!(unit.spend_budget(destination));
    assert_eq!(unit.budget_remaining(destination), Some(0));

    // Two refunds give back two units.
    unit.refund_budget(destination);
    unit.refund_budget(destination);
    assert_eq!(unit.budget_remaining(destination), Some(2));
}

/// A refund against a destination that has no budget at all is a no-op rather than a panic.
#[test]
fn a_refund_against_an_undeclared_destination_does_nothing() {
    let unit: BreakerUnit = BreakerUnit::new();
    unit.refund_budget(DestinationId::new(9));
    assert_eq!(unit.budget_remaining(DestinationId::new(9)), None);
}

/// An exhausted destination is EXCLUDED, and the exclusion takes precedence over whatever its
/// breaker cell reads: a healthy cell on a spent-out destination is still not selectable.
#[test]
fn an_exhausted_budget_excludes_the_destination_whatever_its_cell_says() {
    let unit: BreakerUnit = BreakerUnit::new();
    let destination = DestinationId::new(1);
    unit.set_budget(destination, 1);

    assert_eq!(
        unit.state("primary", destination, 100, &route_token()),
        LaneState::Ready
    );
    assert!(unit.spend_budget(destination));
    assert_eq!(
        unit.state("primary", destination, 100, &route_token()),
        LaneState::BudgetExhausted,
        "the cell is closed and ready; the budget is what excludes it"
    );
    assert_eq!(
        unit.try_admit("primary", destination, 100),
        Err(LaneState::BudgetExhausted)
    );
}

// ── the probe a caller gives back ───────────────────────────────────────────────────────────────

/// A probe won but never dispatched is given back by the release, and the cell is winnable again.
/// Both the state and the journal say so.
#[test]
fn releasing_an_undispatched_probe_gives_the_cell_back() {
    let journal = RecordingJournal::default();
    let unit = BreakerUnit::with_journal(journal.clone());
    let destination = DestinationId::new(1);

    // Touch the pool's own cell first: a hard-down fans out over the pools already registered
    // against the destination, and an untouched pool has no cell to trip.
    let _ = unit.try_admit("primary", destination, 0);
    // Trip the cell hard-down, then let its cooldown elapse so the probe is winnable.
    assert!(unit.observe(
        "primary",
        destination,
        Outcome::HardDown,
        &never_trips(),
        100,
        &route_token(),
    ));
    let after = 100 + crate::DEFAULT_HARD_DOWN_COOLDOWN_SECS;

    let admit = unit
        .try_admit("primary", destination, after)
        .expect("the probe was winnable once the cooldown elapsed");
    let epoch = admit.probe_epoch.expect("this admission won the probe");

    assert_eq!(
        unit.state("primary", destination, after, &route_token()),
        LaneState::ProbeInFlight,
        "while the probe is held nobody else may dispatch"
    );

    unit.release_probe("primary", destination, epoch, after);

    assert_eq!(
        unit.state("primary", destination, after, &route_token()),
        LaneState::Ready,
        "the released probe leaves the cell winnable again rather than wedged half-open"
    );
    assert!(
        unit.try_admit("primary", destination, after)
            .expect("winnable again")
            .probe_epoch
            .is_some(),
        "and the next caller wins a probe of its own"
    );

    let events = journal.events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ProbeEvent::Released { epoch: e_epoch, .. } if *e_epoch == epoch
        )),
        "the release is journaled with the epoch it gave back: {events:?}"
    );
}

/// A release naming a token the cell no longer offers reverts nothing — the late-guard race the
/// owner check exists to close.
#[test]
fn a_release_that_owns_nothing_leaves_a_live_probe_alone() {
    let unit: BreakerUnit = BreakerUnit::new();
    let destination = DestinationId::new(1);
    let _ = unit.try_admit("primary", destination, 0);
    assert!(unit.observe(
        "primary",
        destination,
        Outcome::HardDown,
        &never_trips(),
        100,
        &route_token(),
    ));
    let after = 100 + crate::DEFAULT_HARD_DOWN_COOLDOWN_SECS;

    let epoch = unit
        .try_admit("primary", destination, after)
        .expect("winnable")
        .probe_epoch
        .expect("won");

    unit.release_probe("primary", destination, epoch.wrapping_add(9), after);
    assert_eq!(
        unit.state("primary", destination, after, &route_token()),
        LaneState::ProbeInFlight,
        "a stale release must not revert a probe it does not own"
    );
}

/// A failed recovery probe is journaled with the cooldown the reopen actually armed, not with the
/// instant it happened — a reader of the journal has to be able to say when the lane comes back.
#[test]
fn a_failed_probe_is_journaled_with_the_cooldown_it_armed() {
    let journal = RecordingJournal::default();
    let unit = BreakerUnit::with_journal(journal.clone());
    let destination = DestinationId::new(1);

    let _ = unit.try_admit("primary", destination, 0);
    assert!(unit.observe(
        "primary",
        destination,
        Outcome::HardDown,
        &never_trips(),
        100,
        &route_token(),
    ));
    let after = 100 + crate::DEFAULT_HARD_DOWN_COOLDOWN_SECS;
    assert!(
        unit.try_admit("primary", destination, after)
            .expect("winnable")
            .probe_epoch
            .is_some(),
        "the dispatch that fails below is the one holding the probe"
    );

    // The probe fails, carrying the upstream's own wait: the reopen arms `after + 500`.
    assert!(
        !unit.observe(
            "primary",
            destination,
            Outcome::Transient {
                retry_after: Some(500)
            },
            &never_trips(),
            after,
            &route_token(),
        ),
        "a reopen is not a fresh trip"
    );

    let events = journal.events();
    let recorded = events
        .iter()
        .find_map(|e| match e {
            ProbeEvent::Failed { cooldown_until, .. } => Some(*cooldown_until),
            _ => None,
        })
        .expect("the failed probe was journaled");
    assert_eq!(
        recorded,
        after + 500,
        "the journal names the deadline the reopen armed, not the instant it was recorded"
    );
    assert_eq!(
        unit.state("primary", destination, after, &route_token()),
        LaneState::Suppressed { until: after + 500 },
        "and the cell agrees with what was journaled"
    );
}

// ── the wait the at-capacity terminal advertises ────────────────────────────────────────────────

/// The wait is the SOONEST genuine cooldown among the members offered.
#[test]
fn the_at_capacity_wait_is_the_soonest_genuine_cooldown() {
    let states = [
        LaneState::Suppressed { until: 150 },
        LaneState::Suppressed { until: 130 },
        LaneState::Suppressed { until: 190 },
    ];
    assert_eq!(<BreakerUnit>::on_exhausted_retry_after(states, 100), 30);
}

/// A member in any other state contributes no cooldown, so a pool of them falls to the floor.
#[test]
fn a_pool_with_no_genuine_cooldown_gets_the_floor() {
    for states in [
        vec![],
        vec![LaneState::Ready],
        vec![LaneState::ProbeInFlight, LaneState::BudgetExhausted],
    ] {
        assert_eq!(
            <BreakerUnit>::on_exhausted_retry_after(states.clone(), 100),
            AT_CAPACITY_RETRY_AFTER_SECS,
            "nothing in {states:?} justifies a wait of its own"
        );
    }
    assert_eq!(
        AT_CAPACITY_RETRY_AFTER_SECS, 2,
        "the floor is the value that shipped"
    );
}

/// A suppressed member whose deadline has already passed is NOT a genuine cooldown: it is actually
/// probe-winnable, and a wait computed from it would send the client back for nothing. The edge is
/// exact — at the deadline itself there is nothing left to wait out.
#[test]
fn an_elapsed_cooldown_is_not_a_genuine_wait() {
    // Exactly at the deadline: nothing to wait for, so the floor.
    assert_eq!(
        <BreakerUnit>::on_exhausted_retry_after([LaneState::Suppressed { until: 100 }], 100),
        AT_CAPACITY_RETRY_AFTER_SECS
    );
    // Already past it: the same.
    assert_eq!(
        <BreakerUnit>::on_exhausted_retry_after([LaneState::Suppressed { until: 40 }], 100),
        AT_CAPACITY_RETRY_AFTER_SECS
    );
    // One second short of it: a genuine second to wait.
    assert_eq!(
        <BreakerUnit>::on_exhausted_retry_after([LaneState::Suppressed { until: 101 }], 100),
        1
    );
    // And an elapsed member does not mask a sibling that really is cooling.
    assert_eq!(
        <BreakerUnit>::on_exhausted_retry_after(
            [
                LaneState::Suppressed { until: 40 },
                LaneState::Suppressed { until: 145 },
            ],
            100
        ),
        45
    );
}

/// The answer is never zero: a client told to retry after nothing retries immediately into the same
/// refusal.
#[test]
fn the_wait_is_never_zero() {
    assert_eq!(
        <BreakerUnit>::on_exhausted_retry_after([LaneState::Suppressed { until: 100 }], 100),
        AT_CAPACITY_RETRY_AFTER_SECS
    );
    assert!(<BreakerUnit>::on_exhausted_retry_after([LaneState::Ready], 100) >= 1);
}
