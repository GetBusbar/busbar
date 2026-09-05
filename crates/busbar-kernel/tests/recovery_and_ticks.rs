// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the node owes after a crash, and what the clock does when nothing arrives.

mod common;

use busbar_caps::{Canary, HoldCell, OriginKind, PostingFlags, ReasonCode, StepName, UnitKey};
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::recovery::{
    frame, owed_after, recover_all, truncate_torn_tail, voids_claim, HoldRecord, KillPoint, Owed,
    TailVerdict,
};
use busbar_kernel::slice::{BucketId, ConcurrencyGauge, Epoch, LeaseSet};
use busbar_kernel::teller::{Evidence, Kernel};
use busbar_kernel::tick::{
    drain_outcome, drain_verdict, fleet_action, session_tick, sweep, sweep_settle, DrainVerdict,
    FleetAction, SessionTick, Sweep, SESSION_IDLE_MAX_MS,
};

use common::principal;

fn record(dispatched: bool, checkpointed: u64) -> HoldRecord {
    HoldRecord {
        unit: UnitKey::new(1),
        principal: principal(),
        reserved: 10_000,
        checkpointed,
        dispatched,
        lease_epoch: Epoch(1),
    }
}

#[test]
fn a_hold_from_a_dead_incarnation_comes_back_and_settles() {
    let kernel = Kernel::new();
    let canary = Canary::new();
    let postings = recover_all(
        &kernel,
        &[record(true, 640), record(false, 640)],
        Epoch(2),
        &canary,
    );
    assert_eq!(postings.len(), 2);
    assert_eq!(postings[0].settled(), 640);
    assert!(postings[0].flags().contains(PostingFlags::RECOVERED));
    assert_eq!(postings[1].settled(), 0);
    assert!(postings[1].flags().contains(PostingFlags::VOIDED));
    assert_eq!(canary.counts().settlements, 2);
}

#[test]
fn a_hold_of_the_current_incarnation_is_left_alone() {
    let kernel = Kernel::new();
    let canary = Canary::new();
    let postings = recover_all(&kernel, &[record(true, 100)], Epoch(1), &canary);
    assert!(
        postings.is_empty(),
        "the live node still owns its own holds"
    );
}

#[test]
fn every_kill_point_has_an_answer_and_none_of_them_guesses_upward() {
    let points = [
        KillPoint::BeforeDecode,
        KillPoint::BetweenPreDoorSteps,
        KillPoint::BetweenClaimAndHold,
        KillPoint::AfterHoldBeforeDispatch,
        KillPoint::BetweenLegs,
        KillPoint::AfterRelayBeforeSettle,
        KillPoint::MidWrite,
    ];
    for point in points {
        match owed_after(point) {
            Owed::Nothing => assert!(
                !matches!(
                    point,
                    KillPoint::BetweenLegs | KillPoint::AfterRelayBeforeSettle
                ),
                "{point:?} dispatched something and owes the checkpoint"
            ),
            Owed::LastCheckpoint => assert!(matches!(
                point,
                KillPoint::BetweenLegs | KillPoint::AfterRelayBeforeSettle
            )),
            Owed::TruncateThenDecide => assert_eq!(point, KillPoint::MidWrite),
        }
    }
    assert!(voids_claim(KillPoint::BetweenClaimAndHold));
    assert!(!voids_claim(KillPoint::AfterRelayBeforeSettle));
}

#[test]
fn a_torn_tail_is_truncated_and_a_whole_journal_is_not() {
    let mut journal = Vec::new();
    journal.extend_from_slice(&frame(b"one"));
    journal.extend_from_slice(&frame(b"two"));
    let clean = truncate_torn_tail(&journal);
    assert_eq!(clean.records, 2);
    assert_eq!(clean.verdict, TailVerdict::Clean);
    assert_eq!(clean.valid_bytes, journal.len());

    // The machine died halfway through the third record.
    let good = journal.len();
    let mut torn = journal.clone();
    torn.extend_from_slice(&frame(b"three")[..6]);
    let verdict = truncate_torn_tail(&torn);
    assert_eq!(verdict.records, 2);
    assert_eq!(verdict.verdict, TailVerdict::Torn);
    assert_eq!(verdict.valid_bytes, good);

    // And a record whose bytes were corrupted rather than cut short is refused just the same.
    let mut corrupt = journal.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    let verdict = truncate_torn_tail(&corrupt);
    assert_eq!(verdict.records, 1);
    assert_eq!(verdict.verdict, TailVerdict::Torn);
}

#[test]
fn a_lost_task_is_settled_within_one_tick() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(1),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, principal()),
        })
        .map_err(|_| ())
        .expect("under the cap");

    // The drop guard MARKS; it never ends the unit.
    slot.mark();
    let verdict = sweep(&slot, StepName::Route, 0, 30_000, true);
    assert_eq!(
        verdict,
        Sweep::TaskLost {
            at: StepName::Route
        }
    );

    let evidence = Evidence {
        accrued_floor: 42,
        ..Evidence::default()
    };
    // The unit was holding a concurrency lease when its task disappeared. The sweep is one of the
    // two ends a unit has, so the lease goes back here or it never goes back at all.
    let gauge = ConcurrencyGauge::new();
    let bucket = BucketId::all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");
    let mut leases = LeaseSet::new();
    leases.take(bucket.clone());

    let end = sweep_settle(
        &kernel,
        slot.cell(),
        verdict,
        &evidence,
        &canary,
        &mut leases,
        &gauge,
    )
    .expect("the sweep is the second key to the cell");
    assert_eq!(gauge.count(&bucket), 0, "the lost task kept its lease");
    assert!(leases.is_empty());
    assert_eq!(
        end.outcome(),
        busbar_caps::Outcome::Failed(StepName::Route, ReasonCode::TaskLost)
    );
    assert_eq!(end.posted().map(|p| p.settled()), Ok(42));
    assert_eq!(canary.counts().settlements, 1);

    // And there is no third settlement: a second sweep of the same cell does nothing.
    assert!(sweep_settle(
        &kernel,
        slot.cell(),
        verdict,
        &evidence,
        &canary,
        &mut leases,
        &gauge
    )
    .is_none());
}

#[test]
fn a_slow_unit_is_not_a_lost_one() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let slot = table
        .insert(Enter {
            key: UnitKey::new(2),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, principal()),
        })
        .map_err(|_| ())
        .expect("under the cap");
    slot.touch(0);

    assert_eq!(
        sweep(&slot, StepName::Route, 100, 30_000, true),
        Sweep::Running
    );
    assert_eq!(
        sweep(&slot, StepName::Route, 30_000, 30_000, true),
        Sweep::Stalled {
            at: StepName::Route
        }
    );
    // A protocol whose long silences were never cut is only alarmed about.
    assert_eq!(
        sweep(&slot, StepName::Route, 30_000, 30_000, false),
        Sweep::AlarmOnly
    );

    let cell = HoldCell::new(arrival_hold(&kernel, principal()));
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let mut leases = LeaseSet::new();
    assert!(sweep_settle(
        &kernel,
        &cell,
        Sweep::AlarmOnly,
        &Evidence::default(),
        &canary,
        &mut leases,
        &gauge
    )
    .is_none());
}

#[test]
fn the_session_tick_prices_time_it_could_not_price_last_time() {
    // Nothing priced, nothing changed: nothing to do.
    assert_eq!(
        session_tick(1_000, 1_000, 0, None, false, false, false),
        SessionTick::Idle
    );
    // Nothing priced, but the accrued figure moved: checkpoint it.
    assert_eq!(
        session_tick(1_000, 1_000, 0, Some(77), false, false, false),
        SessionTick::Checkpoint { accrued: 77 }
    );
    // Priced seconds, one clean interval.
    assert_eq!(
        session_tick(1_000, 1_000, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: 1_000,
            late: false,
            clipped: false,
        }
    );
    // A tick that could not run: the next one prices the whole gap, marked late.
    assert_eq!(
        session_tick(1_000, 3_000, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: 3_000,
            late: true,
            clipped: false,
        }
    );
    // A gap longer than the idle bound is clipped at it rather than posted in full.
    assert_eq!(
        session_tick(1_000, SESSION_IDLE_MAX_MS + 1, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: SESSION_IDLE_MAX_MS,
            late: true,
            clipped: true,
        }
    );
}

#[test]
fn a_session_closes_when_it_goes_quiet_or_its_budget_runs_dry() {
    assert_eq!(
        session_tick(1_000, 0, SESSION_IDLE_MAX_MS, None, false, false, false),
        SessionTick::Close {
            reason: ReasonCode::DeadlineExceeded,
        }
    );
    assert_eq!(
        session_tick(1_000, 0, 0, None, true, true, false),
        SessionTick::Close {
            reason: ReasonCode::OverBudget,
        }
    );
    assert_eq!(
        session_tick(1_000, 0, 0, None, false, false, true),
        SessionTick::Close {
            reason: ReasonCode::Revoked,
        }
    );
}

#[test]
fn drain_never_cuts_a_protocol_that_was_never_cut_before() {
    assert_eq!(drain_verdict(false, 30_000), DrainVerdict::RunToEnd);
    assert_eq!(
        drain_verdict(true, 30_000),
        DrainVerdict::PumpThenAbort { grace: 30_000 }
    );
    assert_eq!(
        drain_outcome(),
        busbar_caps::Outcome::Aborted(busbar_caps::Abort::Drain)
    );
}

#[test]
fn a_node_with_no_peers_never_drains_for_a_store_it_cannot_reach() {
    // Every single-node deployment there has ever been. A slow store has never meant "stop
    // serving", and it does not start meaning that now.
    for stale_for in [0, 60_000, 10_000_000] {
        assert_eq!(
            fleet_action(0, 0, 2, stale_for, 30_000, 630_000),
            FleetAction::Serve
        );
    }
}

#[test]
fn a_quorum_of_stale_peers_buys_availability_up_to_a_bound() {
    // The partition is the fleet's, not this node's: keep serving on slices already drawn.
    assert_eq!(
        fleet_action(3, 2, 2, 60_000, 30_000, 630_000),
        FleetAction::ServeStale { until: 630_000 }
    );
    // Past the bound, even a quorum drains: no slice is ever spent on two sides of a partition.
    assert_eq!(
        fleet_action(3, 2, 2, 630_000, 30_000, 630_000),
        FleetAction::Drain
    );
}

#[test]
fn a_node_that_is_the_odd_one_out_serves_only_for_a_short_grace() {
    assert_eq!(
        fleet_action(3, 0, 2, 10_000, 30_000, 630_000),
        FleetAction::ServeStale { until: 30_000 }
    );
    assert_eq!(
        fleet_action(3, 0, 2, 30_000, 30_000, 630_000),
        FleetAction::Drain
    );
    // The quorum branch needs at least two peers to be a quorum at all.
    assert_eq!(
        fleet_action(1, 1, 1, 30_000, 30_000, 630_000),
        FleetAction::Drain
    );
}
