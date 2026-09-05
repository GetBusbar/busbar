// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loop's own cells: every step order, every refusal reason, every end, both audit doors, the
//! one exit, and the canary that says the counts balance.

mod common;

use std::future::Future;
use std::ops::Not;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};

use busbar_caps::{
    Abort, Canary, HoldCellState, OriginKind, Outcome, PostingFlags, ReasonCode, StepName, UnitKey,
};
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseSet};
use busbar_kernel::teller::{
    exit, run_unit, run_unit_async, AccrualMeter, Ended, Evidence, Kernel, Run,
};

use common::{cell, ctx, principal, Door, NeverRoutes, TestDoor, TestUnits};

/// The ten steps, in the one order they are ever called in.
const ORDER: [StepName; 10] = [
    StepName::Arrival,
    StepName::Decode,
    StepName::Authenticate,
    StepName::Verify,
    StepName::Approve,
    StepName::Admit,
    StepName::Route,
    StepName::Meter,
    StepName::Audit,
    StepName::Encode,
];

fn run(units: &TestUnits, kernel: &Kernel, cell: &busbar_caps::HoldCell, canary: &Canary) -> Ended {
    let gauge = ConcurrencyGauge::new();
    let mut leases = LeaseSet::new();
    let meter = AccrualMeter::new();
    run_unit(
        kernel,
        units,
        &ctx(1),
        Run {
            cell,
            parent: None,
            leases: &mut leases,
            gauge: &gauge,
            canary,
            meter: &meter,
        },
    )
}

#[test]
fn every_step_runs_once_in_order() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let ended = run(&units, &kernel, &cell, &canary);
    assert_eq!(units.called(), ORDER.to_vec());
    assert!(matches!(ended, Ended::Settled { .. }));
}

/// THE VERIFY STEP CAN SEAL WHAT IT VERIFIED.
///
/// Sealing a destination takes the trust token, and the loop lends it beside the unit token at
/// verify — the same shape admit is lent the admit token and meter the usage token. Without it a
/// step could decide where a unit may go and have no way to say so, so every implementor would have
/// answered with the empty set. This pins that what verify sealed is what approve is handed.
#[test]
fn the_verify_step_seals_the_destinations_the_later_steps_read() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let ended = run(&units, &kernel, &cell, &canary);
    assert!(matches!(ended, Ended::Settled { .. }));
    assert_eq!(
        units
            .approved_lanes()
            .iter()
            .map(|lane| lane.as_str())
            .collect::<Vec<_>>(),
        vec!["fixture-lane"],
        "the sealed set reaches approve as the verify step sealed it"
    );
}

/// A challenge round is a handshake unit: the authenticate step answers "one more round" rather
/// than an identity, so verify, approve and admit are never asked and no reservation is opened.
/// The design says the step's decision may yield a challenge; this is what the loop does with one.
#[test]
fn a_challenge_round_reaches_no_destination_and_opens_no_reservation() {
    let kernel = Kernel::new();
    let units = TestUnits {
        challenge: true,
        ..TestUnits::passing()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    let ended = run(&units, &kernel, &cell, &canary);

    assert_eq!(
        units.called(),
        vec![
            StepName::Arrival,
            StepName::Decode,
            StepName::Authenticate,
            StepName::Route,
            StepName::Meter,
            StepName::Audit,
            StepName::Encode,
        ],
        "a challenge settles nothing about where the unit may go or whether it may be admitted"
    );
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the round still ends once, through the one exit"
    );
}

#[test]
fn a_refusal_stops_the_chain_at_the_step_that_raised_it() {
    for (index, step) in ORDER.iter().enumerate().take(6) {
        let kernel = Kernel::new();
        let units = TestUnits::refusing(*step, ReasonCode::ScopeDenied);
        let cell = cell(&kernel);
        let canary = Canary::new();
        let ended = run(&units, &kernel, &cell, &canary);
        // Every step up to and including the refusing one ran, then the refused audit door and the
        // encode that renders it. Nothing after the refusal ran.
        let mut expected: Vec<StepName> = ORDER[..=index].to_vec();
        expected.push(StepName::Audit);
        expected.push(StepName::Encode);
        assert_eq!(units.called(), expected, "refusing at {step}");
        match ended {
            Ended::Settled { end, .. } => assert_eq!(
                end.outcome(),
                Outcome::Refused(*step, ReasonCode::ScopeDenied)
            ),
            other => panic!("expected a settled end, got {other:?}"),
        }
    }
}

#[test]
fn a_refusal_after_the_door_still_leaves_through_the_admitted_audit_door() {
    for step in [StepName::Route, StepName::Meter] {
        let kernel = Kernel::new();
        let units = TestUnits::refusing(step, ReasonCode::DestinationUnreachable);
        let cell = cell(&kernel);
        let canary = Canary::new();
        let ended = run(&units, &kernel, &cell, &canary);
        assert_eq!(units.doors(), (false, true), "refusing at {step}");
        match ended {
            Ended::Settled { end, .. } => assert_eq!(
                end.outcome(),
                Outcome::Failed(step, ReasonCode::DestinationUnreachable)
            ),
            other => panic!("expected a settled end, got {other:?}"),
        }
    }
}

#[test]
fn the_two_audit_doors_are_distinct() {
    let kernel = Kernel::new();
    let refused = TestUnits::refusing(StepName::Approve, ReasonCode::HookVeto);
    let canary = Canary::new();
    let cell_a = cell(&kernel);
    run(&refused, &kernel, &cell_a, &canary);
    assert_eq!(refused.doors(), (true, false));

    let passing = TestUnits::passing();
    let cell_b = cell(&kernel);
    run(&passing, &kernel, &cell_b, &canary);
    assert_eq!(passing.doors(), (false, true));
}

#[test]
fn every_refusal_reason_can_end_a_unit_and_still_post() {
    let kernel = Kernel::new();
    for reason in ReasonCode::ALL {
        let units = TestUnits::refusing(StepName::Verify, *reason);
        let cell = cell(&kernel);
        let canary = Canary::new();
        let ended = run(&units, &kernel, &cell, &canary);
        match ended {
            Ended::Settled { end, .. } => {
                assert_eq!(end.outcome(), Outcome::Refused(StepName::Verify, *reason));
                assert!(end.posted().is_ok(), "{reason} posted nothing");
            }
            other => panic!("{reason} did not settle: {other:?}"),
        }
        assert_eq!(canary.counts().settlements, 1);
    }
}

#[test]
fn every_unit_end_leaves_through_the_one_exit() {
    let kernel = Kernel::new();
    let outcomes = [
        Outcome::Completed,
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::PlanePanic),
        Outcome::Aborted(Abort::Client),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Revoked,
        }),
        Outcome::Aborted(Abort::Drain),
        Outcome::Aborted(Abort::Superseded {
            by: busbar_caps::UnitKey::new(9),
        }),
        Outcome::TimedOut(StepName::Route),
    ];
    for outcome in outcomes {
        let units = TestUnits::passing();
        let cell = cell(&kernel);
        let canary = Canary::new();
        let gauge = ConcurrencyGauge::new();
        let mut leases = LeaseSet::new();
        let meter = AccrualMeter::new();
        let ended = exit(
            &kernel,
            &units,
            &ctx(2),
            Run {
                cell: &cell,
                parent: None,
                leases: &mut leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
            outcome,
            true,
        );
        match ended {
            Ended::Settled { end, .. } => assert_eq!(end.outcome(), outcome),
            other => panic!("{outcome:?} did not settle: {other:?}"),
        }
    }
}

#[test]
fn a_unit_is_settled_exactly_once() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let first = run(&units, &kernel, &cell, &canary);
    assert!(matches!(first, Ended::Settled { .. }));

    let gauge = ConcurrencyGauge::new();
    let mut leases = LeaseSet::new();
    let meter = AccrualMeter::new();
    let second = exit(
        &kernel,
        &units,
        &ctx(1),
        Run {
            cell: &cell,
            parent: None,
            leases: &mut leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
        Outcome::Completed,
        true,
    );
    assert!(matches!(second, Ended::AlreadySettled));
    assert_eq!(canary.counts().settlements, 1);
}

#[test]
fn the_canary_balances_over_a_run_of_units() {
    let kernel = Kernel::new();
    let canary = Canary::new();
    for _ in 0..8 {
        let units = TestUnits::passing();
        let cell = cell(&kernel);
        run(&units, &kernel, &cell, &canary);
    }
    let counts = canary.counts();
    assert_eq!(counts.drafts, 8);
    assert_eq!(counts.holds, 8);
    assert_eq!(counts.settlements, 8);
    assert_eq!(canary.balanced(), Ok(()));
}

#[test]
fn a_child_spending_against_its_parent_balances_the_canary_too() {
    let kernel = Kernel::new();
    let canary = Canary::new();

    // A parent that has passed the door and is still open.
    let parent = std::sync::Arc::new(cell(&kernel));
    let admitted = busbar_caps::Hold::open(&kernel.admit_token(), common::principal(), 5_000);
    // The cell hands the arrival hold back rather than dropping it; the parent's admitted hold has
    // taken its place, and this binding is what the loop's own swap does with it.
    let _arrival = parent
        .admit(admitted, &kernel.admit_token())
        .expect("the parent's cell was fresh");

    let child = TestUnits {
        door: Door::Accrual(std::sync::Arc::clone(&parent), 250),
        ..TestUnits::default()
    };
    let child_cell = cell(&kernel);
    let gauge = ConcurrencyGauge::new();
    let mut leases = LeaseSet::new();
    let meter = AccrualMeter::new();
    let ended = run_unit(
        &kernel,
        &child,
        &ctx(1),
        Run {
            cell: &child_cell,
            parent: Some(&parent),
            leases: &mut leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    // The child ends like every other unit: one sealed end carrying one posting. It reserved
    // nothing, because the reservation behind it is the parent's, and its posting is clean —
    // nothing about it is late, because the parent was still open when it ended.
    match ended {
        Ended::Settled { end, requests, fee } => {
            assert_eq!(end.outcome(), Outcome::Completed);
            let posted = end.posted().expect("the child posts like any other unit");
            assert_eq!(posted.settled(), 250);
            assert_eq!(
                posted.reserved(),
                0,
                "the reservation behind it is the parent's"
            );
            assert_eq!(posted.overdraft(), 0);
            assert!(!posted
                .flags()
                .contains(busbar_caps::PostingFlags::LATE_ACCRUAL));
            assert_eq!(
                (requests, fee),
                (0, 0),
                "a child draws no slot and posts no fee; the parent drew both"
            );
        }
        other => panic!("expected a settled child, got {other:?}"),
    }
    assert_eq!(parent.accruals(), 1);
    let counts = canary.counts();
    assert_eq!((counts.drafts, counts.holds, counts.accruals), (1, 0, 1));
    assert_eq!(canary.balanced(), Ok(()));

    // The child opened no reservation, but it entered the table with an arrival hold like every
    // other unit, and its cell is emptied at its end. Leaving it full would leave the sweep — the
    // other holder of a key to that cell — free to settle a unit that has already finished, and its
    // spend is already inside the parent's posting.
    assert_eq!(child_cell.state(), busbar_caps::HoldCellState::Taken);
    let swept = busbar_kernel::tick::sweep_settle(
        &kernel,
        &child_cell,
        busbar_kernel::tick::Sweep::TaskLost {
            at: StepName::Route,
        },
        &Evidence::default(),
        &canary,
        &mut LeaseSet::new(),
        &ConcurrencyGauge::new(),
    );
    assert!(swept.is_none(), "the child was settled a second time");
    assert_eq!(canary.counts().settlements, 1);
}

#[test]
fn a_zero_priced_unit_holds_nothing_and_still_posts() {
    let kernel = Kernel::new();
    let units = TestUnits {
        door: Door::Zero,
        ..TestUnits::default()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    match run(&units, &kernel, &cell, &canary) {
        Ended::Settled { end, .. } => {
            assert_eq!(end.outcome(), Outcome::Completed);
            assert_eq!(end.posted().map(|p| p.settled()), Ok(0));
        }
        other => panic!("expected a settled end, got {other:?}"),
    }
}

#[test]
fn running_past_the_reservation_posts_the_overdraft_rather_than_refusing() {
    let kernel = Kernel::new();
    let units = TestUnits {
        door: Door::Own(100),
        spend: 400,
        evidence: Evidence {
            located: Some(400),
            ..Evidence::default()
        },
        ..TestUnits::default()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    match run(&units, &kernel, &cell, &canary) {
        Ended::Settled { end, .. } => {
            let posted = end.posted().expect("value was delivered, so it posts");
            assert_eq!(posted.settled(), 400);
            assert_eq!(posted.overdraft(), 300);
            assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
        }
        other => panic!("expected a settled end, got {other:?}"),
    }
}

#[test]
fn the_leases_go_back_on_every_end_whatever_it_was() {
    let kernel = Kernel::new();
    let gauge = ConcurrencyGauge::new();
    let bucket = busbar_kernel::slice::bucket_all("team");
    for outcome in [
        Outcome::Completed,
        Outcome::Failed(StepName::Route, ReasonCode::ClientGone),
        Outcome::Aborted(Abort::Drain),
    ] {
        gauge.acquire(&bucket, 4).expect("room in the gauge");
        assert_eq!(gauge.count(&bucket), 1);
        let mut leases = LeaseSet::new();
        leases.take(bucket);
        let units = TestUnits::passing();
        let cell = cell(&kernel);
        let canary = Canary::new();
        let meter = AccrualMeter::new();
        exit(
            &kernel,
            &units,
            &ctx(3),
            Run {
                cell: &cell,
                parent: None,
                leases: &mut leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
            outcome,
            true,
        );
        assert_eq!(gauge.count(&bucket), 0, "after {outcome:?}");
    }
}

/// The loop's shape is part of its contract: no `?`, and no early `return` inside it.
///
/// A `?` in a function that is holding a reservation is a path where the hold is dropped instead of
/// settled. This reads the source and says so.
#[test]
fn the_loop_has_no_early_exits() {
    let source = include_str!("../src/teller.rs");
    let body = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !body.contains("?;"),
        "the loop uses the question mark operator"
    );
    assert!(
        !body.contains("return "),
        "the loop returns early from somewhere"
    );
}

/// THE CLIENT THAT WENT AWAY.
///
/// The loop awaits in one place — the Route leg — so a caller that drops it drops it there, with the
/// hold in the cell, the lease drawn and the unit's slot occupied. Nothing about that end is
/// special: it leaves through the charged audit door like every admitted unit, the exit takes the
/// hold out of the cell, the lease goes back to the gauge and the slot is free for the next arrival.
///
/// What this cell also pins is that cancellation REACHES THE UPSTREAM. A loop that merely stopped
/// polling would leave the upstream's future alive somewhere; the flag below is set by that future's
/// own `Drop`, so the only way it is true is if the loop let go of it.
#[test]
fn a_caller_that_goes_away_drops_the_route_leg_and_frees_the_unit() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let dropped = AtomicBool::new(false);
    let route = NeverRoutes {
        units: &units,
        dropped: &dropped,
    };

    // A table with room for exactly one unit, so the slot this unit occupies IS the node's in-flight
    // ceiling: a second arrival is refused while it is held and admitted the moment it is not.
    let table = InFlight::new(1, 0);
    let key = UnitKey::new(11);
    let slot = table
        .insert(Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
        })
        .expect("the empty table takes the first unit");

    let gauge = ConcurrencyGauge::new();
    let bucket = busbar_kernel::slice::bucket_all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");
    let mut leases = LeaseSet::new();
    leases.take(bucket);
    let canary = Canary::new();
    let meter = AccrualMeter::new();

    let unit = ctx(11);
    {
        let mut running = std::pin::pin!(run_unit_async(
            &kernel,
            &units,
            &unit,
            Run {
                cell: slot.cell(),
                parent: None,
                leases: &mut leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
            &route,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            running.as_mut().poll(&mut cx).is_pending(),
            "an upstream that has not answered leaves the loop waiting at its one await"
        );
        assert_eq!(
            slot.cell().state(),
            HoldCellState::Admitted,
            "the door's hold is in the cell for as long as the unit is in flight"
        );
        assert_eq!(gauge.count(&bucket), 1, "the lease is drawn while it waits");
        assert!(!dropped.load(Ordering::Acquire), "the leg is still alive");
        assert!(
            table.admits(&client(12)).not(),
            "the waiting unit occupies the node's one in-flight slot"
        );
    }
    // The client goes away: the loop's future is dropped, and with it the leg it was awaiting.

    assert!(
        dropped.load(Ordering::Acquire),
        "the upstream's own future is dropped with the loop's — cancellation reached it"
    );
    assert_eq!(
        slot.cell().state(),
        HoldCellState::Taken,
        "the hold came out of the cell at the one exit; the sweep has nothing left to settle"
    );
    assert_eq!(gauge.count(&bucket), 0, "the lease went back to the gauge");
    assert!(
        leases.is_empty(),
        "the unit holds no lease it never gave back"
    );
    assert_eq!(
        units.called(),
        vec![
            StepName::Arrival,
            StepName::Decode,
            StepName::Authenticate,
            StepName::Verify,
            StepName::Approve,
            StepName::Admit,
            StepName::Route,
            StepName::Audit,
            StepName::Encode,
        ],
        "an abandoned unit runs every step it reached and stops at the one it was waiting on"
    );
    assert_eq!(
        units.doors(),
        (false, true),
        "it left through the charged audit door, because it passed the door"
    );

    // The slot is released by the caller that took it, and the ceiling is a table's again rather
    // than a thread pool's: with the unit gone, the next arrival is admitted.
    table.remove(key);
    assert!(
        table.admits(&client(12)),
        "the next unit is admitted once the abandoned one is out of the table"
    );
    canary
        .balanced()
        .expect("one draft, one hold, one settlement — an abandoned unit still balances");
}

/// One client arrival, as the table weighs it against the cap.
fn client(key: u64) -> Enter {
    Enter {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        provider_of_open_session: false,
        zero_hold_tick: false,
        arrival: arrival_hold(&Kernel::new(), &TestDoor, principal()),
    }
}
