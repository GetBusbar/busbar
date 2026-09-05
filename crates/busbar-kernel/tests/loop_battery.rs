// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loop's own cells: every step order, every refusal reason, every end, both audit doors, the
//! one exit, and the canary that says the counts balance.

mod common;

use busbar_caps::{Abort, Canary, Outcome, PostingFlags, ReasonCode, StepName};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseSet};
use busbar_kernel::teller::{exit, run_unit, AccrualMeter, Ended, Evidence, Kernel, Run};

use common::{cell, ctx, Door, TestUnits};

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
    let ended = run(&child, &kernel, &child_cell, &canary);
    match ended {
        Ended::AccruedIntoParent { amount, outcome } => {
            assert_eq!(amount, 250);
            assert_eq!(outcome, Outcome::Completed);
        }
        other => panic!("expected an accrual into the parent, got {other:?}"),
    }
    assert_eq!(parent.accruals(), 1);
    let counts = canary.counts();
    assert_eq!((counts.drafts, counts.holds, counts.accruals), (1, 0, 1));
    assert_eq!(canary.balanced(), Ok(()));
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
    let bucket = busbar_kernel::slice::BucketId::all("team");
    for outcome in [
        Outcome::Completed,
        Outcome::Failed(StepName::Route, ReasonCode::ClientGone),
        Outcome::Aborted(Abort::Drain),
    ] {
        gauge.acquire(&bucket, 4).expect("room in the gauge");
        assert_eq!(gauge.count(&bucket), 1);
        let mut leases = LeaseSet::new();
        leases.take(bucket.clone());
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
