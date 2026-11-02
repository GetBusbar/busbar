// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

use std::future::Future;
use std::ops::Not;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};

use busbar_contract::caps::{
    Abort, HoldCellState, OriginKind, Outcome, PrincipalId, ReasonCode, StepName, UnitKey,
};
use busbar_kernel::canary::Canary;
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::slice::{group_lease, ConcurrencyGauge, LeaseCell, IN_FLIGHT};
use busbar_kernel::teller::{
    exit, run_unit, run_unit_async, AccrualMeter, Ended, Evidence, Kernel, Run,
};

use common::{cell, ctx, principal, Door, NeverRoutes, TestDoor, TestUnits};

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

fn run(
    units: &TestUnits,
    kernel: &Kernel,
    cell: &busbar_contract::caps::HoldCell,
    canary: &Canary,
) -> Ended {
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    run_unit(
        kernel,
        units,
        &ctx(1),
        Run {
            cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary,
            meter: &units.meter,
            taps: None,
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
            StepName::Approve,
            StepName::Admit,
            StepName::Route,
            StepName::Meter,
            StepName::Audit,
            StepName::Encode,
        ],
        "a challenge skips verify but still faces the approve and admit policy seats"
    );
    assert!(
        units.approved_lanes().is_empty(),
        "a challenge seals no destination, so the seats see the empty set"
    );
    assert_eq!(
        units
            .seated_principals()
            .iter()
            .map(PrincipalId::as_str)
            .collect::<Vec<_>>(),
        vec!["anonymous", "anonymous"],
        "both seats decide about the anonymous principal, never an identity nobody established"
    );
    assert_eq!(
        canary.counts().holds,
        1,
        "a challenge swaps no hold into the cell: the arrival hold, which reserves nothing, is the \
         one hold it settles (item 272)"
    );
    assert_eq!(
        canary.balanced(),
        Ok(()),
        "a challenge round balances the canary"
    );
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the round still ends once, through the one exit"
    );
}

#[test]
fn a_challenge_round_still_faces_the_hook_veto_and_the_frozen_group() {
    for (step, reason) in [
        (StepName::Approve, ReasonCode::HookVeto),
        (StepName::Admit, ReasonCode::GroupFrozen),
    ] {
        let kernel = Kernel::new();
        let units = TestUnits {
            challenge: true,
            refuse_at: Some((step, reason)),
            ..TestUnits::passing()
        };
        let cell = cell(&kernel);
        let canary = Canary::new();
        let ended = run(&units, &kernel, &cell, &canary);

        assert!(
            units.called().contains(&step),
            "the challenge round never reached {step:?}"
        );
        let (refused_door, admitted_door) = units.doors();
        assert!(
            refused_door && !admitted_door,
            "a refused challenge leaves through the refused-audit door, not the admitted one \
             ({step:?})"
        );
        match ended {
            Ended::Settled { end, .. } => assert_eq!(
                end.outcome(),
                Outcome::Refused(step, reason),
                "a challenge refused at {step:?} must not settle as anything else"
            ),
            other => panic!("expected a settled refusal at {step:?}, got {other:?}"),
        }
    }
}

#[test]
fn a_refusal_stops_the_chain_at_the_step_that_raised_it() {
    for (index, step) in ORDER.iter().enumerate().take(6) {
        let kernel = Kernel::new();
        let units = TestUnits::refusing(*step, ReasonCode::ScopeDenied);
        let cell = cell(&kernel);
        let canary = Canary::new();
        let ended = run(&units, &kernel, &cell, &canary);

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
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::ClientGone,
        }),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Revoked,
        }),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: busbar_contract::caps::UnitKey::new(9),
        }),
        Outcome::TimedOut(StepName::Route),
    ];
    for outcome in outcomes {
        let units = TestUnits::passing();
        let cell = cell(&kernel);
        let canary = Canary::new();
        let gauge = ConcurrencyGauge::new();
        let leases = LeaseCell::new();
        let meter = AccrualMeter::new();
        let ended = exit(
            &kernel,
            &units,
            &ctx(2),
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
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
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let second = exit(
        &kernel,
        &units,
        &ctx(1),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
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

    let parent = std::sync::Arc::new(cell(&kernel));
    let admitted = busbar_contract::caps::Hold::open(&kernel.admit_token(), common::principal());

    let _arrival = parent
        .admit(admitted, &kernel.admit_token())
        .expect("the parent's cell was fresh");

    let child = TestUnits {
        door: Door::Accrual(std::sync::Arc::clone(&parent)),
        ..TestUnits::default()
    };

    let table = InFlight::new(4);
    let child_slot = table
        .insert(client(1))
        .expect("the empty table takes the child");
    let gauge = ConcurrencyGauge::new();
    let meter = AccrualMeter::new();
    let ended = run_unit(
        &kernel,
        &child,
        &ctx(1),
        Run {
            cell: child_slot.cell(),
            parent: Some(&parent),
            leases: child_slot.leases(),
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        },
    );

    match ended {
        Ended::Settled { end, requests, fee } => {
            assert_eq!(end.outcome(), Outcome::Completed);
            let posted = end.posted().expect("the child posts like any other unit");
            assert_eq!(posted.principal(), &common::principal());
            assert!(!posted
                .flags()
                .contains(busbar_contract::caps::PostingFlags::LATE_ACCRUAL));
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

    assert_eq!(
        child_slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken
    );
    let swept = busbar_kernel::tick::sweep_settle(
        &kernel,
        &child_slot,
        busbar_kernel::tick::Sweep::TaskLost {
            at: StepName::Route,
        },
        &Evidence::default(),
        &canary,
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
            assert_eq!(end.posted().map(|p| p.quantity()), Ok(0));
        }
        other => panic!("expected a settled end, got {other:?}"),
    }
}

#[test]
fn a_unit_that_ran_up_more_than_it_was_admitted_for_posts_it_rather_than_refusing() {
    let kernel = Kernel::new();
    let units = TestUnits {
        door: Door::Own,
        spend: 400,
        evidence: Evidence {
            reported: Some(400),
            ..Evidence::default()
        },
        ..TestUnits::default()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    match run(&units, &kernel, &cell, &canary) {
        Ended::Settled { end, .. } => {
            let posted = end.posted().expect("value was delivered, so it posts");
            assert_eq!(posted.quantity(), 400);
            assert!(posted.flags().is_clean(), "{:?}", posted.flags());
        }
        other => panic!("expected a settled end, got {other:?}"),
    }
}

#[test]
fn the_hold_is_posted_at_the_reported_figure_not_by_a_second_count() {
    let kernel = Kernel::new();
    let units = TestUnits {
        door: Door::Own,
        spend: 150,
        evidence: Evidence {
            reported: Some(80),
            ..Evidence::default()
        },
        ..TestUnits::default()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    match run(&units, &kernel, &cell, &canary) {
        Ended::Settled { end, .. } => {
            let posted = end.posted().expect("value was delivered, so it posts");
            assert_eq!(
                posted.quantity(),
                80,
                "the reported figure, not the meter's 150"
            );
            assert!(posted.flags().is_clean(), "{:?}", posted.flags());
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
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
    ] {
        gauge.acquire(&bucket, 4).expect("room in the gauge");
        assert_eq!(gauge.count(&bucket), 1);
        let leases = LeaseCell::new();
        assert!(leases.take(bucket));
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
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
            outcome,
            true,
        );
        assert_eq!(gauge.count(&bucket), 0, "after {outcome:?}");
    }
}

#[test]
fn a_caller_that_goes_away_drops_the_route_leg_and_frees_the_unit() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let dropped = AtomicBool::new(false);
    let route = NeverRoutes {
        units: &units,
        dropped: &dropped,
    };

    let table = InFlight::new(1);
    let key = UnitKey::new(11);
    let slot = table
        .insert(Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
        })
        .expect("the empty table takes the first unit");

    let gauge = ConcurrencyGauge::new();
    let bucket = busbar_kernel::slice::bucket_all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");

    assert!(slot.leases().take(bucket));
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
                leases: slot.leases(),
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
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
    assert_eq!(
        slot.leases().held(),
        0,
        "the unit holds no lease it never gave back"
    );
    assert!(
        !slot.leases().is_owned(),
        "the slot is unowned: its one end has already reclaimed it"
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

    table.remove(key);
    assert!(
        table.admits(&client(12)),
        "the next unit is admitted once the abandoned one is out of the table"
    );
    canary
        .balanced()
        .expect("one draft, one hold, one settlement — an abandoned unit still balances");
}

#[test]
fn the_door_draws_the_in_flight_lease_and_the_end_gives_it_back() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let dropped = AtomicBool::new(false);
    let route = NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let table = InFlight::new(4);
    let slot = table
        .insert(client(21))
        .map_err(|_| ())
        .expect("under the cap");
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let unit = ctx(21);

    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "nothing is running before the unit starts"
    );
    {
        let mut running = std::pin::pin!(run_unit_async(
            &kernel,
            &units,
            &unit,
            Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
            &route,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            gauge.count(&IN_FLIGHT),
            1,
            "the door said yes, so the node is running one unit and the gauge counts it"
        );
        assert_eq!(
            slot.leases().held(),
            1,
            "and the lease is on the unit's own slot, where both of its ends can reach it"
        );
    }
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "the unit ended, so the slot it occupied is back"
    );
    assert_eq!(slot.leases().held(), 0);
}

#[test]
fn two_capped_groups_are_two_leases_while_the_unit_flies_and_none_after() {
    let kernel = Kernel::new();
    let units = TestUnits::in_groups(&["tenant", "team"]);
    let dropped = AtomicBool::new(false);
    let route = NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let table = InFlight::new(4);
    let slot = table
        .insert(client(31))
        .map_err(|_| ())
        .expect("under the cap");
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let unit = ctx(31);
    let tenant = group_lease("tenant");
    let team = group_lease("team");

    {
        let mut running = std::pin::pin!(run_unit_async(
            &kernel,
            &units,
            &unit,
            Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
            &route,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(gauge.count(&tenant), 1, "the outer group is running one");
        assert_eq!(gauge.count(&team), 1, "and so is the inner one");
        assert_eq!(
            gauge.count(&IN_FLIGHT),
            1,
            "the node-wide reading is unchanged: one unit is one unit"
        );
        assert_eq!(
            slot.leases().held(),
            3,
            "all three are the slot's, so both of the unit's ends can give them back"
        );
    }
    assert_eq!(gauge.count(&tenant), 0);
    assert_eq!(gauge.count(&team), 0);
    assert_eq!(gauge.count(&IN_FLIGHT), 0);
    assert_eq!(slot.leases().held(), 0);
}

#[test]
fn a_challenge_a_tick_and_a_kernel_verb_unit_draw_no_lease() {
    for (name, units, unit_ctx) in [
        (
            "a challenge round opens no reservation and draws no lease",
            TestUnits {
                challenge: true,
                ..TestUnits::passing()
            },
            ctx(31),
        ),
        ("a tick moves no money", TestUnits::passing(), {
            let mut c = ctx(32);
            c.origin = OriginKind::Tick;
            c
        }),
        (
            "a kernel-verb unit answers at a saturated gauge",
            TestUnits::passing(),
            {
                let mut c = ctx(33);
                c.kernel_verb_only = true;
                c
            },
        ),
    ] {
        let kernel = Kernel::new();
        let dropped = AtomicBool::new(false);
        let route = NeverRoutes {
            units: &units,
            dropped: &dropped,
        };
        let leases = LeaseCell::new();
        let gauge = ConcurrencyGauge::new();
        let canary = Canary::new();
        let meter = AccrualMeter::new();
        let cell = cell(&kernel);
        let mut running = std::pin::pin!(run_unit_async(
            &kernel,
            &units,
            &unit_ctx,
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
            &route,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(gauge.count(&IN_FLIGHT), 0, "{name}");
        assert_eq!(leases.held(), 0, "{name}");
    }
}

#[test]
fn a_unit_the_door_refused_draws_no_lease() {
    let kernel = Kernel::new();
    let units = TestUnits::refusing(StepName::Admit, ReasonCode::OverBudget);
    let leases = LeaseCell::new();
    let gauge = ConcurrencyGauge::new();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let ended = run_unit(
        &kernel,
        &units,
        &ctx(41),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        },
    );
    assert!(matches!(ended, Ended::Settled { .. }));
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "a refused unit never occupied a slot, so it never gave one back either"
    );
}

#[test]
fn a_group_capped_at_one_refuses_the_second_unit_until_the_first_has_ended() {
    let kernel = Kernel::new();
    let group = common::CappedGroup::at(1);
    let units = TestUnits::behind(&group);
    let dropped = AtomicBool::new(false);
    let route = NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let table = InFlight::new(4);
    let first = table
        .insert(client(51))
        .map_err(|_| ())
        .expect("under the table's cap");
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let flying = ctx(51);

    {
        let mut running = std::pin::pin!(run_unit_async(
            &kernel,
            &units,
            &flying,
            Run {
                cell: first.cell(),
                parent: None,
                leases: first.leases(),
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
            &route,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(group.live(), 1, "the group is running the unit it admitted");
        assert!(
            first.leases().holds_grant(),
            "and the count that says so is the slot's, not the door step's frame"
        );

        let second_units = TestUnits::behind(&group);
        let second_cell = cell(&kernel);
        let second_leases = LeaseCell::new();
        let ended = run_unit(
            &kernel,
            &second_units,
            &ctx(52),
            Run {
                cell: &second_cell,
                parent: None,
                leases: &second_leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
                taps: None,
            },
        );
        assert!(matches!(ended, Ended::Settled { .. }));
        assert_eq!(
            second_units.doors(),
            (true, false),
            "it left through the refused audit door: it never passed the door at all"
        );
        assert_eq!(
            group.live(),
            1,
            "and a refusal counted nothing, so the group still reads the one unit it is running"
        );
    }

    assert_eq!(
        group.live(),
        0,
        "the first unit ended, so the count it held is back"
    );
    assert!(first.leases().holds_grant().not());

    let third_units = TestUnits::behind(&group);
    let third_cell = cell(&kernel);
    let third_leases = LeaseCell::new();
    let ended = run_unit(
        &kernel,
        &third_units,
        &ctx(53),
        Run {
            cell: &third_cell,
            parent: None,
            leases: &third_leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        },
    );
    assert!(matches!(ended, Ended::Settled { .. }));
    assert_eq!(
        third_units.doors(),
        (false, true),
        "the room the first unit gave back is room the next unit is admitted into"
    );
}

fn client(key: u64) -> Enter {
    Enter {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        arrival: arrival_hold(
            &Kernel::new(),
            &TestDoor,
            principal(),
            Kernel::new().next_call(),
        ),
        now: 0,
    }
}

#[test]
fn the_canary_balances_over_refusals_and_zero_hold_units_too() {
    let kernel = Kernel::new();
    let canary = Canary::new();
    for step in ORDER.iter().take(6) {
        let units = TestUnits::refusing(*step, ReasonCode::ScopeDenied);
        let cell = cell(&kernel);
        run(&units, &kernel, &cell, &canary);
    }
    let challenge = TestUnits {
        challenge: true,
        ..TestUnits::passing()
    };
    let cell_c = cell(&kernel);
    run(&challenge, &kernel, &cell_c, &canary);
    let passing = TestUnits::passing();
    let cell_p = cell(&kernel);
    run(&passing, &kernel, &cell_p, &canary);
    let counts = canary.counts();
    assert_eq!(
        counts.drafts, 8,
        "one draft per unit the loop ran: {counts:?}"
    );
    assert_eq!(canary.balanced(), Ok(()), "{counts:?}");
}
