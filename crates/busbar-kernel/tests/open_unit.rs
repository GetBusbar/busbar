// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOOP'S OPENING, FOR AN ARRIVAL WHOSE SHAPE IS A SESSION.
//!
//! A request is asked the ten questions and ended in one call. An arrival that is a long-lived
//! SESSION cannot be: the questions have to be answered BEFORE the thing that makes the session
//! exist — a socket upgrade is the point of no return, and an admission that lands after it is an
//! admission that cannot refuse — and the wire work then runs per leg, for minutes, on that one
//! answer.
//!
//! So the loop is reached at the line it already breaks on. [`open_unit`] runs the first six steps,
//! all of which answer in place, and STOPS at the door with the hold in the cell and the leases
//! drawn; [`serve_held`] runs the remaining four and the exit on what the door produced. This file
//! is what those two mean, stated as the things a session opener can rely on:
//!
//!   1. the opener asks the first six, in order, and asks none of the last four;
//!   2. a refusal at any of the six leaves through the refused audit door with nothing held;
//!   3. a held unit's hold is IN THE CELL before anything else happens, and the node's sweep can
//!      settle it — a session that dies between its door and its first leg is settled, not leaked;
//!   4. the two halves, run in order, are the loop: the same ten steps, once each, same order.
//!
//! Nothing here names a plane, a dialect, a socket or a modality. The face is session-shaped and
//! that is the whole of what it is.

mod common;

use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell, IN_FLIGHT};
use busbar_kernel::teller::{
    open_unit, refuse_unit, run_unit, serve_held, AccrualMeter, Ended, Kernel, Opened, RouteAwait,
    RouteLeg, Run, UnitCtx,
};

use common::{
    cell, ctx, Canary, HoldCellState, Outcome, ReasonCode, Route, StepName, TestUnits, UnitToken,
};

/// The six the opener asks, in the order it asks them.
const OPENING: [StepName; 6] = [
    StepName::Arrival,
    StepName::Decode,
    StepName::Authenticate,
    StepName::Verify,
    StepName::Approve,
    StepName::Admit,
];

/// The four that are left for the legs.
const REMAINING: [StepName; 4] = [
    StepName::Route,
    StepName::Meter,
    StepName::Audit,
    StepName::Encode,
];

/// THE OPENER ASKS THE FIRST SIX AND STOPS. It reaches the door, opens the hold into the cell, draws
/// the in-flight lease — and asks not one of the four steps that belong to a leg.
#[test]
fn the_opener_runs_to_the_door_and_holds_there() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ctx = ctx(1);

    let opened = open_unit(
        &kernel,
        &units,
        &ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );

    assert!(
        matches!(opened, Opened::Held(_)),
        "a passing plane's session is HELD at the door, not ended there"
    );
    assert_eq!(
        units.called(),
        OPENING.to_vec(),
        "the opener asks the first six steps in order and asks no more than those"
    );
    for step in REMAINING {
        assert!(
            !units.called().contains(&step),
            "{step:?} belongs to a leg, and the opener runs no leg"
        );
    }
    assert_eq!(
        units.doors(),
        (false, false),
        "a unit still held open has left through NEITHER audit door"
    );
    assert_eq!(
        cell.state(),
        HoldCellState::Admitted,
        "the hold is in the cell the moment the door says yes — that is what the session keeps"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "an admitted session occupies the node's in-flight slot for as long as it is open"
    );
}

/// A REFUSED OPEN IS AN END, and the opener hands back an end rather than a hold: the refused audit
/// door sealed it, the bytes left, the cell is empty and the node is not holding a slot for a
/// session that never opened.
#[test]
fn a_refused_open_ends_at_the_refused_door_holding_nothing() {
    let kernel = Kernel::new();
    let units = TestUnits::refusing(StepName::Verify, ReasonCode::ScopeDenied);
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ctx = ctx(2);

    let opened = open_unit(
        &kernel,
        &units,
        &ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );

    let (run, refusal) = match opened {
        Opened::Held(_) => panic!("a refused destination must never hand back a held session"),
        Opened::Refused { run, refusal } => (run, refusal),
    };
    assert_eq!(
        units.doors(),
        (false, false),
        "the opener asks the six and runs no audit door of its own"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "a refused open leaves the node's in-flight gauge exactly where it found it"
    );

    match refuse_unit(&kernel, &units, &ctx, run, refusal) {
        Ended::AlreadySettled => panic!("nobody else had this unit to settle"),
        Ended::Settled { end, requests, fee } => {
            assert!(
                matches!(end.outcome(), Outcome::Refused(StepName::Verify, _)),
                "the end names the step that refused it"
            );
            assert_eq!(
                requests, 0,
                "a session that never opened draws no request slot"
            );
            assert_eq!(fee, 0, "a session that never opened posts no fee");
        }
    }
    assert_eq!(
        units.doors(),
        (true, false),
        "a refusal before the door leaves through the REFUSED audit door and no other"
    );
    assert_eq!(
        cell.state(),
        HoldCellState::Taken,
        "nothing is held for a session the door never admitted"
    );
}

/// THE TWO HALVES ARE THE LOOP. Opened and then served, a unit meets the same ten steps, once each,
/// in the same order the one-call entry point meets them in — which is what makes this a face on the
/// loop rather than a second copy of it.
#[test]
fn opening_then_serving_is_the_same_ten_steps_as_running() {
    let kernel = Kernel::new();

    let in_halves = TestUnits::passing();
    let cell_a = cell(&kernel);
    let canary_a = Canary::new();
    let gauge_a = ConcurrencyGauge::new();
    let leases_a = LeaseCell::new();
    let meter_a = AccrualMeter::new();
    let ctx_a = ctx(3);
    let opened = open_unit(
        &kernel,
        &in_halves,
        &ctx_a,
        Run {
            cell: &cell_a,
            parent: None,
            leases: &leases_a,
            gauge: &gauge_a,
            canary: &canary_a,
            meter: &meter_a,
        },
    );
    let held = match opened {
        Opened::Held(held) => held,
        Opened::Refused { .. } => panic!("a passing plane is admitted"),
    };
    let ended = ready(serve_held(
        &kernel,
        &in_halves,
        &ctx_a,
        held,
        &InPlace(&in_halves),
    ));
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the served unit ends"
    );

    let in_one = TestUnits::passing();
    let cell_b = cell(&kernel);
    let canary_b = Canary::new();
    let gauge_b = ConcurrencyGauge::new();
    let leases_b = LeaseCell::new();
    let meter_b = AccrualMeter::new();
    let ctx_b = ctx(4);
    let _ = run_unit(
        &kernel,
        &in_one,
        &ctx_b,
        Run {
            cell: &cell_b,
            parent: None,
            leases: &leases_b,
            gauge: &gauge_b,
            canary: &canary_b,
            meter: &meter_b,
        },
    );

    assert_eq!(
        in_halves.called(),
        in_one.called(),
        "the same ten steps, once each, in the same order — the halves ARE the loop"
    );
    assert_eq!(
        in_halves.doors(),
        in_one.doors(),
        "and they leave through the same audit door"
    );
}

/// A Route leg that answers in place — the plane whose upstream is already in hand, which is what
/// the synchronous entry point puts in the loop's one await. It is written here rather than reached,
/// because the kernel's own is private to the loop.
struct InPlace<'u>(&'u TestUnits);

impl RouteAwait for InPlace<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a UnitToken<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
    ) -> RouteLeg<'a> {
        Box::pin(std::future::ready(busbar_kernel::teller::Units::route(
            self.0, token, ctx, meter,
        )))
    }
}

/// Drive a future that cannot suspend to its answer, on no runtime at all.
fn ready<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(out) => out,
        std::task::Poll::Pending => panic!("a leg that is ready on its first poll never parks"),
    }
}
