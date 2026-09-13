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
    RouteLeg, Run, SessionPosture, Settles, UnitCtx,
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
        SessionPosture::Hold,
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
        SessionPosture::Hold,
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
        SessionPosture::default(),
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// R-SESSION — WHAT A LIVE SESSION COSTS THE NODE WHILE IT IS LIVE.
//
// A session of any plane is a UNIT. It is not a special case that the loop tolerates, and it is
// not admitted by a door that reserves nothing: it draws the node's request slot at the door and
// holds the in-flight lease for its whole life, exactly as a streaming response does, and it
// settles once, at the session's end. The cells below are that rule stated in the only place it
// can be checked — the bytes the loop's two halves actually move — and nothing in them names a
// plane, a dialect, a transport or a modality.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Units whose verified set carried an upstream candidate — the evidence that makes a client unit
/// draw a request slot, and the shape every real session opening has.
fn reaching_an_upstream() -> TestUnits {
    TestUnits {
        evidence: busbar_kernel::teller::Evidence {
            upstream_candidate: true,
            ..Default::default()
        },
        ..TestUnits::passing()
    }
}

/// ONE REQUEST SLOT, DRAWN AT THE DOOR AND SETTLED AT THE SESSION'S END.
///
/// The slot is drawn by the opening and nothing releases it in between: a session that has been
/// open for an hour is one request this node is still running, which is what the cap is for. The
/// settle happens once, when the session ends, and it names one request and not one per leg.
#[test]
fn a_session_draws_one_request_slot_at_the_door_and_settles_it_at_its_end() {
    let kernel = Kernel::new();
    let units = reaching_an_upstream();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ctx = ctx(5);

    let held = match open_unit(
        &kernel,
        &units,
        &ctx,
        SessionPosture::Hold,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    ) {
        Opened::Held(held) => held,
        Opened::Refused { .. } => panic!("a passing plane's session opens"),
    };
    assert_eq!(
        cell.state(),
        HoldCellState::Admitted,
        "the hold the door gave the session is the session's OWN, and it is in the cell"
    );
    assert_eq!(
        held.settles_at(),
        Settles::SessionEnd,
        "a binding that declared Hold keeps its slot until the SESSION ends, not until this call does"
    );

    // The session is LIVE here. Nothing has settled, nothing has been released, and the node is
    // running one unit — for as long as this goes on.
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "the slot is drawn for the session's life, not for the leg that opened it"
    );

    match ready(serve_held(&kernel, &units, &ctx, held, &InPlace(&units))) {
        Ended::AlreadySettled => panic!("nobody else had this session to settle"),
        Ended::Settled { requests, .. } => assert_eq!(
            requests, 1,
            "a session settles EXACTLY ONE request slot, at its end — the one its door drew"
        ),
    }
    assert_eq!(
        cell.state(),
        HoldCellState::Taken,
        "and the hold leaves the cell exactly once, at the end the settle named"
    );
}

/// A REFUSED OPENING DRAWS NONE. The door never said yes, so there is no slot to release and no
/// lease to give back — a node turning sessions away is not a node filling up with them.
#[test]
fn a_refused_opening_draws_no_request_slot_and_no_lease() {
    let kernel = Kernel::new();
    let units = TestUnits {
        evidence: busbar_kernel::teller::Evidence {
            upstream_candidate: true,
            ..Default::default()
        },
        ..TestUnits::refusing(StepName::Approve, ReasonCode::ScopeDenied)
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ctx = ctx(6);

    let (run, refusal) = match open_unit(
        &kernel,
        &units,
        &ctx,
        SessionPosture::Hold,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    ) {
        Opened::Held(_) => panic!("a refused opening is not a held session"),
        Opened::Refused { run, refusal } => (run, refusal),
    };
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "a session the door refused occupies nothing while it is being refused"
    );
    match refuse_unit(&kernel, &units, &ctx, run, refusal) {
        Ended::AlreadySettled => panic!("nobody else had this to settle"),
        Ended::Settled { requests, fee, .. } => {
            assert_eq!(requests, 0, "a refused opening draws no request slot");
            assert_eq!(
                fee, 0,
                "and posts no fee — the per-leg fees never get a leg"
            );
        }
    }
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "and the gauge is exactly where the refusal found it"
    );
}

/// THE LEASE SPANS THE SESSION, and the span is the point. It is taken by the opening, it is still
/// taken across whatever the session does in between — this cell stands in for minutes of it — and
/// it goes back at the session's end and at no other moment. N live sessions occupy N of the node's
/// in-flight slots, which is the byte a deployment is sized by.
#[test]
fn the_in_flight_lease_spans_the_session_rather_than_one_leg() {
    let kernel = Kernel::new();
    let gauge = ConcurrencyGauge::new();

    let first = reaching_an_upstream();
    let cell_a = cell(&kernel);
    let canary_a = Canary::new();
    let leases_a = LeaseCell::new();
    let meter_a = AccrualMeter::new();
    let ctx_a = ctx(7);
    let held_a = match open_unit(
        &kernel,
        &first,
        &ctx_a,
        SessionPosture::Hold,
        Run {
            cell: &cell_a,
            parent: None,
            leases: &leases_a,
            gauge: &gauge,
            canary: &canary_a,
            meter: &meter_a,
        },
    ) {
        Opened::Held(held) => held,
        Opened::Refused { .. } => panic!("a passing plane's session opens"),
    };
    assert_eq!(gauge.count(&IN_FLIGHT), 1, "one live session, one slot");

    // A SECOND SESSION OPENS WHILE THE FIRST IS STILL LIVE. This is the whole of what "for its
    // whole life" means to a node: the two are counted together because both are running.
    let second = reaching_an_upstream();
    let cell_b = cell(&kernel);
    let canary_b = Canary::new();
    let leases_b = LeaseCell::new();
    let meter_b = AccrualMeter::new();
    let ctx_b = ctx(8);
    let held_b = match open_unit(
        &kernel,
        &second,
        &ctx_b,
        SessionPosture::Hold,
        Run {
            cell: &cell_b,
            parent: None,
            leases: &leases_b,
            gauge: &gauge,
            canary: &canary_b,
            meter: &meter_b,
        },
    ) {
        Opened::Held(held) => held,
        Opened::Refused { .. } => panic!("a passing plane's session opens"),
    };
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        2,
        "TWO live sessions occupy TWO of the node's in-flight slots"
    );

    let _ = ready(serve_held(
        &kernel,
        &first,
        &ctx_a,
        held_a,
        &InPlace(&first),
    ));
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "the first session's end gives back the first session's slot and nobody else's"
    );
    let _ = ready(serve_held(
        &kernel,
        &second,
        &ctx_b,
        held_b,
        &InPlace(&second),
    ));
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "and the node is empty only when the last session has ended"
    );
}

/// A BINDING THAT DECLARED NOTHING SETTLES AT THE EXIT, which is what every binding has always done.
///
/// `Release` is the default, so this cell is also the statement that nothing shipped moves: the
/// undeclared posture and the explicitly-released one are the same value, and the unit they open
/// ends where the call that opened it ends.
#[test]
fn an_undeclared_binding_is_released_and_settles_at_this_exit() {
    let kernel = Kernel::new();
    let units = reaching_an_upstream();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ctx = ctx(9);

    assert_eq!(
        SessionPosture::default(),
        SessionPosture::Release,
        "an undeclared binding is a RELEASED one — the default is what nothing shipped changing means"
    );

    let held = match open_unit(
        &kernel,
        &units,
        &ctx,
        SessionPosture::Release,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    ) {
        Opened::Held(held) => held,
        Opened::Refused { .. } => panic!("a passing plane's request is admitted"),
    };
    assert_eq!(
        held.settles_at(),
        Settles::ThisExit,
        "a released binding's unit gives the node's slot back when THIS call ends"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "it occupies a slot while it runs"
    );
    match ready(serve_held(&kernel, &units, &ctx, held, &InPlace(&units))) {
        Ended::AlreadySettled => panic!("nobody else had this unit to settle"),
        Ended::Settled { requests, .. } => {
            assert_eq!(requests, 1, "one request, settled at its own exit")
        }
    }
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "and the slot is back the moment the call that drew it ended"
    );
}

/// THE POSTURE IS THE DECLARATION'S, NOT THE PLANE'S. Two different planes — two different `Units`
/// implementations, answering with different doors' worth of detail — declared at the same posture
/// are opened, held and settled by the identical bytes: the same steps in the same order, the same
/// slot drawn, the same end. There is nothing in the kernel for a plane to vary here, which is the
/// whole of what "no plane implements holding itself" means.
#[test]
fn two_different_planes_at_one_posture_are_opened_and_settled_identically() {
    let kernel = Kernel::new();

    // Two planes that differ in what their door says — one names capped groups on its yes, the other
    // names none — and agree on nothing else except the posture their binding declared.
    let plane_a = reaching_an_upstream();
    let plane_b = TestUnits {
        evidence: busbar_kernel::teller::Evidence {
            upstream_candidate: true,
            ..Default::default()
        },
        ..TestUnits::in_groups(&["a-capped-group"])
    };

    let mut ends = Vec::new();
    let mut walks = Vec::new();
    let mut settles = Vec::new();
    for (key, units) in [(10u64, &plane_a), (11u64, &plane_b)] {
        let cell = cell(&kernel);
        let canary = Canary::new();
        let gauge = ConcurrencyGauge::new();
        let leases = LeaseCell::new();
        let meter = AccrualMeter::new();
        let ctx = ctx(key);
        let held = match open_unit(
            &kernel,
            units,
            &ctx,
            SessionPosture::Hold,
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
        ) {
            Opened::Held(held) => held,
            Opened::Refused { .. } => panic!("both planes' sessions open"),
        };
        settles.push(held.settles_at());
        assert_eq!(
            gauge.count(&IN_FLIGHT),
            1,
            "one session, one slot, either plane"
        );
        let requests = match ready(serve_held(&kernel, units, &ctx, held, &InPlace(units))) {
            Ended::AlreadySettled => panic!("nobody else had this session to settle"),
            Ended::Settled { requests, .. } => requests,
        };
        assert_eq!(
            gauge.count(&IN_FLIGHT),
            0,
            "and it goes back at the session's end"
        );
        ends.push(requests);
        walks.push((units.called(), units.doors()));
    }

    assert_eq!(
        settles[0], settles[1],
        "the same declared posture answers the same end for either plane"
    );
    assert_eq!(
        walks[0], walks[1],
        "the same ten steps, the same order, the same audit door — the plane varies none of it"
    );
    assert_eq!(
        ends[0], ends[1],
        "and the same one request slot is settled at the same one end"
    );
}
