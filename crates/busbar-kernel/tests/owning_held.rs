// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNING FORM OF THE LOOP'S OPENING — a held unit that can cross the await that makes a session
//! exist.
//!
//! [`open_unit`] hands back a [`Held`] that BORROWS its run, and a run borrows a cell and a lease set
//! a synchronous driver mints on its stack. That is exactly the thing a session cannot keep: the
//! socket upgrade a duplex session is built on is an await, and a value that borrows the stack cannot
//! be held across it. [`open_unit_owned`] answers with a [`SessionHold`] that OWNS its slot — the
//! cell and the leases, in an [`Arc<UnitSlot>`] drawn from the in-flight table — so the hold the door
//! put in the cell survives the upgrade and stays reachable by the node's sweep the whole time.
//!
//! This file is the one thing that owning form has to be true of, stated as bytes the loop moves:
//!
//!   1. a session opened this way draws ONE request slot at the door and holds ONE in-flight lease;
//!   2. the held unit crosses an `.await` — the point of the owning form — with the hold still in the
//!      cell and the slot still in the table;
//!   3. it settles EXACTLY ONCE, at the session's end, giving the slot and the lease back there and
//!      nowhere else.
//!
//! Nothing here names a plane, a dialect, a socket or a modality. The face is session-shaped and that
//! is the whole of what it is.

mod common;

use std::sync::Arc;

use busbar_kernel::inflight::{Enter, InFlight};
use busbar_kernel::slice::{ConcurrencyGauge, IN_FLIGHT};
use busbar_kernel::teller::{
    open_unit_owned, run_unit, AccrualMeter, Ended, Evidence, Kernel, OpenedOwned, Run,
    SessionPosture, Settles, UnitCtx,
};

use common::{
    ctx, Canary, Hold, HoldCellState, OriginKind, PrincipalId, ReasonCode, StepName, TestUnits,
    UnitKey,
};

/// A slot drawn from the table exactly as the door draws one: an arrival hold minted for it, entered
/// under the cap, handed back as the [`Arc`] the sweep and the exit path both hold a key to.
fn draw_slot(
    kernel: &Kernel,
    table: &InFlight,
    key: u64,
) -> Arc<busbar_kernel::inflight::UnitSlot> {
    let arrival = Hold::open(&kernel.admit_token(), PrincipalId::new("acct:battery"), 0);
    table
        .insert(Enter {
            key: UnitKey::new(key),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival,
            now: 0,
        })
        .unwrap_or_else(|_| panic!("the table has room for the session's slot"))
}

/// Units whose verified set carried an upstream candidate — the evidence that makes a client unit
/// draw a request slot, and the shape every real session opening has.
fn reaching_an_upstream() -> TestUnits {
    TestUnits {
        evidence: Evidence {
            upstream_candidate: true,
            ..Default::default()
        },
        ..TestUnits::passing()
    }
}

/// AN OWNING HELD IS Send. The whole point of it is to cross an upgrade, which on a real runtime is a
/// suspension point a value is only carried across if it is `Send` — so this is a property the type
/// must have and not just a thing this test happens to do on one thread.
#[test]
fn an_owning_held_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<OpenedOwned<'static>>();
}

/// THE OWNING FORM SURVIVES AN AWAIT AND SETTLES ONCE, AT THE END.
///
/// The slot is drawn, the six steps run and the hold sits in the cell; the held unit is then carried
/// across a real `.await` — the thing the borrowing form cannot do — and only at the far side, at
/// the session's end, is it settled. One request slot goes in at the door and comes back at the
/// settle, and the in-flight lease with it; the cell is emptied exactly once.
#[test]
fn an_owning_held_crosses_an_await_and_settles_once_at_the_end() {
    let kernel = Kernel::new();
    let units = reaching_an_upstream();
    let table = InFlight::new(8, 2);
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let ctx = ctx(1);

    let slot = draw_slot(&kernel, &table, 1);
    // A second key on the same Arc, so the cell can be read AFTER the hold has moved into the owning
    // form — this is the sweep's view of the same slot, by design.
    let slot_view = Arc::clone(&slot);

    let held = match open_unit_owned(
        &kernel,
        &units,
        &ctx,
        SessionPosture::Hold,
        slot,
        &gauge,
        &canary,
    ) {
        OpenedOwned::Held(held) => held,
        OpenedOwned::Refused(_) => panic!("a passing plane's session opens"),
    };

    assert_eq!(
        held.settles_at(),
        Settles::SessionEnd,
        "a binding that declared Hold keeps its slot until the SESSION ends, not until this call does"
    );
    assert_eq!(
        slot_view.cell().state(),
        HoldCellState::Admitted,
        "the hold is in the cell the moment the door says yes — that is what the session keeps"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "an admitted session occupies the node's in-flight slot for as long as it is open"
    );

    // THE UPGRADE, as far as the loop is concerned: an await, with the held unit carried across it.
    // The borrowing `Held` cannot be here at all — this is the whole reason the owning form exists.
    let ended = drive(async move {
        std::future::ready(()).await;
        held.settle(&kernel, &units, &ctx)
    });

    match ended {
        Ended::AlreadySettled => panic!("nobody else had this session to settle"),
        Ended::Settled { requests, .. } => assert_eq!(
            requests, 1,
            "a session settles EXACTLY ONE request slot, at its end — the one its door drew"
        ),
    }
    assert_eq!(
        slot_view.cell().state(),
        HoldCellState::Taken,
        "the hold leaves the cell exactly once, at the end the settle named"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "and the in-flight lease goes back to the node at that same one end"
    );
}

/// A REFUSED OPENING DRAWS NOTHING AND OWES NO SETTLE. The door never said yes, so the owning form
/// hands back an [`Ended`] rather than a held unit: the refused audit door already sealed it on the
/// slot the caller drew, and the in-flight gauge is exactly where it was found.
#[test]
fn an_owning_open_that_refuses_holds_no_slot_and_owes_no_settle() {
    let kernel = Kernel::new();
    let units = TestUnits {
        evidence: Evidence {
            upstream_candidate: true,
            ..Default::default()
        },
        ..TestUnits::refusing(StepName::Verify, ReasonCode::ScopeDenied)
    };
    let table = InFlight::new(8, 2);
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let ctx = ctx(2);

    let slot = draw_slot(&kernel, &table, 2);
    let slot_view = Arc::clone(&slot);

    match open_unit_owned(
        &kernel,
        &units,
        &ctx,
        SessionPosture::Hold,
        slot,
        &gauge,
        &canary,
    ) {
        OpenedOwned::Held(_) => panic!("a refused destination must never hand back a held session"),
        OpenedOwned::Refused(Ended::Settled { requests, .. }) => {
            assert_eq!(
                requests, 0,
                "a session that never opened draws no request slot"
            );
        }
        OpenedOwned::Refused(Ended::AlreadySettled) => {
            panic!("nobody else had this unit to settle")
        }
    }
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "a refused open leaves the node's in-flight gauge exactly where it found it"
    );
    assert_eq!(
        slot_view.cell().state(),
        HoldCellState::Taken,
        "the refused unit left through its exit — nothing is held for a session the door refused"
    );
}

/// A LEG SERVED ON AN ALREADY-ADMITTED SESSION DRAWS NOTHING — no request slot — even though it
/// reaches an upstream.
///
/// This is the crux the whole form exists for. The session's own opening drew the one request slot
/// and the one in-flight lease the whole session runs on (the cell above); a leg served on it is a
/// `session_member`, spends against that admission and draws NEITHER — so a session that relayed a
/// thousand frames still settles ONE request slot, not one per frame. The contrast is baked into the
/// one cell: the SAME unit and the SAME evidence, but NOT a session member, draws one — which is what
/// makes `session_member` load-bearing rather than cosmetic, and is exactly the per-frame draw this
/// turns off. Nothing here names a plane, a dialect, a socket or a modality: a leg is session-shaped
/// and that is the whole of what it is.
#[test]
fn a_session_member_leg_reaching_an_upstream_draws_no_request_slot() {
    let kernel = Kernel::new();

    // THE LEG: a `session_member`, whose verified set reaches an upstream. It runs the ordinary loop
    // on its own slot — a child of nothing, writing its own end — and settles ZERO request slots.
    let member = UnitCtx {
        session_member: true,
        ..ctx(10)
    };
    let leg_requests = run_one(&kernel, 10, &member);
    assert_eq!(
        leg_requests, 0,
        "a leg on an admitted session draws no request slot — the session's opening drew the one"
    );

    // THE CONTRAST, in the same cell: the SAME evidence, NOT a session member, draws one — the
    // behaviour every Client unit reaching an upstream has always had, and the per-frame red this
    // form turns off for a leg.
    let opener = ctx(11);
    let opener_requests = run_one(&kernel, 11, &opener);
    assert_eq!(
        opener_requests, 1,
        "a non-member Client unit reaching an upstream draws one — the flag is what decides"
    );
}

/// Run one unit reaching an upstream on its own drawn slot, and answer how many request slots it
/// settled. The unit runs the ordinary loop (not the owning form): a leg is an ordinary unit.
fn run_one(kernel: &Kernel, key: u64, ctx: &UnitCtx) -> u32 {
    let units = reaching_an_upstream();
    let table = InFlight::new(8, 2);
    let slot = draw_slot(kernel, &table, key);
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let ended = run_unit(
        kernel,
        &units,
        ctx,
        Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    match ended {
        Ended::Settled { requests, .. } => requests,
        Ended::AlreadySettled => panic!("the unit had its own cell to settle"),
    }
}

/// Drive a future to its answer on no runtime at all — the whole test being about a hold that
/// crosses the await, not about a leg that suspends, the one await here is ready on its first poll.
fn drive<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(out) => out,
        std::task::Poll::Pending => panic!("the one await here is ready on its first poll"),
    }
}
