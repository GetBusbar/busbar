// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the clock does when nothing arrives: the sweep of a lost unit, and the drain and fleet
//! answers. (Crash recovery of open holds went with the second ledger, MONEY-DESIGN §4: the one
//! ledger is the store's usage counts, which a restart reads back as they are.)

mod common;

use busbar_contract::caps::{
    Canary, HoldCellState, OriginKind, PostingFlags, ReasonCode, StepName, UnitKey,
};
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::slice::{bucket_all, ConcurrencyGauge};
use busbar_kernel::teller::{Evidence, Kernel};
use busbar_kernel::tick::{sweep, sweep_settle, Sweep};

use common::{principal, TestDoor};

#[test]
fn a_lost_task_is_settled_within_one_tick() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(1),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
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

    // What the plane reported before its task disappeared: the writer writes it as told.
    let evidence = Evidence {
        reported: Some(42),
        ..Evidence::default()
    };
    // The unit was holding a concurrency lease when its task disappeared. The lease is recorded on
    // the SLOT, which is the only place the sweep can reach: the task's own frame went with the
    // task. The sweep is one of the two ends a unit has, so the lease goes back here or never.
    let gauge = ConcurrencyGauge::new();
    let bucket = bucket_all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");
    assert!(
        slot.leases().take(bucket),
        "the door records it on the slot"
    );
    assert_eq!(slot.leases().held(), 1);

    let end = sweep_settle(&kernel, &slot, verdict, &evidence, &canary, &gauge)
        .expect("the sweep is the second key to the cell")
        .end;
    assert_eq!(gauge.count(&bucket), 0, "the lost task kept its lease");
    assert!(!slot.leases().is_owned(), "the slot is unowned now");
    assert_eq!(
        end.outcome(),
        busbar_contract::caps::Outcome::Failed(StepName::Route, ReasonCode::TaskLost)
    );
    assert_eq!(end.posted().map(|p| p.quantity()), Ok(42));
    assert_eq!(canary.counts().settlements, 1);

    // And there is no third settlement: a second sweep of the same slot does nothing, and gives
    // back no lease a second time.
    assert!(sweep_settle(&kernel, &slot, verdict, &evidence, &canary, &gauge).is_none());
    assert_eq!(gauge.count(&bucket), 0);
    assert!(
        !slot.leases().take(bucket),
        "a reclaimed slot takes no lease"
    );
}

/// A SWEPT UNIT'S LINE, ITS CLASS AND ITS AUDIT PASS (Q128 p29#5, p29#6).
///
/// THE DESIGN §7 U14 (`BUSBAR-1.6.0.md` l.1061-1065): one audit record per unit, sealed at its one
/// line; l.1066-1070: the one line resolves the classes the unit reported. The sweep settles a unit
/// whose task disappeared, so it hands back the exact line it posted and the unit's audit pass, bound
/// to the call the unit's hold was opened under, and it writes the line under the class the unit
/// reported, as the exit does.
///
/// RED before the fix: `sweep_settle` answered a bare `UnitEnd` (no line, no pass: the swept unit
/// had nothing to seal its record with), and wrote its line under the kernel's own class whatever
/// class the unit reported.
#[test]
fn a_swept_unit_hands_back_its_line_under_its_reported_class_and_its_audit_pass() {
    const REPORTED: busbar_contract::caps::MeterClassId =
        busbar_contract::caps::MeterClassId::new("widget_units");
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let call = kernel.next_call();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(7),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), call),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");
    slot.mark();
    let verdict = sweep(&slot, StepName::Route, 0, 30_000, true);
    // The plane reported a figure, under a class of its own, before its task disappeared.
    let evidence = Evidence {
        reported: Some(42),
        class: Some(REPORTED),
        ..Evidence::default()
    };
    let swept = sweep_settle(
        &kernel,
        &slot,
        verdict,
        &evidence,
        &canary,
        &ConcurrencyGauge::new(),
    )
    .expect("the sweep is the second key to the cell");
    assert_eq!(
        swept.line,
        busbar_contract::caps::UsageLine {
            class: REPORTED,
            quantity: 42,
            source: busbar_contract::caps::QuantitySource::Count,
            estimated: false,
        },
        "the line is written under the class the unit reported, never the kernel's own"
    );
    assert_eq!(
        swept.end.posted().map(|p| p.quantity()),
        Ok(swept.line.quantity),
        "the money the posting settled is the line handed back"
    );
    assert!(
        swept.audit.bound_to(call),
        "the audit pass is the swept unit's own, bound to the call its hold was opened under"
    );

    // A unit that reported no class is written under the kernel's own, estimated when it reported
    // nothing, and still hands back its pass.
    let slot = table
        .insert(Enter {
            key: UnitKey::new(8),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");
    slot.mark();
    let swept = sweep_settle(
        &kernel,
        &slot,
        verdict,
        &Evidence::default(),
        &canary,
        &ConcurrencyGauge::new(),
    )
    .expect("the sweep is the second key to the cell");
    assert_eq!(
        swept.line.class,
        busbar_kernel::teller::KERNEL_ACCRUAL_CLASS
    );
    assert_eq!(swept.line.quantity, 0);
    assert!(
        swept.line.estimated,
        "nothing reported: the zero is estimated"
    );
    assert!(swept.audit.call() != busbar_contract::caps::CallId::UNBOUND);
}

/// THE LOST UNIT'S OWN LEASE, drawn by the loop and given back by the sweep.
///
/// The cell above hands the slot a lease by hand, which proves the sweep gives back what it finds.
/// This one proves there is something to find: the lease the DOOR drew, through the real loop, on a
/// unit whose task then disappeared. The loop is polled to its one await and then leaked — which is
/// what a lost task is, a frame nobody will ever run again — so the exit path it would have used
/// never runs and the sweep is the unit's only remaining end.
///
/// Without the draw, the gauge reads zero here whatever the sweep does, and a node whose tasks are
/// dying quietly looks idle right up until it stops admitting anything.
#[test]
fn the_sweep_gives_back_the_lease_the_door_drew_on_a_lost_task() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let units = common::TestUnits::passing();
    let dropped = std::sync::atomic::AtomicBool::new(false);
    let route = common::NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let gauge = ConcurrencyGauge::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(9),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");

    let unit = common::ctx(9);
    let mut running = Box::pin(busbar_kernel::teller::run_unit_async(
        &kernel,
        &units,
        &unit,
        busbar_kernel::teller::Run {
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
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(running.as_mut(), &mut cx).is_pending());
    assert_eq!(
        gauge.count(&busbar_kernel::slice::IN_FLIGHT),
        1,
        "the door drew the unit's lease on its slot"
    );
    // The task is gone: its frame is never polled again and never dropped, so nothing it owns comes
    // back on its own. Everything the unit still holds is on the slot.
    std::mem::forget(running);

    slot.mark();
    let verdict = sweep(&slot, StepName::Route, 0, 30_000, true);
    assert_eq!(
        verdict,
        Sweep::TaskLost {
            at: StepName::Route
        }
    );
    sweep_settle(
        &kernel,
        &slot,
        verdict,
        &Evidence::default(),
        &canary,
        &gauge,
    )
    .expect("the sweep is the second key to the cell");
    assert_eq!(
        gauge.count(&busbar_kernel::slice::IN_FLIGHT),
        0,
        "the lost unit's slot is back on the gauge"
    );
    assert!(!slot.leases().is_owned(), "and the slot is unowned now");
}

/// AND THE LOST UNIT'S GROUP LEASES WITH IT. A group whose count a dead task kept would be a group
/// that admits less and less until it admits nothing, and no reading anywhere would say why.
///
/// The same lost task as above, this time through a door that names two capped groups. The sweep
/// does not know the names and does not have to: the leases are the slot's, all three of them, and
/// the one release gives back everything the slot holds.
#[test]
fn the_sweep_gives_back_the_group_leases_of_a_lost_task_too() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let units = common::TestUnits::in_groups(&["tenant", "team"]);
    let dropped = std::sync::atomic::AtomicBool::new(false);
    let route = common::NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let gauge = ConcurrencyGauge::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let tenant = busbar_kernel::slice::group_lease("tenant");
    let team = busbar_kernel::slice::group_lease("team");
    let slot = table
        .insert(Enter {
            key: UnitKey::new(11),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            now: 0,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
        })
        .map_err(|_| ())
        .expect("under the cap");

    let unit = common::ctx(11);
    let mut running = Box::pin(busbar_kernel::teller::run_unit_async(
        &kernel,
        &units,
        &unit,
        busbar_kernel::teller::Run {
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
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(running.as_mut(), &mut cx).is_pending());
    assert_eq!(gauge.count(&tenant), 1, "the door counted the outer group");
    assert_eq!(gauge.count(&team), 1, "and the inner one");
    // The task is gone, exactly as above: nothing it owns comes back on its own.
    std::mem::forget(running);

    slot.mark();
    let verdict = sweep(&slot, StepName::Route, 0, 30_000, true);
    sweep_settle(
        &kernel,
        &slot,
        verdict,
        &Evidence::default(),
        &canary,
        &gauge,
    )
    .expect("the sweep is the second key to the cell");

    assert_eq!(gauge.count(&tenant), 0, "the group has its count back");
    assert_eq!(gauge.count(&team), 0, "and so does the other one");
    assert_eq!(gauge.count(&busbar_kernel::slice::IN_FLIGHT), 0);
}

/// AND THE DOOR'S OWN COUNT OF THE LOST UNIT, which is the one that caps the group.
///
/// The kernel's per-group leases above are a reading. The count the door took when it said yes is
/// the cap itself, and a task that disappears while holding one is a group whose ceiling drops by
/// one for the life of the process — until it admits nothing at all, with no reading anywhere to
/// say why. The slot is where the count lives for exactly this reason: the sweep is the unit's
/// other end, and it can only give back what the slot holds.
///
/// The proof is that the group admits again afterwards. A count that came back is a unit that runs.
#[test]
fn the_sweep_gives_back_the_door_count_a_lost_task_was_holding() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let group = common::CappedGroup::at(1);
    let units = common::TestUnits::behind(&group);
    let dropped = std::sync::atomic::AtomicBool::new(false);
    let route = common::NeverRoutes {
        units: &units,
        dropped: &dropped,
    };
    let gauge = ConcurrencyGauge::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(12),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            now: 0,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
        })
        .map_err(|_| ())
        .expect("under the cap");

    let unit = common::ctx(12);
    let mut running = Box::pin(busbar_kernel::teller::run_unit_async(
        &kernel,
        &units,
        &unit,
        busbar_kernel::teller::Run {
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
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(running.as_mut(), &mut cx).is_pending());
    assert_eq!(group.live(), 1, "the door counted the unit it admitted");
    assert!(slot.leases().holds_grant(), "and the slot is holding it");
    // The task is gone. Nothing on its frame comes back on its own — which is the whole reason the
    // count is not on its frame.
    std::mem::forget(running);

    slot.mark();
    let verdict = sweep(&slot, StepName::Route, 0, 30_000, true);
    sweep_settle(
        &kernel,
        &slot,
        verdict,
        &Evidence::default(),
        &canary,
        &gauge,
    )
    .expect("the sweep is the second key to the cell");

    assert_eq!(group.live(), 0, "the lost unit's count is back");
    assert!(!slot.leases().holds_grant());

    // AND THE NEXT UNIT IS ADMITTED into the room the sweep gave back.
    let next_units = common::TestUnits::behind(&group);
    let cell = busbar_contract::caps::HoldCell::new(busbar_kernel::inflight::arrival_hold(
        &kernel,
        &TestDoor,
        principal(),
        kernel.next_call(),
    ));
    let leases = busbar_kernel::slice::LeaseCell::new();
    let ended = busbar_kernel::teller::run_unit(
        &kernel,
        &next_units,
        &common::ctx(13),
        busbar_kernel::teller::Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        },
    );
    assert!(matches!(
        ended,
        busbar_kernel::teller::Ended::Settled { .. }
    ));
    assert_eq!(
        next_units.doors(),
        (false, true),
        "it passed the door: the group has room again"
    );
}

/// A sweep that races a unit which is still running reclaims nothing of it.
///
/// The unit's leases live on the slot now, where the sweep can reach them, so this is a rule and
/// not an accident of the sweep having no way to get at them: a slot whose unit is still there is
/// left alone — its hold, its leases, all of it.
#[test]
fn a_sweep_racing_a_running_unit_reclaims_nothing_of_it() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(7),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");

    let gauge = ConcurrencyGauge::new();
    let bucket = bucket_all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");
    assert!(slot.leases().take(bucket));

    slot.touch(0);
    let verdict = sweep(&slot, StepName::Route, 100, 30_000, true);
    assert_eq!(verdict, Sweep::Running);
    assert!(sweep_settle(
        &kernel,
        &slot,
        verdict,
        &Evidence::default(),
        &canary,
        &gauge
    )
    .is_none());
    assert_eq!(gauge.count(&bucket), 1, "the running unit still holds it");
    assert!(slot.leases().is_owned(), "and the slot is still its own");
    assert_eq!(canary.counts().settlements, 0);

    // Its own end is the one that gives the lease back, and the sweep that lands a moment later
    // finds a slot with nothing of the unit's left in it.
    assert_eq!(slot.leases().release_all(&gauge), Some(1));
    assert_eq!(gauge.count(&bucket), 0);
    assert_eq!(
        slot.leases().release_all(&gauge),
        None,
        "one lease, given back once"
    );
}

/// A unit is idle from the moment it entered, not from the moment the node booted.
///
/// The slot's progress clock started at zero, so on a node that had been up longer than one unit's
/// maximum duration every unit was born already over the bound: the first sweep after it entered
/// called it stalled, took its hold, and settled a unit that had done nothing wrong. The clock
/// starts when the unit does.
#[test]
fn a_unit_that_just_entered_is_never_already_stalled() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    // A node that has been up for a day, and a unit arriving on it right now.
    let now = 86_400_000;
    let slot = table
        .insert(Enter {
            key: UnitKey::new(3),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now,
        })
        .map_err(|_| ())
        .expect("under the cap");

    assert_eq!(slot.idle_for(now), 0, "it has been here no time at all");
    assert_eq!(
        sweep(&slot, StepName::Route, now, 30_000, true),
        Sweep::Running,
        "the sweep swept a unit that had just arrived"
    );
    // And it is stalled once it has actually been quiet for the duration.
    assert_eq!(
        sweep(&slot, StepName::Route, now + 30_000, 30_000, true),
        Sweep::Stalled {
            at: StepName::Route
        }
    );
}

#[test]
fn a_slow_unit_is_not_a_lost_one() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let slot = table
        .insert(Enter {
            key: UnitKey::new(2),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
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

    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    assert!(sweep_settle(
        &kernel,
        &slot,
        Sweep::AlarmOnly,
        &Evidence::default(),
        &canary,
        &gauge
    )
    .is_none());
    // "Takes no hold and ends no unit": the cell's hold is still there, untaken, and no
    // settlement was written for it.
    assert_eq!(slot.cell().state(), HoldCellState::Arrival);
    assert_eq!(canary.counts().settlements, 0);
}

/// A stalled unit ends where it stopped: the floor is posted, the lease goes back, and it is one
/// settlement.
///
/// The verdict had been decided and never carried through the settling path. `TaskLost` was, and
/// the two are not the same end — a stall is a unit that is still there and has stopped moving, so
/// it is the SWEEP and not the unit's own task that takes the hold, and everything the unit was
/// holding has to come back on that side.
#[test]
fn a_stalled_unit_posts_its_floor_and_gives_its_lease_back() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(13),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");
    // The plane reported nothing before it stalled: the writer writes zero, marked estimated. The
    // kernel adds no floor of its own (`BUSBAR-1.6.0.md` §7).
    let evidence = Evidence::default();

    let gauge = ConcurrencyGauge::new();
    let bucket = bucket_all("team");
    gauge.acquire(&bucket, 4).expect("room in the gauge");
    assert!(
        slot.leases().take(bucket),
        "the door records it on the slot"
    );

    let verdict = Sweep::Stalled {
        at: StepName::Route,
    };
    let end = sweep_settle(&kernel, &slot, verdict, &evidence, &canary, &gauge)
        .expect("a stall is an end, and an end settles")
        .end;
    assert_eq!(
        end.outcome(),
        busbar_contract::caps::Outcome::Failed(StepName::Route, ReasonCode::Stalled)
    );
    assert_eq!(
        end.posted().map(|p| p.quantity()),
        Ok(0),
        "a unit that stopped with nothing reported is billed nothing: the kernel adds no floor"
    );
    assert!(end
        .posted()
        .map(|p| p.flags().contains(PostingFlags::ESTIMATED))
        .unwrap_or(false));
    assert_eq!(gauge.count(&bucket), 0, "the stalled unit kept its lease");
    assert!(!slot.leases().is_owned(), "the slot is unowned now");
    assert_eq!(canary.counts().settlements, 1);

    // And the second key to the slot finds it empty.
    assert!(sweep_settle(&kernel, &slot, verdict, &evidence, &canary, &gauge).is_none());
    assert_eq!(canary.counts().settlements, 1);
}
