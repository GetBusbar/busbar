// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the node owes after a crash, and what the clock does when nothing arrives.

mod common;

use busbar_caps::{Canary, OriginKind, PostingFlags, ReasonCode, StepName, UnitKey};
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::recovery::{
    frame, owed_after, recover_all, truncate_torn_tail, voids_claim, HoldRecord, KillPoint, Owed,
    TailVerdict, RECORD_HEADER_BYTES,
};
use busbar_kernel::slice::{bucket_all, ConcurrencyGauge, Epoch};
use busbar_kernel::teller::{Evidence, Kernel};
use busbar_kernel::tick::{
    drain_outcome, drain_verdict, fleet_action, session_tick, sweep, sweep_settle, DrainVerdict,
    FleetAction, SessionTick, Sweep, MIN_QUORUM_PEERS, SESSION_IDLE_MAX_MS,
};

use common::{principal, TestDoor};

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
    let good_one = journal.len();
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

    // And a record whose bytes were corrupted rather than cut short is a different answer: the
    // record is all there, so nothing about it says "died mid-write".
    let mut corrupt = journal.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    let verdict = truncate_torn_tail(&corrupt);
    assert_eq!(verdict.records, 1);
    assert_eq!(verdict.verdict, TailVerdict::Corrupt { at: good_one });
}

#[test]
fn a_checksum_failure_in_the_middle_is_not_the_answer_a_cut_off_tail_gets() {
    let mut journal = Vec::new();
    journal.extend_from_slice(&frame(b"one"));
    let second = journal.len();
    journal.extend_from_slice(&frame(b"two"));
    journal.extend_from_slice(&frame(b"three"));

    // The middle record's payload was rewritten by something that was not this node. Every record
    // after it is whole and readable, and truncating here would throw all of them away for a fault
    // that says nothing about them.
    let mut corrupt = journal.clone();
    corrupt[second + RECORD_HEADER_BYTES] ^= 0xFF;
    let verdict = truncate_torn_tail(&corrupt);
    assert_eq!(verdict.records, 1);
    assert_eq!(verdict.valid_bytes, second);
    assert_eq!(verdict.verdict, TailVerdict::Corrupt { at: second });
    assert!(
        !verdict.verdict.truncates(),
        "a corrupt record is raised, never quietly cut away"
    );

    // The cut-off tail keeps the answer it always had, and that one does truncate.
    let mut torn = journal.clone();
    torn.truncate(journal.len() - 2);
    let verdict = truncate_torn_tail(&torn);
    assert_eq!(verdict.records, 2);
    assert_eq!(verdict.verdict, TailVerdict::Torn);
    assert!(verdict.verdict.truncates());
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
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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

    let evidence = Evidence {
        accrued_floor: 42,
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
        .expect("the sweep is the second key to the cell");
    assert_eq!(gauge.count(&bucket), 0, "the lost task kept its lease");
    assert!(!slot.leases().is_owned(), "the slot is unowned now");
    assert_eq!(
        end.outcome(),
        busbar_caps::Outcome::Failed(StepName::Route, ReasonCode::TaskLost)
    );
    assert_eq!(end.posted().map(|p| p.settled()), Ok(42));
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
    let table = InFlight::new(4, 0);
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
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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
    let table = InFlight::new(4, 0);
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
            provider_of_open_session: false,
            zero_hold_tick: false,
            now: 0,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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

/// A sweep that races a unit which is still running reclaims nothing of it.
///
/// The unit's leases live on the slot now, where the sweep can reach them, so this is a rule and
/// not an accident of the sweep having no way to get at them: a slot whose unit is still there is
/// left alone — its hold, its leases, all of it.
#[test]
fn a_sweep_racing_a_running_unit_reclaims_nothing_of_it() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(7),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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
    let table = InFlight::new(4, 0);
    // A node that has been up for a day, and a unit arriving on it right now.
    let now = 86_400_000;
    let slot = table
        .insert(Enter {
            key: UnitKey::new(3),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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
    let table = InFlight::new(4, 0);
    let slot = table
        .insert(Enter {
            key: UnitKey::new(2),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
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
    let table = InFlight::new(4, 0);
    let canary = Canary::new();
    let slot = table
        .insert(Enter {
            key: UnitKey::new(13),
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
            now: 0,
        })
        .map_err(|_| ())
        .expect("under the cap");
    let evidence = Evidence {
        accrued_floor: 1_750,
        ..Evidence::default()
    };

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
        .expect("a stall is an end, and an end settles");
    assert_eq!(
        end.outcome(),
        busbar_caps::Outcome::Failed(StepName::Route, ReasonCode::Stalled)
    );
    assert_eq!(
        end.posted().map(|p| p.settled()),
        Ok(1_750),
        "a unit that stopped is billed the floor the kernel counted"
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
            checkpoint: None,
        }
    );
    // A tick that could not run: the next one prices the whole gap, marked late.
    assert_eq!(
        session_tick(1_000, 3_000, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: 3_000,
            late: true,
            clipped: false,
            checkpoint: None,
        }
    );
    // A gap longer than the idle bound is clipped at it rather than posted in full.
    assert_eq!(
        session_tick(1_000, SESSION_IDLE_MAX_MS + 1, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: SESSION_IDLE_MAX_MS,
            late: true,
            clipped: true,
            checkpoint: None,
        }
    );
}

/// A priced session checkpoints what it has accrued, exactly as an unpriced one does.
///
/// The two jobs of a session tick are not alternatives: pricing an interval of session time and
/// writing down what has accrued so far are different things, and a session that does the first
/// still has to do the second. Deciding them as one if/else meant a priced session NEVER
/// checkpointed, so its journal record carried a checkpoint of zero — and recovery, which posts the
/// last checkpointed figure, posted nothing for a session that had been billing all along.
#[test]
fn a_priced_session_still_checkpoints_what_it_accrued() {
    let verdict = session_tick(1_000, 1_000, 0, Some(4_200), true, false, false);
    assert_eq!(
        verdict,
        SessionTick::Accrue {
            elapsed: 1_000,
            late: false,
            clipped: false,
            checkpoint: Some(4_200),
        },
        "the priced branch swallowed the checkpoint"
    );

    // And what the tick checkpointed is what a crash pays out on.
    let kernel = Kernel::new();
    let canary = Canary::new();
    let checkpointed = match verdict {
        SessionTick::Accrue {
            checkpoint: Some(accrued),
            ..
        } => accrued,
        other => panic!("the tick answered {other:?}"),
    };
    let postings = recover_all(&kernel, &[record(true, checkpointed)], Epoch(2), &canary);
    assert_eq!(postings.len(), 1);
    assert_eq!(
        postings[0].settled(),
        4_200,
        "recovery posted a figure the tick never wrote down"
    );
    assert!(postings[0].flags().contains(PostingFlags::RECOVERED));
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
        busbar_caps::Outcome::Aborted(busbar_caps::Abort::Kernel {
            reason: busbar_caps::ReasonCode::Drain,
        })
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

/// A two-node fleet takes the odd-one-out answer, whatever its one peer is doing.
///
/// Neither node can tell which side of a partition holds the majority — each sees exactly one peer
/// it cannot reach — so "my only peer is stale too" is not the fleet agreeing, and reading it that
/// way would have both nodes serving on slices the other believes it still holds. The bound that
/// says so is named, and this is the case it is named for.
#[test]
fn a_two_node_fleet_has_no_quorum_to_appeal_to() {
    assert_eq!(MIN_QUORUM_PEERS, 2);
    // One peer, stale, and a quorum a single peer would meet: still the short grace, not the long
    // stale-serve bound the quorum branch buys.
    assert_eq!(
        fleet_action(1, 1, 1, 10_000, 30_000, 630_000),
        FleetAction::ServeStale { until: 30_000 },
        "one peer agreeing is not the fleet agreeing"
    );
    assert_eq!(
        fleet_action(1, 1, 1, 30_000, 30_000, 630_000),
        FleetAction::Drain
    );
    // With one more peer the same quorum IS a quorum, and availability is bought to the bound.
    assert_eq!(
        fleet_action(2, 1, 1, 10_000, 30_000, 630_000),
        FleetAction::ServeStale { until: 630_000 }
    );
}
