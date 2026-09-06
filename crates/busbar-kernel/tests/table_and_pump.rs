// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The in-flight table, the sessions beside it, and the pump that feeds them.
//!
//! The cells here are the ones about pressure: what a node sheds when it is full, what it keeps,
//! what a barge-in does to the unit it is replacing, and what happens to a paying push that arrives
//! when there is no room for it.

mod common;

use busbar_caps::{Canary, OriginKind, PostingFlags, ReasonCode, StepName};
use busbar_kernel::grammar::DeepestPointer;
use busbar_kernel::inflight::{
    arrival_hold, cap_refusal_step, reserve_for, Binding, Enter, InFlight, Progression, Sessions,
};
use busbar_kernel::pump::{
    BodySpool, Direction, Dispatch, Emission, EmissionClock, NestedPool, Scheduler, Shape,
    SpillBudget, StreamId, TransportKind, MAX_NEEDMORE_FRAMES,
};
use busbar_kernel::teller::{settle_amount, Evidence, Kernel};

use common::{principal, TestDoor};

fn enter(kernel: &Kernel, key: u64, origin: OriginKind) -> Enter {
    Enter {
        key: busbar_caps::UnitKey::new(key),
        origin,
        session: None,
        admin_listener: false,
        provider_of_open_session: false,
        zero_hold_tick: false,
        arrival: arrival_hold(kernel, &TestDoor, principal()),
        now: 0,
    }
}

#[test]
fn the_reserve_is_a_tenth_of_the_table_and_only_where_sessions_exist() {
    assert_eq!(reserve_for(100, true), 10);
    assert_eq!(reserve_for(100, false), 0);
}

#[test]
fn a_full_table_sheds_new_arrivals_before_it_sheds_an_open_session() {
    let kernel = Kernel::new();
    let table = InFlight::new(10, reserve_for(10, true));
    // Nine client units fill the table up to the reserve.
    for key in 0..9 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("under the ceiling");
    }
    // The tenth client unit is refused: the last slot is not for it.
    let refused = table
        .insert(enter(&kernel, 9, OriginKind::Client))
        .expect_err("the reserve is held back");
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);

    // A provider frame of a session that is already open takes the reserved slot.
    let mut push = enter(&kernel, 10, OriginKind::Provider);
    push.provider_of_open_session = true;
    assert!(table.insert(push).is_ok());
}

#[test]
fn the_administrative_listener_and_the_heartbeat_are_outside_the_cap() {
    let kernel = Kernel::new();
    let table = InFlight::new(2, 0);
    for key in 0..2 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("under the cap");
    }
    let mut admin = enter(&kernel, 2, OriginKind::Client);
    admin.admin_listener = true;
    assert!(
        table.insert(admin).is_ok(),
        "the admin listener still answers"
    );

    let mut tick = enter(&kernel, 3, OriginKind::Tick);
    tick.zero_hold_tick = true;
    assert!(table.insert(tick).is_ok(), "the sweep always runs");
}

#[test]
fn an_in_flight_cap_refusal_is_stamped_at_the_step_the_unit_was_constructed_at() {
    assert_eq!(cap_refusal_step(OriginKind::Client), StepName::Arrival);
    for origin in [
        OriginKind::Provider,
        OriginKind::Tick,
        OriginKind::Nested {
            parent: busbar_caps::UnitKey::new(1),
        },
        OriginKind::Delivery {
            parent: busbar_caps::UnitKey::new(1),
        },
    ] {
        assert_eq!(cap_refusal_step(origin), StepName::Decode);
    }
}

#[test]
fn an_unsolicited_push_refused_at_the_cap_still_posts_the_floor_line() {
    let kernel = Kernel::new();
    let table = InFlight::new(1, 0);
    table
        .insert(enter(&kernel, 0, OriginKind::Client))
        .map(|_| ())
        .expect("the first unit fits");

    let refused = table
        .insert(enter(&kernel, 1, OriginKind::Provider))
        .expect_err("the table is full");
    // The hold comes BACK rather than being dropped: content the upstream will invoice is never
    // simply discarded, so the floor is posted against the session's principal.
    let hold = refused.hold;
    assert_eq!(hold.principal(), &principal());
    let evidence = Evidence {
        located: None,
        accrued_floor: 2_500,
        ..Evidence::default()
    };
    let (amount, flags) = settle_amount(
        &busbar_caps::Outcome::Refused(refused.step, refused.reason),
        &evidence,
    );
    assert_eq!(amount, 2_500);
    assert!(flags.contains(PostingFlags::ESTIMATED));
}

#[test]
fn the_cap_holds_when_everything_arrives_at_once() {
    // The table's size is the bound the crash-exposure figure is computed from, so "is there room?"
    // and "take the room" have to be one step. Sixteen arrivals racing for four slots must produce
    // four admissions, however the threads interleave.
    let kernel = Kernel::new();
    for _ in 0..200 {
        let table = std::sync::Arc::new(InFlight::new(4, 0));
        let mut racers = Vec::new();
        for key in 0..16u64 {
            let table = std::sync::Arc::clone(&table);
            let entering = enter(&kernel, key, OriginKind::Client);
            racers.push(std::thread::spawn(move || {
                table.insert(entering).map(|_| ()).is_ok()
            }));
        }
        let admitted = racers
            .into_iter()
            .filter(|_| true)
            .map(|racer| racer.join().expect("the thread finished"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 4, "the table admitted {admitted} units over 4");
        assert_eq!(table.len(), 4);
    }
}

#[test]
fn a_session_pairs_no_ninth_upstream_however_the_dials_interleave() {
    let kernel = Kernel::new();
    for _ in 0..200 {
        let sessions = Sessions::new(4);
        let slot = sessions
            .open(kernel.session_id(1), Binding::Bound, 0)
            .expect("the budget has room");
        let mut racers = Vec::new();
        for _ in 0..16 {
            let slot = std::sync::Arc::clone(&slot);
            racers.push(std::thread::spawn(move || slot.add_upstream().is_ok()));
        }
        let paired = racers
            .into_iter()
            .filter(|_| true)
            .map(|racer| racer.join().expect("the thread finished"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(paired, 8, "{paired} upstreams were paired");
        assert_eq!(slot.upstreams(), 8);
    }
}

#[test]
fn the_table_empties_as_units_leave() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    for key in 0..4 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("under the cap");
    }
    assert_eq!(table.len(), 4);
    assert!(table.remove(busbar_caps::UnitKey::new(2)).is_some());
    assert_eq!(table.len(), 3);
    assert!(table.insert(enter(&kernel, 9, OriginKind::Client)).is_ok());
}

#[test]
fn an_interrupt_is_one_compare_and_set_and_only_before_the_meter() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let slot = table
        .insert(enter(&kernel, 1, OriginKind::Client))
        .map_err(|_| ())
        .expect("under the cap");

    slot.step().advance_to(StepName::Route);
    assert!(
        slot.step().supersede(),
        "a unit before the meter is replaceable"
    );
    assert_eq!(slot.step().get(), Progression::Superseded);
    assert!(
        !slot.step().supersede(),
        "a second interrupt on the same unit is a no-op"
    );

    let other = table
        .insert(enter(&kernel, 2, OriginKind::Client))
        .map_err(|_| ())
        .expect("under the cap");
    other.step().advance_to(StepName::Meter);
    assert!(
        !other.step().supersede(),
        "a unit that has priced what it did is too late to replace"
    );
}

#[test]
fn a_step_advancing_can_never_undo_the_interrupt() {
    // The interrupt runs on another task. A step that read "running" a moment before the barge-in
    // landed must not put the superseded unit back on the loop: that is two units relaying one
    // direction under two holds.
    let kernel = Kernel::new();
    for _ in 0..2_000 {
        let table = InFlight::new(4, 0);
        let slot = table
            .insert(enter(&kernel, 1, OriginKind::Client))
            .map_err(|_| ())
            .expect("under the cap");
        let advancing = std::sync::Arc::clone(&slot);
        let interrupting = std::sync::Arc::clone(&slot);
        let advance = std::thread::spawn(move || advancing.step().advance_to(StepName::Route));
        let supersede = std::thread::spawn(move || interrupting.step().supersede());
        advance.join().expect("the thread finished");
        if supersede.join().expect("the thread finished") {
            assert_eq!(
                slot.step().get(),
                Progression::Superseded,
                "a step advance overwrote the interrupt"
            );
        }
    }
}

#[test]
fn a_second_open_on_an_occupied_direction_is_refused_and_the_session_stays_up() {
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(1), Binding::Bound, 0)
        .expect("under the session budget");
    let scheduler = Scheduler::default();

    let first = scheduler.dispatch(
        Some(&session),
        &table,
        StreamId(1),
        Direction::Inbound,
        Shape::Open { interrupt: None },
    );
    assert_eq!(first, Dispatch::OpenUnit);
    session
        .claim_open(
            StreamId(1),
            Direction::Inbound,
            busbar_caps::UnitKey::new(1),
        )
        .expect("the slot was free");

    let second = scheduler.dispatch(
        Some(&session),
        &table,
        StreamId(1),
        Direction::Inbound,
        Shape::Open { interrupt: None },
    );
    assert_eq!(
        second,
        Dispatch::Refuse {
            step: StepName::Decode,
            reason: ReasonCode::OpenSlotBusy,
        }
    );
    assert!(!session.is_closed(), "the session stays open");
}

#[test]
fn a_peer_that_only_ever_asks_for_more_is_refused_at_the_declared_ceiling() {
    // MAX_NEEDMORE_FRAMES is the handshake framing ceiling. A peer that answers "not a whole
    // anything yet" forever holds a session slot for as long as it cares to, so the ceiling has to
    // be a refusal rather than a number in a doc comment.
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(11), Binding::Bound, 0)
        .expect("under the session budget");
    let scheduler = Scheduler::default();

    let wait = |n: usize| {
        let mut last = Dispatch::Drop;
        for _ in 0..n {
            last = scheduler.dispatch(
                Some(&session),
                &table,
                StreamId(1),
                Direction::Inbound,
                Shape::NeedMore,
            );
        }
        last
    };

    assert_eq!(
        wait(MAX_NEEDMORE_FRAMES),
        Dispatch::Wait,
        "up to the ceiling"
    );
    assert_eq!(
        wait(1),
        Dispatch::Refuse {
            step: StepName::Decode,
            reason: ReasonCode::Stalled,
        },
        "the frame past the ceiling"
    );
    assert!(
        !session.is_closed(),
        "the session stays open to be told why"
    );
}

#[test]
fn any_other_shape_forgives_the_frames_that_asked_for_more() {
    // The ceiling counts CONSECUTIVE asks. A peer that is slow but making progress must never walk
    // into the refusal, however long the session runs.
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(12), Binding::Bound, 0)
        .expect("under the session budget");
    let scheduler = Scheduler::default();

    for _ in 0..4 {
        for _ in 0..MAX_NEEDMORE_FRAMES {
            assert_eq!(
                scheduler.dispatch(
                    Some(&session),
                    &table,
                    StreamId(1),
                    Direction::Inbound,
                    Shape::NeedMore,
                ),
                Dispatch::Wait
            );
        }
        // One frame that IS something resets the run.
        assert_eq!(
            scheduler.dispatch(
                Some(&session),
                &table,
                StreamId(1),
                Direction::Inbound,
                Shape::Discard,
            ),
            Dispatch::Drop
        );
    }
}

/// A closed session takes its run of "not yet" with it.
///
/// The run lived in a node-global map keyed by session id, and nothing ever took an entry out of
/// it: connect, send one byte, disconnect, repeat, and the map grew for as long as the node ran.
/// It also outlived the connection it described — a later session on the same id inherited the
/// dead one's stalling run and was refused for frames it never sent. The run belongs to the
/// session, so it ends when the session does.
#[test]
fn a_run_of_asks_ends_with_the_session_that_made_them() {
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let scheduler = Scheduler::default();
    let id = kernel.session_id(13);

    let stalling = sessions
        .open(id, Binding::Bound, 0)
        .expect("under the session budget");
    for _ in 0..MAX_NEEDMORE_FRAMES {
        assert_eq!(
            scheduler.dispatch(
                Some(&stalling),
                &table,
                StreamId(1),
                Direction::Inbound,
                Shape::NeedMore,
            ),
            Dispatch::Wait
        );
    }
    sessions.remove(id);
    drop(stalling);

    // A new connection on the same id starts from nothing.
    let fresh = sessions
        .open(id, Binding::Bound, 0)
        .expect("the slot came back with the close");
    assert_eq!(
        scheduler.dispatch(
            Some(&fresh),
            &table,
            StreamId(1),
            Direction::Inbound,
            Shape::NeedMore,
        ),
        Dispatch::Wait,
        "the new session was charged the old one's run"
    );
}

#[test]
fn a_superseding_open_reaches_the_compare_and_set_even_on_an_occupied_direction() {
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(2), Binding::Bound, 0)
        .expect("under the session budget");
    let target = busbar_caps::UnitKey::new(7);
    let slot = table
        .insert(Enter {
            key: target,
            ..enter(&kernel, 7, OriginKind::Client)
        })
        .map_err(|_| ())
        .expect("under the cap");
    slot.step().advance_to(StepName::Route);
    session
        .claim_open(StreamId(1), Direction::Inbound, target)
        .expect("the slot was free");

    let scheduler = Scheduler::default();
    let verdict = scheduler.dispatch(
        Some(&session),
        &table,
        StreamId(1),
        Direction::Inbound,
        Shape::Open {
            interrupt: Some(target),
        },
    );
    assert_eq!(verdict, Dispatch::Supersede { target, won: true });
    assert_eq!(
        session.open_unit(StreamId(1), Direction::Inbound),
        None,
        "the direction is free for the unit taking over"
    );
}

/// The interrupt names a unit; the frame carrying it names a direction. A plane may put the two
/// apart, and when it does the direction the frame arrived on belongs to somebody else. Freeing it
/// would hand a live conversation's direction to the unit taking over from a DIFFERENT one, which
/// is the two-holds-on-one-direction the whole slot exists to prevent.
#[test]
fn a_supersede_frees_only_the_direction_the_superseded_unit_was_holding() {
    let kernel = Kernel::new();
    let table = InFlight::new(8, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(3), Binding::Bound, 0)
        .expect("under the session budget");

    let target = busbar_caps::UnitKey::new(21);
    let bystander = busbar_caps::UnitKey::new(22);
    for key in [target, bystander] {
        table
            .insert(Enter {
                key,
                ..enter(&kernel, key.get(), OriginKind::Client)
            })
            .map_err(|_| ())
            .expect("under the cap");
    }
    session
        .claim_open(StreamId(1), Direction::Inbound, target)
        .expect("the slot was free");
    session
        .claim_open(StreamId(2), Direction::Inbound, bystander)
        .expect("the slot was free");

    // The interrupt names the unit on stream 1; the frame arrives on stream 2.
    let scheduler = Scheduler::default();
    let verdict = scheduler.dispatch(
        Some(&session),
        &table,
        StreamId(2),
        Direction::Inbound,
        Shape::Open {
            interrupt: Some(target),
        },
    );
    assert_eq!(verdict, Dispatch::Supersede { target, won: true });
    assert_eq!(
        session.open_unit(StreamId(2), Direction::Inbound),
        Some(bystander),
        "the bystander still owns the direction its own frame arrived on"
    );
}

#[test]
fn one_shots_run_under_a_small_fixed_concurrency() {
    let kernel = Kernel::new();
    let table = InFlight::new(64, 0);
    let scheduler = Scheduler::new(2);
    let _ = kernel;
    assert_eq!(
        scheduler.dispatch(
            None,
            &table,
            StreamId(0),
            Direction::Inbound,
            Shape::OneShot
        ),
        Dispatch::OpenOneShot
    );
    assert_eq!(
        scheduler.dispatch(
            None,
            &table,
            StreamId(0),
            Direction::Inbound,
            Shape::OneShot
        ),
        Dispatch::OpenOneShot
    );
    assert_eq!(
        scheduler.dispatch(
            None,
            &table,
            StreamId(0),
            Direction::Inbound,
            Shape::OneShot
        ),
        Dispatch::Refuse {
            step: StepName::Decode,
            reason: ReasonCode::InFlightCap
        },
        "the third is REFUSED rather than crowding out the open conversation — and refused rather \
         than told to wait, because a whole unit arrived in that frame and the pump holds no queue \
         to keep it in: `Wait` is what a partial frame is answered with, and answering a whole one \
         with it is a unit nobody renders, nobody counts and nobody ends"
    );
    scheduler.finish_one_shot();
    assert_eq!(
        scheduler.dispatch(
            None,
            &table,
            StreamId(0),
            Direction::Inbound,
            Shape::OneShot
        ),
        Dispatch::OpenOneShot
    );
}

#[test]
fn k_parents_blocked_on_children_wait_rather_than_deadlock() {
    let pool = NestedPool::new(2, 4);
    let first = pool.enter(0).expect("a permit");
    let second = pool.enter(0).expect("a permit");
    assert_eq!(pool.available(), 0);

    // Two more parents want children and there are none to be had. Neither deadlocks, and both
    // refusals are COUNTED — a refusal is a thing that happened, not a parent still standing in
    // the pool: the refused parent is already back with its caller and will never call `leave`.
    // Counted as a gauge it only ever went up, and the number an operator reads as "the pool is
    // the bottleneck right now" was really "the pool has ever been the bottleneck".
    assert_eq!(pool.enter(0), Err(ReasonCode::InFlightCap));
    assert_eq!(pool.enter(0), Err(ReasonCode::InFlightCap));
    assert_eq!(pool.refusals(), 2);

    pool.leave(first);
    assert_eq!(pool.available(), 1);
    assert_eq!(
        pool.refusals(),
        2,
        "giving a permit back un-refuses nothing"
    );
    pool.leave(second);
    // Every permit is back, so the pool is whole again however many refusals it made.
    assert_eq!(pool.available(), pool.size());

    // And nesting past the depth bound is refused whatever the pool looks like — for want of
    // depth, which is not the pool having nothing to give.
    assert_eq!(pool.enter(4), Err(ReasonCode::ScopeDenied));
    assert_eq!(pool.refusals(), 2);
}

#[test]
fn a_discarded_frame_changes_no_state() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(3), Binding::Unbound, 0)
        .expect("under the budget");
    let scheduler = Scheduler::default();
    assert_eq!(
        scheduler.dispatch(
            Some(&session),
            &table,
            StreamId(4),
            Direction::Inbound,
            Shape::Discard
        ),
        Dispatch::Drop
    );
    assert!(!session.is_closed());
    assert_eq!(table.len(), 0);
}

#[test]
fn pacing_pushes_back_on_a_stream_and_drops_on_a_datagram() {
    let mut stream = EmissionClock::new(1_000, 1, TransportKind::Stream);
    assert_eq!(stream.offer(0), Emission::Send);
    assert!(matches!(stream.offer(0), Emission::Backpressure { .. }));
    assert!(matches!(stream.offer(0), Emission::Backpressure { .. }));

    let mut datagram = EmissionClock::new(1_000, 1, TransportKind::Datagram);
    assert_eq!(datagram.offer(0), Emission::Send);
    assert!(matches!(datagram.offer(0), Emission::Backpressure { .. }));
    assert_eq!(
        datagram.offer(0),
        Emission::Unemitted,
        "there is nowhere to push back to, so the frame is dropped and journaled"
    );
}

/// A queue that fills has to empty again, and the thing that empties it is a frame leaving.
///
/// The clock depth was only ever pushed UP by a test: `emitted` was declared and never called, so
/// nothing proved that a connection draining its queue takes the backpressure off. A queue that
/// only fills is a connection throttled for the rest of its life.
#[test]
fn a_queue_that_drains_takes_the_backpressure_off() {
    let mut clock = EmissionClock::new(1_000, 2, TransportKind::Stream);
    assert_eq!(clock.offer(0), Emission::Send);
    assert_eq!(clock.depth(), 0, "the first frame went straight out");

    assert!(matches!(clock.offer(0), Emission::Backpressure { .. }));
    assert!(matches!(clock.offer(0), Emission::Backpressure { .. }));
    assert_eq!(clock.depth(), 2, "both are queued behind the pace");

    // The connection takes them.
    clock.emitted();
    clock.emitted();
    assert_eq!(clock.depth(), 0);

    // And the next frame, offered past the pace the queued ones bought, goes out unpaced.
    assert_eq!(clock.offer(3_000), Emission::Send);
    assert_eq!(clock.depth(), 0);

    // A frame that never queued cannot be emitted into a negative depth.
    clock.emitted();
    assert_eq!(clock.depth(), 0);
}

#[test]
fn a_body_opens_its_unit_only_once_the_deepest_pointer_has_resolved() {
    let budget = SpillBudget::new(1 << 20);
    let head = br#"{"padding":"#;
    let tail = br#""x","lane":"gold"}"#;
    let mut spool = BodySpool::new(None, DeepestPointer::Offset(0));

    spool.push(head, &budget).expect("within the budget");
    assert!(
        !spool.try_resolve("/lane"),
        "a pointer is never read off a truncated document"
    );
    spool.push(tail, &budget).expect("within the budget");
    assert!(spool.try_resolve("/lane"), "the key has arrived");
    assert!(spool.ready());
}

#[test]
fn a_body_is_bounded_by_its_bytes_and_never_by_its_chunk_count() {
    // The frame bound belongs to handshakes, not to bodies. A client that dribbles its body a byte
    // at a time is served exactly as one that sends it whole: the only thing counted here is bytes,
    // and it is counted in real bytes against the node's own budget.
    let budget = SpillBudget::new(1 << 20);
    let mut spool = BodySpool::new(None, DeepestPointer::Offset(0));

    let head = br#"{"padding":""#;
    spool.push(head, &budget).expect("within the budget");
    for _ in 0..4_000 {
        spool.push(b"x", &budget).expect("no bound on chunk count");
        assert!(!spool.try_resolve("/lane"), "the key has not arrived yet");
    }
    spool
        .push(br#"","lane":"gold"}"#, &budget)
        .expect("within the budget");

    assert!(
        spool.try_resolve("/lane"),
        "the key arrived after 4,000 chunks"
    );
    assert!(spool.ready());
    assert_eq!(spool.len(), head.len() + 4_000 + 16);
    assert_eq!(budget.used(), spool.len(), "charged in actual bytes");

    // And the bytes go back when the unit ends, so a long-running node does not leak the budget.
    let spooled = spool.len();
    spool.release(&budget);
    assert_eq!(budget.used(), 0, "{spooled} bytes were returned");
}

#[test]
fn the_spill_budget_refuses_rather_than_growing() {
    let budget = SpillBudget::new(8);
    let mut spool = BodySpool::new(None, DeepestPointer::EndOfBody);
    assert!(spool.push(b"12345678", &budget).is_ok());
    assert_eq!(spool.push(b"9", &budget), Err(ReasonCode::SpillBudget));
    spool.release(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_session_counts_its_upstreams_and_refuses_the_ninth() {
    let kernel = Kernel::new();
    let sessions = Sessions::new(2);
    let session = sessions
        .open(kernel.session_id(4), Binding::Bound, 0)
        .expect("under the budget");
    for expected in 0..8 {
        assert_eq!(session.add_upstream(), Ok(expected));
    }
    assert_eq!(session.add_upstream(), Err(ReasonCode::SessionBudget));
}

#[test]
fn the_session_budget_bounds_the_table() {
    let kernel = Kernel::new();
    let sessions = Sessions::new(1);
    assert!(sessions
        .open(kernel.session_id(5), Binding::Bound, 0)
        .is_ok());
    assert_eq!(
        sessions.open(kernel.session_id(6), Binding::Bound, 0).err(),
        Some(ReasonCode::SessionBudget)
    );
}

/// The session budget is a bound, so asking it and spending it have to be one step.
///
/// The table's own cap already took its slot atomically; the session table asked "is there room?",
/// built the slot, and only then counted it, which is three steps a peer can arrive in the middle
/// of. Sixteen connections racing for four session slots must open four, however they interleave —
/// a node that opens more sessions than its budget is a node whose budget is a suggestion.
#[test]
fn the_session_budget_holds_when_everything_connects_at_once() {
    let kernel = Kernel::new();
    for _ in 0..200 {
        let sessions = std::sync::Arc::new(Sessions::new(4));
        let mut racers = Vec::new();
        for id in 0..16u64 {
            let sessions = std::sync::Arc::clone(&sessions);
            let session = kernel.session_id(id);
            racers.push(std::thread::spawn(move || {
                sessions.open(session, Binding::Bound, 0).is_ok()
            }));
        }
        let opened = racers
            .into_iter()
            .map(|racer| racer.join().expect("the thread finished"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(opened, 4, "the node opened {opened} sessions over 4");
        assert_eq!(sessions.len(), 4);
    }
}

#[test]
fn a_canary_over_the_table_is_still_balanced_when_nothing_ran() {
    let canary = Canary::new();
    assert_eq!(canary.balanced(), Ok(()));
}

/// A forged datagram is one datagram: it is discarded, it posts nothing, and the session stands.
///
/// The design carves this out explicitly — a decode failure hard-closes on a STREAM transport,
/// where losing sync makes every later byte suspect, and never on a datagram one, where the next
/// message is unaffected. The hard-close decision could not see the difference, so the stream arm
/// fired for datagrams too: anyone able to send one forged packet could drop somebody's session.
#[test]
fn a_forged_datagram_is_discarded_and_the_session_stands() {
    use busbar_contract::Framing;
    use busbar_kernel::inflight::{hard_closes, HardClose};

    // The same ending, read on each framing.
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::DecodeFailed,
            Framing::Stream,
            Binding::Unbound,
        ),
        Some(HardClose::DecodeFailedOnStream),
        "a stream that has lost sync cannot be trusted to resynchronise"
    );
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::DecodeFailed,
            Framing::Datagram,
            Binding::Unbound,
        ),
        None,
        "one unreadable datagram says nothing about the next one"
    );

    // And the frame itself is dropped without touching the table or the session.
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(7), Binding::Unbound, 0)
        .expect("under the budget");
    let scheduler = Scheduler::default();
    assert_eq!(
        scheduler.dispatch(
            Some(&session),
            &table,
            StreamId(1),
            Direction::Inbound,
            Shape::Discard
        ),
        Dispatch::Drop
    );
    assert!(!session.is_closed(), "the session is intact");
    assert_eq!(table.len(), 0, "and nothing entered the table to be posted");
}

/// A bound session whose cached principal stops authenticating is closed, and an unbound one is not.
///
/// This is what BINDING is for. On a bound session the cached principal is the thing every later
/// unit runs as; when the re-check refuses it, there is nothing left on that connection to be — the
/// session is standing on a fact that is no longer true, so it closes. On an unbound session every
/// unit authenticates for itself, and "wrong credential, try again" is an ordinary thing for a
/// client to do on a connection that stays up. The decision could not see the binding at all, so
/// one of the two answers was unreachable and the other was given to both.
#[test]
fn a_bound_session_closes_when_its_cached_principal_stops_authenticating() {
    use busbar_contract::Framing;
    use busbar_kernel::inflight::{hard_closes, HardClose};

    for framing in [Framing::Stream, Framing::Datagram] {
        assert_eq!(
            hard_closes(
                OriginKind::Client,
                StepName::Authenticate,
                ReasonCode::Unauthenticated,
                framing,
                Binding::Bound,
            ),
            Some(HardClose::BoundPrincipalFailed),
            "the session is running as somebody it can no longer prove it is"
        );
        assert_eq!(
            hard_closes(
                OriginKind::Client,
                StepName::Authenticate,
                ReasonCode::Unauthenticated,
                framing,
                Binding::Unbound,
            ),
            None,
            "an unbound session authenticates per unit and survives a bad one"
        );
    }

    // A refusal somewhere other than the re-check is not the cached principal failing.
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Admit,
            ReasonCode::Unauthenticated,
            Framing::Stream,
            Binding::Bound,
        ),
        None
    );
}

/// A handoff neither leg declared closes the session it happened on, on either framing.
///
/// The variant was declared and nothing produced it, which made it a comment. An upgrade the
/// adopting layer never declared leaves the session standing on a stack nobody wrote down, and no
/// later frame makes that true again — so it is a hard close and not a refusal that renders.
#[test]
fn a_handoff_mismatch_closes_the_session_on_either_framing() {
    use busbar_contract::Framing;
    use busbar_kernel::inflight::{hard_closes, HardClose};

    for framing in [Framing::Stream, Framing::Datagram] {
        assert_eq!(
            hard_closes(
                OriginKind::Client,
                StepName::Verify,
                ReasonCode::HandoffMismatch,
                framing,
                Binding::Bound,
            ),
            Some(HardClose::HandoffMismatch),
            "the stack the session stands on is not a per-frame question"
        );
    }
}

/// A key already live is not a slot to take, and the unit that asks for it is refused.
///
/// The session table one screen below already answers this: `Sessions::open` notices that the id it
/// inserted displaced another and hands the claim straight back. The unit table has to answer it
/// harder, because a displaced UNIT slot is not just a number — it is a `HoldCell` with a hold in
/// it. Displaced out of the shard map, the slot is unreachable by `get`, by `remove` and above all
/// by the SWEEP, which walks `snapshot`: nothing will ever take that hold, so it is a unit that
/// never posts. And the count keeps the slot it claimed for it, so every duplicate ratchets the
/// node one unit closer to a cap it will never come back down from.
#[test]
fn a_key_already_in_the_table_is_refused_rather_than_displacing_the_unit_holding_it() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let live = table
        .insert(enter(&kernel, 7, OriginKind::Client))
        .expect("the first unit takes the slot");

    let refused = table
        .insert(enter(&kernel, 7, OriginKind::Client))
        .expect_err("the key is live, so there is no slot to take");
    assert_eq!(
        refused.reason,
        ReasonCode::InFlight,
        "not the cap — the table has room; this key does not"
    );

    assert_eq!(
        table.len(),
        1,
        "the refused unit's claim went back: a duplicate must not ratchet the count"
    );
    assert!(
        table
            .snapshot()
            .iter()
            .any(|slot| std::sync::Arc::ptr_eq(slot, &live)),
        "and the unit that was already holding the key is still the one the sweep can reach"
    );

    // The claim really did come back: the table still admits up to its cap.
    for key in 8..11 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("three more fit under a cap of four");
    }
}
