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
    SpillBudget, StreamId, TransportKind,
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
        Dispatch::Wait,
        "the third waits rather than crowding out the open conversation"
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

    // Two more parents want children and there are none to be had. They are counted as blocked,
    // which is the number that says the pool is the bottleneck, and neither of them deadlocks.
    assert_eq!(pool.enter(0), Err(ReasonCode::InFlightCap));
    assert_eq!(pool.enter(0), Err(ReasonCode::InFlightCap));
    assert_eq!(pool.blocked(), 2);

    pool.leave(first);
    assert_eq!(pool.available(), 1);
    assert_eq!(pool.blocked(), 1);
    pool.leave(second);

    // And nesting past the depth bound is refused whatever the pool looks like.
    assert_eq!(pool.enter(4), Err(ReasonCode::ScopeDenied));
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
            Framing::Stream
        ),
        Some(HardClose::DecodeFailedOnStream),
        "a stream that has lost sync cannot be trusted to resynchronise"
    );
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::DecodeFailed,
            Framing::Datagram
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
