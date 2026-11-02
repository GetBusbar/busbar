// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

use busbar_contract::caps::{OriginKind, PostingFlags, ReasonCode, StepName};
use busbar_kernel::canary::Canary;
use busbar_kernel::inflight::{
    arrival_hold, cap_refusal_step, Binding, Enter, InFlight, Progression, Sessions,
};
use busbar_kernel::pump::NestedPool;
use busbar_kernel::teller::{settle_written, Evidence, Kernel, Written};

use common::{principal, TestDoor};

fn enter(kernel: &Kernel, key: u64, origin: OriginKind) -> Enter {
    Enter {
        key: busbar_contract::caps::UnitKey::new(key),
        origin,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        arrival: arrival_hold(kernel, &TestDoor, principal(), kernel.next_call()),
        now: 0,
    }
}

#[test]
fn a_full_table_refuses_every_counted_unit_at_the_cap_and_holds_no_slot_back() {
    let kernel = Kernel::new();
    let table = InFlight::new(10);

    for key in 0..10 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("under the cap");
    }
    let refused = table
        .insert(enter(&kernel, 10, OriginKind::Client))
        .expect_err("the table is full");
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);

    let refused = table
        .insert(enter(&kernel, 11, OriginKind::Provider))
        .expect_err("a provider frame gets no reserved slot");
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Decode);
    assert_eq!(table.len(), 10, "the refusals took no slot");
}

#[test]
fn the_administrative_listener_and_the_heartbeat_are_outside_the_cap() {
    let kernel = Kernel::new();
    let table = InFlight::new(2);
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
            parent: busbar_contract::caps::UnitKey::new(1),
        },
        OriginKind::Delivery {
            parent: busbar_contract::caps::UnitKey::new(1),
        },
    ] {
        assert_eq!(cap_refusal_step(origin), StepName::Decode);
    }
}

#[test]
fn an_unsolicited_push_refused_at_the_cap_still_posts_its_reported_line() {
    let kernel = Kernel::new();
    let table = InFlight::new(1);
    table
        .insert(enter(&kernel, 0, OriginKind::Client))
        .map(|_| ())
        .expect("the first unit fits");

    let refused = table
        .insert(enter(&kernel, 1, OriginKind::Provider))
        .expect_err("the table is full");

    let hold = refused.hold;
    assert_eq!(hold.principal(), &principal());
    let evidence = Evidence {
        reported: Some(2_500),
        ..Evidence::default()
    };
    let Written { amount, flags, .. } = settle_written(
        &busbar_contract::caps::Outcome::Refused(refused.step, refused.reason),
        &evidence,
    );
    assert_eq!(amount, 2_500);
    assert!(flags.is_clean(), "a reported figure is written unmarked");

    let Written { amount, flags, .. } = settle_written(
        &busbar_contract::caps::Outcome::Refused(refused.step, refused.reason),
        &Evidence::default(),
    );
    assert_eq!(amount, 0);
    assert!(flags.contains(PostingFlags::ESTIMATED));
}

#[test]
fn the_cap_holds_when_everything_arrives_at_once() {
    let kernel = Kernel::new();
    for _ in 0..200 {
        let table = std::sync::Arc::new(InFlight::new(4));
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
    let table = InFlight::new(4);
    for key in 0..4 {
        table
            .insert(enter(&kernel, key, OriginKind::Client))
            .map(|_| ())
            .expect("under the cap");
    }
    assert_eq!(table.len(), 4);
    assert!(table
        .remove(busbar_contract::caps::UnitKey::new(2))
        .is_some());
    assert_eq!(table.len(), 3);
    assert!(table.insert(enter(&kernel, 9, OriginKind::Client)).is_ok());
}

#[test]
fn an_interrupt_is_one_compare_and_set_and_only_before_the_meter() {
    let kernel = Kernel::new();
    let table = InFlight::new(4);
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
    let kernel = Kernel::new();
    for _ in 0..2_000 {
        let table = InFlight::new(4);
        let slot = table
            .insert(enter(&kernel, 1, OriginKind::Client))
            .map_err(|_| ())
            .expect("under the cap");
        let advancing = std::sync::Arc::clone(&slot);
        let interrupting = std::sync::Arc::clone(&slot);
        let advance = std::thread::spawn(move || advancing.step().advance_to(StepName::Route));
        let supersede = std::thread::spawn(move || interrupting.step().supersede());
        advance.join().expect("the thread finished");

        assert!(
            supersede.join().expect("the thread finished"),
            "an interrupt raised before the meter lost its compare-and-set"
        );
        assert_eq!(
            slot.step().get(),
            Progression::Superseded,
            "a step advance overwrote the interrupt"
        );
    }
}

#[test]
fn k_parents_blocked_on_children_wait_rather_than_deadlock() {
    let pool = NestedPool::new(2, 4);
    let first = pool.enter(0).expect("a permit");
    let second = pool.enter(0).expect("a permit");
    assert_eq!(pool.available(), 0);

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

    assert_eq!(pool.available(), pool.size());

    assert_eq!(pool.enter(4), Err(ReasonCode::ScopeDenied));
    assert_eq!(pool.refusals(), 2);
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
fn a_canary_over_the_table_balances_only_when_both_sides_agree() {
    let canary = Canary::new();
    assert_eq!(canary.balanced(), Ok(()));

    canary.draft_accepted();
    canary.hold_opened();
    canary.settled();
    assert_eq!(canary.balanced(), Ok(()));

    canary.draft_accepted();
    canary.accrual_taken();
    canary.settled();
    assert_eq!(canary.balanced(), Ok(()));

    canary.draft_accepted();
    canary.hold_opened();
    let broken = canary
        .balanced()
        .expect_err("the unsettled hold is a break");
    assert_eq!(broken.drafts, 3);
    assert_eq!(broken.holds, 2);
    assert_eq!(broken.accruals, 1);
    assert_eq!(broken.settlements, 2);
}

#[test]
fn a_forged_datagram_is_discarded_and_the_session_stands() {
    use busbar_contract::Framing;
    use busbar_kernel::inflight::{hard_closes, HardClose};

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
}

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
