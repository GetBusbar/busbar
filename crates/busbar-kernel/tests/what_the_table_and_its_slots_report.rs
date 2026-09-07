// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the in-flight table, a unit's slot and a session's slot REPORT about themselves.
//!
//! Everything here is a reading rather than a decision, which is exactly why each one needs a cell
//! of its own: the decisions above them — the cap, the sweep, the interrupt, the one-open-unit rule
//! — are proven against tables and slots the cell itself set up, so a reading that answered a
//! constant would still let every one of those cells pass while an operator's `/stats`, the sweep's
//! idle clock and the accrual's subject all read something that was never true.
//!
//! One unit of work per cell, and each figure is read at two moments that must differ: before and
//! after the thing that changes it.

mod common;

use busbar_caps::{OriginKind, ReasonCode, SessionId, StepName, UnitKey};
use busbar_kernel::inflight::{
    arrival_hold, Binding, CancelToken, Enter, InFlight, Progression, Sessions, StepState,
};
use busbar_kernel::pump::{Direction, StreamId};
use busbar_kernel::teller::Kernel;

use common::{principal, TestDoor};

fn enter(kernel: &Kernel, key: u64, session: Option<SessionId>) -> Enter {
    Enter {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session,
        admin_listener: false,
        provider_of_open_session: false,
        zero_hold_tick: false,
        arrival: arrival_hold(kernel, &TestDoor, principal()),
        now: 0,
    }
}

/// The table reports the ceiling it was built with, the reserve inside it, and what it is holding.
///
/// These four figures are what an operator reads to know whether the node is full, and the cap and
/// the reserve are also what every cell above them sets up. A table that reported a cap of one
/// while admitting eight would look identical to one that was working.
#[test]
fn the_table_reports_its_ceiling_its_reserve_and_what_it_holds() {
    let kernel = Kernel::new();
    let table = InFlight::new(8, 2);
    assert_eq!(table.cap(), 8, "the ceiling it was built with");
    assert_eq!(table.reserve(), 2, "and the reserve held back inside it");
    assert_eq!(table.len(), 0);
    assert!(table.is_empty(), "a node that has admitted nothing");

    let _slot = table
        .insert(enter(&kernel, 1, None))
        .expect("the empty table takes the first unit");
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty(), "a node running one unit is not idle");

    let second = table
        .insert(enter(&kernel, 2, None))
        .expect("under the ceiling");
    assert_eq!(table.len(), 2);
    drop(second);

    table.remove(UnitKey::new(2));
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty(), "one unit is still in flight");
    table.remove(UnitKey::new(1));
    assert_eq!(table.len(), 0);
    assert!(table.is_empty(), "and now the node is doing nothing");
}

/// A reserve larger than the table is the table, not a ceiling of nothing.
#[test]
fn a_reserve_bigger_than_the_table_is_clamped_to_it() {
    let table = InFlight::new(4, 10);
    assert_eq!(table.cap(), 4);
    assert_eq!(table.reserve(), 4, "the reserve is never more than the table");
}

/// A unit's slot carries the unit's OWN session, cancellation and progress clock.
///
/// The sweep reads the slot's idle clock and the exit reads its cancellation, and both are reached
/// through the slot rather than through the task — that is the whole reason they live here. A slot
/// that handed back a fresh token, or forgot which session the unit belonged to, would make a
/// cancelled unit look live to one of its two ends and charge a session's time to nobody.
#[test]
fn a_slot_carries_the_units_own_session_clock_and_cancellation() {
    let kernel = Kernel::new();
    let table = InFlight::new(4, 0);
    let session = kernel.session_id(7);
    let slot = table
        .insert(enter(&kernel, 3, Some(session)))
        .expect("room in the table");

    assert_eq!(
        slot.session(),
        Some(session),
        "the unit knows the session it belongs to"
    );

    // The progress clock: touched at one moment, read against another.
    assert_eq!(slot.idle_for(0), 0);
    slot.touch(1_000);
    assert_eq!(
        slot.idle_for(1_500),
        500,
        "the sweep measures from the last thing the unit did"
    );
    slot.touch(1_400);
    assert_eq!(slot.idle_for(1_500), 100, "and a later touch moves it on");

    // The cancellation token is the SLOT's, so tripping it through the slot is visible through the
    // slot: a fresh token handed back per call would read untripped forever.
    assert!(!slot.cancel().is_tripped());
    assert!(slot.cancel().trip(ReasonCode::ClientGone));
    assert!(slot.cancel().is_tripped(), "the slot holds the one token");
    assert_eq!(slot.cancel().reason(), Some(ReasonCode::ClientGone));

    // And the guard's mark is the slot's too.
    assert!(!slot.is_marked());
    slot.mark();
    assert!(slot.is_marked());
}

/// The token is tripped once, by one caller, and it remembers who won and why.
#[test]
fn a_cancellation_is_decided_once_and_says_what_decided_it() {
    let token = CancelToken::new();
    assert!(!token.is_tripped(), "a fresh token has not been tripped");
    assert_eq!(token.reason(), None, "and it has no reason to give");

    assert!(
        token.trip(ReasonCode::Drain),
        "the first caller is the one that decided it"
    );
    assert!(token.is_tripped());
    assert_eq!(
        token.reason(),
        Some(ReasonCode::Drain),
        "the reason is the one the winner gave"
    );

    assert!(
        !token.trip(ReasonCode::ClientGone),
        "a second caller did not decide anything"
    );
    assert_eq!(
        token.reason(),
        Some(ReasonCode::Drain),
        "and it did not overwrite the reason the first one gave"
    );
}

/// A unit ends once: the second caller is told the unit was already over.
///
/// Both of a unit's two ends run this, and the answer is what tells the second one it has nothing
/// to do. An `end` that always answered yes would let a sweep and an exit path both believe they
/// ended the same unit.
#[test]
fn a_unit_ends_once_and_the_second_end_is_told_so() {
    let step = StepState::new();
    assert_eq!(step.get(), Progression::At(StepName::Arrival));
    assert!(step.advance_to(StepName::Route));
    assert_eq!(step.get(), Progression::At(StepName::Route));

    assert!(step.end(), "the first end is the one that ended it");
    assert_eq!(step.get(), Progression::Ended);
    assert!(!step.end(), "the second end finds the unit already over");
    assert_eq!(step.get(), Progression::Ended);

    // And a step cannot resurrect a unit somebody already closed.
    assert!(!step.advance_to(StepName::Meter));
    assert_eq!(step.get(), Progression::Ended);
}

/// A session remembers who its last unit was, and forgets it when the connection renegotiates.
///
/// The cached principal is who an accrual between turns is charged to. A session that never
/// remembered one would charge a provider push to nobody; one that never forgot would charge the
/// pre-upgrade caller for what the post-upgrade caller did.
#[test]
fn a_session_remembers_its_principal_until_an_upgrade_clears_it() {
    let kernel = Kernel::new();
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(2), Binding::Bound, 0)
        .expect("under the session budget");

    assert_eq!(session.principal(), None, "nothing has arrived yet");
    session.remember(principal());
    assert_eq!(
        session.principal(),
        Some(principal()),
        "the subject an accrual between turns is charged to"
    );

    session.clear_principal();
    assert_eq!(
        session.principal(),
        None,
        "an in-band upgrade forgets the connection's negotiated state"
    );
}

/// The one open slot per direction is given back at the unit's end, and the next unit may have it.
///
/// The refusal above this is proven where a slot is claimed; what is proven here is the release —
/// a direction that was never given back is a session that can never open another unit on it,
/// which looks exactly like a peer that stopped talking.
#[test]
fn the_direction_a_unit_held_is_free_once_the_unit_has_ended() {
    let kernel = Kernel::new();
    let sessions = Sessions::new(4);
    let session = sessions
        .open(kernel.session_id(3), Binding::Bound, 0)
        .expect("under the session budget");

    let first = UnitKey::new(21);
    session
        .claim_open(StreamId(1), Direction::Inbound, first)
        .expect("the slot was free");
    assert_eq!(
        session.open_unit(StreamId(1), Direction::Inbound),
        Some(first)
    );
    assert_eq!(
        session.claim_open(StreamId(1), Direction::Inbound, UnitKey::new(22)),
        Err(ReasonCode::OpenSlotBusy),
        "one open unit per direction"
    );

    session.release_open(StreamId(1), Direction::Inbound);
    assert_eq!(
        session.open_unit(StreamId(1), Direction::Inbound),
        None,
        "the unit's end gave the direction back"
    );
    session
        .claim_open(StreamId(1), Direction::Inbound, UnitKey::new(22))
        .expect("the next unit may have the direction");
    assert_eq!(
        session.open_unit(StreamId(1), Direction::Inbound),
        Some(UnitKey::new(22))
    );
}
