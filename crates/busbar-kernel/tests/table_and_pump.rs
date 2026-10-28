// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The in-flight table, the sessions beside it, and the pump that feeds them.
//!
//! The cells here are the ones about pressure: what a node sheds when it is full, what it keeps,
//! what a barge-in does to the unit it is replacing, and what happens to a paying push that arrives
//! when there is no room for it.

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

/// NO SLOT IS HELD BACK (item 280). The table used to carry a "reserve" for provider frames of
/// open sessions, but no caller ever built one or marked a frame as belonging to an open session,
/// so it was deleted. What replaces it: the cap is the cap for every counted unit — a full table
/// refuses the next client arrival AND a provider frame alike, at the step each was constructed
/// at, and every one of the `cap` slots is available to the first arrivals.
#[test]
fn a_full_table_refuses_every_counted_unit_at_the_cap_and_holds_no_slot_back() {
    let kernel = Kernel::new();
    let table = InFlight::new(10);
    // All ten slots go to client arrivals: nothing is held back.
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

    // A provider frame is refused at the same cap, stamped at Decode.
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
    // The hold comes BACK rather than being dropped: content the upstream will invoice is never
    // simply discarded, so what the plane reported is posted against the session's principal.
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
    // Nothing reported on a refused end: zero, marked estimated; never a floor.
    let Written { amount, flags, .. } = settle_written(
        &busbar_contract::caps::Outcome::Refused(refused.step, refused.reason),
        &Evidence::default(),
    );
    assert_eq!(amount, 0);
    assert!(flags.contains(PostingFlags::ESTIMATED));
}

#[test]
fn the_cap_holds_when_everything_arrives_at_once() {
    // The table's size is the bound the crash-exposure figure is computed from, so "is there room?"
    // and "take the room" have to be one step. Sixteen arrivals racing for four slots must produce
    // four admissions, however the threads interleave.
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
    // The interrupt runs on another task. A step that read "running" a moment before the barge-in
    // landed must not put the superseded unit back on the loop: that is two units relaying one
    // direction under two holds.
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
        // The interrupt is asserted to have WON, not merely checked if it happened to. Both racing
        // steps are before the meter, so the compare-and-set has nothing that can refuse it — and
        // under the `if` a `supersede` that had become a no-op returning false would skip the only
        // assertion in the loop and leave a green test over two units relaying one direction.
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

/// The canary balances a quiet table, balances a table that ran, and breaks when a side is short.
///
/// A fresh canary is all zeroes, so `balanced()` on it reads `0 == 0 && 0 == 0` — true no matter
/// what the comparison says. Asserting only that case proves nothing about the relation the canary
/// exists to check: replacing the whole body of `balanced()` with an unconditional `Ok(())` left
/// the empty-canary assertion green. So the quiet case is kept and the two cases that actually
/// pin the relation are asserted beside it — a draft matched by a hold and a settlement balances,
/// and a draft whose settlement never arrived is reported as the break it is.
#[test]
fn a_canary_over_the_table_balances_only_when_both_sides_agree() {
    // Nothing ran: the quiet table is balanced.
    let canary = Canary::new();
    assert_eq!(canary.balanced(), Ok(()));

    // A whole unit went through: drafted, held, settled. Both sides agree.
    canary.draft_accepted();
    canary.hold_opened();
    canary.settled();
    assert_eq!(canary.balanced(), Ok(()));

    // An accrual settles into a parent's hold and posts its own settlement: still agreeing.
    canary.draft_accepted();
    canary.accrual_taken();
    canary.settled();
    assert_eq!(canary.balanced(), Ok(()));

    // A draft that opened a hold but never settled: the canary reports the break, with the counts.
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
