// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's open-call table and its port: which answer wakes which wait, what the sweep ends, and
//! that a table the served path uses returns every row it takes.

use super::*;

/// The correlation a client's reply carries, as the plane reads it off the bytes.
fn reply(call_id: &str) -> CorrelationRef<'_> {
    tool_call(call_id)
}

/// Enter `call_id`'s wait for `unit` on `session`, as the pump's planning does.
fn plan(table: &OpenToolCalls, session: u64, unit: u64, call_id: &str, now: Millis) {
    table
        .planned(
            session,
            UnitKey::new(unit),
            TOOL_REPLY_LEG,
            Some(tool_call(call_id)),
            now,
        )
        .expect("a minted identifier under the leg's own key is a wait");
}

/// The plane's declared reply deadline, in milliseconds.
fn deadline() -> u64 {
    u64::from(crate::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000
}

/// **Two calls open at once, and each reply wakes only its own.**
///
/// A turn that asks for two tools opens two calls, identical apart from the identifier each minted —
/// same key, same deadline — which is exactly the pair a wait on a constant, or on a fold of an
/// identifier, is free to confuse. The replies come back in the opposite order to the calls, so
/// "whichever is waiting" cannot pass either.
#[test]
fn two_tool_calls_on_one_session_each_wake_only_the_call_they_answer() {
    let table = OpenToolCalls::new();
    let (weather, tide) = (11, 22);
    plan(&table, 7, weather, "call_aaa", 0);
    plan(&table, 7, tide, "call_bbb", 0);
    assert_eq!(table.open(), 2, "two calls are open, not one");

    assert_eq!(
        table.replied(7, reply("call_bbb")),
        Ok(UnitKey::new(tide)),
        "the reply wakes the call whose identifier it carries"
    );
    assert!(
        table.waiting(7, UnitKey::new(weather)),
        "and leaves the other call waiting on its own identifier, untouched"
    );
    assert_eq!(
        table.replied(7, reply("call_aaa")),
        Ok(UnitKey::new(weather)),
        "which is still there for its own answer"
    );
    assert_eq!(table.open(), 0, "and both calls are settled");
    assert_eq!(
        table.ending(7, UnitKey::new(weather)),
        Some(CallEnd::Answered),
        "each call's ending is read, once"
    );
    assert_eq!(table.ending(7, UnitKey::new(weather)), None);
}

/// A reply nobody is waiting for is refused, not dropped.
#[test]
fn a_reply_for_a_call_nobody_opened_is_refused_rather_than_dropped() {
    let table = OpenToolCalls::new();
    plan(&table, 7, 11, "call_aaa", 0);
    assert_eq!(
        table.replied(7, reply("call_zzz")),
        Err(ReplyRefused::UnknownCall),
        "an unmatched reply is not paid out against the only call standing"
    );
    assert_eq!(
        table.replied(9, reply("call_aaa")),
        Err(ReplyRefused::NoSuchSession),
        "and the same identifier on another session is another conversation's business"
    );
    assert!(
        table.waiting(7, UnitKey::new(11)),
        "the open call is untouched by either"
    );
    assert_eq!(table.replied(7, reply("call_aaa")), Ok(UnitKey::new(11)));
}

/// **An unanswered call ends at the deadline it declared** — not one millisecond early, and it ends
/// as unanswered rather than as though the answer had arrived.
#[test]
fn an_unanswered_tool_call_ends_at_the_deadline_its_leg_declared() {
    let table = OpenToolCalls::new();
    plan(&table, 7, 11, "call_aaa", 0);
    plan(&table, 7, 22, "call_bbb", 20_000);
    assert!(
        table.expired(deadline() - 1).is_empty(),
        "a call is not swept one millisecond before its own deadline"
    );
    assert_eq!(
        table.expired(deadline() + 1),
        vec![UnansweredCall {
            session: 7,
            unit: UnitKey::new(11)
        }],
        "the first call's deadline is up; the one opened twenty seconds later is not"
    );
    assert_eq!(table.open(), 1, "the second call is still waiting");
    assert_eq!(
        table.ending(7, UnitKey::new(11)),
        Some(CallEnd::Unanswered),
        "the swept call ended under its deadline"
    );
}

/// A call that minted no identifier is not entered as a wildcard.
#[test]
fn a_tool_call_that_minted_no_identifier_is_refused_rather_than_entered() {
    let table = OpenToolCalls::new();
    assert_eq!(
        table.planned(7, UnitKey::new(11), TOOL_REPLY_LEG, None, 0),
        Err(NotWaiting::NoCorrelationOut)
    );
    assert_eq!(table.open(), 0, "and nothing is waiting");
}

/// A conversation that is over cannot answer anything.
#[test]
fn a_closed_session_stops_waiting_on_the_calls_it_had_open() {
    let table = OpenToolCalls::new();
    plan(&table, 7, 11, "call_aaa", 0);
    table.closed(7);
    assert_eq!(table.open(), 0);
    assert_eq!(
        table.replied(7, reply("call_aaa")),
        Err(ReplyRefused::NoSuchSession)
    );
}

/// **The port the served path reaches the table through**: the same answers — woken, refused, swept
/// — asked in the spelling the session runtime asks them in.
#[test]
fn the_runtimes_port_reaches_the_nodes_own_table() {
    let port = NodeCalls::new(Arc::new(OpenToolCalls::new()), keys());
    assert!(port.planned(7, "call_aaa", 0), "a planned leg is a wait");
    assert!(port.planned(7, "call_bbb", 0));
    assert_eq!(
        port.replied(9, "call_aaa"),
        Err(ReplyRefusal::NoSuchSession),
        "a reply on a session this node holds nothing for wakes nothing"
    );
    assert_eq!(
        port.replied(7, "call_zzz"),
        Err(ReplyRefusal::UnknownCall),
        "and one naming a call nobody is waiting on is refused, not matched to whichever is open"
    );
    assert_eq!(
        port.replied(7, "call_bbb"),
        Ok(()),
        "the answer wakes its own"
    );
    assert_eq!(
        port.table().open(),
        1,
        "and the call it did not answer waits"
    );
    assert_eq!(port.expired(deadline() - 1), 0, "not one millisecond early");
    assert_eq!(
        port.expired(deadline() + 1),
        1,
        "the unanswered call is swept"
    );
}

/// **VOICE-R4 residue: the served path frees every row it takes.** An answered call and a swept call
/// both leave the table — the wait AND its ending — and a session's teardown forgets whatever it
/// still had open. Before the port read the endings, every answered or swept call left an ending row
/// behind for a unit the served path does not have, and a finished session's entry was never removed.
#[test]
fn the_port_frees_every_row_it_answers_sweeps_or_closes() {
    let port = NodeCalls::new(Arc::new(OpenToolCalls::new()), keys());
    assert!(port.planned(7, "call_answered", 0));
    assert!(port.planned(7, "call_swept", 0));
    assert!(port.planned(8, "call_open", 0));
    assert_eq!(port.table().rows(), 3);

    assert_eq!(port.replied(7, "call_answered"), Ok(()));
    assert_eq!(
        port.table().rows(),
        2,
        "the answered call's row left with its wait"
    );

    assert_eq!(
        port.expired(deadline() + 1),
        2,
        "both remaining waits are past their deadline"
    );
    assert_eq!(
        port.table().rows(),
        0,
        "and the swept calls' endings were read, not left behind"
    );

    assert!(port.planned(8, "call_late", deadline() + 2));
    port.closed(8);
    assert_eq!(
        port.table().rows(),
        0,
        "a closed session forgets what it had open"
    );
    assert_eq!(
        port.replied(8, "call_late"),
        Err(ReplyRefusal::NoSuchSession),
        "and a reply for it answers nothing"
    );
}

/// A node allocator for the port under test: unique keys from 1, as the kernel's mint hands them.
fn keys() -> Box<dyn Fn() -> UnitKey + Send + Sync> {
    let next = std::sync::atomic::AtomicU64::new(1);
    Box::new(move || UnitKey::new(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}
