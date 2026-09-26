// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The plane composes its own open-call table.** Its own binary, because the table behind the
//! served door is set once per process: a cell sharing a test binary with the plane's other
//! composition cells would race them for the first write.

#![cfg(feature = "runtime")]

/// After this plane's compose step, the served door binds every session it opens to the node's
/// table, two sessions are told apart before either has a call open, and a second compose is a
/// no-op rather than a silent swap of the table live sessions are keyed into.
#[test]
fn the_planes_compose_step_governs_every_served_session() {
    assert!(
        busbar_voice::mount::served_governed_session().is_none(),
        "before the compose step nothing is bound"
    );
    assert!(
        busbar_voice::mount::compose_node_calls(),
        "the plane's compose step writes the table"
    );
    assert!(
        !busbar_voice::mount::compose_node_calls(),
        "and a second compose never swaps it"
    );
    let bound = busbar_voice::mount::served_governed_session()
        .expect("after the compose step, every session the door opens is bound to a table");
    let next = busbar_voice::mount::served_governed_session().expect("and so is the next one");
    assert_ne!(
        bound.session, next.session,
        "two conversations are told apart before either has a call open"
    );
    assert!(
        bound.calls.planned(bound.session, "call_aaa", 0),
        "the table enters a planned client-served leg"
    );
    assert_eq!(
        next.calls.replied(next.session, "call_aaa"),
        Err(busbar_voice::runtime::ReplyRefusal::NoSuchSession),
        "and keys it by the session that planned it: the same identifier on another session wakes nothing"
    );
    assert_eq!(bound.calls.replied(bound.session, "call_aaa"), Ok(()));
}
