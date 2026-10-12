// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: transport`, BOTH WAYS, THROUGH THE ONE DISPATCHER, OVER THE SHIPPED DOOR** (TODO
//! ABI-b4 for the transport kind; M6/contract: exact crossing counts).
//!
//! The subject is the shipped plugin of the table's `transport` row, not a fixture: its door LINKED (the
//! `linked::door` a busbar build holds, reached by KIND through the both-ways table's `transport`
//! row) and DROPPED IN (the row's pinned cdylib, the same lookup every extracted plugin's dropped leg
//! uses). That row is a CARRIER (TRANSPORT-STACK (2): a carrier listens, accepts, dials, reads,
//! writes and closes over the host's `io.*`; framing is a framer's), so the script it is driven
//! through is the published suite's carrier script (`conformance::carrier`) — the one the plugin's own
//! repo runs: every framer op REFUSED; a listen and an accept that the host admitted; a dial to an
//! echoing far end, frames exchanged, a read with nothing to read pending and resumed when the host
//! wakes it; shut twice; a dial the host did not admit REFUSED by the host; close, and a dial after
//! it a FAULT.
//!
//! Two things are compared, by the suite's own comparators: the FOLDS (every step's answer, line for
//! line, linked against dropped in), and the CROSSINGS (every step's count the dispatcher made is the
//! count the step pins, exactly; "greater than zero" would pass a leg that swallowed or duplicated an
//! op).
//!
//! RED ARMS, KEPT: the door asked for as another kind is refused on both legs
//! ([`the_door_asked_for_as_another_kind_is_refused_both_ways`]); a count moved by one at any step,
//! or doubled, is seen ([`a_miscount_is_seen`]).

use busbar_contract::abi::mechanism::KindCode;

use super::door_both_ways as both;
use crate::both_ways::transport_linked as shipped;
use crate::both_ways::{hot_cdylib, HOT_FIXTURES};
use crate::conformance::{self, Subject};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{load_dropped, load_linked, LinkedRow, LoadError};

/// The carrier's inputs: it listens, it dials an authority, one exchange, one pending read.
const INPUTS: &str = r#"{
  "settings": {},
  "transport": {
    "carrier": {
      "listen": true,
      "dial": "authority",
      "exchange": [
        { "write": "to the far side", "read": "to the far side" }
      ],
      "pending": { "write": "again", "read": "again" }
    }
  }
}"#;

fn subject() -> Subject {
    let (_, krate) = HOT_FIXTURES
        .iter()
        .find(|(k, _)| *k == "transport")
        .expect("the both-ways table has a transport row");
    Subject::new(shipped::door, krate, INPUTS)
}

#[test]
fn a_linked_and_a_dropped_in_carrier_carry_identically() {
    // The dropped-in leg's library is the row's: a missing one is a failure, never a skip.
    let _ = hot_cdylib("transport");
    conformance::both_ways(&subject());
}

/// THE RED ARM, KEPT: the count rule is not vacuous. A step's count moved by one, at any step, or
/// every count doubled, is refused.
#[test]
fn a_miscount_is_seen() {
    conformance::red_count(&subject());
}

/// THE RED ARM, KEPT: the row's door is a transport. Asked for as a hook it is refused, linked (by the
/// door's own kind) and dropped in (by the stated kind, before the library is opened).
#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let door = shipped::door;
    let want = (KindCode::Transport, KindCode::Hook);
    let row = LinkedRow::of(door).expect("the door states itself");
    let linked = both::linked::<Transport>(door);
    match load_linked::<Hook>(&row, both::bind(&linked.dispatcher)) {
        Err(LoadError::WrongKind { door, want: asked }) => assert_eq!((door, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    let path = hot_cdylib("transport");
    match load_dropped::<Hook>(&path, &row.statement, both::bind(&linked.dispatcher)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}
