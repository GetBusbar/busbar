// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::KindCode;

use super::door_both_ways as both;
use crate::both_ways::transport_fixture::linked as shipped;
use crate::both_ways::{fixture, fixture_cdylib};
use crate::conformance::{self, Subject};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{load_dropped, load_linked, LinkedRow, LoadError};

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
    Subject::new(shipped::door, fixture("transport").1, INPUTS)
}

#[test]
fn a_linked_and_a_dropped_in_carrier_carry_identically() {
    let _ = fixture_cdylib("transport");
    conformance::both_ways(&subject());
}

#[test]
fn a_miscount_is_seen() {
    conformance::red_count(&subject());
}

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let door = shipped::door;
    let want = (KindCode::Transport, KindCode::Hook);
    let row = LinkedRow::of(door).expect("the door states itself");
    let linked = both::linked::<Transport>(door);
    match load_linked::<Hook>(&row, both::bind(&linked.dispatcher)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    let path = fixture_cdylib("transport");
    match load_dropped::<Hook>(&path, &row.statement, both::bind(&linked.dispatcher)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}
