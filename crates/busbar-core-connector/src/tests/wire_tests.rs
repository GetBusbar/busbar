// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot fold's admission of a transport entry: an entry is admitted under its first claim, and
//! one that states no claim or names a transport it composes over is refused.

use super::*;
use crate::support::{Knobs, TestDoor};

#[test]
fn an_entry_is_admitted_under_its_first_claim() {
    let door = TestDoor::new("msg", &["msg", "msgs"], &[], Knobs::default());
    let wire = HostWire::new(&door).expect("an entry that names no layer is admitted");
    assert_eq!(wire.key(), "msg");
}

#[test]
fn an_entry_that_composes_over_a_layer_is_not_served_over_the_socket() {
    let door = TestDoor::new("over", &["over"], &["under"], Knobs::default());
    assert!(HostWire::new(&door).is_err());
}

#[test]
fn an_entry_that_states_no_claim_is_refused() {
    let door = TestDoor::new("nameless", &[], &[], Knobs::default());
    let refused = HostWire::new(&door).expect_err("an entry with no claim has no key");
    assert!(refused.contains("nameless"), "{refused}");
}

/// The Debug output names the wire and its key.
#[test]
fn debug_names_the_wire_and_its_key() {
    let wire = HostWire::new(&TestDoor::identity("bytes")).unwrap();
    let shown = format!("{wire:?}");
    assert!(shown.contains("HostWire"), "{shown}");
    assert!(shown.contains("bytes"), "{shown}");
}
