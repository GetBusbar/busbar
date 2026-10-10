// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-LINKED ROSTER, witnessed. `tests/linked/mod.rs` is how every cross-plane test here
//! gets real planes without naming one; these two arms prove the mechanism is not vacuous:
//!
//! - GREEN: every crate in `[package.metadata.busbar] test-linked` registers exactly one plane, so
//!   the registry the tests address holds as many planes as the manifest lists.
//! - RED: an address no linked plane answers refuses, naming what was asked for and the manifest
//!   list — so a test addressed at a plane that is not test-linked fails, never passes over an
//!   empty roster.

mod linked;

#[test]
fn every_test_linked_crate_registers_one_plane() {
    let keys: Vec<&str> = linked::planes().iter().map(|d| d.key).collect();
    assert_eq!(
        keys.len(),
        linked::linked_count(),
        "each test-linked crate registers exactly one plane: {keys:?}"
    );
    let mut dedup = keys.clone();
    dedup.sort_unstable();
    dedup.dedup();
    assert_eq!(dedup.len(), keys.len(), "plane keys are distinct: {keys:?}");
}

/// THE RED ARM: address a section no linked plane declares. The lookup must refuse, and the refusal
/// must say where the linked list lives.
#[test]
#[should_panic(expected = "no test-linked plane declares the `no-such-section:` config section")]
fn an_address_no_linked_plane_answers_refuses() {
    let _ = linked::owning("no-such-section");
}
