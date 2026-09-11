// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the admitted-identity handle table (`crate::admitted`).
//!
//! The host-vtable's inbound-admission slot had no battery over the handle discipline itself: its
//! two tests drove the whole auth chain end to end and could not distinguish "the handle round
//! trips" from "the chain admits". These pin the discipline on its own.

use crate::admitted::Admitted;

/// The round trip: a stashed value comes back as the SAME value, through a handle that is never the
/// reserved none-handle.
#[test]
fn a_stashed_identity_comes_back_through_its_handle() {
    let table: Admitted<String> = Admitted::new();
    let handle = table.stash("principal:alice".to_string());
    assert_ne!(
        handle,
        Admitted::<String>::NONE,
        "a live handle is never the reserved none-handle"
    );
    assert_eq!(
        table.take(handle),
        Some("principal:alice".to_string()),
        "the handle recovers the exact value the admission produced"
    );
}

/// SINGLE USE IS THE DISCIPLINE: the second presentation of a handle is unknown, not a second
/// admission. A replayed handle and a forged one read the same way, which is the fail-closed
/// reading — an admission that cannot be recovered is an admission that did not happen.
#[test]
fn a_handle_answers_once_and_a_replay_is_refused() {
    let table: Admitted<u32> = Admitted::new();
    let handle = table.stash(7);
    assert_eq!(table.take(handle), Some(7), "the first consume recovers it");
    assert_eq!(
        table.take(handle),
        None,
        "the same handle presented again names no admission"
    );
}

/// The reserved handle names nothing, so a zeroed or defaulted field cannot accidentally name a
/// live admission — and neither can a handle this table never minted.
#[test]
fn the_none_handle_and_an_unminted_handle_both_name_nothing() {
    let table: Admitted<u32> = Admitted::new();
    let _live = table.stash(1);
    assert_eq!(
        table.take(Admitted::<u32>::NONE),
        None,
        "the reserved none-handle names no admission"
    );
    assert_eq!(
        table.take(u64::MAX),
        None,
        "a handle this table never minted names no admission"
    );
}

/// Handles are distinct per admission: two admissions in flight recover their OWN identity, never
/// each other's. A table that reused a handle would let one session be served as another.
#[test]
fn two_admissions_in_flight_recover_their_own_identity() {
    let table: Admitted<&'static str> = Admitted::new();
    let a = table.stash("alice");
    let b = table.stash("bob");
    assert_ne!(a, b, "each admission gets its own handle");
    assert_eq!(table.take(b), Some("bob"));
    assert_eq!(table.take(a), Some("alice"));
}
