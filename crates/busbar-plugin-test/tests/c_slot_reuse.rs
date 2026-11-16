// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-REUSE (ABI-MIN3-INTERFACE §14): A freed slot is reused without crossing tokens.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::slots::{pack, unpack, Slots};

use crate::bridge_fixture::{self as fx, Status};

/// The table: a freed slot comes back from the free list under the next generation, so its old token misses
/// and the new occupant is never reached through it. The shim: two NEEDing chains in turn on one instance get the
/// same slot index and different tokens, and each answers its own value.
#[test]
fn a_freed_slot_is_reused_without_crossing_tokens() {
    let slots: Slots<&'static str> = Slots::new();
    let Some((index, generation)) = slots.insert("first") else {
        panic!("insert");
    };
    assert_eq!(slots.remove(index, generation), Some("first"));
    let Some((again, newer)) = slots.insert("second") else {
        panic!("insert");
    };
    assert_eq!(again, index, "the freed slot is reused");
    assert_ne!(newer, generation);
    assert_ne!(pack(false, again, newer), pack(false, index, generation));
    assert_eq!(
        slots.remove(index, generation),
        None,
        "the old token misses"
    );
    assert_eq!(slots.count_live(), 1);
    assert_eq!(slots.remove(again, newer), Some("second"));

    let instance = fx::instance();
    let mut first = fx::parked(&instance, b"secret");
    let first_token = first.token();
    let mut lease = fx::lease();
    assert_eq!(
        fx::resume_secret(&mut first, b"one", &mut lease),
        Some(Status::OK)
    );
    assert_eq!(fx::texts(&lease), [b"one".to_vec()]);
    drop(lease);
    let mut second = fx::parked(&instance, b"secret");
    let second_token = second.token();
    let (_, first_index, first_generation) = unpack(first_token);
    let (session, second_index, second_generation) = unpack(second_token);
    assert!(!session);
    assert_eq!(second_index, first_index, "the chain slot is reused");
    assert_ne!(
        second_generation, first_generation,
        "under a new generation"
    );
    let mut lease = fx::lease();
    assert_eq!(
        fx::resume_secret(&mut second, b"two", &mut lease),
        Some(Status::OK)
    );
    assert_eq!(fx::texts(&lease), [b"two".to_vec()]);
}
