// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LEAK (ABI-MIN3-INTERFACE §14): A `Box::leak` handle used from a later chain and from a sync call.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use crate::bridge_fixture::{self as fx, Describe, Status};

/// A chain leaks its `ChainBytes` (`Box::leak`) into a static; a later chain and a sync crossing (the describe
/// entry) each read it: FAULT StaleHandle both times.
#[test]
fn a_leaked_handle_used_later_faults() {
    let instance = fx::instance();
    assert_eq!(fx::done(&instance, b"leak"), Status::OK);
    assert_eq!(fx::done(&instance, b"read-leak"), Status::FAULT);
    assert_eq!(fx::describe(Describe::ReadLeaked), Status::FAULT);
    assert_eq!(fx::describe(Describe::Plain), Status::OK);
}
