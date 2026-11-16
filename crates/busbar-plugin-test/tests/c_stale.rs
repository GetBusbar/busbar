// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STALE (ABI-MIN3-INTERFACE §14): A ChainBytes stashed and read after its chain.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use crate::bridge_fixture::{self as fx, Status};

/// A chain stashes its `ChainBytes` argument in a `static Mutex` and ends; a later chain of the same instance
/// reads the stash: FAULT StaleHandle, and the instance keeps serving.
#[test]
fn a_stashed_chainbytes_read_after_its_chain_faults() {
    let instance = fx::instance();
    assert_eq!(fx::done(&instance, b"stash"), Status::OK);
    assert_eq!(fx::done(&instance, b"read-stash"), Status::FAULT);
    let mut chain = fx::parked(&instance, b"secret");
    assert_eq!(
        fx::resume_secret(&mut chain, b"after", &mut fx::lease()),
        Some(Status::OK)
    );
}
