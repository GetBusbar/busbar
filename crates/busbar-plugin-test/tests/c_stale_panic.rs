// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STALE-PANIC (ABI-MIN3-INTERFACE §14): A stash after a panic mid-poll FAULTs StaleHandle; CURRENT is restored;
//! the negative controls must be red.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use crate::bridge_fixture::{self as fx, Describe, Status};

/// Chain X stashes its `ChainBytes` and panics mid-poll (FAULT). Afterwards, on the same thread: a sync crossing
/// that reads the stash FAULTs StaleHandle; a sync crossing that polls a Need future FAULTs NeedOutsideAsync (the
/// bridge's CURRENT was restored on unwind, so no dead chain's mail is reachable); a later chain of X's instance
/// that reads the stash FAULTs StaleHandle (the second panic, from a stale read); and a fresh chain still works.
///
/// The round-13 negative controls (a bridge built with bare stores instead of the guard must fail this case;
/// a sync entry makes zero abi thread-local accesses) need a test-only build of busbar-ffi's poll and are not
/// in this arm; the guard's restore on unwind is also pinned by `bridge::tests` in busbar-plugin-abi.
#[test]
fn a_stale_stash_after_a_panic_faults() {
    let instance = fx::instance();
    assert_eq!(fx::done(&instance, b"stash-panic"), Status::FAULT);
    assert_eq!(fx::describe(Describe::ReadPanicked), Status::FAULT);
    assert_eq!(fx::describe(Describe::PollNeed), Status::FAULT);
    assert_eq!(fx::done(&instance, b"read-panicked"), Status::FAULT);
    let other = fx::instance();
    let mut chain = fx::parked(&other, b"secret");
    assert_eq!(
        fx::resume_secret(&mut chain, b"fresh", &mut fx::lease()),
        Some(Status::OK)
    );
}
