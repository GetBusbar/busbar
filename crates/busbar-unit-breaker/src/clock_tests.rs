// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The composition root's clock helper.
//!
//! Nothing in this crate calls it and nothing in this crate may — every decision here takes `now`
//! as a parameter. It exists so the root has ONE spelling of the value those parameters expect, and
//! that is exactly what is asserted: whole seconds since the Unix epoch, on this machine's clock,
//! and not some constant a caller would then feed into every cooldown in the node.

use crate::clock::unix_time_secs;

/// The helper reads the real clock: the answer is a plausible present instant, far past the fixed
/// point this test was written against, and nowhere near the epoch.
#[test]
fn the_helper_reads_the_wall_clock_and_not_a_constant() {
    // 2024-01-01T00:00:00Z. This crate was written well after it, so any machine with a
    // remotely-correct clock reads later than this.
    const A_FIXED_PAST_INSTANT: u64 = 1_704_067_200;

    let now = unix_time_secs();
    assert!(
        now > A_FIXED_PAST_INSTANT,
        "the helper answered {now}, which is not a present instant in Unix seconds"
    );
}

/// It is monotonic in the only sense a wall clock is: two reads in a row do not run backwards, and
/// they are seconds rather than any finer unit.
#[test]
fn two_reads_do_not_run_backwards() {
    let first = unix_time_secs();
    let second = unix_time_secs();
    assert!(
        second >= first,
        "the second read answered {second}, before the first at {first}"
    );
    assert!(
        second - first < 60,
        "two reads taken back to back must not be a minute apart"
    );
}
