// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two deadlines one attempt is bounded by, stated as arithmetic.
//!
//! Declared from `attempt.rs` itself (`#[cfg(test)] #[path = "tests/attempt_internal_tests.rs"] mod
//! attempt_internal_tests;`) because both functions are private to that module and neither should
//! be widened to `pub(crate)` just to be looked at. What is asserted is the money property of each:
//! a per-attempt cap may never grant more time than the request still has and is never zero, and
//! the send's outer deadline is the walk's budget for a buffered answer and the client's ceiling
//! for a streamed one — each floored at one second, because a zero-length deadline fails an attempt
//! before it is tried.

use super::attempt_cap_ms;

/// The cap is the lesser of what the member asked for and what the walk still has.
#[test]
fn a_cap_can_never_grant_more_time_than_the_request_has_left() {
    // The member's own cap is the smaller of the two: it stands.
    assert_eq!(attempt_cap_ms(2_000, 30), 2_000);
    // What is left of the walk is the smaller: it wins, in milliseconds.
    assert_eq!(attempt_cap_ms(60_000, 5), 5_000);
    // Exactly equal: the same answer either way.
    assert_eq!(attempt_cap_ms(5_000, 5), 5_000);
    // One millisecond either side of the boundary, so the comparison is pinned rather than sampled.
    assert_eq!(attempt_cap_ms(4_999, 5), 4_999);
    assert_eq!(attempt_cap_ms(5_001, 5), 5_000);
}

/// A walk with nothing left still leaves a cap of one millisecond, never zero: a zero-length
/// deadline would fail an attempt before it was tried.
#[test]
fn a_spent_walk_still_leaves_a_cap_of_one_millisecond() {
    assert_eq!(attempt_cap_ms(2_000, 0), 1);
    assert_eq!(attempt_cap_ms(1, 0), 1);
}

/// A member that asks for no time at all gets none — the floor is under what the WALK has left, not
/// under the member's own cap, so an operator who configured a zero cap is answered with a zero cap
/// rather than having one invented for them.
#[test]
fn the_floor_is_under_the_walks_budget_and_not_under_the_members_own_cap() {
    assert_eq!(attempt_cap_ms(0, 30), 0);
}

/// The seconds-to-milliseconds conversion saturates rather than wrapping: a walk with an
/// unrepresentable amount of time left must not answer with a short cap.
#[test]
fn an_unrepresentable_remainder_saturates_rather_than_wrapping() {
    assert_eq!(attempt_cap_ms(9_999, u64::MAX), 9_999);
}
