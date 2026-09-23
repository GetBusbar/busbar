// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the push rate limiter in `pushback.rs`. Lifted out of the implementation file so
//! its line count measures implementation and nothing else; still a direct child module, so
//! `use super::*` reaches the private items it always did.

use super::*;

/// **THE FIXED WINDOW, DRIVEN DIRECTLY AGAINST AN INJECTED CLOCK — never a real sleep.**
///
/// `PushLimiter::admit` takes `now` as a plain argument (the same seam
/// `busbar_kernel::ratelimit::MutationLimiter::check` uses), so the window's roll is provable
/// without waiting on it: 60 pushes inside one window are admitted, the 61st inside that SAME
/// window is refused, and a `now` that has moved into the NEXT window admits again.
#[test]
fn sixty_per_task_per_window_then_denied_then_the_window_rolls() {
    let limiter = PushLimiter::new();
    let t = 1_000_000; // window-aligned enough (fixed windows key on now - now % 60)

    for i in 0..PUSH_RATE_LIMIT {
        assert!(
            limiter.admit("task-a", t),
            "push {i} of {PUSH_RATE_LIMIT} must be within the window's budget"
        );
    }
    assert!(
        !limiter.admit("task-a", t),
        "the 61st push inside one window must be refused"
    );
    // Still refused on a later ask within the SAME window — the limiter does not admit again
    // just because it was asked again.
    assert!(
        !limiter.admit("task-a", t + 1),
        "a second ask later in the SAME window must still be refused"
    );

    // A different task has its OWN untouched budget — the key is the task, not a shared
    // process-wide counter.
    assert!(
        limiter.admit("task-b", t),
        "a different task must have its own budget"
    );

    // AND THE WINDOW ROLLS: once `now` has moved a full window forward, the next request is
    // admitted again.
    assert!(
        limiter.admit("task-a", t + PUSH_RATE_WINDOW_SECS),
        "a new window must refill the budget"
    );
}

/// A REQUEST CARRYING AN OLDER CLOCK MUST NOT REFILL A SPENT BUDGET — the same regressed-clock
/// posture `MutationLimiter` is proved under, reproduced here for a task key.
#[test]
fn an_out_of_order_now_cannot_refill_a_spent_budget() {
    let limiter = PushLimiter::new();
    for i in 0..PUSH_RATE_LIMIT {
        assert!(limiter.admit("task-a", 120), "push {i} within the budget");
    }
    assert!(!limiter.admit("task-a", 120));
    // Some OTHER task, judged at an EARLIER `now`. This must not rewind the live window.
    let _ = limiter.admit("task-b", 60);
    assert!(
        !limiter.admit("task-a", 120),
        "a request from an earlier window must not wipe task-a's live counter"
    );
    let _ = limiter.admit("task-b", 0);
    assert!(
        !limiter.admit("task-a", 120),
        "an unreadable wall clock read as 0 must not wipe task-a's live counter"
    );
}
