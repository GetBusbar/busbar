// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gate-first stage's rewrite refusal (SEAM-L(q)).

use super::rewrite_refusal;
use crate::hooks::{REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS};

/// SEAM-L(q): a panicking `on_error: reject` hook is the seam's own failed verdict and answers
/// predev's 503 with the shared words (RED: clamped to 403); a hook's own out-of-range status
/// is still clamped, and its own 503 with other words is a hook-chosen status, clamped.
#[test]
fn the_seams_own_failed_verdict_keeps_its_503_and_a_hook_status_is_clamped() {
    assert_eq!(
        rewrite_refusal(
            REQUIRED_HOOK_UNAVAILABLE_STATUS,
            REQUIRED_HOOK_UNAVAILABLE_MESSAGE
        ),
        (
            REQUIRED_HOOK_UNAVAILABLE_STATUS,
            REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string()
        )
    );
    assert_eq!(rewrite_refusal(503, "mine").0, 403);
    assert_eq!(rewrite_refusal(200, "ok").0, 403);
    assert_eq!(rewrite_refusal(429, "slow").0, 429);
}

/// THE GATES ARE BOUND OVER THE ENTRY THE KERNEL RECORDED (audit kernel-K2 leftover A4): the entry
/// the plane's `arrive` named at decode, never the plane's later word. A projection naming another
/// entry, or one where `arrive` named none, refuses the unit; the same entry is bound.
#[test]
fn the_gates_bind_over_the_recorded_entry_and_a_projection_naming_another_is_refused() {
    use super::recorded_entry;
    assert_eq!(recorded_entry(Some(b"files"), "files").ok(), Some("files"));
    assert_eq!(recorded_entry(None, "").ok(), Some(""));
    assert!(
        recorded_entry(Some(b"files"), "shell").is_err(),
        "a projection naming another entry bound that entry's gates"
    );
    assert!(
        recorded_entry(None, "shell").is_err(),
        "a projection naming an entry arrive never named bound that entry's gates"
    );
}
