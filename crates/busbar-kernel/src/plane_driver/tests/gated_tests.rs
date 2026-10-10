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
/// entry, or one where `arrive` named none, refuses the unit; the same entry is bound. A pool's unit
/// binds the member its projection names; a projection with no entry and no body binds nothing.
#[test]
fn the_gates_bind_over_the_recorded_entry_and_a_projection_naming_another_is_refused() {
    use super::bound_entry;
    use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL};
    let named = |entry: &str| super::Projection {
        pool: entry.to_string(),
        projected: Some(b"{}".to_vec()),
        ..super::Projection::default()
    };
    let (files, shell, none) = (named("files"), named("shell"), named(""));
    assert_eq!(
        bound_entry(Some(b"files"), ROUTE_DIRECT, &files).ok(),
        Some(Some("files"))
    );
    assert_eq!(bound_entry(None, ROUTE_LOCAL, &none).ok(), Some(Some("")));
    assert!(
        bound_entry(Some(b"files"), ROUTE_DIRECT, &shell).is_err(),
        "a projection naming another entry bound that entry's gates"
    );
    assert!(
        bound_entry(None, ROUTE_LOCAL, &shell).is_err(),
        "a projection naming an entry arrive never named bound that entry's gates"
    );
    assert!(
        bound_entry(None, ROUTE_POOL, &shell).is_err(),
        "a pool route naming no pool bound the projection's entry"
    );
    assert_eq!(
        bound_entry(Some(b"pair"), ROUTE_POOL, &files).ok(),
        Some(Some("files")),
        "a pool's unit binds the member its projection names"
    );
    assert_eq!(
        bound_entry(Some(b"files"), ROUTE_DIRECT, &super::Projection::default()).ok(),
        Some(None),
        "a projection with no entry and no body has nothing to screen"
    );
}
