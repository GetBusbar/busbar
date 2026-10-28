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

/// F25 row 218: rehomed from the retired engine crate's src/engine/tests/gate_policy_503_literals_tests.rs::
/// the_refusal_literal_is_the_shared_constant. The refusal a failed load-bearing hook produces is
/// ONE constant at 1.5.5's literal and status, and the gate-first stage serves it as it is, so the
/// two seats cannot drift into two different client-visible refusals.
#[test]
fn the_refusal_literal_is_the_shared_constant() {
    const GATE_COULD_NOT_COMPLETE: &str =
        "A required gate could not complete. Please retry shortly.";
    assert_eq!(GATE_COULD_NOT_COMPLETE, REQUIRED_HOOK_UNAVAILABLE_MESSAGE);
    assert_eq!(503, REQUIRED_HOOK_UNAVAILABLE_STATUS);
    assert_eq!(
        rewrite_refusal(503, GATE_COULD_NOT_COMPLETE),
        (503, GATE_COULD_NOT_COMPLETE.to_string()),
        "the gate-first stage serves the shared refusal unchanged"
    );
}

/// RED (Q128 p21#4; THE DESIGN §11.7, the hook view's `ingress_protocol`): the gate-first binder
/// names the plane's dialects, so a gate-first unit's in-session hooks are told the dialect it
/// arrived in and its access amendments record it as the op, as its screen does. Before the fix
/// the binder took the trait default and every in-session hook was told an empty dialect.
#[test]
fn the_gate_first_binder_names_the_dialect_a_unit_arrived_in() {
    use super::super::HookBinder;
    let host: super::GenerationHost =
        std::sync::Arc::new(|| -> std::sync::Arc<dyn crate::plane_driver::EngineHost> {
            unreachable!("naming a dialect reads no generation")
        });
    let binder = super::HostGatedHooks {
        host,
        plane_key: "plane-a".to_string(),
        keys: std::sync::Arc::new(
            |_: &str| -> Option<std::sync::Arc<busbar_contract::records::VirtualKey>> { None },
        ),
        dialects: vec!["dialect-0".to_string(), "dialect-1".to_string()],
    };
    assert_eq!(binder.dialect(1), "dialect-1");
    assert_eq!(binder.dialect(0), "dialect-0");
    assert_eq!(
        binder.dialect(9),
        "",
        "an index past the plane's dialects names none"
    );
}
