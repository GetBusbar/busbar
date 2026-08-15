// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for metering attribution.
//!
//! Most of these check what busbar does NOT claim. That is the unusual half and it is the half
//! that gets quietly lost: a number reported for something nobody measured reads exactly like a
//! number for something somebody did.

use super::*;

#[test]
fn a_received_task_bills_the_presenting_key_and_its_downstream_l2_spend_too() {
    // busbar owns both altitudes here: the fronted agent's MCP tool calls are busbar's OWN traffic,
    // governed by busbar's key/budget/policy plane one level down, so the same key pays for them.
    let a = Attribution::receiving("k-caller", "planner", "ctx-1", "task-1");
    assert_eq!(a.direction, Direction::Receiving);
    assert_eq!(a.billed_key_id, "k-caller");
    assert_eq!(a.agent_id, "planner");
    assert_eq!(a.target_agent_id, None);
    assert!(a.covers_downstream_l2_spend);
    assert!(!a.covers_callee_internal_spend);
}

#[test]
fn a_delegation_bills_the_initiating_key_for_the_hop_and_claims_nothing_beyond_it() {
    // THE CHAIN TERMINATES AT THE HOP. busbar records who delegated, to which registered agent,
    // under which context, with what outcome. What the callee then spends on its own tools and
    // models is the vendor's plane and never touches busbar.
    let a = Attribution::delegating(
        "k-caller",
        "planner",
        "vendor-researcher",
        "ctx-1",
        "task-2",
    );
    assert_eq!(a.direction, Direction::Delegating);
    assert_eq!(
        a.billed_key_id, "k-caller",
        "the INITIATING key, not a synthetic identity for the fronted agent: a hop billed to the \
         agent is a hop nobody's budget constrains"
    );
    assert_eq!(a.agent_id, "planner");
    assert_eq!(a.target_agent_id.as_deref(), Some("vendor-researcher"));
    assert!(
        !a.covers_downstream_l2_spend,
        "busbar made ONE hop; there is no downstream L2 traffic of busbar's own on this arm"
    );
    assert!(!a.covers_callee_internal_spend);
}

#[test]
fn nothing_can_construct_an_attribution_that_claims_the_callees_internal_spend() {
    // The asymmetry is a property of the TYPE rather than a sentence in a document. Both
    // constructors are exercised, and there is no third.
    for a in [
        Attribution::receiving("k", "planner", "ctx", "t"),
        Attribution::delegating("k", "planner", "vendor", "ctx", "t"),
    ] {
        assert!(
            !a.covers_callee_internal_spend,
            "a gateway that reported a number for what happens inside a black box would be \
             reporting a guess"
        );
    }
}

#[test]
fn the_context_id_is_the_grouping_key_on_both_arms() {
    // `contextId` is what groups related tasks into a session, and it is busbar's metering
    // attribution and provenance key. Two tasks in one session must carry the same one.
    let first = Attribution::receiving("k", "planner", "ctx-7", "task-a");
    let second = Attribution::delegating("k", "planner", "vendor", "ctx-7", "task-b");
    assert_eq!(first.context_id, second.context_id);
    assert_ne!(first.task_id, second.task_id);
}

#[test]
fn an_unlimited_key_is_always_admitted() {
    assert_eq!(admit(1_000_000, None, 60), Admission::Admit);
    assert!(admit(1_000_000, None, 60).status().is_none());
}

#[test]
fn reaching_the_limit_is_over_it_and_the_refusal_carries_a_retry_after() {
    // An operator who wrote the number they consider unacceptable did not mean "one more than
    // this".
    assert_eq!(admit(9, Some(10), 45), Admission::Admit);
    assert_eq!(
        admit(10, Some(10), 45),
        Admission::OverLimit {
            retry_after_secs: 45
        }
    );
    assert_eq!(admit(11, Some(10), 45).status(), Some(429));
}

#[test]
fn a_retry_after_is_never_zero() {
    // `Retry-After: 0` invites an immediate retry, which is a client-side hot loop pointed at a
    // gateway that just said no.
    assert_eq!(
        admit(10, Some(10), 0),
        Admission::OverLimit {
            retry_after_secs: 1
        }
    );
}

#[test]
fn a_zero_limit_admits_nothing() {
    assert_eq!(
        admit(0, Some(0), 30),
        Admission::OverLimit {
            retry_after_secs: 30
        }
    );
}
