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
