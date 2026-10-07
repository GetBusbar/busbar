// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE-POLICY TRANSPARENCY FIELDS WITH THE OPERATOR'S SWITCH ON (`advanced.response_headers.
//! route_policy: true`), on the driver: the door serving the `pools` map, its hook stage bound,
//! the hook parity suite's rig. The switch is a process-wide setting made once at boot, so this
//! binary turns it on and never off; its twin `route_policy_headers_off` never turns it on. Between
//! them the four combinations of the switch and a policy that chose the member are each pinned.
//!
//! Built wherever the plane serving the `pools` map is linked (its row rides the node axis:
//! `linked_axis_node`).

#![cfg(linked_axis_node)]

// The linked plane doors (`LINKED_PLANE_DOORS`), generated from the manifest.
include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

#[path = "../../../busbar-kernel/tests/common/mod.rs"]
mod common;

#[allow(dead_code)]
#[path = "../hook_parity_driver/policies.rs"]
mod policies;

#[allow(dead_code)]
#[path = "../hook_parity_driver/rig.rs"]
mod rig;

use busbar_kernel::proxy::{configure_route_policy_headers, HDR_ROUTE_POLICY, HDR_ROUTE_TARGET};
use policies::{canned_gate, Canned};
use rig::{member, Answered, Hooks, Pool, Rig};

fn pool() -> Pool {
    Pool {
        name: "p",
        members: vec![member("lane-a", "alpha"), member("lane-b", "beta")],
    }
}

fn chat_body() -> serde_json::Value {
    serde_json::json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    })
}

/// The value of the answer's field `name`, if it carries one.
fn field(answer: &Answered, name: &str) -> Option<String> {
    answer
        .fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
}

/// Ports legacy `wire_tests.rs::route_policy_headers_present_only_when_both_gates_open`: with the
/// switch on and a policy that chose the member, the answer carries the policy's name and the
/// member it chose.
#[tokio::test]
async fn with_the_switch_on_a_policy_chosen_member_names_the_policy_and_the_member() {
    configure_route_policy_headers(true);
    let rig = Rig::new(
        pool(),
        None,
        Hooks {
            gates: vec![(0, canned_gate(Canned::Order(vec![1]), "cheapest"))],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "beta",
        "the policy's order chose the member"
    );
    assert_eq!(
        field(&answer, HDR_ROUTE_POLICY).as_deref(),
        Some("cheapest")
    );
    assert_eq!(field(&answer, HDR_ROUTE_TARGET).as_deref(), Some("lane-b"));
}

/// Ports legacy `wire_tests.rs::route_policy_headers_absent_for_a_default_policy_even_when_outer_gate_enabled`:
/// with the switch on, a member the default weighted walk chose (no policy named it) carries no
/// route field: the default path stays free of them whatever the operator opted into.
#[tokio::test]
async fn with_the_switch_on_a_member_no_policy_chose_carries_no_route_field() {
    configure_route_policy_headers(true);
    let rig = Rig::new(pool(), None, Hooks::default());
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(field(&answer, HDR_ROUTE_POLICY), None);
    assert_eq!(field(&answer, HDR_ROUTE_TARGET), None);
}
