// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE-POLICY TRANSPARENCY FIELDS WITH THE OPERATOR'S SWITCH OFF (the default:
//! `advanced.response_headers.route_policy` unset), on the driver: the door serving the `pools`
//! map, its hook stage bound, the hook parity suite's rig. The switch is a process-wide setting made
//! once at boot, so this binary never turns it on; its twin `route_policy_headers_on` turns it on.
//! Between them the four combinations of the switch and a policy that chose the member are each
//! pinned.
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

use busbar_kernel::proxy::{route_policy_headers_enabled, HDR_ROUTE_POLICY, HDR_ROUTE_TARGET};
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

/// Ports legacy `wire_tests.rs::route_policy_headers_suppressed_when_outer_gate_disabled_even_with_a_policy_name`:
/// with the switch off, even a member a named policy chose carries neither route field.
#[tokio::test]
async fn with_the_switch_off_even_a_policy_chosen_member_carries_no_route_field() {
    assert!(
        !route_policy_headers_enabled(),
        "the switch is off by default"
    );
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
        "the policy did choose the member, so only the switch keeps the fields off"
    );
    assert_eq!(field(&answer, HDR_ROUTE_POLICY), None);
    assert_eq!(field(&answer, HDR_ROUTE_TARGET), None);
}

/// Ports legacy `wire_tests.rs::route_policy_headers_absent_when_both_gates_closed`: with the switch
/// off and no policy choosing, nothing is emitted.
#[tokio::test]
async fn with_the_switch_off_and_no_policy_nothing_is_emitted() {
    assert!(!route_policy_headers_enabled());
    let rig = Rig::new(pool(), None, Hooks::default());
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(field(&answer, HDR_ROUTE_POLICY), None);
    assert_eq!(field(&answer, HDR_ROUTE_TARGET), None);
}
