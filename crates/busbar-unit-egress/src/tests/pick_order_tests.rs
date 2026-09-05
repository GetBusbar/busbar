// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick order, and where a member is excluded from it.
//!
//! Carried over from the previous release's ordered-walk tests. The claims are the same ones: a
//! ranking is honoured but never over an unhealthy or drained member; an unranked member is
//! lowest priority and still reachable; session affinity is a preference that drain overrides;
//! and the one member that consumes a turn of the rotation is the one that was at capacity.

use super::harness::Health;
use super::{member, Node};
use crate::ports::Unavailable;
use crate::select::RequestCtx;
use busbar_contract::DestinationId;

fn three_lanes() -> (Node, Vec<crate::pool::Member>) {
    let node = Node::with_lanes(&["a", "b", "c"]);
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
        member(DestinationId::new(2), "c"),
    ];
    (node, members)
}

#[test]
fn a_ranking_takes_its_first_healthy_choice() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(2));
}

#[test]
fn a_ranking_walks_past_a_suppressed_preferred_member() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(0));
}

#[test]
fn a_ranking_walks_past_a_member_this_request_already_tried() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    ctx.exclude(DestinationId::new(2));
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(0));
}

#[test]
fn a_ranking_that_covers_only_unhealthy_members_falls_through_to_the_floor() {
    let (mut node, members) = three_lanes();
    // The ranking names only the suppressed member; the other two are healthy and unranked.
    node.preference = Some(vec![DestinationId::new(2)]);
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert!(
        picked.destination == DestinationId::new(0) || picked.destination == DestinationId::new(1),
        "an unranked member is lowest priority but never stranded"
    );
}

#[test]
fn an_empty_ranking_is_the_plain_floor() {
    let (mut node, members) = three_lanes();
    node.preference = Some(Vec::new());
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_some());
}

#[test]
fn a_ranking_never_selects_a_drained_member() {
    let (mut node, mut members) = three_lanes();
    members[2].weight = 0;
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_ne!(
        picked.destination,
        DestinationId::new(2),
        "weight zero is the operator's drain signal and no path may defeat it"
    );
}

#[test]
fn a_fully_drained_pool_selects_nothing() {
    let (node, mut members) = three_lanes();
    for m in &mut members {
        m.weight = 0;
    }
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
}

#[test]
fn session_affinity_never_pins_to_a_drained_member() {
    let (mut node, mut members) = three_lanes();
    members[0].weight = 0;
    // A hash that lands on position zero, which is the drained member.
    node.affinity = Some(3);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_ne!(
        picked.destination,
        DestinationId::new(0),
        "a session whose hash lands on a drained member must not keep pinning to it"
    );
}

#[test]
fn session_affinity_is_offered_first() {
    let (mut node, members) = three_lanes();
    node.affinity = Some(1);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(1));
}

#[test]
fn a_member_at_capacity_is_recorded_as_such() {
    let (node, members) = three_lanes();
    for destination in 0..3 {
        node.capacity
            .set_ceiling(DestinationId::new(destination), 1);
    }
    let held: Vec<_> = (0..3)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    let reasons = ctx.excluded_reasons();
    assert_eq!(reasons.len(), 3, "every member was passed over");
    assert!(reasons
        .iter()
        .all(|(_, why)| matches!(why, Unavailable::AtCapacity { .. })));
    drop(held);
}

#[test]
fn a_suppressed_member_is_recorded_with_its_own_reason() {
    let (node, members) = three_lanes();
    for destination in 0..3 {
        node.breaker.set(
            DestinationId::new(destination),
            Health {
                cooldown: 42,
                ..Health::default()
            },
        );
    }
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert!(ctx
        .excluded_reasons()
        .iter()
        .all(|(_, why)| matches!(why, Unavailable::BreakerOpen { .. })));
}

#[test]
fn only_a_member_at_capacity_spends_a_turn_of_the_rotation() {
    // Two members. One is suppressed, so it is filtered before the rotation and can never spend a
    // turn; the other is at capacity, so it is selected and only then refused, which is what
    // spends one. The proof is that the healthy-but-busy member is the ONLY one the admission was
    // ever asked about.
    let node = Node::with_lanes(&["a", "b"]);
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held = node.capacity.saturate(DestinationId::new(1));

    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert_eq!(
        node.breaker.pick_order(),
        vec![DestinationId::new(1)],
        "the suppressed member was excluded before the rotation, never selected and refused"
    );
    assert_eq!(
        ctx.excluded_reasons(),
        &[(
            DestinationId::new(1),
            Unavailable::AtCapacity {
                drain_hint_ms: None
            }
        )]
    );
    drop(held);
}

#[test]
fn a_deadline_far_in_the_future_does_not_overflow() {
    let ctx = RequestCtx::new(u64::MAX, u64::MAX - 1, u128::MAX - 1);
    assert!(ctx.expired(u64::MAX));
    assert_eq!(ctx.remaining_secs(u64::MAX), 0);
}
