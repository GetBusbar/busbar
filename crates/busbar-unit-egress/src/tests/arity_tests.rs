// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arity posture on the pick: how many of the fitting candidates a binding admits.
//!
//! `Any` is every pool that has ever shipped — several members may serve and the pick chooses
//! between them, exactly as before. `One` is the other honest posture: the binding declares that
//! exactly one candidate may serve, so a fitting set of more than one is an ambiguity the walk
//! refuses rather than resolves by guessing. The refusal names the ambiguous candidates for the
//! AUDIT step and names no amount; it is the contract's own [`busbar_contract::decide_arity`] the
//! pick consults, so both sides read one decision.

use super::harness::Health;
use super::{member, Node};
use crate::pool::Arity;
use crate::wire::{RouteOutcome, Shed};
use busbar_contract::DestinationId;

fn two() -> (Node, Vec<crate::pool::Member>) {
    let node = Node::with_lanes(&["a", "b"]);
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];
    (node, members)
}

#[test]
fn one_arity_refuses_a_fitting_set_of_more_than_one_and_names_them() {
    let (mut node, members) = two();
    node.arity = Arity::One;
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx);
    assert!(
        picked.is_none(),
        "a One-arity binding declines to choose between two candidates that fit"
    );
    assert_eq!(
        ctx.ambiguous(),
        &[DestinationId::new(0), DestinationId::new(1)],
        "the refusal names the ambiguous candidates, in the fitting order, for the AUDIT step"
    );
}

#[test]
fn one_arity_admits_the_single_fitting_candidate() {
    let (mut node, mut members) = two();
    node.arity = Arity::One;
    // `b` is drained, so exactly one candidate fits and the binding admits it.
    members[1].weight = 0;
    let mut ctx = node.request_ctx();
    let picked = node
        .pick("p", &members, &mut ctx)
        .expect("the one candidate that fits is admitted");
    assert_eq!(picked.destination, DestinationId::new(0));
    assert!(
        ctx.ambiguous().is_empty(),
        "one fitting candidate is a choice, not an ambiguity"
    );
}

#[test]
fn one_arity_with_nothing_fitting_is_the_ordinary_empty() {
    let (mut node, mut members) = two();
    node.arity = Arity::One;
    members[0].weight = 0;
    members[1].weight = 0;
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert!(
        ctx.ambiguous().is_empty(),
        "no candidate is the existing empty answer, which arity did not invent"
    );
}

#[test]
fn any_arity_chooses_among_a_fitting_set_of_more_than_one() {
    let (node, members) = two(); // default Any
    let mut ctx = node.request_ctx();
    assert!(
        node.pick("p", &members, &mut ctx).is_some(),
        "Any is today's walk: several fitting candidates is the case the pick is FOR"
    );
    assert!(ctx.ambiguous().is_empty());
}

#[test]
fn one_arity_is_over_the_fitting_set_not_the_configured_set() {
    // Two members, one suppressed by the breaker: exactly one FITS, so the binding admits rather
    // than refusing. Arity narrows by the same health filter the walk spends a turn behind.
    let (mut node, members) = two();
    node.arity = Arity::One;
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    let mut ctx = node.request_ctx();
    let picked = node
        .pick("p", &members, &mut ctx)
        .expect("the one healthy candidate is admitted");
    assert_eq!(picked.destination, DestinationId::new(0));
    assert!(ctx.ambiguous().is_empty());
}

#[test]
fn the_walk_refuses_an_ambiguous_one_arity_pool_without_attempting_anyone() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "p",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.tune("p", |pool| pool.failover.arity = Arity::One);
    let mut ctx = node.request_ctx();
    let outcome = node.route_with("p", &mut ctx);
    match outcome {
        RouteOutcome::Refused(shed) => assert_eq!(
            shed,
            Shed::ambiguous(),
            "the walk refuses with the ambiguity shed, which carries no amount"
        ),
        other => panic!("expected an ambiguity refusal, got {other:?}"),
    }
    assert_eq!(
        ctx.ambiguous(),
        &[DestinationId::new(0), DestinationId::new(1)],
        "the ambiguous ids are on the context for the AUDIT step"
    );
    assert!(
        node.transport
            .dialled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "no member is attempted under an ambiguity: the walk declines before the first dial"
    );
}

#[test]
fn the_walk_serves_the_same_pool_unchanged_under_the_default_any() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "p",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.transport.script(
        "a",
        super::harness::Script::Frames(super::harness::ok_frames()),
    );
    node.transport.script(
        "b",
        super::harness::Script::Frames(super::harness::ok_frames()),
    );
    // No arity tune: the default is Any, and the two-member pool delivers exactly as it shipped.
    let outcome = node.route("p");
    assert!(
        matches!(outcome, RouteOutcome::Delivered(_)),
        "the default arity leaves a two-member pool serving as before, got {outcome:?}"
    );
}
