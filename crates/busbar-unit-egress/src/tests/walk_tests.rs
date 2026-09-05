// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk: how many attempts, which cell they record against, when a failure fails over, and
//! when it does not.
//!
//! Carried over from the previous release's pool-cell and reroute tests. The claims are the same:
//! a member that cannot be reached at all is failed over from; a member that answered is not; the
//! outcome lands on the ROUTING pool's cell and not the default one; the hop cap is a hop cap and
//! not an attempt cap; and the request budget is spent once, after the success, and given back
//! when the answer does not arrive whole.

use busbar_contract::{StatusClass, TransportError};

use super::harness::{frame, ok_frames, Health, Script};
use super::{member, Node};
use crate::ports::{disposition, Outcome};
use crate::wire::RouteOutcome;
use busbar_contract::DestinationId;

fn two_lane_pool() -> Node {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node
}

#[test]
fn a_member_that_cannot_be_dialled_is_failed_over_from() {
    let node = two_lane_pool();
    node.transport
        .script("a", Script::DialError(TransportError::Refused));
    node.transport.script("b", Script::Frames(ok_frames()));
    // Ask for `a` first, so the failure is the one under test rather than a rotation accident.
    let mut node = node;
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(1));
            assert_eq!(delivered.pool, "primary");
        }
        other => panic!("expected the sibling to serve, got {other:?}"),
    }
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
        "the failure is recorded against the ROUTING pool's cell"
    );
    assert!(
        node.breaker.outcomes("", DestinationId::new(0)).is_empty(),
        "and never against the default cell"
    );
}

#[test]
fn a_success_closes_the_routing_pools_cell_and_not_the_default_one() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success]
    );
    assert!(node.breaker.outcomes("", DestinationId::new(0)).is_empty());
}

#[test]
fn the_walk_takes_the_hop_cap_plus_one_attempts() {
    let mut node = Node::with_lanes(&["a", "b", "c", "d", "e"]);
    node.pool(
        "primary",
        (0..5)
            .map(|d| member(DestinationId::new(d), &format!("m{d}")))
            .collect(),
    );
    node.tune("primary", |p| p.failover.max_hops = 3);
    for lane in ["a", "b", "c", "d", "e"] {
        node.transport
            .script(lane, Script::DialError(TransportError::Refused));
    }

    let outcome = node.route("primary");
    assert!(outcome.shed().is_some(), "every attempt failed");
    let attempts = node.telemetry.attempts.lock().unwrap().len();
    assert_eq!(
        attempts, 4,
        "a cap of three hops attempts four members: the first attempt is not a hop"
    );
}

#[test]
fn there_is_no_failover_after_the_first_byte() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    // The first frame is relayed and then the upstream dies before its terminal frame. The client
    // already has part of the answer, so the walk must not try the sibling.
    node.transport.script(
        "a",
        Script::Truncated(frame(Some(StatusClass::Success), "head")),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(
                delivered.destination,
                DestinationId::new(0),
                "the answer stays with the member that started it"
            );
            assert_eq!(delivered.frames, 1);
        }
        other => panic!("expected the truncated answer to be returned, got {other:?}"),
    }
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        1,
        "only one member was ever attempted"
    );
}

#[test]
fn a_truncated_answer_gives_the_request_budget_unit_back() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Truncated(frame(Some(StatusClass::Success), "head")),
    );

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "the unit spent on the success is given back when the body does not arrive whole"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "and the failed transfer is recorded as a compensating transient"
    );
}

#[test]
fn a_whole_answer_keeps_the_request_budget_unit() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "the charge stands"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success]
    );
}

#[test]
fn the_callers_own_fault_is_relayed_and_the_member_is_not_penalised() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame(Some(StatusClass::ClientError), "bad")]),
    );

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(0));
            assert_eq!(delivered.status, Some(StatusClass::ClientError));
        }
        other => panic!("expected the client fault to be relayed, got {other:?}"),
    }
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::RecordNothing],
        "the caller's bad input is not the member's fault"
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        1,
        "and it does not fail over"
    );
}

#[test]
fn a_member_that_answers_with_a_server_error_is_failed_over_from() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame(Some(StatusClass::ServerError), "boom")]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1))
    );
    assert_eq!(
        node.telemetry.failovers.lock().unwrap().as_slice(),
        &[("primary".to_string(), disposition::TRANSIENT)]
    );
}

#[test]
fn a_request_too_large_excludes_every_member_with_the_same_or_a_smaller_window() {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    let mut members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
        member(DestinationId::new(2), "c"),
    ];
    members[0].context_max = Some(8_000);
    members[1].context_max = Some(8_000);
    members[2].context_max = Some(200_000);
    node.pool("primary", members);
    node.preference = Some(vec![
        DestinationId::new(0),
        DestinationId::new(1),
        DestinationId::new(2),
    ]);
    // The classifier says this answer means the request was too big for the member's window.
    node.breaker.set_verdict(
        0,
        crate::ports::Classified {
            disposition: crate::ports::Disposition::ContextLength,
            outcome: Outcome::RecordNothing,
            label: disposition::CONTEXT_LENGTH,
        },
    );
    let too_big = frame(Some(StatusClass::ClientError), "too big");
    node.transport
        .script("a", Script::Frames(vec![too_big.clone()]));
    node.transport.script("b", Script::Frames(vec![too_big]));
    node.transport.script("c", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(2)),
        "the sibling that shares the window that just refused it is excluded too: {outcome:?}"
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        2,
        "the equal-window sibling is never attempted"
    );
}

#[test]
fn a_dispatch_that_cannot_be_recorded_sends_nothing() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    *node.journal.fail.lock().unwrap() = true;

    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.status, crate::wire::STATUS_INTERNAL_ERROR);
    assert!(
        node.transport.dialled.lock().unwrap().is_empty(),
        "the record is durable BEFORE the dial, so a failed record means no dial at all"
    );
    assert!(
        node.breaker
            .outcomes("primary", DestinationId::new(0))
            .is_empty(),
        "and nothing is recorded against the member"
    );
}

#[test]
fn every_attempt_is_recorded_before_its_dial() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport
        .script("a", Script::DialError(TransportError::Refused));
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let dispatched = node.journal.dispatched.lock().unwrap();
    assert_eq!(dispatched.len(), 2, "one record per attempt");
    assert_eq!(dispatched[0].destination, DestinationId::new(0));
    assert_eq!(dispatched[0].attempt, 1);
    assert_eq!(dispatched[1].destination, DestinationId::new(1));
    assert_eq!(dispatched[1].attempt, 2);
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        1,
        "the attempt that produced nothing is explicitly abandoned"
    );
}

#[test]
fn an_answer_that_could_not_be_assembled_records_nothing_against_the_member() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    *node.plane.refuse_encode.lock().unwrap() = true;

    let shed = node.route("primary");
    assert_eq!(
        shed.shed().expect("a refusal").detail,
        crate::wire::DETAIL_INTERNAL_ERROR
    );
    assert!(node
        .breaker
        .outcomes("primary", DestinationId::new(0))
        .is_empty());
    assert!(node.transport.dialled.lock().unwrap().is_empty());
}

#[test]
fn the_decoration_reaches_the_bytes_the_lane_check_ran_on() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let written = node.transport.written.lock().unwrap();
    let sent = String::from_utf8_lossy(&written[0]).to_string();
    assert!(
        sent.contains("authorization: decorated"),
        "the decoration is on the wire: {sent}"
    );
    assert!(
        sent.ends_with("request"),
        "and so is the plane's body: {sent}"
    );
}

#[test]
fn a_member_that_is_dead_is_never_attempted() {
    let mut node = two_lane_pool();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            dead: true,
            ..Health::default()
        },
    );
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(
        matches!(node.route("primary"), RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1))
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().as_slice(),
        &[("primary".to_string(), DestinationId::new(1))]
    );
}
