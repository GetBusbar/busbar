// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two deadlines: the walk's own, checked before every attempt, and the per-attempt cap on
//! time to the first answer.
//!
//! The first claim here is the one the previous release states most plainly and the one easiest to
//! lose in a refactor: the walk's deadline is checked UNCONDITIONALLY before every attempt,
//! streaming included. A streamed answer is exempt from the per-attempt cap's SHAPE — it is
//! bounded by the client-level ceiling instead of the walk budget once it is under way — but it is
//! not exempt from the check that there was any budget left to start it with.

use super::harness::{frame, Script};
use super::{member, Node};
use crate::ports::{disposition, Clock};
use busbar_contract::DestinationId;
use busbar_contract_transport::wire::StatusClass;

/// The client-level ceiling every walk in this module runs under, in milliseconds. The harness
/// hands the unit `stream_ceiling_secs: 300`.
const CEILING_MS: u64 = 300 * 1000;

fn one_lane_pool(stream: bool) -> Node {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = stream;
    node
}

#[test]
fn a_spent_deadline_refuses_before_the_first_attempt() {
    let node = one_lane_pool(false);
    let mut ctx = node.request_ctx();
    node.clock.advance_secs(node.timeout_secs + 1);

    let outcome = node.route_with("primary", &mut ctx);
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.detail, crate::wire::DETAIL_REQUEST_TIMEOUT);
    assert_eq!(shed.status, crate::wire::STATUS_SERVICE_UNAVAILABLE);
    assert!(
        node.transport.dialled.lock().unwrap().is_empty(),
        "nothing is dialled once the walk's budget is spent"
    );
}

#[test]
fn a_spent_deadline_refuses_before_a_streaming_attempt_too() {
    let node = one_lane_pool(true);
    let mut ctx = node.request_ctx();
    node.clock.advance_secs(node.timeout_secs + 1);

    let outcome = node.route_with("primary", &mut ctx);
    assert_eq!(
        outcome.shed().expect("a refusal").detail,
        crate::wire::DETAIL_REQUEST_TIMEOUT,
        "a streamed answer is bounded by the client ceiling once under way, never excused from \
         the check that there was budget to start it"
    );
    assert!(node.transport.dialled.lock().unwrap().is_empty());
}

#[test]
fn a_deadline_that_expires_between_hops_stops_the_walk() {
    // With budget in hand the sibling serves.
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.timeout_secs = 1;
    node.transport.script(
        "a",
        Script::DialError(busbar_contract_transport::wire::TransportError::Refused),
    );
    node.transport
        .script("b", Script::Frames(super::harness::ok_frames()));
    assert!(node.route("primary").is_delivered());

    // With the budget spent between the hops the walk stops instead, and says so.
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.timeout_secs = 1;
    let mut ctx = node.request_ctx();
    node.clock.advance_secs(2);
    assert_eq!(
        node.route_with("primary", &mut ctx)
            .shed()
            .expect("a refusal")
            .detail,
        crate::wire::DETAIL_REQUEST_TIMEOUT
    );
}

#[test]
fn an_upstream_that_says_nothing_is_cut_by_the_per_attempt_cap() {
    let mut node = Node::with_lanes(&["a", "b"]);
    let mut members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];
    members[0].attempt_timeout_ms = Some(500);
    node.pool("primary", members);
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Hang);
    node.transport
        .script("b", Script::Frames(super::harness::ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, crate::wire::RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1))
    );
    let failures = node.telemetry.failures.lock().unwrap();
    assert_eq!(
        failures.as_slice(),
        &[(
            "primary".to_string(),
            DestinationId::new(0),
            disposition::ATTEMPT_TIMEOUT
        )],
        "a hang is counted under its own label, not lumped in with a refusal"
    );
    assert!(
        node.journal
            .abandoned
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.destination == DestinationId::new(0)),
        "the attempt that hung is explicitly abandoned"
    );
}

#[test]
fn an_upstream_that_says_nothing_and_has_no_cap_is_cut_by_the_walk_budget() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script("a", Script::Hang);

    let outcome = node.route("primary");
    assert!(outcome.shed().is_some());
    let failures = node.telemetry.failures.lock().unwrap();
    assert!(
        failures
            .iter()
            .any(|(_, _, label)| *label == disposition::TRANSIENT),
        "with no per-attempt cap the outer deadline is what ends it"
    );
}

/// A drip-fed stream: `count` frames, one every `step_ms`, the last one terminal when asked.
fn drip(node: &Node, count: usize, step_ms: u64, terminal: bool) -> Script {
    let mut frames: Vec<_> = (0..count)
        .map(|_| frame(Some(StatusClass::Success), "head"))
        .collect();
    if terminal {
        frames.pop();
        frames.push(frame(Some(StatusClass::Success), "end"));
    }
    Script::Drip {
        frames,
        step_ms,
        clock: node.clock.clone(),
    }
}

#[test]
fn the_stream_ceiling_bounds_the_whole_answer_not_each_frame() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = true;
    // An upstream that never finishes and never quite goes quiet: a frame every quarter of the
    // ceiling, twenty of them. Bounded by the whole answer, four arrive and the answer is cut at
    // the ceiling; bounded per frame, all twenty arrive and the send runs five times as long.
    node.transport.script("a", drip(&node, 20, CEILING_MS / 4, false));

    let started = node.clock.now_millis();
    let outcome = node.route("primary");
    let elapsed = node.clock.now_millis() - started;

    let crate::wire::RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("the frames that did arrive are relayed, not shed: {outcome:?}");
    };
    assert_eq!(
        u64::try_from(elapsed).unwrap(),
        CEILING_MS,
        "the send is cut at the ceiling, measured from the send start"
    );
    assert_eq!(
        delivered.frames, 4,
        "only the frames that fit inside the ceiling are relayed"
    );
    assert_eq!(
        delivered.finish,
        Some(busbar_contract::FinishClass::Partial),
        "a cut answer is a partial one"
    );
}

#[test]
fn a_streamed_answer_that_finishes_inside_the_ceiling_is_untouched() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = true;
    // Three frames at a quarter of the ceiling each: the terminal one lands with budget to spare.
    node.transport.script("a", drip(&node, 3, CEILING_MS / 4, true));

    let outcome = node.route("primary");
    let crate::wire::RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("a whole answer is delivered: {outcome:?}");
    };
    assert_eq!(delivered.frames, 3);
    assert_eq!(
        delivered.finish,
        Some(busbar_contract::FinishClass::Complete),
        "the answer ended on its own terminal frame"
    );
}
