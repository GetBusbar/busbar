// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two deadlines: the walk's own, checked before every step, and the per-attempt cap on time
//! to the first answer.
//!
//! The first claim here is the one the previous release states most plainly and the one easiest to
//! lose in a refactor: the walk's deadline is checked UNCONDITIONALLY before every attempt,
//! streaming included. A streamed answer is exempt from the per-attempt cap's SHAPE — it is
//! bounded by the client-level ceiling instead of the walk budget once it is under way — but it is
//! not exempt from the check that there was any budget left to start it with.

use super::harness::{frame, ok_frames, Script};
use super::{member, Node, Refusal, Routed, STREAM_CEILING_SECS};
use busbar_contract::conn::ConnError;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::DestinationId;
use busbar_kernel_egress::ports::{disposition, Clock};

/// The client-level ceiling every far end in this module runs under, in milliseconds.
const CEILING_MS: u64 = STREAM_CEILING_SECS * 1000;

fn one_lane_pool(stream: bool) -> Node {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = stream;
    node
}

/// The timeout refusal, as the far end hands it on: the overload status and no Retry-After.
fn timed_out() -> Refusal {
    Refusal {
        status: u32::from(busbar_kernel_egress::wire::STATUS_SERVICE_UNAVAILABLE),
        retry_after: None,
    }
}

#[test]
fn a_spent_deadline_refuses_before_the_first_attempt() {
    let node = one_lane_pool(false);

    // The walk's own answer, in the words that shipped.
    let mut walker = node.walker("primary");
    node.clock.advance_secs(node.timeout_secs + 1);
    let shed = walker.shed();
    assert_eq!(
        shed.detail,
        busbar_kernel_egress::wire::DETAIL_REQUEST_TIMEOUT
    );
    assert_eq!(
        shed.status,
        busbar_kernel_egress::wire::STATUS_SERVICE_UNAVAILABLE
    );

    // And through the far end: nothing is opened once the walk's budget is spent.
    let node = one_lane_pool(false);
    let outcome = node.route_with("primary", |node, attempt| {
        if attempt == 1 {
            node.clock.advance_secs(node.timeout_secs + 1);
        }
    });
    assert_eq!(outcome.shed(), Some(&timed_out()), "{outcome:?}");
    assert!(
        node.conns.dialled().is_empty(),
        "nothing is dialled once the walk's budget is spent"
    );
}

#[test]
fn a_spent_deadline_refuses_before_a_streamed_attempt_too() {
    let node = one_lane_pool(true);
    let outcome = node.route_with("primary", |node, attempt| {
        if attempt == 1 {
            node.clock.advance_secs(node.timeout_secs + 1);
        }
    });
    assert_eq!(
        outcome.shed(),
        Some(&timed_out()),
        "a streamed answer is bounded by the client ceiling once under way, never excused from \
         the check that there was budget to start it: {outcome:?}"
    );
    assert!(node.conns.dialled().is_empty());
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
    node.timeout_secs = 1;
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(ok_frames()));
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
    node.timeout_secs = 1;
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(ok_frames()));
    let outcome = node.route_with("primary", |node, attempt| {
        if attempt == 2 {
            node.clock.advance_secs(2);
        }
    });
    assert_eq!(outcome.shed(), Some(&timed_out()), "{outcome:?}");
    assert_eq!(
        node.conns.dialled(),
        vec!["a".to_string()],
        "the sibling is never dialled once the budget is spent"
    );

    // The walk's own words for it.
    let mut walker = node.walker("primary");
    drop(walker.take());
    node.clock.advance_secs(2);
    assert_eq!(
        walker.shed().detail,
        busbar_kernel_egress::wire::DETAIL_REQUEST_TIMEOUT
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
    node.conns.script("a", Script::Hang);
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(1)),
        "{outcome:?}"
    );
    let failures = node.telemetry.failures.lock().unwrap();
    assert_eq!(
        failures.as_slice(),
        &[(
            "primary".to_string(),
            DestinationId::new(0),
            disposition::ATTEMPT_TIMEOUT
        )],
        "a hang is counted under its own label, not lumped in with a refusal (v1.5.5 \
         `crates/busbar/src/proxy/engine/mod.rs:1713-1743`: the member cap's own arm)"
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

/// The member's raw cap never reaches the connector: `attempt_cap_ms` floors it to what the walk
/// has left before the open is handed it.
#[test]
fn a_per_attempt_cap_larger_than_the_walk_budget_is_clamped_to_it_before_it_reaches_the_clock() {
    let mut node = Node::with_lanes(&["a"]);
    let mut members = vec![member(DestinationId::new(0), "a")];
    members[0].attempt_timeout_ms = Some(500_000); // far past any walk budget below
    node.pool("primary", members);
    node.timeout_secs = 2; // 2_000ms of walk budget
    node.conns.script("a", Script::Hang);

    let _ = node.route("primary");

    let caps: Vec<u64> = node
        .conns
        .opened
        .lock()
        .unwrap()
        .iter()
        .map(|(_, cap)| *cap)
        .collect();
    assert!(
        !caps.contains(&500_000),
        "the raw per-member cap must never reach the connector unclamped: {caps:?}"
    );
    assert_eq!(
        caps,
        vec![2_000],
        "the cap must be floored to the walk's remaining budget in ms"
    );
}

#[test]
fn an_upstream_that_says_nothing_and_has_no_cap_is_cut_by_the_walk_budget() {
    let node = one_lane_pool(false);
    node.conns.script("a", Script::Hang);

    let started = node.clock.now_millis();
    let outcome = node.route("primary");
    assert!(outcome.shed().is_some(), "{outcome:?}");
    assert_eq!(
        node.clock.now_millis() - started,
        u128::from(node.timeout_secs * 1000),
        "with no per-attempt cap the walk's budget is what ends it"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![busbar_kernel_egress::ports::Outcome::Transient { retry_after: None }],
        "and the member that never answered is recorded against"
    );
    // 1.5.5 counted it as the walk's own timeout, not a hang the member's cap detected: with no
    // `attempt_timeout_ms` the send ran under the request's remaining budget and its expiry took
    // the transport-error arm — `upstream_failure(transient_upstream)`, `failover(timeout)`
    // (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1696-1698`, `:1753-1781`).
    assert_eq!(
        node.telemetry.failures.lock().unwrap().as_slice(),
        &[(
            "primary".to_string(),
            DestinationId::new(0),
            disposition::TRANSIENT
        )]
    );
    assert_eq!(
        node.telemetry.failovers.lock().unwrap().as_slice(),
        &[(
            "primary".to_string(),
            busbar_kernel_egress::ports::net::TIMEOUT
        )]
    );
}

/// A drip-fed answer: `count` pieces, one every `step_ms`, completing when asked.
fn drip(count: usize, step_ms: u64, complete: bool) -> Script {
    Script::Drip {
        replies: (0..count)
            .map(|_| frame(Some(WireStatusClass::Success), "head"))
            .collect(),
        step_ms,
        complete,
    }
}

#[test]
fn the_stream_ceiling_bounds_the_whole_answer_not_each_frame() {
    let node = one_lane_pool(true);
    // A far end that never finishes and never quite goes quiet: a piece every quarter of the
    // ceiling, twenty of them. Bounded by the whole answer, four arrive and the answer is cut at
    // the ceiling; bounded per piece, all twenty arrive and the send runs five times as long.
    node.conns.script("a", drip(20, CEILING_MS / 4, false));

    let started = node.clock.now_millis();
    let outcome = node.route("primary");
    let elapsed = node.clock.now_millis() - started;

    let Routed::Delivered(delivered) = &outcome else {
        panic!("the pieces that did arrive are relayed, not shed: {outcome:?}");
    };
    assert_eq!(
        u64::try_from(elapsed).unwrap(),
        CEILING_MS,
        "the send is cut at the ceiling, measured from the send start"
    );
    assert_eq!(
        delivered.pieces, 4,
        "only the pieces that fit inside the ceiling are relayed"
    );
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "a cut answer is a partial one: its budget unit is given back"
    );
}

#[test]
fn a_streamed_answer_that_finishes_inside_the_ceiling_is_untouched() {
    let node = one_lane_pool(true);
    // Three pieces at a quarter of the ceiling each: the last one lands with budget to spare.
    node.conns.script("a", drip(3, CEILING_MS / 4, true));

    let outcome = node.route("primary");
    let Routed::Delivered(delivered) = &outcome else {
        panic!("a whole answer is delivered: {outcome:?}");
    };
    assert_eq!(delivered.pieces, 3);
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "the answer ended on its own completion, so its charge stands"
    );
}
