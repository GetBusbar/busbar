// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk: how many attempts, which cell they record against, when a failure fails over, and
//! when it does not.
//!
//! Carried over from the previous release's pool-cell and reroute tests. The claims are the same:
//! a member that cannot be reached at all is failed over from; a member that answered is not; the
//! outcome lands on the ROUTING pool's cell and not the default one; the hop cap is a hop cap and
//! not an attempt cap; and the request budget is spent once, after the success, and given back
//! when the answer does not arrive whole. Every route here is the walk's members, attempted by the
//! production far end.

use busbar_contract::abi::transport::STATUS_CALLER_FAULT;
use busbar_contract::conn::ConnError;
use busbar_contract::transport::registry::status_ns;
use busbar_contract::transport::wire::WireStatus;
use busbar_contract::transport::wire::WireStatusClass;

use super::harness::{frame, frame_with_upstream, ok_frames, Health, Script};
use super::{member, Node, Routed};
use busbar_contract::DestinationId;
use busbar_kernel_egress::ports::{disposition, Outcome};

/// Two members of equal weight: the walk's floor offers `a` first.
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
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    match outcome {
        Routed::Delivered(delivered) => {
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
    let node = two_lane_pool();
    node.conns.script("a", Script::Frames(ok_frames()));

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
        node.conns
            .script(lane, Script::DialError(ConnError::Refused));
    }

    let outcome = node.route("primary");
    assert!(outcome.shed().is_some(), "every attempt failed");
    let attempts = node.telemetry.attempts.lock().unwrap().len();
    assert_eq!(
        attempts, 4,
        "a cap of three hops attempts four members: the first attempt is not a hop"
    );

    // The same count off the walk itself: four members taken, then the pool's terminal.
    let mut walker = node.walker("primary");
    for _ in 0..4 {
        drop(walker.take());
    }
    assert_eq!(
        walker.shed().status,
        busbar_kernel_egress::wire::STATUS_SERVICE_UNAVAILABLE,
        "the fifth step is the terminal, not a fifth member"
    );
}

#[test]
fn there_is_no_failover_after_the_first_byte() {
    let node = two_lane_pool();
    // The first piece is relayed and then the far end drops before the answer completes. The
    // caller already has part of the answer, so the walk must not try the sibling.
    node.conns.script(
        "a",
        Script::Truncated(frame(Some(WireStatusClass::Success), "head")),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    match outcome {
        Routed::Delivered(delivered) => {
            assert_eq!(
                delivered.destination,
                DestinationId::new(0),
                "the answer stays with the member that started it"
            );
            assert_eq!(delivered.pieces, 1);
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
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Truncated(frame(Some(WireStatusClass::Success), "head")),
    );

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "the unit spent on the success is given back when the body does not arrive whole"
    );
    // v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:329-353` (buffered) and
    // `crates/busbar/src/proxy/response_body.rs:358-409` (streamed): the headers recorded a
    // success, the body never arrived intact, so a compensating transient is recorded AND the
    // budget unit is refunded.
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "and the failed transfer is recorded as a compensating transient"
    );
}

#[test]
fn a_whole_answer_keeps_the_request_budget_unit() {
    let node = two_lane_pool();
    node.conns.script("a", Script::Frames(ok_frames()));

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
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame(Some(WireStatusClass::CallerFault), "bad")]),
    );

    let outcome = node.route("primary");
    match outcome {
        Routed::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(0));
            assert_eq!(
                delivered.status.map(|(_, class)| class),
                Some(u32::from(STATUS_CALLER_FAULT))
            );
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
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame(Some(WireStatusClass::FarEndFault), "boom")]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(1)),
        "{outcome:?}"
    );
    assert_eq!(
        node.telemetry.failovers.lock().unwrap().as_slice(),
        &[("primary".to_string(), disposition::TRANSIENT)]
    );
}

/// A withdrawn credential answers 403, and 403 is a 4xx — so the coarse class alone says
/// `CallerFault`, which is the caller's own fault and penalises nothing. The exact number is the
/// only thing that tells the two apart, and it has to reach the classifier for the destination to
/// go down. The verdict here is stated against the NUMBER: a walk that hands the classifier no
/// number falls through to the coarse-class default and relays instead of failing over.
#[test]
fn a_403_reaches_the_classifier_as_a_403_and_the_destination_goes_hard_down() {
    let node = two_lane_pool();
    node.breaker.set_verdict(
        WireStatus::new(status_ns::HTTP, 403),
        busbar_kernel_egress::ports::Classified {
            disposition: busbar_kernel_egress::ports::Disposition::HardDown,
            outcome: Outcome::HardDown,
            label: disposition::HARD_DOWN,
        },
    );
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::CallerFault),
            Some(WireStatus::new(status_ns::HTTP, 403)),
            None,
            "forbidden",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert_eq!(
        node.breaker
            .classified
            .lock()
            .unwrap()
            .first()
            .map(|s| s.code),
        Some(Some(WireStatus::new(status_ns::HTTP, 403))),
        "the far end's own number crossed the seam, not just the 4xx class"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::HardDown],
        "and the destination is recorded hard-down, which is what fans out to its siblings"
    );
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(1)),
        "a hard-down member is failed over from, never relayed: {outcome:?}"
    );
}

/// The wait a far end asks for is a fact about THAT answer, and the only layer that ever sees it
/// is the connector that read the response head. It has to arrive at the classifier or the
/// cooldown is computed from the ladder alone and the far end's floor is silently dropped.
#[test]
fn a_429_carries_the_upstreams_own_retry_after_through_to_the_breaker() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::CallerFault),
            Some(WireStatus::new(status_ns::HTTP, 429)),
            Some(7),
            "slow down",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(
        seen.map(|s| s.code),
        Some(Some(WireStatus::new(status_ns::HTTP, 429)))
    );
    assert_eq!(
        seen.map(|s| s.retry_after),
        Some(Some(7)),
        "the seven seconds the far end asked for reached the classifier"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient {
            retry_after: Some(7)
        }],
        "and it is what the breaker is told to floor the cooldown at"
    );
}

/// The other half of the same claim: a far end that asked for nothing must not have a wait
/// invented for it. `None` here is what leaves the cooldown to the ladder.
#[test]
fn a_server_error_with_no_retry_after_leaves_the_cooldown_to_the_ladder() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::FarEndFault),
            Some(WireStatus::new(status_ns::HTTP, 503)),
            None,
            "boom",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(
        seen.map(|s| s.code),
        Some(Some(WireStatus::new(status_ns::HTTP, 503)))
    );
    assert_eq!(seen.map(|s| s.retry_after), Some(None));
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
    );
}

/// A gRPC far end that refuses with a trailers-only `UNAVAILABLE`. The piece the connector hands
/// up carries `14` in the `grpc` numbering — gRPC's number, named as gRPC's — and the walk must do
/// with it exactly what it does with an HTTP 503: record a transient failure against the
/// destination and fail over to the sibling.
///
/// The number alone did neither. `14` matched no HTTP band, classified as the caller's fault, and
/// the walk relayed a dead far end's refusal without recording anything or trying the next member.
#[test]
fn a_grpc_unavailable_records_a_failure_and_fails_over() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::FarEndFault),
            Some(WireStatus::new(status_ns::GRPC, 14)),
            None,
            "",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(
        node.route("primary").is_delivered(),
        "the walk failed over to the sibling rather than relaying the refusal"
    );
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(
        seen.map(|s| s.code),
        Some(Some(WireStatus::new(status_ns::GRPC, 14))),
        "the number crossed the seam WITH the numbering that spelled it"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
        "and the destination that said UNAVAILABLE was recorded against"
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
    // The classifier says this answer means the request was too big for the member's window.
    node.breaker.set_verdict(
        WireStatus::new(status_ns::HTTP, 0),
        busbar_kernel_egress::ports::Classified {
            disposition: busbar_kernel_egress::ports::Disposition::ContextLength,
            outcome: Outcome::RecordNothing,
            label: disposition::CONTEXT_LENGTH,
        },
    );
    let too_big = frame(Some(WireStatusClass::CallerFault), "too big");
    node.conns
        .script("a", Script::Frames(vec![too_big.clone()]));
    node.conns.script("b", Script::Frames(vec![too_big]));
    node.conns.script("c", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(2)),
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
    let node = two_lane_pool();
    *node.journal.fail.lock().unwrap() = true;

    let outcome = node.route("primary");
    // 1.5.5 had no dispatch record; its internal failures before a dispatch answered 500 with the
    // internal words at once, the probe given back, no other member tried (v1.5.5
    // `crates/busbar/src/proxy/engine/mod.rs:1514-1526`, `:1621-1631`).
    assert_eq!(
        outcome.shed(),
        Some(&super::Refusal {
            status: u32::from(busbar_kernel_egress::wire::STATUS_INTERNAL_ERROR),
            retry_after: None,
        }),
        "{outcome:?}"
    );
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        0,
        "nothing was recorded, so nothing is abandoned"
    );
    assert_eq!(
        node.breaker.pick_order(),
        vec![DestinationId::new(0)],
        "and no other member is taken"
    );
    assert!(
        node.conns.dialled().is_empty(),
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
    let node = two_lane_pool();
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let dispatched = node.journal.dispatched.lock().unwrap();
    assert_eq!(dispatched.len(), 2, "one record per attempt");
    assert_eq!(dispatched[0].destination, DestinationId::new(0));
    assert_eq!(dispatched[1].destination, DestinationId::new(1));
    // v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1448` numbered its attempts from one.
    assert_eq!(dispatched[0].attempt, 1);
    assert_eq!(dispatched[1].attempt, 2);
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        1,
        "the attempt that produced nothing is explicitly abandoned"
    );
}

#[test]
fn an_attempt_whose_caller_goes_away_mid_send_abandons_its_record() {
    let node = two_lane_pool();
    // The member accepts the open and then says nothing, so the attempt is parked on its answer
    // when the caller drops it.
    node.conns.script("a", Script::Hang);

    node.abandon_mid_answer("primary");

    assert_eq!(
        node.journal.dispatched.lock().unwrap().len(),
        1,
        "the record was made durable before the dial"
    );
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        1,
        "a record left behind by a cancelled attempt is settled by recovery as a crash unless the \
         attempt says it was abandoned"
    );
}

#[test]
fn a_member_that_is_dead_is_never_attempted() {
    let node = two_lane_pool();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            dead: true,
            ..Health::default()
        },
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(1)),
        "{outcome:?}"
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().as_slice(),
        &[("primary".to_string(), DestinationId::new(1))]
    );
}
