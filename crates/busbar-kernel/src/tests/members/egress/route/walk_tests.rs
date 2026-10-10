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
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::wire::{WireFault, WireStatus};

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

/// A MID-STREAM CUT IS NOT A REFUND (spec Part 2 #62, OWNER-LOCKED; #77(2) "no refunds"): once a
/// byte of a STREAMED answer has reached the caller, a cut bills what streamed to the cut point and
/// the budget unit the success spent stands. The transfer is still recorded as failed, as 1.5.5 did
/// on a stream cut after its first byte (v1.5.5 `crates/busbar/src/proxy/response_body.rs:279-306`,
/// the `had_first && is_sse` arm: the compensating transient, the stream marked ended, nothing
/// refunded).
#[test]
fn a_stream_cut_after_its_first_byte_refunds_nothing() {
    let mut node = two_lane_pool();
    node.wants_stream = true;
    node.conns.script(
        "a",
        Script::Truncated(frame(Some(WireStatusClass::Success), "head")),
    );

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "the unit spent on the success stands: what streamed is billed, not refunded"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "and the failed transfer is recorded as a compensating transient"
    );
}

/// A BUFFERED answer cut mid-transfer delivered nothing to the caller, whatever bytes of its body
/// had arrived: the unit its head spent is given back, with the compensating transient. 1.5.5's
/// buffered read refunded through its `budget_guard` on a mid-body transport failure (v1.5.5
/// `crates/busbar/src/proxy/engine/mod.rs:329-353`), and its non-stream passthrough body refunded
/// on a post-first-byte non-SSE failure (`crates/busbar/src/proxy/response_body.rs:358-409`). #62
/// bills what was delivered to the caller; a buffered answer delivered nothing.
#[test]
fn a_buffered_answer_cut_after_its_first_byte_refunds_the_budget_unit() {
    let node = two_lane_pool();
    assert!(!node.wants_stream, "the caller asked for a buffered answer");
    node.conns.script(
        "a",
        Script::Truncated(frame(Some(WireStatusClass::Success), "head")),
    );

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "nothing reached the caller, so the unit spent on the head is given back"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "and the failed transfer is recorded as a compensating transient"
    );
}

/// A client that goes away while a BUFFERED answer is being read takes nothing with it: 1.5.5's
/// `budget_guard` dropped armed and gave the unit back (v1.5.5
/// `crates/busbar/src/proxy/engine/mod.rs:229-256`, `BudgetSpendGuard::drop`; the non-stream
/// passthrough body's `FirstByteBody::drop`, `crates/busbar/src/proxy/response_body.rs:608-617`).
/// The registered #62 difference moves only a STREAMED answer's cancel. A client that left is not
/// the member's fault, so nothing is recorded against it.
#[test]
fn a_buffered_answer_the_client_cancels_after_its_first_byte_refunds_the_budget_unit() {
    let node = two_lane_pool();
    assert!(!node.wants_stream, "the caller asked for a buffered answer");
    node.conns.script(
        "a",
        Script::Drip {
            replies: vec![
                frame(Some(WireStatusClass::Success), "head"),
                frame(Some(WireStatusClass::Success), "more"),
            ],
            step_ms: 1_000,
            complete: true,
        },
    );

    assert_eq!(node.cancel_after_first_piece("primary"), b"head");
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "nothing reached the caller, so the unit spent on the head is given back"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success],
        "the client's leaving records nothing against the member"
    );
    assert_eq!(
        node.conns.closed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "and its connection is closed"
    );
}

/// A stream the CLIENT cancels after its first byte is a cut like any other (spec Part 2 #62 names
/// "disconnect" among them; #77(2) "no refunds, no adjusting lines"): what streamed is billed and the
/// budget unit its success spent stands. 1.5.5 gave the unit back here (v1.5.5
/// `crates/busbar/src/proxy/response_body.rs:608-617`, `FirstByteBody::drop`); that difference is
/// the owner's, registered in `testing/shadow-oracle/accepted-differences.json` and named in the
/// CHANGELOG. A client that left is not the member's fault, so nothing is recorded against it.
#[test]
fn a_stream_the_client_cancels_after_its_first_byte_refunds_nothing() {
    let mut node = two_lane_pool();
    node.wants_stream = true;
    node.conns.script(
        "a",
        Script::Drip {
            replies: vec![
                frame(Some(WireStatusClass::Success), "head"),
                frame(Some(WireStatusClass::Success), "more"),
            ],
            step_ms: 1_000,
            complete: true,
        },
    );

    assert_eq!(node.cancel_after_first_piece("primary"), b"head");
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "the unit spent on the success stands: what streamed is billed, not refunded"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success],
        "the client's leaving records nothing against the member"
    );
    assert_eq!(
        node.conns.closed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "and its connection is closed"
    );
}

/// The other side of #62: a success whose answer is cut before ANY byte reached the caller
/// delivered nothing, so the unit its head spent is given back, with the compensating transient
/// (v1.5.5 `crates/busbar/src/proxy/response_body.rs:358-409`, the pre-first-byte arm;
/// `crates/busbar/src/proxy/engine/mod.rs:329-353`, a buffered body that failed before the caller
/// saw any of it).
#[test]
fn a_cut_before_the_first_byte_refunds_the_budget_unit() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Truncated(frame(Some(WireStatusClass::Success), "")),
    );

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.pieces == 0),
        "nothing of the answer reached the caller: {outcome:?}"
    );
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "nothing streamed, so the unit spent on the head is given back"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }]
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

/// A withdrawn credential is a caller-fault CLASS (the fee leg), which alone would penalise
/// nothing. The transport's fault reading is what says the credential was refused, and it has to
/// reach the classifier for the destination to go down. The verdict here is stated against the
/// READING: a walk that hands the classifier no reading falls through to the caller's answer, which
/// records nothing, so the destination is never recorded hard-down.
#[test]
fn a_hard_reading_reaches_the_classifier_and_the_destination_goes_hard_down() {
    let node = two_lane_pool();
    node.breaker.set_verdict(
        Some(WireFault::Hard),
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
            Some(WireFault::Hard),
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
            .map(|s| s.fault),
        Some(Some(WireFault::Hard)),
        "the transport's reading crossed the seam, not just the caller-fault class"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::HardDown],
        "and the destination is recorded hard-down, which is what fans out to its siblings"
    );
    // The hard-down is recorded and then RELAYED to the plane (step 24, member-401: 1.5.5's attempt
    // classifier ends the walk on an auth hard-down, and the plane's judge renders it); the far end
    // no longer fails it over before the plane has seen it.
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(0)
            && d.status.map(|(code, _)| code) == Some(403)),
        "a hard-down member's answer is relayed to the plane, not failed over: {outcome:?}"
    );
}

/// The wait a far end asks for is a fact about THAT answer, and the only layer that ever sees it
/// is the connector that read the response head. It has to arrive at the classifier or the
/// cooldown is computed from the ladder alone and the far end's floor is silently dropped.
#[test]
fn a_transient_reading_carries_the_upstreams_own_wait_through_to_the_breaker() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::CallerFault),
            None,
            Some(WireFault::Transient),
            Some(7),
            "slow down",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(seen.map(|s| s.fault), Some(Some(WireFault::Transient)));
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
fn a_transient_reading_with_no_wait_leaves_the_cooldown_to_the_ladder() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::FarEndFault),
            None,
            Some(WireFault::Transient),
            None,
            "boom",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(seen.map(|s| s.fault), Some(Some(WireFault::Transient)));
    assert_eq!(seen.map(|s| s.retry_after), Some(None));
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
    );
}

/// THE RED ARM, AT THE WALK: a far end whose framer states no fault reading (it declares no fault
/// table) is read as the caller's whatever its class says. The class is the fee leg and never
/// stands in for the breaker's reading: nothing is recorded and the answer is relayed.
#[test]
fn an_answer_with_no_fault_reading_records_nothing_and_is_relayed() {
    let node = two_lane_pool();
    node.conns.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(WireStatusClass::FarEndFault),
            None,
            None,
            None,
            "boom",
        )]),
    );
    node.conns.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(0)),
        "relayed from the member that answered, not failed over: {outcome:?}"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::RecordNothing],
        "and nothing is held against it"
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
        Some(WireFault::Caller),
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
