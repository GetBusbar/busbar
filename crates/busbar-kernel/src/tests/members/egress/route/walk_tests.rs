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

// ── THE SERVED BREAKER UNDER THE WALK ──────────────────────────────────────────────────────────
//
// The cases below are the previous release's pool-cell, budget and stream-cut tests, rehomed
// (F25 row 155) at the strength they had: what they pin is a breaker cell's state, its window and
// a destination's lifetime budget, so they run over busbar-kernel-breaker's `BreakerUnit` bound to
// the egress port as the composition root binds it, not over the scripted `TestBreaker`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::transport::{FAULT_NONE, STATUS_FAR_END_FAULT, STATUS_SUCCESS};
use busbar_contract::caps::{Pass, Route};
use busbar_kernel_breaker::cell::{BreakerCell, BreakerState};
use busbar_kernel_breaker::cfg::{BreakerCfg, TripConfig, TripMode};
use busbar_kernel_breaker::{BreakerUnit, LaneState};
use busbar_kernel_egress::pool::OnExhausted;
use busbar_kernel_egress::ports::{
    Admit, Breaker, Capacity, Classified, Clock, Unavailable, UpstreamStatus,
};
use busbar_kernel_egress::wire::STATUS_SERVICE_UNAVAILABLE;

use super::harness::{route_token, Reply};
use super::{Refusal, Served};
use crate::plane_driver::{Egress, FarEnd, FarPiece, Pick};

/// THE SERVED BREAKER: busbar-kernel-breaker's [`BreakerUnit`] bound to the egress port exactly as
/// the composition root's `BreakerAdapter` binds it (`crates/busbar/src/root/adapters.rs`), every
/// pool under one ladder. Beside it, the one fact the unit does not hold (a destination that is
/// administratively dead, the port's [`Unavailable::Dead`]) and every outcome the far end recorded,
/// in order.
pub(super) struct RealBreaker {
    pub(super) unit: BreakerUnit,
    cfg: BreakerCfg,
    dead: Mutex<Vec<DestinationId>>,
    observed: Mutex<Vec<(String, DestinationId, Outcome)>>,
}

impl RealBreaker {
    /// The served breaker, every pool under the default ladder.
    pub(super) fn new() -> Arc<Self> {
        Self::with_cfg(BreakerCfg::default())
    }

    /// The served breaker, every pool under `cfg`.
    pub(super) fn with_cfg(cfg: BreakerCfg) -> Arc<Self> {
        Arc::new(Self {
            unit: BreakerUnit::new(),
            cfg,
            dead: Mutex::new(Vec::new()),
            observed: Mutex::new(Vec::new()),
        })
    }

    /// Mark `destination` administratively dead.
    pub(super) fn kill(&self, destination: DestinationId) {
        self.dead
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(destination);
    }

    fn is_dead(&self, destination: DestinationId) -> bool {
        self.dead
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&destination)
    }

    /// The `(pool, destination)` cell of the unit.
    pub(super) fn cell(&self, pool: &str, destination: DestinationId) -> Arc<BreakerCell> {
        self.unit.cell(pool, destination)
    }

    /// Every outcome the far end recorded against `pool`'s cell of `destination`, in order.
    pub(super) fn outcomes(&self, pool: &str, destination: DestinationId) -> Vec<Outcome> {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(p, d, _)| p == pool && *d == destination)
            .map(|(_, _, o)| *o)
            .collect()
    }

    /// How many successes the far end recorded against any member of `pool`.
    pub(super) fn successes(&self, pool: &str) -> usize {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(p, _, o)| p == pool && *o == Outcome::Success)
            .count()
    }
}

fn to_unit(outcome: Outcome) -> busbar_kernel_breaker::Outcome {
    use busbar_kernel_breaker::Outcome as B;
    match outcome {
        Outcome::Success => B::Success,
        Outcome::Transient { retry_after } => B::Transient { retry_after },
        Outcome::HardDown => B::HardDown,
        Outcome::RecordNothing => B::RecordNothing,
    }
}

fn from_unit(outcome: busbar_kernel_breaker::Outcome) -> Outcome {
    use busbar_kernel_breaker::Outcome as B;
    match outcome {
        B::Success => Outcome::Success,
        B::Transient { retry_after } => Outcome::Transient { retry_after },
        B::HardDown => Outcome::HardDown,
        B::RecordNothing => Outcome::RecordNothing,
    }
}

impl Breaker for RealBreaker {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        if self.is_dead(destination) {
            return Err(Unavailable::Dead);
        }
        match self.unit.try_admit(pool, destination, now) {
            Ok(admit) => Ok(Admit {
                probe_epoch: admit.probe_epoch,
            }),
            Err(LaneState::Suppressed { until }) => Err(Unavailable::BreakerOpen { until }),
            Err(LaneState::BudgetExhausted) => Err(Unavailable::BudgetExhausted),
            Err(LaneState::ProbeInFlight | LaneState::Ready) => Err(Unavailable::ProbeInFlight),
        }
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        !self.is_dead(destination)
            && busbar_kernel_breaker::Breaker::state(&self.unit, pool, destination, now, token)
                == LaneState::Ready
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        !self.is_dead(destination) && self.unit.budget_remaining(destination) != Some(0)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        match busbar_kernel_breaker::Breaker::state(&self.unit, pool, destination, now, token) {
            LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        // The root adapter's own reading (`root::adapters`): no number crosses, the transport's
        // fault reading of the frame does; no class and no reading at all is no answer.
        let reading = if status.class.is_none() && status.fault.is_none() {
            busbar_kernel_breaker::classify::Reading::NoAnswer
        } else {
            busbar_kernel_breaker::classify::Reading::Answered(status.fault)
        };
        let classified = busbar_kernel_breaker::port::classify_upstream(
            busbar_kernel_breaker::port::UpstreamStatus {
                reading,
                retry_after: status.retry_after,
            },
        );
        Classified {
            disposition: classified.disposition,
            outcome: from_unit(classified.outcome),
            label: classified.label,
        }
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), destination, outcome));
        busbar_kernel_breaker::Breaker::observe(
            &self.unit,
            pool,
            destination,
            to_unit(outcome),
            &self.cfg,
            now,
            token,
        )
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.unit.suppressing(destination, now)
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        self.unit.probed(
            destination,
            to_unit(outcome),
            &|_: &str| Some(self.cfg.clone()),
            now,
            token,
        );
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, _now: u64) {
        self.unit.release_probe(pool, destination, epoch);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.unit.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.unit.refund_budget(destination);
    }
}

/// The node's production far end, its breaker the served one.
pub(super) fn real_egress(node: &Node, real: &Arc<RealBreaker>) -> Egress {
    let mut egress = node.egress();
    egress.breaker = Arc::clone(real) as Arc<dyn Breaker>;
    egress
}

/// A two-piece answer whose first piece states HTTP `status`, in its class.
pub(super) fn answer(status: u32) -> Vec<Reply> {
    let class = match status {
        200..=299 => WireStatusClass::Success,
        400..=499 => WireStatusClass::CallerFault,
        _ => WireStatusClass::FarEndFault,
    };
    // The fault reading a framer whose table follows its class states (`harness::frame`'s).
    let fault = match class {
        WireStatusClass::FarEndFault => Some(WireFault::Transient),
        WireStatusClass::CallerFault => Some(WireFault::Caller),
        _ => None,
    };
    vec![
        frame_with_upstream(
            Some(class),
            Some(WireStatus::new(status_ns::HTTP, status)),
            fault,
            None,
            "head",
        ),
        frame(Some(class), "end"),
    ]
}

/// The status a 200 answer's first piece hands the plane: the number and its class.
pub(super) fn ok_200() -> Option<(u32, u32)> {
    Some((200, u32::from(STATUS_SUCCESS)))
}

/// [`Node::route`] over `egress`: every attempt as the pump makes it, until an answer ends or the
/// walk refuses.
pub(super) async fn route_async(node: &Node, egress: &Egress, pool: &str) -> Routed {
    let token = route_token();
    let far = egress.unit(node.unit_route(pool));
    let mut attempt_no = 0;
    'attempt: loop {
        attempt_no += 1;
        let (member, pool) = match far.member(&token, attempt_no).await {
            Pick::Member { name, pool, .. } => (name, pool),
            Pick::Exhausted {
                status,
                retry_after,
                ..
            } => {
                return Routed::Refused(Refusal {
                    status,
                    retry_after,
                })
            }
            Pick::Vetoed { status, .. } => {
                return Routed::Refused(Refusal {
                    status,
                    retry_after: None,
                })
            }
            // A member credential refusal; none occurs in these walk proofs (the harness's own
            // route answers it the same way).
            Pick::Refused(_) => {
                return Routed::Refused(Refusal {
                    status: 502,
                    retry_after: None,
                })
            }
        };
        let destination = node.destination_of(&pool, &member);
        if !far
            .send(&token, super::request(&member, &pool, attempt_no))
            .await
        {
            continue 'attempt;
        }
        let mut served = Served {
            destination,
            pool,
            status: None,
            pieces: 0,
        };
        loop {
            let piece = far.next(&token).await.unwrap_or(FarPiece {
                last: true,
                ..FarPiece::default()
            });
            if piece.fail_over {
                continue 'attempt;
            }
            if served.status.is_none() {
                served.status = piece.status;
            }
            if !piece.fields && !piece.bytes.is_empty() {
                served.pieces += 1;
            }
            if piece.last {
                return Routed::Delivered(served);
            }
        }
    }
}

/// [`route_async`] on the node's paused runtime, bounded so a route that never resolves fails the
/// test instead of hanging it.
pub(super) fn route_over(node: &Node, egress: &Egress, pool: &str) -> Routed {
    node.rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(86_400), route_async(node, egress, pool))
            .await
            .expect("the route resolves; it never hangs")
    })
}

/// F25 row 95: rehomed from the retired engine crate's src/engine/tests/dial_refusal_failover_tests.rs::a_refused_primary_fails_over_to_the_next_lane.
/// The primary's dial is refused before any connection opens (the destination guard's refusal, as
/// the connector reports it to the far end; the name's resolution and the judgement are the
/// connector's): the walk moves on and the next member answers 200, the primary never got a
/// connection, and the served breaker has the primary cooling down on a transient in its cell.
#[test]
fn a_refused_primary_fails_over_to_the_next_lane() {
    let node = two_lane_pool();
    let real = RealBreaker::new();
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(answer(200)));

    let outcome = route_over(&node, &real_egress(&node, &real), "primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.destination == DestinationId::new(1) && d.status == ok_200()),
        "the next lane answered 200: {outcome:?}"
    );
    assert_eq!(
        node.conns.closed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the refused dial never opened a connection: the only one closed is the next lane's"
    );
    assert_eq!(
        real.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }]
    );
    let now = node.clock.now_secs();
    let token = route_token();
    assert!(
        !real.ready("primary", DestinationId::new(0), now, &token),
        "the refused lane is unusable: it cools down as a transient failure"
    );
    assert!(real.cooldown_remaining("primary", DestinationId::new(0), now, &token) > 0);
}

/// The degraded rig of rows 118-121: pool `primary`'s only member (`a`) is administratively dead,
/// so the pool spills into `fb`, whose member `b` has its `fb` cell expired-Open (its recovery probe
/// due). `b` answers with `script`.
fn fallback_probe_rig(script: Script) -> (Node, Arc<RealBreaker>) {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.pool("fb", vec![member(DestinationId::new(1), "b")]);
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("fb".to_string());
    });
    node.conns.script("a", Script::Frames(answer(200)));
    node.conns.script("b", script);
    let real = RealBreaker::new();
    real.kill(DestinationId::new(0));
    let now = node.clock.now_secs();
    let _ = real
        .cell("fb", DestinationId::new(1))
        .hard_down(now.saturating_sub(10), 0);
    assert!(
        matches!(
            real.cell("fb", DestinationId::new(1)).state(),
            BreakerState::Open { until } if until < now
        ),
        "precondition: the fb pool cell is expired-Open"
    );
    (node, real)
}

/// F25 row 118: rehomed from the retired engine crate's src/engine/tests/forward_once_pool_cell_tests.rs::test_forward_once_fallback_2xx_closes_pool_cell_not_default.
/// A fallback-pool member whose cell is probing answers 200: it is relayed, the FALLBACK POOL's
/// cell goes HalfOpen to Closed, and the default cell is untouched (Closed, nothing recorded).
#[test]
fn test_forward_once_fallback_2xx_closes_pool_cell_not_default() {
    let (node, real) = fallback_probe_rig(Script::Frames(answer(200)));
    let b = DestinationId::new(1);

    let outcome = route_over(&node, &real_egress(&node, &real), "primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "fb" && d.destination == b && d.status == ok_200()),
        "the fallback pool must serve the 2xx: {outcome:?}"
    );
    assert_eq!(
        real.cell("fb", b).state(),
        BreakerState::Closed,
        "the fb POOL cell closes on the 2xx"
    );
    assert_eq!(real.outcomes("fb", b), vec![Outcome::Success]);
    assert_eq!(
        real.cell("", b).state(),
        BreakerState::Closed,
        "the default cell stays Closed: the recording targeted the pool cell"
    );
    assert!(real.outcomes("", b).is_empty());
}

/// F25 row 119: rehomed from the retired engine crate's src/engine/tests/forward_once_pool_cell_tests.rs::test_forward_once_fallback_transport_error_opens_pool_cell.
/// The same rig with the fallback member's dial refused while its cell is probing: the failed probe
/// reopens the FALLBACK POOL's cell with a fresh cooldown (Open, not wedged HalfOpen), the chain is
/// spent, and the default cell is untouched.
#[test]
fn test_forward_once_fallback_transport_error_opens_pool_cell() {
    let (node, real) = fallback_probe_rig(Script::DialError(ConnError::Refused));
    let b = DestinationId::new(1);

    let outcome = route_over(&node, &real_egress(&node, &real), "primary");

    assert_eq!(
        outcome.shed().map(|r| r.status),
        Some(u32::from(STATUS_SERVICE_UNAVAILABLE)),
        "{outcome:?}"
    );
    let now = node.clock.now_secs();
    assert!(
        matches!(real.cell("fb", b).state(), BreakerState::Open { until } if until > now),
        "the fb POOL cell reopens with a fresh cooldown; got {:?}",
        real.cell("fb", b).state()
    );
    assert_eq!(
        real.outcomes("fb", b),
        vec![Outcome::Transient { retry_after: None }]
    );
    assert_eq!(
        real.cell("", b).state(),
        BreakerState::Closed,
        "the default cell stays Closed"
    );
}

/// F25 row 120: rehomed from the retired engine crate's src/engine/tests/forward_once_pool_cell_tests.rs::test_forward_once_fallback_5xx_fault_trips_and_releases_probe.
/// The same rig with the probing fallback member answering 503: the 503 is relayed, the probe is
/// resolved (the cell is not wedged HalfOpen), the cooldown is extended by the backoff so an
/// immediate admission is refused, a day on the cell admits again, and the default cell is
/// untouched.
#[test]
fn test_forward_once_fallback_5xx_fault_trips_and_releases_probe() {
    let (node, real) = fallback_probe_rig(Script::Frames(answer(503)));
    let b = DestinationId::new(1);

    let outcome = route_over(&node, &real_egress(&node, &real), "primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "fb" && d.status == Some((503, u32::from(STATUS_FAR_END_FAULT)))),
        "the fallback pool relays the upstream 503 verbatim: {outcome:?}"
    );
    assert_ne!(
        real.cell("fb", b).state(),
        BreakerState::HalfOpen,
        "the fb POOL cell must not be wedged HalfOpen after the 503"
    );
    assert_eq!(
        real.outcomes("fb", b),
        vec![Outcome::Transient { retry_after: None }],
        "the 503 records a transient against the probing cell"
    );
    let now = node.clock.now_secs();
    assert!(
        real.unit.try_admit("fb", b, now).is_err(),
        "the cooldown is extended by the backoff: no immediate re-probe"
    );
    assert!(
        real.unit.try_admit("fb", b, now + 86_400).is_ok(),
        "the cell admits again once the backoff has passed"
    );
    assert_eq!(real.cell("", b).state(), BreakerState::Closed);
}

/// F25 row 121: rehomed from the retired engine crate's src/engine/tests/forward_once_pool_cell_tests.rs::test_forward_once_fallback_client_4xx_does_not_trip_breaker.
/// The same rig with the probing fallback member answering 400 (the caller's own fault): the 400 is
/// relayed, nothing is recorded against the member, the probe is given back (Open, not HalfOpen)
/// with its expired cooldown intact, so the cell admits again at once; the default cell is
/// untouched.
#[test]
fn test_forward_once_fallback_client_4xx_does_not_trip_breaker() {
    let (node, real) = fallback_probe_rig(Script::Frames(answer(400)));
    let b = DestinationId::new(1);

    let outcome = route_over(&node, &real_egress(&node, &real), "primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "fb" && d.status == Some((400, u32::from(STATUS_CALLER_FAULT)))),
        "the fallback pool relays the client-error 400 verbatim: {outcome:?}"
    );
    assert!(
        matches!(real.cell("fb", b).state(), BreakerState::Open { .. }),
        "the probe is given back, not wedged HalfOpen; got {:?}",
        real.cell("fb", b).state()
    );
    assert_eq!(
        real.cell("fb", b).err_count(),
        0,
        "a client-error 400 records no failure"
    );
    let now = node.clock.now_secs();
    assert!(
        real.unit.try_admit("fb", b, now).is_ok(),
        "no backoff was recorded: the fb POOL cell is re-acquirable at once"
    );
    assert_eq!(real.cell("", b).state(), BreakerState::Closed);
}

/// F25 row 135: rehomed from the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_max_requests_budget_caps_lane_and_counts_ok.
/// A lane with a lifetime budget of 2 in pool `pc`: requests 1 and 2 are served 200, request 3 is
/// refused 503; the lane's cell holds exactly two successes and no failure, its budget is spent,
/// and it is no longer usable.
#[test]
fn test_max_requests_budget_caps_lane_and_counts_ok() {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.pool("pc", vec![member(lane, "glm-4.6")]);
    node.conns.script("a", Script::Frames(answer(200)));
    let real = RealBreaker::new();
    real.unit.set_budget(lane, 2);
    let egress = real_egress(&node, &real);

    for n in 1..=2 {
        let outcome = route_over(&node, &egress, "pc");
        assert!(
            matches!(&outcome, Routed::Delivered(d) if d.status == ok_200()),
            "request {n} is within the budget and served: {outcome:?}"
        );
    }
    let third = route_over(&node, &egress, "pc");
    assert_eq!(
        third.shed().map(|r| r.status),
        Some(u32::from(STATUS_SERVICE_UNAVAILABLE)),
        "the third request is refused once the max_requests budget is spent: {third:?}"
    );

    let now = node.clock.now_secs();
    assert_eq!(real.unit.budget_remaining(lane), Some(0));
    assert_eq!(
        real.outcomes("pc", lane),
        vec![Outcome::Success, Outcome::Success],
        "each success is recorded against the lane"
    );
    assert_eq!(
        real.cell("pc", lane).outcomes_in_window(now, 60),
        (2, 0),
        "the lane's cell holds the two successes and no failure"
    );
    assert!(
        !real.admissible(lane),
        "the lane is unusable once its max_requests budget is spent"
    );
    assert!(real.unit.try_admit("pc", lane, now).is_err());
}

/// F25 row 136: rehomed from the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_failover_exclusions_remove_member_from_pool.
/// A pool's `failover.exclusions` removes the named member: five requests over a pool of `alpha`
/// and `beta` with `beta` excluded are all served by `alpha`, and `beta` is never dialled and has
/// nothing recorded.
#[test]
fn test_failover_exclusions_remove_member_from_pool() {
    let (alpha, beta) = (DestinationId::new(0), DestinationId::new(1));
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool("pe", vec![member(alpha, "alpha"), member(beta, "beta")]);
    node.tune("pe", |p| p.failover.exclusions = vec!["beta".to_string()]);
    node.conns.script("a", Script::Frames(answer(200)));
    node.conns.script("b", Script::Frames(answer(200)));
    let real = RealBreaker::new();
    let egress = real_egress(&node, &real);

    for n in 0..5 {
        let outcome = route_over(&node, &egress, "pe");
        assert!(
            matches!(&outcome, Routed::Delivered(d)
                if d.destination == alpha && d.status == ok_200()),
            "the excluded member must never serve; request {n}: {outcome:?}"
        );
    }
    assert_eq!(node.conns.dialled(), vec!["a".to_string(); 5]);
    assert!(
        real.outcomes("pe", beta).is_empty(),
        "the excluded lane has nothing recorded"
    );
    assert_eq!(
        real.cell("pe", beta)
            .outcomes_in_window(node.clock.now_secs(), 60),
        (0, 0),
        "the excluded lane has 0 successes"
    );
    assert_eq!(real.successes("pe"), 5);
}

/// F25 row 155: rehomed from the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_permit_lifetime_during_stream.
/// A lane of one concurrency slot streams a five-piece answer: the slot is free before the request,
/// held while the stream is relayed (after its 200 head), and free again once it is drained. The
/// test is the plane: it states its reading of every far-end piece it is handed, as the plane
/// driver does for each one (`plane_driver::route`'s `judged_stating`), so the last one's reading
/// settles the attempt.
#[test]
fn test_permit_lifetime_during_stream() {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.pool("default", vec![member(lane, "test-model")]);
    node.wants_stream = true;
    node.capacity.set_ceiling(lane, 1);
    let mut replies = vec![frame_with_upstream(
        Some(WireStatusClass::Success),
        Some(WireStatus::new(status_ns::HTTP, 200)),
        None,
        None,
        "data-0",
    )];
    replies.extend((1..5).map(|_| frame(Some(WireStatusClass::Success), "data-n")));
    node.conns.script(
        "a",
        Script::Drip {
            replies,
            step_ms: 10,
            complete: true,
        },
    );
    assert!(
        node.capacity.try_acquire(lane).is_some(),
        "the lane's one permit is free before the request"
    );

    let egress = node.egress();
    let token = route_token();
    let far = egress.unit(node.unit_route("default"));
    node.rt.block_on(async {
        let Pick::Member { name, pool, .. } = far.member(&token, 1).await else {
            panic!("a member to send to");
        };
        assert!(far.send(&token, super::request(&name, &pool, 1)).await);
        let head = far.next(&token).await.expect("the stream's first piece");
        far.judged(&token, FAULT_NONE);
        assert_eq!(head.status, ok_200());
        assert!(!head.last && !head.fail_over, "{head:?}");
        assert!(
            node.capacity.try_acquire(lane).is_none(),
            "the permit is held while the stream is relayed"
        );
        let mut pieces = 1;
        loop {
            let piece = far.next(&token).await.expect("the rest of the stream");
            far.judged(&token, FAULT_NONE);
            if !piece.fields && !piece.bytes.is_empty() {
                pieces += 1;
            }
            if piece.last {
                break;
            }
        }
        assert_eq!(pieces, 5, "the whole stream was relayed");
        assert!(
            node.capacity.try_acquire(lane).is_some(),
            "the permit is released once the stream is drained"
        );
    });
}

/// F25 row 364: rehomed from the retired engine crate's src/engine/tests/ingress_indistinguishability_tests.rs::test_repeated_pre_first_byte_failures_trip_breaker.
/// Three consecutive streamed attempts on pool `p`'s member, each a 200 head cut before its first
/// byte: every cut is counted against the pool cell (its error count 1, 2, 3), the cell stays
/// Closed after the first two and is Open after the third. Through the far end each head records
/// its optimistic success first (as 1.5.5's did), which resets a consecutive streak, so the trip is
/// read on the error-rate ladder: 3 cuts among 6 outcomes reach its 0.5 threshold at its 5-outcome
/// floor exactly on the third attempt, and without the cuts the window holds successes only.
#[test]
fn test_repeated_pre_first_byte_failures_trip_breaker() {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["m"]);
    node.pool("p", vec![member(lane, "m")]);
    node.wants_stream = true;
    node.conns.script(
        "m",
        Script::Truncated(frame_with_upstream(
            Some(WireStatusClass::Success),
            Some(WireStatus::new(status_ns::HTTP, 200)),
            None,
            None,
            "",
        )),
    );
    let real = RealBreaker::with_cfg(BreakerCfg {
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        },
        // A sub-threshold failure benches nothing, so the next attempt is admitted at once.
        bench_below_trip_threshold: false,
        ..BreakerCfg::default()
    });
    let egress = real_egress(&node, &real);

    for attempt in 1..=3u64 {
        let outcome = route_over(&node, &egress, "p");
        assert!(
            matches!(&outcome, Routed::Delivered(d) if d.pieces == 0),
            "attempt {attempt}: the cut came before the first byte: {outcome:?}"
        );
        let cell = real.cell("p", lane);
        assert_eq!(
            cell.err_count(),
            attempt,
            "attempt {attempt}: the pre-first-byte cut is counted"
        );
        if attempt < 3 {
            assert_eq!(
                cell.state(),
                BreakerState::Closed,
                "attempt {attempt}: below the threshold the cell stays Closed"
            );
        } else {
            assert!(
                matches!(cell.state(), BreakerState::Open { .. }),
                "the 3rd pre-first-byte cut trips the cell Closed to Open; got {:?}",
                cell.state()
            );
        }
    }
}

/// One post-first-byte transport cut on pool `p`'s member, whose lifetime budget is one unit; the
/// caller asked for a streamed answer when `stream`. Answers whether the unit the head spent came
/// back: a fresh spend succeeds.
fn refunded_after_a_post_first_byte_cut(stream: bool) -> bool {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["m"]);
    node.pool("p", vec![member(lane, "m")]);
    node.wants_stream = stream;
    node.conns.script(
        "m",
        Script::Truncated(frame_with_upstream(
            Some(WireStatusClass::Success),
            Some(WireStatus::new(status_ns::HTTP, 200)),
            None,
            None,
            "{\"id\":\"x\",",
        )),
    );
    let real = RealBreaker::new();
    real.unit.set_budget(lane, 1);

    let outcome = route_over(&node, &real_egress(&node, &real), "p");

    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.pieces == 1),
        "stream={stream}: the first chunk reached the plane before the cut: {outcome:?}"
    );
    assert_eq!(
        real.outcomes("p", lane),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "stream={stream}: the head's success, then the cut's compensating transient"
    );
    assert_eq!(
        real.unit.budget_remaining(lane),
        Some(if stream { 0 } else { 1 }),
        "stream={stream}"
    );
    real.unit.spend_budget(lane)
}

/// F25 row 366: rehomed from the retired engine crate's src/engine/tests/ingress_indistinguishability_tests.rs::test_streaming_nonsse_post_first_byte_cut_refunds_the_lane_unit.
/// The same post-first-byte transport cut, a lane budget of one: on a buffered (non-SSE) answer the
/// head's unit comes back (a second spend succeeds); on a streamed (SSE) answer it is kept (a
/// second spend fails). Both arms in one test: the rule is that they differ.
#[test]
fn test_streaming_nonsse_post_first_byte_cut_refunds_the_lane_unit() {
    assert!(
        refunded_after_a_post_first_byte_cut(false),
        "a post-first-byte transport cut on a NON-SSE body refunds the lane's max_requests unit"
    );
    assert!(
        !refunded_after_a_post_first_byte_cut(true),
        "a post-first-byte transport cut on an SSE body KEEPS the lane's max_requests unit"
    );
}

/// F25 row 587: rehomed from the retired engine crate's src/engine/tests/reroute_pool_tests.rs::a_saturated_primary_is_passed_over_inside_the_one_loop_and_the_twin_serves.
/// A breaker-healthy primary whose one slot is held is offered by the order, refused by the
/// admission and passed over inside the one loop: the twin serves 200 and the primary is never
/// dialled.
#[test]
fn a_saturated_primary_is_passed_over_inside_the_one_loop_and_the_twin_serves() {
    let (primary, twin) = (DestinationId::new(0), DestinationId::new(1));
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool("", vec![member(primary, "primary"), member(twin, "twin")]);
    node.conns.script("a", Script::Frames(answer(200)));
    node.conns.script("b", Script::Frames(answer(200)));
    node.capacity.set_ceiling(primary, 1);
    let held = node.capacity.saturate(primary);

    let outcome = node.route("");

    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == twin && d.status == ok_200()),
        "a saturated primary must be passed over to the twin: {outcome:?}"
    );
    assert_eq!(
        node.conns.dialled(),
        vec!["b".to_string()],
        "the saturated primary is never dispatched to"
    );
    assert_eq!(
        node.breaker.pick_order(),
        vec![primary, twin],
        "the order offered the primary and the admission refused it, inside the one loop"
    );
    drop(held);
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
