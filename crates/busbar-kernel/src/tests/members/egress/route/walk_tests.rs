// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::transport::STATUS_CALLER_FAULT;
use busbar_contract::conn::ConnError;
use busbar_contract::transport::registry::status_ns;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::wire::{WireFault, WireStatus};

use super::harness::{frame, frame_with_upstream, ok_frames, Health, Script};
use super::{member, Node, Routed};
use busbar_contract::DestinationId;
use busbar_kernel_egress::ports::{disposition, Outcome};

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

    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(0)
            && d.status.map(|(code, _)| code) == Some(403)),
        "a hard-down member's answer is relayed to the plane, not failed over: {outcome:?}"
    );
}

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

use super::harness::Reply;
use crate::plane_driver::{Egress, FarEnd, Pick};

pub(super) struct RealBreaker {
    pub(super) unit: BreakerUnit,
    cfg: BreakerCfg,
    dead: Mutex<Vec<DestinationId>>,
    observed: Mutex<Vec<(String, DestinationId, Outcome)>>,
}

impl RealBreaker {
    pub(super) fn new() -> Arc<Self> {
        Self::with_cfg(BreakerCfg::default())
    }

    pub(super) fn with_cfg(cfg: BreakerCfg) -> Arc<Self> {
        Arc::new(Self {
            unit: BreakerUnit::new(),
            cfg,
            dead: Mutex::new(Vec::new()),
            observed: Mutex::new(Vec::new()),
        })
    }

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

    pub(super) fn cell(&self, pool: &str, destination: DestinationId) -> Arc<BreakerCell> {
        self.unit.cell(pool, destination)
    }

    pub(super) fn outcomes(&self, pool: &str, destination: DestinationId) -> Vec<Outcome> {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(p, d, _)| p == pool && *d == destination)
            .map(|(_, _, o)| *o)
            .collect()
    }

    pub(super) fn successes(&self, pool: &str) -> usize {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(p, _, o)| p == pool && *o == Outcome::Success)
            .count()
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
        self.unit
            .try_admit(pool, destination, now)
            .map_err(|state| match state {
                LaneState::Suppressed { until } => Unavailable::BreakerOpen { until },
                LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                LaneState::ProbeInFlight | LaneState::Ready => Unavailable::ProbeInFlight,
            })
    }

    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        if self.is_dead(destination) {
            return Some(Unavailable::Dead);
        }
        match busbar_kernel_breaker::Breaker::state(&self.unit, pool, destination, now, token) {
            busbar_kernel_breaker::LaneState::Ready => None,
            busbar_kernel_breaker::LaneState::Suppressed { until } => {
                Some(Unavailable::BreakerOpen { until })
            }
            busbar_kernel_breaker::LaneState::BudgetExhausted => Some(Unavailable::BudgetExhausted),
            busbar_kernel_breaker::LaneState::ProbeInFlight => Some(Unavailable::ProbeInFlight),
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
        let reading = if status.class.is_none() && status.fault.is_none() {
            busbar_kernel_breaker::classify::Reading::NoAnswer
        } else {
            busbar_kernel_breaker::classify::Reading::Answered(status.fault)
        };
        busbar_kernel_breaker::port::classify_upstream(
            busbar_kernel_breaker::port::UpstreamStatus {
                reading,
                retry_after: status.retry_after,
            },
        )
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
            outcome,
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
            outcome,
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

pub(super) fn real_egress(node: &Node, real: &Arc<RealBreaker>) -> Egress {
    let mut egress = node.egress();
    egress.breaker = crate::plane_driver::fixed_breaker(Arc::clone(real) as Arc<dyn Breaker>);
    egress
}

pub(super) fn answer(status: u32) -> Vec<Reply> {
    let class = match status {
        200..=299 => WireStatusClass::Success,
        400..=499 => WireStatusClass::CallerFault,
        _ => WireStatusClass::FarEndFault,
    };

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

pub(super) fn ok_200() -> Option<(u32, u32)> {
    Some((200, u32::from(STATUS_SUCCESS)))
}

pub(super) fn route_over(node: &Node, egress: &Egress, pool: &str) -> Routed {
    node.rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(86_400),
            node.route_on(egress, pool, |_, _| {}),
        )
        .await
        .expect("the route resolves; it never hangs")
    })
}

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
    let token = Pass::<busbar_contract::caps::Route>::mint(&crate::seal::acquire());
    assert!(
        !real.ready("primary", DestinationId::new(0), now, &token),
        "the refused lane is unusable: it cools down as a transient failure"
    );
    assert!(real.cooldown_remaining("primary", DestinationId::new(0), now, &token) > 0);
}

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
    let token = Pass::<busbar_contract::caps::Route>::mint(&crate::seal::acquire());
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
