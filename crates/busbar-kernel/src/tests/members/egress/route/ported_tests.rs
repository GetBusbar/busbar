// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The previous release's engine tests whose behaviour now lives in the walk: the last resort, the
//! spill, the wait and the shed when a pool is spent, session affinity over a member that cannot
//! take the request, a member's slot across a streamed answer, and a hang on the degraded walk.
//!
//! Each test names the legacy test it carries over and keeps that test's inputs and expected
//! outcome; only the harness is new. Where the old test drove a real far end and read the lane
//! store, this one drives the production far end over the scripted node and reads the breaker,
//! the permit store and the connection table the walk wrote to. Where the old test measured a wall
//! clock, this one reads the node's paused clock, which the walk's own deadline also reads, so a
//! bound the old test could only say was "not parked to the deadline" is checked exactly here.
//!
//! The waits that need a slot freed while two requests are parked run over [`Slots`], a permit
//! store that hands a freed slot to the longest waiter once, as the node's own store does.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::DestinationId;
use busbar_kernel_egress::exhaustion::AT_CAPACITY_RETRY_AFTER_SECS;
use busbar_kernel_egress::pool::OnExhausted;
use busbar_kernel_egress::ports::{
    BoxFut, Capacity, Clock, Outcome, Permit, PermitHandle, Unavailable,
};
use busbar_kernel_egress::walk::{Step, Walk, WalkPorts};
use busbar_kernel_egress::wire::{DETAIL_OVERLOADED, STATUS_SERVICE_UNAVAILABLE};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::harness::{frame, ok_frames, Health, Script};
use super::{member, request, route_token, Node, Routed, STREAM_CEILING_SECS};
use crate::plane_driver::{FarEnd, FarPiece, Pick};

const D0: DestinationId = DestinationId::new(0);
const D1: DestinationId = DestinationId::new(1);
const D2: DestinationId = DestinationId::new(2);

/// The previous release's failover budget for these worlds, seconds: small enough that a request
/// parked to the deadline is told apart from one shed at once.
const FAILOVER_SECS: u64 = 2;

fn cooling(secs: u64) -> Health {
    Health {
        cooldown: secs,
        ..Health::default()
    }
}

fn delivered(outcome: &Routed) -> (DestinationId, String) {
    match outcome {
        Routed::Delivered(d) => (d.destination, d.pool.clone()),
        Routed::Refused(r) => panic!("expected an answer, got the refusal {r:?}"),
    }
}

// ── a member's slot across a streamed answer ─────────────────────────────────────────────────────

/// Ports legacy `forward_pool_integration_tests.rs::test_permit_lifetime_during_stream`: the
/// member's one concurrency slot is held for as long as its streamed answer is open, and given back
/// once the body completed.
#[test]
fn a_streamed_answer_holds_its_members_slot_until_its_body_completes() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("default", vec![member(D0, "a")]);
    node.wants_stream = true;
    node.capacity.set_ceiling(D0, 1);
    node.conns.script(
        "a",
        Script::Drip {
            replies: (0..5)
                .map(|_| frame(Some(WireStatusClass::Success), "data"))
                .collect(),
            step_ms: 10,
            complete: true,
        },
    );
    assert!(
        node.capacity.try_acquire(D0).is_some(),
        "the slot is free before the request"
    );

    let egress = node.egress();
    let token = route_token();
    let far = egress.unit(node.unit_route("default"));
    let pieces = node.rt.block_on(async {
        let Pick::Member { name, pool, .. } = far.member(&token, 1).await else {
            panic!("a member to send to");
        };
        assert!(far.send(&token, request(&name, &pool, 1)).await);
        let first = far.next(&token).await.expect("the answer's first piece");
        assert!(!first.fail_over && !first.last, "{first:?}");
        assert!(
            node.capacity.try_acquire(D0).is_none(),
            "the slot is held while the streamed answer is open"
        );
        let mut pieces = 1;
        loop {
            let piece = far.next(&token).await.unwrap_or(FarPiece {
                last: true,
                ..FarPiece::default()
            });
            assert!(!piece.fail_over, "{piece:?}");
            if piece.last {
                break pieces;
            }
            pieces += 1;
            assert!(
                node.capacity.try_acquire(D0).is_none(),
                "the slot is held for every piece of the answer"
            );
        }
    });
    assert!(pieces >= 5, "the whole answer was read: {pieces} pieces");
    drop(far);
    assert!(
        node.capacity.try_acquire(D0).is_some(),
        "the slot is given back once the body completed"
    );
}

// ── the last resort ─────────────────────────────────────────────────────────────────────────────

/// Ports legacy `forward_pool_integration_tests.rs::test_forward_once_records_success_and_spends_budget`:
/// the last resort's dispatch is recorded like any other: its 2xx is a success on the member's cell
/// and spends one unit of the member's lifetime budget.
#[test]
fn the_last_resorts_answer_records_a_success_and_spends_the_budget_unit() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("leastbad", vec![member(D0, "a")]);
    node.tune("leastbad", |p| p.on_exhausted = OnExhausted::LeastBad);
    node.breaker.set(
        D0,
        Health {
            cooldown: 600,
            budget_remaining: Some(2),
            ..Health::default()
        },
    );
    node.conns.script("a", Script::Frames(ok_frames()));

    let outcome = node.route("leastbad");
    assert_eq!(delivered(&outcome).0, D0, "the last resort serves the 2xx");
    assert_eq!(
        node.breaker.outcomes("leastbad", D0),
        vec![Outcome::Success],
        "the degraded dispatch records its success, or a half-open member never recovers"
    );
    assert_eq!(
        node.breaker.budget_net(D0),
        1,
        "the degraded dispatch spends the member's budget unit"
    );
}

/// Ports legacy `on_exhausted_tests.rs::least_bad_still_serves_the_only_member_after_it_was_tried`:
/// the last resort ranks the pool's membership, not what this request has not tried yet, so a pool's
/// only member is still served after the request already took it.
#[test]
fn the_last_resort_still_serves_the_only_member_after_it_was_tried() {
    // The previous release's case: the only member is suppressed.
    let mut node = Node::with_lanes(&["solo"]);
    node.pool("ps", vec![member(D0, "solo")]);
    node.tune("ps", |p| p.on_exhausted = OnExhausted::LeastBad);
    node.breaker.set(D0, cooling(30));
    node.conns.script("solo", Script::Frames(ok_frames()));
    let outcome = node.route("ps");
    assert_eq!(
        delivered(&outcome).0,
        D0,
        "the last resort must still override the suppression for the member"
    );

    // And the case its name states: the member was taken once already by this very request.
    let mut node = Node::with_lanes(&["solo"]);
    node.pool("ps", vec![member(D0, "solo")]);
    node.tune("ps", |p| p.on_exhausted = OnExhausted::LeastBad);
    let mut walker = node.walker("ps");
    let first = walker.take();
    assert_eq!(first.member.destination, D0);
    assert!(!first.degraded);
    drop(first);
    let again = walker.take();
    assert_eq!(
        again.member.destination, D0,
        "the member the request already tried is still the last resort's"
    );
    assert!(again.degraded, "and the dispatch is the degraded one");
}

/// Ports legacy `send_envelope_tests.rs::a_black_holed_stream_send_on_the_degraded_walk_times_out_at_the_ceiling`:
/// a member that accepts the request and never sends its head is cut on the degraded walk by the
/// same bound that cuts it on the ordered walk, and the hang is recorded against it.
#[test]
fn a_silent_member_on_the_last_resort_is_cut_by_the_same_bound_as_on_the_ordered_walk() {
    let walk = |least_bad: bool| {
        let mut node = Node::with_lanes(&["a"]);
        node.pool("p", vec![member(D0, "a")]);
        node.wants_stream = true;
        node.conns.script("a", Script::Hang);
        if least_bad {
            node.tune("p", |p| p.on_exhausted = OnExhausted::LeastBad);
            node.breaker.set(D0, cooling(300));
        }
        let started = node.clock.now_millis();
        let outcome = node.route("p");
        let elapsed = node.clock.now_millis() - started;
        let refused = outcome.shed().map(|r| r.status);
        (refused, elapsed, node.breaker.outcomes("p", D0), node)
    };
    let (ordered, ordered_ms, _, _) = walk(false);
    let (degraded, degraded_ms, recorded, node) = walk(true);
    assert_eq!(
        degraded,
        Some(u32::from(STATUS_SERVICE_UNAVAILABLE)),
        "a silent head on the degraded walk ends in an upstream-failure status, never a hang"
    );
    assert_eq!(ordered, degraded);
    assert_eq!(
        degraded_ms, ordered_ms,
        "the degraded walk's send rides the same bound as the ordered walk's"
    );
    assert!(
        degraded_ms <= u128::from(STREAM_CEILING_SECS * 1000),
        "and never runs past the stream ceiling: {degraded_ms}ms"
    );
    assert_eq!(
        degraded_ms,
        u128::from(node.timeout_secs * 1000),
        "cut at the walk's budget"
    );
    assert_eq!(
        recorded,
        vec![Outcome::Transient { retry_after: None }],
        "the expiry on the degraded walk records the transient against the member"
    );
}

// ── session affinity over a member that cannot take the request ─────────────────────────────────

/// Ports legacy `forward_pool_integration_tests.rs::test_sticky_yields_when_tripped`: a session
/// whose affinity lands on a suppressed member is served by the healthy one, and the suppressed one
/// is never dialled.
#[test]
fn a_session_pinned_to_a_suppressed_member_yields_to_the_healthy_one() {
    let two = || {
        let mut node = Node::with_lanes(&["lane0", "lane1"]);
        node.pool(
            "failover-test",
            vec![member(D0, "lane0"), member(D1, "lane1")],
        );
        // The affinity hash lands on position zero, the first member.
        node.affinity = Some(0);
        node
    };
    // The control: with nothing wrong, the session lands on the first member, so the case below
    // really is the sticky member being the suppressed one.
    let healthy = two();
    assert_eq!(delivered(&healthy.route("failover-test")).0, D0);

    let node = two();
    node.breaker.set(D0, cooling(600));
    let outcome = node.route("failover-test");
    assert_eq!(
        delivered(&outcome).0,
        D1,
        "the sticky member is suppressed, so the healthy member serves"
    );
    assert_eq!(
        node.conns.dialled(),
        vec!["lane1".to_string()],
        "the suppressed sticky member is never dialled"
    );
}

/// Ports legacy `ordered_walk_tests.rs::sticky_fall_through_records_reason`: a session whose
/// affinity lands on a member at capacity falls through, and the exclusion records why.
#[test]
fn a_session_pinned_to_a_member_at_capacity_falls_through_recording_why() {
    let mut node = Node::with_lanes(&["m0"]);
    node.affinity = Some(0x5e55_1011);
    let members = vec![member(D0, "m0")];
    node.capacity.set_ceiling(D0, 1);
    let held = node.capacity.saturate(D0);

    let mut ctx = node.request_ctx();
    assert!(
        node.pick("p", &members, &mut ctx).is_none(),
        "the sticky member at capacity yields no pick"
    );
    assert!(
        ctx.excluded_reasons()
            .iter()
            .any(|(d, why)| *d == D0 && matches!(why, Unavailable::AtCapacity { .. })),
        "the sticky fall-through records its reason, got {:?}",
        ctx.excluded_reasons()
    );
    drop(held);
}

// ── the spill from a pool that is merely busy ───────────────────────────────────────────────────

/// A primary pool of `busy` members every one at capacity, spilling into `overflow`'s free member.
/// Lanes: the busy members first, then the overflow member.
fn busy_primary(busy: usize) -> (Node, Vec<Permit>) {
    // The busy members' lanes, then the fast overflow member's.
    let lanes: &[&'static str] = match busy {
        1 => &["slow", "fast"],
        _ => &["slowA", "slowB", "fast"],
    };
    let mut node = Node::with_lanes(lanes);
    node.timeout_secs = 300;
    node.pool(
        "primary",
        (0..busy)
            .map(|d| member(DestinationId::new(d as u64), lanes[d]))
            .collect(),
    );
    let fast = DestinationId::new(busy as u64);
    node.pool("overflow", vec![member(fast, lanes[busy])]);
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("overflow".to_string());
    });
    let held = (0..busy)
        .map(|d| {
            let d = DestinationId::new(d as u64);
            node.capacity.set_ceiling(d, 1);
            node.capacity.saturate(d)
        })
        .collect();
    (node, held)
}

/// Ports legacy `lane_availability_proptest_tests.rs::bug1_witness_fallback_spills_served_by_fallback_not_primary`:
/// a breaker-healthy primary at capacity under `fallback_pool` spills; the fallback serves and the
/// primary serves nothing, never parked and then served once its slot frees.
#[test]
fn a_healthy_primary_at_capacity_spills_and_the_fallback_serves() {
    let (mut node, held) = busy_primary(1);
    node.timeout_secs = FAILOVER_SECS;
    let outcome = node.route("primary");
    assert_eq!(
        delivered(&outcome),
        (D1, "overflow".to_string()),
        "the fallback pool serves the spilled request"
    );
    assert!(
        node.breaker.outcomes("primary", D0).is_empty(),
        "the primary at capacity served nothing"
    );
    assert_eq!(node.conns.dialled(), vec!["fast".to_string()]);
    drop(held);
}

/// Ports legacy `on_exhausted_tests.rs::at_capacity_fallback_spills_to_fast_member`: the
/// saturated primary does not serialize the request; it spills at once to the fallback's fast
/// member, and the primary serves nothing.
#[test]
fn a_saturated_primary_spills_at_once_to_the_fallbacks_fast_member() {
    let (node, held) = busy_primary(1);
    let started = node.clock.now_millis();
    let outcome = node.route("primary");
    assert_eq!(
        node.clock.now_millis() - started,
        0,
        "the spill happens at once, never parked behind the busy slot"
    );
    assert_eq!(delivered(&outcome), (D1, "overflow".to_string()));
    assert_eq!(
        node.breaker.outcomes("overflow", D1),
        vec![Outcome::Success],
        "the fast overflow member serves the spilled request"
    );
    assert!(node.breaker.outcomes("primary", D0).is_empty());
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 0);
    drop(held);
}

/// Ports legacy `on_exhausted_tests.rs::at_capacity_all_members_busy_two_member_pool_spills`: a
/// pool whose two members are both at their one-slot capacity is exhausted and spills.
#[test]
fn a_pool_whose_every_member_is_busy_spills() {
    let (node, held) = busy_primary(2);
    let outcome = node.route("primary");
    assert_eq!(
        delivered(&outcome),
        (D2, "overflow".to_string()),
        "with every member at capacity the pool is exhausted and spills"
    );
    assert!(node.breaker.outcomes("primary", D0).is_empty());
    assert!(node.breaker.outcomes("primary", D1).is_empty());
    assert_eq!(node.conns.dialled(), vec!["fast".to_string()]);
    drop(held);
}

/// Ports legacy `on_exhausted_tests.rs::at_capacity_fallback_chain_spills_through_to_third_pool`:
/// A spills to B, B is at capacity too and spills to C, and C serves.
#[test]
fn saturation_spills_through_a_chain_until_a_pool_can_serve() {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    node.timeout_secs = 300;
    node.pool("pa", vec![member(D0, "a")]);
    node.pool("pb", vec![member(D1, "b")]);
    node.pool("pc", vec![member(D2, "c")]);
    node.tune("pa", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("pb".to_string());
    });
    node.tune("pb", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("pc".to_string());
    });
    let held: Vec<Permit> = [D0, D1]
        .into_iter()
        .map(|d| {
            node.capacity.set_ceiling(d, 1);
            node.capacity.saturate(d)
        })
        .collect();

    let outcome = node.route("pa");
    assert_eq!(
        delivered(&outcome),
        (D2, "pc".to_string()),
        "the at-capacity signal cascades through the whole chain to the pool that can serve"
    );
    assert!(node.breaker.outcomes("pa", D0).is_empty());
    assert!(node.breaker.outcomes("pb", D1).is_empty());
    assert_eq!(node.conns.dialled(), vec!["c".to_string()]);
    drop(held);
}

/// Ports legacy `lane_availability_proptest_tests.rs::budget_contract_holds_under_full_saturation_for_every_policy`:
/// with every member at capacity, each of the four terminals sheds within the failover budget
/// rather than parking to the deadline, and the queue's wait ends at its own setting.
#[test]
fn every_terminal_sheds_within_the_budget_when_every_member_is_saturated() {
    for policy in [
        OnExhausted::Status503,
        OnExhausted::LeastBad,
        OnExhausted::Queue { max_ms: 50 },
        OnExhausted::FallbackPool("overflow".to_string()),
    ] {
        let mut node = Node::with_lanes(&["busy", "overflow"]);
        node.timeout_secs = FAILOVER_SECS;
        node.pool("primary", vec![member(D0, "busy")]);
        if matches!(policy, OnExhausted::FallbackPool(_)) {
            // The fallback is saturated too, so the spill cascades to the shed.
            node.pool("overflow", vec![member(D1, "overflow")]);
        }
        node.tune("primary", |p| {
            p.on_exhausted = policy.clone();
            p.failover.max_hops = 3;
        });
        let held: Vec<Permit> = [D0, D1]
            .into_iter()
            .map(|d| {
                node.capacity.set_ceiling(d, 1);
                node.capacity.saturate(d)
            })
            .collect();

        let started = node.clock.now_millis();
        let outcome = node.route("primary");
        let elapsed = node.clock.now_millis() - started;
        let refusal = outcome
            .shed()
            .unwrap_or_else(|| panic!("a fully saturated pool must shed under {policy:?}"));
        assert_eq!(refusal.status, u32::from(STATUS_SERVICE_UNAVAILABLE));
        assert!(
            refusal.retry_after.is_some(),
            "the shed carries a Retry-After under {policy:?}"
        );
        assert!(
            elapsed <= u128::from(FAILOVER_SECS * 1000),
            "ingress to disposition took {elapsed}ms, past the failover budget, under {policy:?}"
        );
        if let OnExhausted::Queue { max_ms } = policy {
            assert!(
                elapsed <= u128::from(max_ms),
                "the queue's wait ends at its own {max_ms}ms, took {elapsed}ms"
            );
        }
        assert!(node.conns.dialled().is_empty(), "nothing was dispatched");
        drop(held);
    }
}

// ── the wait, over a store that hands a freed slot to one waiter ────────────────────────────────

/// A permit store whose members each hold a fixed number of slots, handed out first come, first
/// served: a freed slot goes to the longest waiter, once.
#[derive(Debug, Default)]
struct Slots {
    limits: HashMap<DestinationId, Arc<Semaphore>>,
}

#[derive(Debug)]
struct Slot {
    destination: DestinationId,
    _held: Option<OwnedSemaphorePermit>,
}

impl PermitHandle for Slot {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

impl Slots {
    fn new(limits: &[(DestinationId, usize)]) -> Self {
        Self {
            limits: limits
                .iter()
                .map(|(d, n)| (*d, Arc::new(Semaphore::new(*n))))
                .collect(),
        }
    }

    fn free(&self, destination: DestinationId) -> usize {
        self.limits
            .get(&destination)
            .map_or(usize::MAX, |s| s.available_permits())
    }

    fn slot(destination: DestinationId, held: Option<OwnedSemaphorePermit>) -> Permit {
        Permit::new(Box::new(Slot {
            destination,
            _held: held,
        }))
    }
}

impl Capacity for Slots {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        match self.limits.get(&destination) {
            None => Some(Self::slot(destination, None)),
            Some(slots) => Arc::clone(slots)
                .try_acquire_owned()
                .ok()
                .map(|held| Self::slot(destination, Some(held))),
        }
    }

    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        type Acquire = std::pin::Pin<
            Box<
                dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>> + Send,
            >,
        >;
        let mut waits: Vec<(DestinationId, Acquire)> = destinations
            .iter()
            .filter_map(|d| {
                let slots = Arc::clone(self.limits.get(d)?);
                Some((*d, Box::pin(slots.acquire_owned()) as Acquire))
            })
            .collect();
        Box::pin(std::future::poll_fn(move |cx| {
            let mut i = 0;
            while i < waits.len() {
                match waits[i].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(held)) => {
                        let d = waits[i].0;
                        return Poll::Ready(Some((d, Self::slot(d, Some(held)))));
                    }
                    Poll::Ready(Err(_)) => {
                        drop(waits.swap_remove(i));
                    }
                    Poll::Pending => i += 1,
                }
            }
            if waits.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }))
    }
}

/// A one-member pool `p` whose terminal is the wait, bounded by `max_ms`.
fn waiting_node(max_ms: u64) -> Node {
    let mut node = Node::with_lanes(&["svc"]);
    node.pool("p", vec![member(D0, "svc")]);
    node.tune("p", |p| p.on_exhausted = OnExhausted::Queue { max_ms });
    node
}

/// Poll `f` once with a waker that goes nowhere: whether it finished.
fn polled_once<F: Future + Unpin>(f: &mut F) -> bool {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    std::pin::Pin::new(f).poll(&mut cx).is_ready()
}

/// Ports legacy `on_exhausted_tests.rs::queue_two_waiters_one_freed_permit_wakes_exactly_one`:
/// two requests parked on a one-slot member, one slot freed: exactly one wakes and takes it while
/// the other stays parked; the second is served on the slot once the first gives it back.
#[test]
fn one_freed_slot_wakes_exactly_one_of_two_parked_requests() {
    let node = waiting_node(30_000);
    let slots = Slots::new(&[(D0, 1)]);
    let held = slots.try_acquire(D0).expect("the member's one slot");
    let pools = node.timed_pools();
    let ports = WalkPorts {
        breaker: node.breaker.as_ref(),
        capacity: &slots,
        clock: node.clock.as_ref(),
        telemetry: node.telemetry.as_ref(),
        floor: &node.floor,
        pools: &pools,
    };
    let token = route_token();
    let mut a = Walk::start(&ports, "p");
    let mut b = Walk::start(&ports, "p");
    let Step::Wait(wait_a) = a.next(&ports, None, &token) else {
        panic!("the first request reaches the wait");
    };
    let Step::Wait(wait_b) = b.next(&ports, None, &token) else {
        panic!("the second request reaches the wait");
    };
    let parked_a = a.park(&ports, &wait_a, &token).expect("a waits");
    let parked_b = b.park(&ports, &wait_b, &token).expect("b waits");

    node.rt.block_on(async {
        let mut fa = Box::pin(parked_a.wait(&ports));
        let mut fb = Box::pin(parked_b.wait(&ports));
        assert!(!polled_once(&mut fa) && !polled_once(&mut fb));
        assert_eq!(
            *node.telemetry.queue_depth.lock().unwrap(),
            2,
            "both requests are parked"
        );

        // Free exactly one slot.
        drop(held);
        let (won, mut fb) = match futures::future::select(fa, fb).await {
            futures::future::Either::Left(first) => first,
            futures::future::Either::Right(_) => {
                panic!("the longest waiter takes the freed slot")
            }
        };
        let winner = a
            .waited(&ports, won, &token)
            .expect("the winner takes the member");
        assert_eq!(winner.member.destination, D0);
        assert!(
            winner.degraded,
            "a dispatch out of the wait is a degraded one"
        );
        assert_eq!(
            slots.free(D0),
            0,
            "the one freed slot is the winner's: none is left for a second dispatcher"
        );
        assert!(
            !polled_once(&mut fb),
            "while the winner holds the only slot the other request is still parked"
        );
        assert_eq!(*node.telemetry.queue_depth.lock().unwrap(), 1);

        // The winner gives its slot back: the survivor takes it.
        drop(winner);
        let survivor = b
            .waited(&ports, fb.await, &token)
            .expect("the survivor is served on the slot the winner gave back");
        assert_eq!(survivor.member.destination, D0);
        assert_eq!(slots.free(D0), 0);
        drop(survivor);
    });
    assert_eq!(
        *node.telemetry.queue_depth.lock().unwrap(),
        0,
        "the depth returns to zero once both requests resolved"
    );
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 2);
}

/// Ports legacy `on_exhausted_tests.rs::queue_no_lost_wakeup_when_permit_freed_in_the_window`: a
/// slot freed right around the moment the request parks is kept for it, so a short wait still
/// dispatches rather than missing the wake and shedding.
#[test]
fn a_slot_freed_as_the_request_parks_is_not_lost() {
    // Freed after the park and before the wait first asks; then freed after the wait asked once.
    for free_after_first_poll in [false, true] {
        let node = waiting_node(400);
        let slots = Slots::new(&[(D0, 1)]);
        let held = slots.try_acquire(D0).expect("the member's one slot");
        let pools = node.timed_pools();
        let ports = WalkPorts {
            breaker: node.breaker.as_ref(),
            capacity: &slots,
            clock: node.clock.as_ref(),
            telemetry: node.telemetry.as_ref(),
            floor: &node.floor,
            pools: &pools,
        };
        let token = route_token();
        let mut walk = Walk::start(&ports, "p");
        let Step::Wait(wait) = walk.next(&ports, None, &token) else {
            panic!("the request reaches the wait");
        };
        let parked = walk.park(&ports, &wait, &token).expect("it waits");
        let started = node.clock.now_millis();
        let taken = node.rt.block_on(async {
            let mut waiting = Box::pin(parked.wait(&ports));
            if free_after_first_poll {
                assert!(!polled_once(&mut waiting));
            }
            drop(held);
            walk.waited(&ports, waiting.await, &token)
        });
        let taken = taken.unwrap_or_else(|shed| {
            panic!("a slot freed in the window must not be lost, got the shed {shed:?}")
        });
        assert_eq!(taken.member.destination, D0, "the freed member serves it");
        assert!(
            node.clock.now_millis() - started < 400,
            "it dispatched inside the short wait"
        );
    }
}

/// Ports legacy `on_exhausted_tests.rs::queue_won_permit_but_breaker_now_open_never_dispatches`:
/// a parked request wins the freed slot, but the member's breaker opened while it waited; the
/// admission asked again on the won member refuses, and the request is shed without dispatching.
#[test]
fn a_slot_won_on_a_member_whose_breaker_opened_while_waiting_is_never_dispatched() {
    let node = waiting_node(2_000);
    let slots = Slots::new(&[(D0, 1)]);
    let held = slots.try_acquire(D0).expect("the member's one slot");
    let pools = node.timed_pools();
    let ports = WalkPorts {
        breaker: node.breaker.as_ref(),
        capacity: &slots,
        clock: node.clock.as_ref(),
        telemetry: node.telemetry.as_ref(),
        floor: &node.floor,
        pools: &pools,
    };
    let token = route_token();
    let mut walk = Walk::start(&ports, "p");
    let Step::Wait(wait) = walk.next(&ports, None, &token) else {
        panic!("the request reaches the wait");
    };
    let parked = walk.park(&ports, &wait, &token).expect("it waits");
    let waited = node.rt.block_on(async {
        let mut waiting = Box::pin(parked.wait(&ports));
        assert!(!polled_once(&mut waiting), "the request is parked");
        // The breaker opens while the request is parked, and only then the slot frees.
        node.breaker.set(D0, cooling(300));
        drop(held);
        waiting.await
    });
    let shed = walk
        .waited(&ports, waited, &token)
        .expect_err("a member whose breaker opened while queued is never dispatched to");
    assert_eq!(shed.status, STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(300));
    assert_eq!(
        slots.free(D0),
        1,
        "the won slot is given back, nothing was dispatched on it"
    );
    assert!(node.conns.dialled().is_empty());
}

// ── the property, over generated worlds ─────────────────────────────────────────────────────────

/// A member's breaker, as a generated world states it.
#[derive(Clone, Copy, Debug)]
enum Cell {
    /// Healthy.
    Closed,
    /// Suppressed for this many seconds yet.
    OpenActive(u64),
    /// Its cooldown ran out: the next admission wins the recovery probe.
    OpenExpired,
    /// A peer holds the recovery probe.
    HalfOpen,
}

/// A member's concurrency, as a generated world states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cap {
    Unbounded,
    BoundedFree(usize),
    /// One slot, held for the whole case.
    Saturated,
}

#[derive(Clone, Copy, Debug)]
struct Gen {
    dead: bool,
    budget_out: bool,
    cell: Cell,
    cap: Cap,
}

impl Gen {
    fn admissible(&self) -> bool {
        !self.dead && !self.budget_out
    }

    /// What the admission would take for one uncontended request.
    fn eligible(&self) -> bool {
        self.admissible()
            && matches!(self.cell, Cell::Closed | Cell::OpenExpired)
            && self.cap != Cap::Saturated
    }

    fn cooldown(&self) -> u64 {
        match self.cell {
            Cell::OpenActive(secs) => secs,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug)]
enum Policy {
    Reject,
    LeastBad,
    Fallback,
    Queue(u64),
}

#[derive(Clone, Debug)]
struct World {
    primary: Vec<Gen>,
    fallback: Vec<Gen>,
    policy: Policy,
}

/// A small deterministic generator (xorshift), so every case is reproducible from its seed.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn coin(&mut self) -> bool {
        self.below(2) == 1
    }

    fn member(&mut self) -> Gen {
        Gen {
            dead: self.coin(),
            budget_out: self.coin(),
            cell: match self.below(4) {
                0 => Cell::Closed,
                1 => Cell::OpenActive([30, 90, 600][self.below(3) as usize]),
                2 => Cell::OpenExpired,
                _ => Cell::HalfOpen,
            },
            cap: match self.below(3) {
                0 => Cap::Unbounded,
                1 => Cap::BoundedFree(1 + self.below(8) as usize),
                _ => Cap::Saturated,
            },
        }
    }

    fn world(&mut self) -> World {
        let primary = (0..=self.below(5)).map(|_| self.member()).collect();
        let fallback = (0..=self.below(4)).map(|_| self.member()).collect();
        let policy = match self.below(4) {
            0 => Policy::Reject,
            1 => Policy::LeastBad,
            2 => Policy::Fallback,
            _ => Policy::Queue(5 + self.below(46)),
        };
        World {
            primary,
            fallback,
            policy,
        }
    }
}

const LANES: [&str; 9] = ["l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8"];

/// Drive one request through the walk and the far end for `world` and check the disposition its
/// policy calls for.
fn run_world(world: &World) {
    let p = world.primary.len();
    let total = p + world.fallback.len();
    let fallback = matches!(world.policy, Policy::Fallback);
    let mut node = Node::with_lanes(&LANES[..total]);
    node.timeout_secs = FAILOVER_SECS;
    node.pool(
        "primary",
        (0..p)
            .map(|d| member(DestinationId::new(d as u64), LANES[d]))
            .collect(),
    );
    if fallback {
        node.pool(
            "fallback",
            (p..total)
                .map(|d| member(DestinationId::new(d as u64), LANES[d]))
                .collect(),
        );
    }
    node.tune("primary", |pool| {
        pool.failover.max_hops = 3;
        pool.on_exhausted = match world.policy {
            Policy::Reject => OnExhausted::Status503,
            Policy::LeastBad => OnExhausted::LeastBad,
            Policy::Fallback => OnExhausted::FallbackPool("fallback".to_string()),
            Policy::Queue(max_ms) => OnExhausted::Queue { max_ms },
        };
    });
    let all: Vec<Gen> = world
        .primary
        .iter()
        .chain(world.fallback.iter())
        .copied()
        .collect();
    let mut held = Vec::new();
    for (d, m) in all.iter().enumerate() {
        let destination = DestinationId::new(d as u64);
        let mut health = Health {
            dead: m.dead,
            budget_exhausted: m.budget_out,
            ..Health::default()
        };
        match m.cell {
            Cell::Closed => {}
            Cell::OpenActive(secs) => health.cooldown = secs,
            Cell::OpenExpired => health.offers_probe = Some(1),
            Cell::HalfOpen => health.probe_in_flight = true,
        }
        node.breaker.set(destination, health);
        match m.cap {
            Cap::Unbounded => {}
            Cap::BoundedFree(n) => node.capacity.set_ceiling(destination, n),
            Cap::Saturated => {
                node.capacity.set_ceiling(destination, 1);
                held.push(node.capacity.saturate(destination));
            }
        }
    }

    // The oracle, from the world as stated.
    let eligible_primary = world.primary.iter().any(Gen::eligible);
    let soonest = world
        .primary
        .iter()
        .filter(|m| m.admissible())
        .map(Gen::cooldown)
        .filter(|c| *c > 0)
        .min();
    let last_resort_serves = world
        .primary
        .iter()
        .any(|m| m.admissible() && m.cap != Cap::Saturated);
    let fallback_serves = fallback && world.fallback.iter().any(Gen::eligible);

    let started = node.clock.now_millis();
    let outcome = node.route("primary");
    let elapsed = node.clock.now_millis() - started;
    let dialled = node.conns.dialled();
    let primary_lanes = &LANES[..p];

    assert!(
        elapsed <= u128::from(FAILOVER_SECS * 1000),
        "ingress to disposition took {elapsed}ms, past the failover budget: {world:?}"
    );
    let served_by_primary = |outcome: &Routed| {
        let (d, pool) = delivered(outcome);
        assert_eq!(pool, "primary", "{world:?}");
        assert!((d.get() as usize) < p, "{world:?}");
        assert_eq!(dialled.len(), 1, "one dispatch: {dialled:?} {world:?}");
        assert!(primary_lanes.contains(&dialled[0].as_str()), "{world:?}");
    };
    let shed = |outcome: &Routed| -> Option<u32> {
        let refusal = outcome
            .shed()
            .unwrap_or_else(|| panic!("expected the shed, got {outcome:?}: {world:?}"));
        assert_eq!(
            refusal.status,
            u32::from(STATUS_SERVICE_UNAVAILABLE),
            "{world:?}"
        );
        assert!(refusal.retry_after.is_some(), "a Retry-After: {world:?}");
        assert!(dialled.is_empty(), "nothing dispatched: {world:?}");
        refusal.retry_after
    };

    if eligible_primary {
        // An eligible member existed: the request is served there, never shed, never spilled.
        served_by_primary(&outcome);
        return;
    }
    match world.policy {
        Policy::Reject => {
            let wait = shed(&outcome);
            assert_eq!(
                wait.map(u64::from),
                Some(soonest.unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS)),
                "the wait is the soonest genuine cooldown, else the at-capacity floor: {world:?}"
            );
        }
        Policy::LeastBad if last_resort_serves => served_by_primary(&outcome),
        Policy::LeastBad => {
            shed(&outcome);
        }
        Policy::Fallback if fallback_serves => {
            let (d, pool) = delivered(&outcome);
            assert_eq!(pool, "fallback", "{world:?}");
            assert!((d.get() as usize) >= p, "{world:?}");
            assert_eq!(dialled.len(), 1, "{world:?}");
            assert!(
                !primary_lanes.contains(&dialled[0].as_str()),
                "the primary serves nothing once the request spilled: {world:?}"
            );
        }
        Policy::Fallback => {
            shed(&outcome);
        }
        Policy::Queue(max_ms) => {
            shed(&outcome);
            assert!(
                elapsed <= u128::from(max_ms),
                "the wait ends at its own {max_ms}ms, took {elapsed}ms: {world:?}"
            );
        }
    }
    drop(held);
}

/// Ports legacy `lane_availability_proptest_tests.rs::strengthened_lane_availability_invariant`:
/// over generated worlds (one to five primary members, one to four fallback members, each bounded,
/// unbounded or saturated, its breaker closed, open, expired or half-open, its budget spent or not,
/// dead or not, under each of the four terminals) a request is served by an eligible member when one
/// exists, and otherwise disposed of as its policy says: the shed with the honest wait, the last
/// resort on a free admissible member, the spill to an eligible fallback (the primary serving
/// nothing), or the bounded wait; and always inside the failover budget.
#[test]
fn every_generated_world_is_served_by_an_eligible_member_or_disposed_of_per_its_policy() {
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    for _ in 0..512 {
        let world = draw.world();
        run_world(&world);
    }
    // The shapes the property must reach are reached: a healthy primary at capacity that spills,
    // and a world whose every member is out.
    run_world(&World {
        primary: vec![Gen {
            dead: false,
            budget_out: false,
            cell: Cell::Closed,
            cap: Cap::Saturated,
        }],
        fallback: vec![Gen {
            dead: false,
            budget_out: false,
            cell: Cell::Closed,
            cap: Cap::Unbounded,
        }],
        policy: Policy::Fallback,
    });
}
