// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk's own proof.
//!
//! These are the previous release's failover, pick-order, exhaustion and probe tests, carried over
//! and re-asserted against the ONE walk: the egress unit's stepper ([`Walk`]), driven directly
//! where the claim is the walk's (its order, its terminals and their words, its deadline), and
//! through the production far end that runs every attempt it takes where the claim is about what
//! an attempt does to the walk (failover, the breaker's record, the budget, the dispatch record).
//! What each one checks is unchanged; what it drives is a scripted connection table instead of a
//! real far end.
//!
//! They live here, not in the egress crate, because driving a route step needs a `Pass<Route>` and
//! minting one is legal only in this crate.

mod harness;

mod deadline_tests;
mod exhaustion_tests;
mod pick_order_tests;
mod probe_tests;
mod relay_tests;
mod walk_tests;
mod zero_copy_tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::{InstanceId, NeedId};

use busbar_kernel_egress::pool::{Member, Pool};
use busbar_kernel_egress::ports::Clock;
use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::select::{RequestCtx, WeightedFloor};
use busbar_kernel_egress::walk::{Step, Taken, Walk, WalkPorts};
use busbar_kernel_egress::wire::Shed;

use crate::plane_driver::{
    Egress, EgressFarEnd, FarEnd, FarPiece, MemberRoute, OutboundRequest, Pick, ResponseKeep,
    UnitRoute, DEFAULT_ERROR_BODY_MAX,
};

pub(crate) use harness::*;

/// The ceiling on a streamed answer every far end in this module runs under, seconds.
pub(crate) const STREAM_CEILING_SECS: u64 = 300;

/// A node in miniature: the walk's ports, the pools, a scripted connection table, and the paused
/// runtime the far end runs on.
pub(crate) struct Node {
    pub breaker: Arc<TestBreaker>,
    pub capacity: Arc<TestCapacity>,
    pub journal: Arc<TestJournal>,
    pub clock: Arc<TestClock>,
    pub telemetry: Arc<TestTelemetry>,
    pub conns: Arc<TestConns>,
    pub pools: HashMap<String, Pool>,
    /// The lane of each destination, by index: destination `n` is reached at `<lanes[n]>.test`.
    pub lanes: Vec<&'static str>,
    pub floor: WeightedFloor,
    /// Every pool's request timeout as the walk reads it, seconds.
    pub timeout_secs: u64,
    pub affinity: Option<u64>,
    /// A ranking hook's preference, for the pick-level cases (`Node::pick`); the walk names none.
    pub preference: Option<Vec<DestinationId>>,
    pub wants_stream: bool,
    /// Where the body of every request the route handed the far end lies.
    pub sent_at: Mutex<Vec<usize>>,
    rt: tokio::runtime::Runtime,
}

/// What one route came back with: the member that answered, or the walk's terminal.
#[derive(Debug)]
pub(crate) enum Routed {
    Delivered(Served),
    Refused(Refusal),
}

/// The answer one member gave.
#[derive(Debug)]
pub(crate) struct Served {
    pub destination: DestinationId,
    /// The pool the walk took the member from.
    pub pool: String,
    /// The answer's status, as its first piece carried it: the number and its class.
    pub status: Option<(u32, u32)>,
    /// How many pieces of the answer's body reached the plane.
    pub pieces: usize,
}

/// The walk's terminal, as the far end hands it to the pump.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub status: u32,
    pub retry_after: Option<u32>,
}

impl Routed {
    pub fn shed(&self) -> Option<&Refusal> {
        match self {
            Self::Refused(r) => Some(r),
            Self::Delivered(_) => None,
        }
    }

    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered(_))
    }
}

impl Node {
    /// A node whose destinations are these lanes, in order, so destination `n` is lane `n`.
    pub fn with_lanes(lanes: &[&'static str]) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("the harness runtime builds");
        Self {
            breaker: Arc::new(TestBreaker::new()),
            capacity: Arc::new(TestCapacity::new()),
            journal: Arc::new(TestJournal::new()),
            clock: Arc::new(TestClock::at(rt.handle().clone(), 1_000)),
            telemetry: Arc::new(TestTelemetry::new()),
            conns: Arc::new(TestConns::new()),
            pools: HashMap::new(),
            lanes: lanes.to_vec(),
            floor: WeightedFloor::new(),
            timeout_secs: 120,
            affinity: None,
            preference: None,
            wants_stream: false,
            sent_at: Mutex::new(Vec::new()),
            rt,
        }
    }

    /// Add a pool of these members.
    pub fn pool(&mut self, name: &str, members: Vec<Member>) -> &mut Self {
        self.pools
            .insert(name.to_string(), Pool::new(name, members));
        self
    }

    /// Change a pool that is already in the table.
    pub fn tune(&mut self, name: &str, f: impl FnOnce(&mut Pool)) -> &mut Self {
        f(self.pools.get_mut(name).expect("the pool is in the table"));
        self
    }

    /// The pools as the walk reads them: every one's request timeout is the node's.
    fn timed_pools(&self) -> HashMap<String, Pool> {
        let mut pools = self.pools.clone();
        for pool in pools.values_mut() {
            pool.failover.timeout_secs = self.timeout_secs;
        }
        pools
    }

    /// A fresh request context on this node's clock.
    pub fn request_ctx(&self) -> RequestCtx {
        RequestCtx::new(
            self.timeout_secs,
            self.clock.now_secs(),
            self.clock.now_millis(),
        )
    }

    /// THE WALK over `pool`, starting now, stepped by hand.
    pub fn walker(&self, pool: &str) -> Walker<'_> {
        let pools = self.timed_pools();
        let walk = Walk::start(&ports(self, &pools), pool);
        Walker {
            node: self,
            pools,
            token: route_token(),
            walk,
        }
    }

    /// The production far end over this node: its ports, its pools, and a route per lane.
    pub fn egress(&self) -> Egress {
        Egress {
            caller: InstanceId(1),
            conns: self.conns.clone(),
            breaker: self.breaker.clone(),
            capacity: self.capacity.clone(),
            clock: self.clock.clone(),
            journal: self.journal.clone(),
            telemetry: self.telemetry.clone(),
            floor: WeightedFloor::new(),
            pools: self.timed_pools(),
            routes: self
                .lanes
                .iter()
                .enumerate()
                .map(|(n, lane)| {
                    (
                        DestinationId::new(n as u64),
                        MemberRoute {
                            anchors: Default::default(),
                            rides: Vec::new(),
                            need: NeedId(0),
                            base_url: format!("https://{lane}.test/"),
                            auth: None,
                            provider: (*lane).to_string(),
                            keep: ResponseKeep::default(),
                        },
                    )
                })
                .collect(),
            stream_ceiling_secs: STREAM_CEILING_SECS,
            error_body_max: DEFAULT_ERROR_BODY_MAX,
        }
    }

    /// The unit's route over `pool`.
    pub fn unit_route(&self, pool: &str) -> UnitRoute {
        UnitRoute {
            pool: pool.to_string(),
            affinity: self.affinity,
            wants_stream: self.wants_stream,
            ..UnitRoute::default()
        }
    }

    /// Route one unit over `pool` through the far end, attempt by attempt as the pump does, and
    /// answer with what came back.
    pub fn route(&self, pool: &str) -> Routed {
        self.route_with(pool, |_, _| {})
    }

    /// [`Node::route`], with `before` run ahead of every attempt's pick (its number from `1`): the
    /// walk has started by then, so a test can spend its budget between two hops.
    pub fn route_with(&self, pool: &str, mut before: impl FnMut(&Node, u32)) -> Routed {
        let egress = self.egress();
        let token = route_token();
        let far = egress.unit(self.unit_route(pool));
        self.rt.block_on(async {
            let mut attempt_no = 0;
            'attempt: loop {
                attempt_no += 1;
                before(self, attempt_no);
                let (member, pool) = match far.member(&token, attempt_no).await {
                    Pick::Member { name, pool, .. } => (name, pool),
                    Pick::Exhausted {
                        status,
                        retry_after,
                    } => {
                        return Routed::Refused(Refusal {
                            status,
                            retry_after,
                        })
                    }
                    // A hook restriction's refusal; no hook binds in these walk proofs.
                    Pick::Vetoed { status, .. } => {
                        return Routed::Refused(Refusal {
                            status,
                            retry_after: None,
                        })
                    }
                };
                let destination = self.destination_of(&pool, &member);
                let bound = request(&member, &pool, attempt_no);
                self.sent_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(bound.body.as_ptr() as usize);
                if !far.send(&token, bound).await {
                    // Not sent, so nothing reached the caller: fail over, as the pump does.
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
        })
    }

    /// Take a member, send it the request, poll its answer once, and drop the unit there — the
    /// way a caller that goes away mid-send leaves one.
    pub fn abandon_mid_answer(&self, pool: &str) {
        let egress = self.egress();
        let token = route_token();
        let far: EgressFarEnd<'_> = egress.unit(self.unit_route(pool));
        self.rt.block_on(async {
            let Pick::Member { name, pool, .. } = far.member(&token, 1).await else {
                panic!("a member to send to");
            };
            assert!(far.send(&token, request(&name, &pool, 1)).await);
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            let mut next = Box::pin(far.next(&token));
            assert!(
                std::future::Future::poll(next.as_mut(), &mut cx).is_pending(),
                "the far end was expected to park rather than answer on the first poll"
            );
        });
        drop(far);
    }

    /// Take a member, send it the request, read the first piece of its answer, then poll for the
    /// next once and drop the unit there — a CLIENT that goes away after its first byte. Answers
    /// the first piece's bytes.
    pub fn cancel_after_first_piece(&self, pool: &str) -> Vec<u8> {
        let egress = self.egress();
        let token = route_token();
        let far: EgressFarEnd<'_> = egress.unit(self.unit_route(pool));
        let first = self.rt.block_on(async {
            let Pick::Member { name, pool, .. } = far.member(&token, 1).await else {
                panic!("a member to send to");
            };
            assert!(far.send(&token, request(&name, &pool, 1)).await);
            let first = far.next(&token).await.expect("the answer's first piece");
            assert!(!first.fail_over && !first.last, "{first:?}");
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            let mut next = Box::pin(far.next(&token));
            assert!(
                std::future::Future::poll(next.as_mut(), &mut cx).is_pending(),
                "the far end was expected to park on the rest of the answer"
            );
            first.bytes
        });
        drop(far);
        first
    }

    /// The destination of the member named `name` in `pool`.
    fn destination_of(&self, pool: &str, name: &str) -> DestinationId {
        self.pools
            .get(pool)
            .and_then(|p| p.members.iter().find(|m| m.name == name))
            .map(|m| m.destination)
            .expect("the far end picked a member of the pool")
    }

    /// One pick against these members, without a walk around it.
    pub fn pick<'a>(
        &'a self,
        pool: &'a str,
        members: &'a [Member],
        ctx: &mut RequestCtx,
    ) -> Option<busbar_kernel_egress::select::Picked<'a>> {
        // Test-only: the route step's pass, as the walk's own pick is handed it.
        let token = route_token();
        busbar_kernel_egress::select::pick_among(
            &busbar_kernel_egress::select::PickInput {
                breaker: self.breaker.as_ref(),
                capacity: self.capacity.as_ref(),
                floor: &self.floor,
                pool,
                members,
                affinity: self.affinity,
                preference: self.preference.as_deref(),
                now: self.clock.now_secs(),
                token: &token,
            },
            ctx,
        )
    }
}

/// The walk's ports over a node and the pools it reads.
fn ports<'p>(node: &'p Node, pools: &'p HashMap<String, Pool>) -> WalkPorts<'p> {
    WalkPorts {
        breaker: node.breaker.as_ref(),
        capacity: node.capacity.as_ref(),
        clock: node.clock.as_ref(),
        telemetry: node.telemetry.as_ref(),
        floor: &node.floor,
        pools,
    }
}

/// One attempt's request, as a plane bound it for the far end.
fn request(member: &str, pool: &str, attempt_no: u32) -> OutboundRequest {
    OutboundRequest {
        need: 0,
        member: member.to_string(),
        pool: pool.to_string(),
        attempt_no,
        verb: b"POST".to_vec(),
        target: b"/v1/test".to_vec(),
        fields: Vec::new(),
        body: b"request".to_vec(),
    }
}

/// THE WALK, stepped by hand over a node: every step is [`Walk::next`], and the queue terminal's
/// wait is parked, awaited on the node's runtime and handed back, as the far end does it.
pub(crate) struct Walker<'n> {
    node: &'n Node,
    pools: HashMap<String, Pool>,
    token: Pass<Route>,
    pub walk: Walk,
}

impl Walker<'_> {
    /// The walk's next step, its wait (if it is the queue's) already run.
    pub fn step(&mut self) -> Step {
        let Walker {
            node,
            pools,
            token,
            walk,
        } = self;
        let ports = ports(node, pools);
        match walk.next(&ports, node.affinity, token) {
            Step::Wait(wait) => {
                let parked = match walk.park(&ports, &wait, token) {
                    Ok(parked) => parked,
                    Err(shed) => return Step::Shed(shed),
                };
                let waited = node.rt.block_on(parked.wait(&ports));
                match walk.waited(&ports, waited, token) {
                    Ok(taken) => Step::Take(taken),
                    Err(shed) => Step::Shed(shed),
                }
            }
            step => step,
        }
    }

    /// Step to the queue terminal, park its wait, poll it once and drop it there — the way a
    /// caller that goes away while its request is parked leaves the wait.
    pub fn abandon_wait(&mut self) {
        let Walker {
            node,
            pools,
            token,
            walk,
        } = self;
        let ports = ports(node, pools);
        let Step::Wait(wait) = walk.next(&ports, node.affinity, token) else {
            panic!("expected the queue terminal's wait");
        };
        let parked = walk
            .park(&ports, &wait, token)
            .unwrap_or_else(|shed| panic!("expected a wait, got the shed {shed:?}"));
        node.rt.block_on(async {
            let mut waiting = Box::pin(parked.wait(&ports));
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            assert!(
                std::future::Future::poll(waiting.as_mut(), &mut cx).is_pending(),
                "the wait was expected to park rather than finish on the first poll"
            );
        });
    }

    /// The next step, which must be a member.
    pub fn take(&mut self) -> Taken {
        match self.step() {
            Step::Take(taken) => taken,
            other => panic!("expected the walk to take a member, got {other:?}"),
        }
    }

    /// The next step, which must be the walk's refusal.
    pub fn shed(&mut self) -> Shed {
        match self.step() {
            Step::Shed(shed) => shed,
            other => panic!("expected the walk's refusal, got {other:?}"),
        }
    }
}

/// A member on the destination of the same index, named for its lane, with weight one.
pub(crate) fn member(destination: DestinationId, name: &str) -> Member {
    Member::new(destination, name, 1)
}
