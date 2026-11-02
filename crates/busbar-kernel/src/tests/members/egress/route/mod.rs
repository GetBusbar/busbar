// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod harness;

mod attempt_span_tests;
mod deadline_tests;
mod exhaustion_tests;
mod pick_order_tests;
mod probe_tests;
mod relay_tests;
mod walk_tests;
mod zero_copy_tests;

use crate::test_support::tokens::pass;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::{InstanceId, NeedId};

use busbar_kernel_egress::pool::{Member, Pool};
use busbar_kernel_egress::ports::Clock;
use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::select::{RequestCtx, WeightedFloor};
use busbar_kernel_egress::walk::{Shape, Step, Taken, Walk, WalkPorts};
use busbar_kernel_egress::wire::Shed;

use crate::plane_driver::{
    Egress, EgressFarEnd, FarEnd, FarPiece, MemberRoute, OutboundRequest, Pick, ResponseKeep,
    UnitRoute, DEFAULT_ERROR_BODY_MAX,
};

pub(crate) use harness::*;

pub(crate) const STREAM_CEILING_SECS: u64 = 300;

pub(crate) struct Node {
    pub breaker: Arc<TestBreaker>,
    pub capacity: Arc<TestCapacity>,
    pub journal: Arc<TestJournal>,
    pub clock: Arc<TestClock>,
    pub telemetry: Arc<TestTelemetry>,
    pub conns: Arc<TestConns>,
    pub pools: HashMap<String, Pool>,

    pub lanes: Vec<&'static str>,
    pub floor: WeightedFloor,

    pub timeout_secs: u64,
    pub affinity: Option<u64>,

    pub preference: Option<Vec<DestinationId>>,
    pub wants_stream: bool,

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

    pub fn pool(&mut self, name: &str, members: Vec<Member>) -> &mut Self {
        self.pools
            .insert(name.to_string(), Pool::new(name, members));
        self
    }

    pub fn tune(&mut self, name: &str, f: impl FnOnce(&mut Pool)) -> &mut Self {
        f(self.pools.get_mut(name).expect("the pool is in the table"));
        self
    }

    fn timed_pools(&self) -> HashMap<String, Pool> {
        let mut pools = self.pools.clone();
        for pool in pools.values_mut() {
            pool.failover.timeout_secs = self.timeout_secs;
        }
        pools
    }

    pub fn request_ctx(&self) -> RequestCtx {
        RequestCtx::new(
            self.timeout_secs,
            self.clock.now_secs(),
            self.clock.now_millis(),
        )
    }

    pub fn walker(&self, pool: &str) -> Walker<'_> {
        let pools = self.timed_pools();
        let walk = Walk::start(&ports(self, &pools), pool);
        Walker {
            node: self,
            pools,
            token: pass::<Route>(),
            walk,
            shape: None,
        }
    }

    pub fn egress(&self) -> Egress {
        Egress {
            caller: InstanceId(1),
            conns: self.conns.clone(),
            breaker: crate::plane_driver::fixed_breaker(self.breaker.clone()),
            capacity: self.capacity.clone(),
            clock: self.clock.clone(),
            journal: self.journal.clone(),
            telemetry: self.telemetry.clone(),
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
                            spelled: Vec::new(),
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
            stated_ceiling_secs: 0,
            error_body_max: DEFAULT_ERROR_BODY_MAX,
        }
    }

    pub fn unit_route(&self, pool: &str) -> UnitRoute {
        UnitRoute {
            pool: pool.to_string(),
            affinity: self.affinity,
            wants_stream: self.wants_stream,
            ..UnitRoute::default()
        }
    }

    pub fn route(&self, pool: &str) -> Routed {
        self.route_with(pool, |_, _| {})
    }

    pub fn route_with(&self, pool: &str, before: impl FnMut(&Node, u32)) -> Routed {
        let egress = self.egress();
        self.rt.block_on(self.route_on(&egress, pool, before))
    }

    pub async fn route_on(
        &self,
        egress: &Egress,
        pool: &str,
        mut before: impl FnMut(&Node, u32),
    ) -> Routed {
        let token = pass::<Route>();
        let far = egress.unit(self.unit_route(pool));
        let mut attempt_no = 0;
        'attempt: loop {
            attempt_no += 1;
            before(self, attempt_no);
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

                Pick::Refused(_) => {
                    return Routed::Refused(Refusal {
                        status: 502,
                        retry_after: None,
                    })
                }
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

    pub fn abandon_mid_answer(&self, pool: &str) {
        let egress = self.egress();
        let token = pass::<Route>();
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

    pub fn cancel_after_first_piece(&self, pool: &str) -> Vec<u8> {
        let egress = self.egress();
        let token = pass::<Route>();
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

    fn destination_of(&self, pool: &str, name: &str) -> DestinationId {
        self.pools
            .get(pool)
            .and_then(|p| p.members.iter().find(|m| m.name == name))
            .map(|m| m.destination)
            .expect("the far end picked a member of the pool")
    }

    pub fn pick<'a>(
        &'a self,
        pool: &'a str,
        members: &'a [Member],
        ctx: &mut RequestCtx,
    ) -> Option<busbar_kernel_egress::select::Picked<'a>> {
        let token = pass::<Route>();
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

fn ports<'p>(node: &'p Node, pools: &'p HashMap<String, Pool>) -> WalkPorts<'p> {
    WalkPorts {
        breaker: node.breaker.as_ref(),
        capacity: node.capacity.as_ref(),
        clock: node.clock.as_ref(),
        telemetry: node.telemetry.as_ref(),
        pools,
    }
}

fn request(member: &str, pool: &str, attempt_no: u32) -> OutboundRequest {
    OutboundRequest {
        text: false,
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

pub(crate) struct Walker<'n> {
    node: &'n Node,
    pools: HashMap<String, Pool>,
    token: Pass<Route>,
    pub walk: Walk,

    shape: Option<Box<dyn Shape>>,
}

impl Walker<'_> {
    #[must_use]
    pub fn shaped(mut self, shape: impl Shape + 'static) -> Self {
        self.shape = Some(Box::new(shape));
        self
    }

    pub fn step(&mut self) -> Step {
        let Walker {
            node,
            pools,
            token,
            walk,
            shape,
        } = self;
        let ports = ports(node, pools);
        match walk.next_shaped(&ports, node.affinity, shape.as_deref(), token) {
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

    pub fn abandon_wait(&mut self) {
        let Walker {
            node,
            pools,
            token,
            walk,
            shape,
        } = self;
        let ports = ports(node, pools);
        let Step::Wait(wait) = walk.next_shaped(&ports, node.affinity, shape.as_deref(), token)
        else {
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

    pub fn take(&mut self) -> Taken {
        match self.step() {
            Step::Take(taken) => taken,
            other => panic!("expected the walk to take a member, got {other:?}"),
        }
    }

    pub fn shed(&mut self) -> Shed {
        match self.step() {
            Step::Shed(shed) => shed,
            other => panic!("expected the walk's refusal, got {other:?}"),
        }
    }
}

pub(crate) fn member(destination: DestinationId, name: &str) -> Member {
    Member::new(destination, name, 1)
}
