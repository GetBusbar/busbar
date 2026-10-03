// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's own proof.
//!
//! These are the previous release's failover, pick-order, exhaustion and probe tests, carried over
//! and re-asserted against the moved code. What each one checks is unchanged; what it drives is a
//! scripted transport instead of a real upstream, which is the only difference between the two and
//! the reason each is a unit test here rather than an integration test elsewhere.
//!
//! Moved from `busbar-kernel-egress`'s `src/tests/` with the [`Node`] that drives them: a route
//! step needs a `Pass<Route>`, and minting one is legal only in this crate. The egress crate keeps
//! its tests that mint nothing.

mod harness;

mod allocation_tests;
mod deadline_tests;
mod exhaustion_tests;
mod pick_order_tests;
mod probe_tests;
mod upstream_half_tests;
mod walk_tests;

use std::sync::Arc;

use busbar_contract::VerifiedDestination;

use busbar_kernel_egress::pool::{Member, Pool, PoolTable};
use busbar_kernel_egress::ports::Clock;
use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::select::{RequestCtx, WeightedFloor};
use busbar_kernel_egress::wire::RouteOutcome;

pub(crate) use harness::*;

/// A node in miniature: the ports, the plane, the transport, the pools and the verified set.
pub(crate) struct Node {
    pub breaker: Arc<TestBreaker>,
    pub capacity: Arc<TestCapacity>,
    pub journal: Arc<TestJournal>,
    pub egress_auth: Arc<TestEgressAuth>,
    pub clock: Arc<TestClock>,
    pub telemetry: Arc<TestTelemetry>,
    pub transport: Arc<TestTransport>,
    pub plane: Arc<TestPlane>,
    /// A plane that keeps codec state per upstream, routed through in place of [`Node::plane`]
    /// when set.
    pub session_plane: Option<Arc<dyn busbar_contract::SessionPlane>>,
    pub pools: PoolTable,
    pub verified: Vec<VerifiedDestination>,
    pub floor: WeightedFloor,
    pub timeout_secs: u64,
    pub affinity: Option<u64>,
    pub preference: Option<Vec<DestinationId>>,
    pub wants_stream: bool,
    /// The envelope field the lane name is carried in, for the lane cross-check. `None` by
    /// default: most tests have no lane field to check and the cross-check is a no-op for them.
    pub lane_field: Option<&'static str>,
}

impl Node {
    /// A node whose verified set is these lanes, in order, so destination `n` is lane `n`.
    pub fn with_lanes(lanes: &[&'static str]) -> Self {
        Self {
            breaker: Arc::new(TestBreaker::new()),
            capacity: Arc::new(TestCapacity::new()),
            journal: Arc::new(TestJournal::new()),
            egress_auth: Arc::new(TestEgressAuth::new()),
            clock: Arc::new(TestClock::at(1_000)),
            telemetry: Arc::new(TestTelemetry::new()),
            transport: Arc::new(TestTransport::new()),
            plane: Arc::new(TestPlane::new()),
            session_plane: None,
            pools: PoolTable::new(),
            verified: lanes.iter().map(|lane| sealed(lane)).collect(),
            floor: WeightedFloor::new(),
            timeout_secs: 120,
            affinity: None,
            preference: None,
            wants_stream: false,
            lane_field: None,
        }
    }

    /// Add a pool of these members.
    pub fn pool(&mut self, name: &str, members: Vec<Member>) -> &mut Self {
        self.pools.insert(Pool::new(name, members));
        self
    }

    /// Change a pool that is already in the table.
    pub fn tune(&mut self, name: &str, f: impl FnOnce(&mut Pool)) -> &mut Self {
        let mut pool = self
            .pools
            .get(name)
            .expect("the pool is in the table")
            .clone();
        f(&mut pool);
        self.pools.insert(pool);
        self
    }

    /// Walk one pool and answer with what came back.
    pub fn route(&self, pool: &str) -> RouteOutcome {
        let mut ctx = self.request_ctx();
        self.route_with(pool, &mut ctx)
    }

    /// A fresh request context on this node's clock.
    pub fn request_ctx(&self) -> RequestCtx {
        RequestCtx::new(
            self.timeout_secs,
            self.clock.now_secs(),
            self.clock.now_millis(),
        )
    }

    /// Walk one pool with a context the caller keeps, so a test can read what was excluded.
    pub fn route_with(&self, pool: &str, ctx: &mut RequestCtx) -> RouteOutcome {
        self.with_request(pool, |request| {
            busbar_kernel_egress::race::block_on(busbar_kernel_egress::walk::walk(request, ctx))
        })
    }

    /// Poll one walk exactly once and then drop the future, the way a client that goes away
    /// part-way through leaves one. Nothing completes; the point of this is what the abandoned
    /// future left behind it.
    pub fn route_poll_once_then_drop(&self, pool: &str, ctx: &mut RequestCtx) {
        use std::future::Future;
        self.with_request(pool, |request| {
            let mut future = Box::pin(busbar_kernel_egress::walk::walk(request, ctx));
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            assert!(
                future.as_mut().poll(&mut cx).is_pending(),
                "the walk was expected to park rather than finish on the first poll"
            );
            drop(future);
        });
    }

    /// Build one route request over this node and hand it to `f`.
    fn with_request<R>(
        &self,
        pool: &str,
        f: impl FnOnce(&busbar_kernel_egress::walk::RouteRequest<'_>) -> R,
    ) -> R {
        let plane_ctx = PlaneContext::new();
        let unit = test_unit();
        let keys = keys();
        let context = plane_ctx.ctx();
        // Test-only: mints the capability token through the kernel seal exactly as CG-29 says a
        // real deployment would (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only
        // outside test modules).
        let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
        let token: busbar_contract::caps::Pass<busbar_contract::caps::Route> =
            busbar_contract::caps::Pass::mint(&seal);
        let request = busbar_kernel_egress::walk::RouteRequest {
            breaker: self.breaker.as_ref(),
            token: &token,
            capacity: self.capacity.as_ref(),
            journal: self.journal.as_ref(),
            egress_auth: self.egress_auth.as_ref(),
            clock: self.clock.as_ref(),
            telemetry: self.telemetry.as_ref(),
            transport: self.transport.as_ref(),
            plane: match &self.session_plane {
                Some(plane) => busbar_kernel_egress::PlaneRef::Session(plane.as_ref()),
                None => busbar_kernel_egress::PlaneRef::Stateless(self.plane.as_ref()),
            },
            keys: &keys,
            verified: &self.verified,
            pools: &self.pools,
            pool,
            unit: &unit,
            ctx: &context,
            affinity: self.affinity,
            preference: self.preference.as_deref(),
            leg: 0,
            wants_stream: self.wants_stream,
            stream_ceiling_secs: 300,
            lane_field: self.lane_field,
            stream: busbar_contract::StreamId(0),
            floor: &self.floor,
        };
        f(&request)
    }
}

impl Node {
    /// One pick against these members, without a walk around it.
    pub fn pick<'a>(
        &'a self,
        pool: &'a str,
        members: &'a [Member],
        ctx: &mut RequestCtx,
    ) -> Option<busbar_kernel_egress::select::Picked<'a>> {
        // Test-only: mints the capability token through the kernel seal exactly as CG-29 says a
        // real deployment would (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only
        // outside test modules), matching `route_with`'s own minting above.
        let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
        let token: busbar_contract::caps::Pass<busbar_contract::caps::Route> =
            busbar_contract::caps::Pass::mint(&seal);
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

/// A member on the destination of the same index, named for its lane, with weight one.
pub(crate) fn member(destination: DestinationId, name: &str) -> Member {
    Member::new(destination, name, 1)
}
