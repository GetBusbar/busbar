// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's own proof.
//!
//! These are the previous release's failover, pick-order, exhaustion and probe tests, carried over
//! and re-asserted against the moved code. What each one checks is unchanged; what it drives is a
//! scripted transport instead of a real upstream, which is the only difference between the two and
//! the reason each is a unit test here rather than an integration test elsewhere.

mod harness;

mod deadline_tests;
mod exhaustion_tests;
mod pick_order_tests;
mod probe_tests;
mod walk_tests;

use std::sync::Arc;

use busbar_contract::VerifiedDestination;

use crate::pool::{Member, Pool, PoolTable};
use crate::ports::Clock;
use crate::ports::DestinationId;
use crate::select::{RequestCtx, WeightedFloor};
use crate::wire::RouteOutcome;

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
    pub pools: PoolTable,
    pub verified: Vec<VerifiedDestination>,
    pub floor: WeightedFloor,
    pub timeout_secs: u64,
    pub affinity: Option<u64>,
    pub preference: Option<Vec<DestinationId>>,
    pub wants_stream: bool,
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
            pools: PoolTable::new(),
            verified: lanes.iter().map(|lane| sealed(lane)).collect(),
            floor: WeightedFloor::new(),
            timeout_secs: 120,
            affinity: None,
            preference: None,
            wants_stream: false,
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
        let plane_ctx = PlaneContext::new();
        let unit = test_unit();
        let keys = keys();
        let context = plane_ctx.ctx();
        // Test-only: mints the capability token through the kernel seal exactly as CG-29 says a
        // real deployment would (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only
        // outside test modules).
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let token: busbar_caps::UnitToken<busbar_caps::Route> = busbar_caps::UnitToken::mint(&seal);
        let request = crate::walk::RouteRequest {
            breaker: self.breaker.as_ref(),
            token: &token,
            capacity: self.capacity.as_ref(),
            journal: self.journal.as_ref(),
            egress_auth: self.egress_auth.as_ref(),
            clock: self.clock.as_ref(),
            telemetry: self.telemetry.as_ref(),
            transport: self.transport.as_ref(),
            plane: self.plane.as_ref(),
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
            lane_field: None,
            stream: busbar_contract::StreamId(0),
            floor: &self.floor,
        };
        crate::race::block_on(crate::walk::walk(&request, ctx))
    }
}

impl Node {
    /// One pick against these members, without a walk around it.
    pub fn pick(
        &self,
        pool: &str,
        members: &[Member],
        ctx: &mut RequestCtx,
    ) -> Option<crate::select::Picked> {
        crate::select::pick_among(
            &crate::select::PickInput {
                breaker: self.breaker.as_ref(),
                capacity: self.capacity.as_ref(),
                floor: &self.floor,
                pool,
                members,
                affinity: self.affinity,
                preference: self.preference.as_deref(),
                now: self.clock.now_secs(),
            },
            ctx,
        )
    }
}

/// A member on the destination of the same index, named for its lane, with weight one.
pub(crate) fn member(destination: DestinationId, name: &str) -> Member {
    Member::new(destination, name, 1)
}
