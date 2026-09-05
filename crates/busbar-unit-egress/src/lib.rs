// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # busbar-unit-egress — the egress unit
//!
//! The design gives this unit the fifth step of the loop and one sentence's worth of job: take the
//! plane's route plan, walk the verified set the trust unit sealed, and send. Everything under
//! that sentence is here and nothing else is.
//!
//! ## The four parts
//!
//! **The pool.** This unit owns the pool per transport and destination: the membership, each
//! member's weight and overrides, the walk's deadline and hop count, the per-pool blocklist, and
//! what to do when there is nowhere to send. A member's lifetime request budget is the breaker
//! unit's counter, but it is this unit that spends it — after the upstream's success, never at
//! selection — and this unit that gives it back when the answer does not arrive whole.
//!
//! **The walk.** One loop, in [`walk`]: the deadline before every attempt including a streaming
//! one, the pick, the attempt, and what a failure means for the next hop. It runs the pool's hop
//! cap plus one attempts, and it fails over only before the first byte reaches the client.
//!
//! **The one attempt.** In [`attempt`]: the delta record durable before the dial, the dial from
//! the pool with the breaker consulted for this attempt, the wire request from the verified
//! destination and the plane's egress encode, the egress-auth decoration, the lane cross-check on
//! the post-decoration bytes, the send, and the plane's response decode per frame relayed under
//! the hold.
//!
//! **The terminals.** In [`exhaustion`]: the shed with its honest wait, the spill into another
//! pool, the bounded wait for a slot, and the one documented breaker bypass.
//!
//! ## What is deliberately not here
//!
//! The dialect codecs are the plane's. This unit calls `encode_egress` and `decode_response` and
//! reads no body: it never parses an answer, never knows what a protocol is, and holds no literal
//! from one.
//!
//! The breaker's state machine is the breaker unit's. This unit consults it before an attempt and
//! records against it after, through the one trait in [`ports`]. The table that says what a given
//! upstream status means to a given destination is data that trait consumes, not a match arm here
//! — which is why the same walk serves a destination whose operator remapped every code.
//!
//! The money is the admission and ledger units'. This unit produces the evidence — which member
//! served the request, what the transport made of the answer, how many frames were relayed — and
//! settles nothing.
//!
//! ## What is bound by the integrator
//!
//! Everything in [`ports`] marked `// contract:`: the breaker, the egress-auth unit, the journal,
//! the pool's permit store, the clock and the counters. Each is a small trait with a settled
//! shape; none of them is a decision this unit is still waiting to make.
//!
//! ## A note on the words
//!
//! The refusals this unit produces carry the literal words of the previous release, gathered in
//! [`wire`] so they cannot drift. What goes on the wire is the plane's rendering of them; what is
//! fixed here is the status, the kind, the words and the wait.

pub mod attempt;
pub mod exhaustion;
pub mod pool;
pub mod ports;
pub mod race;
pub mod select;
pub mod walk;
pub mod wire;

pub use pool::{
    Failover, Member, OnExhausted, Pool, PoolTable, DEFAULT_FAILOVER_CAP,
    DEFAULT_FAILOVER_DEADLINE_SECS,
};
pub use select::{RequestCtx, WeightedFloor};
pub use walk::RouteRequest;
pub use wire::{Delivered, RouteOutcome, Shed};

use busbar_caps::{Route, UnitToken};

mod sealed {
    /// The private supertrait that closes the unit trait below.
    pub trait Sealed {}
}

/// The egress unit's sealed trait shape.
///
/// The design writes it as `Egress::route(&RoutePlan, &Pool, &UnitToken<Route>)`, and that is what
/// is below: the plane's plan, the pool to walk it over, and the token that proves the loop is at
/// the route step for this unit right now. The token is taken by reference and never stored — the
/// kernel mints a fresh one per step call and drops it when the call returns — so this unit cannot
/// route a unit it was not asked to route, and cannot route the same one twice.
///
/// It is sealed on a private supertrait, so no plugin crate can implement it. That is the same
/// seal every unit trait in the design carries and it means the same thing: a unit is not a plugin
/// kind, and the set of units is closed.
pub trait Egress: sealed::Sealed {
    /// Walk one leg of the plan over the pool, and answer with what came back.
    ///
    /// The route request carries the borrowed views this walk reads — the ports, the plane, the
    /// transport, the verified set — and the request context carries the mutable state of one
    /// request: its deadline, everything it has tried, and the pools it has been through. They are
    /// separate because the first is shared and the second is not.
    fn route<'a>(
        &'a self,
        request: &'a RouteRequest<'a>,
        ctx: &'a mut RequestCtx,
        token: &'a UnitToken<Route>,
    ) -> ports::BoxFut<'a, RouteOutcome>;
}

/// The egress unit.
///
/// It holds one thing across requests: the weighted floor's rotation memory, which is stateful by
/// nature — the smoothness IS the memory — and which is per pool and per member, so the same
/// destination in two pools is two independent rotations. Everything else a walk needs is
/// borrowed for the length of one call.
#[derive(Debug, Default)]
pub struct EgressUnit {
    floor: WeightedFloor,
}

impl EgressUnit {
    /// An egress unit with no rotation history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rotation memory, so a caller can hand the same floor to a walk it drives itself.
    #[must_use]
    pub fn floor(&self) -> &WeightedFloor {
        &self.floor
    }
}

impl sealed::Sealed for EgressUnit {}

impl Egress for EgressUnit {
    fn route<'a>(
        &'a self,
        request: &'a RouteRequest<'a>,
        ctx: &'a mut RequestCtx,
        _token: &'a UnitToken<Route>,
    ) -> ports::BoxFut<'a, RouteOutcome> {
        // `request.token` (not `_token`) is what actually reaches every `Breaker::observe` call
        // through `Hop`/`RouteRequest` — see those types' own doc comments. `route`'s own token
        // parameter is the step-shaped seal every unit trait in the design carries; the caller
        // that builds `request` is the one that puts the SAME token borrow in both places.
        Box::pin(walk::walk(request, ctx))
    }
}

#[cfg(test)]
mod tests;
