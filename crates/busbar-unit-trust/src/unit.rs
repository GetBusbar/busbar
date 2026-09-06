// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: the unit the loop calls at the verify step.

use busbar_caps::VerifiedDestination;
use busbar_caps::{Decision, Refusal, TrustToken, UnitToken, Verify};

use crate::destination::{
    kind_permitted, kind_rule_passes, DestinationFacts, KindFacts, OriginKind,
};
use crate::guard::{destination_guard, PoolView};
use crate::lane::{BreakerQuery, BreakerView};

/// Everything the unit is given about one verification.
pub struct VerifyRequest<'a> {
    /// Where the unit came from — which decides which kinds it may reach at all.
    pub origin: OriginKind,
    /// The candidates the plane proposed.
    pub candidates: &'a [DestinationFacts],
    /// The pool the request named.
    pub pool: &'a str,
    /// The unit's pinned arrival epoch, which is the moment every readiness peek of this step is
    /// asked at. Never a fresh clock read on the request path: a peek taken at a different moment
    /// from the walk's own is a second opinion about a lane nothing happened to.
    pub now: u64,
    /// The caller-facing text for the unpriced refusal, which names what the caller asked for.
    pub unpriced_message: &'static str,
}

/// The verify unit.
pub struct Trust;

impl Trust {
    /// Judge where this unit may go.
    ///
    /// The shape of the answer is the design's own: the guards run first and can refuse; then every
    /// candidate is checked against the kinds its origin may reach and against its own per-kind
    /// rule; whatever survives is sealed.
    ///
    /// The one arm that surprises people is the empty one. A pool with every lane excluded does NOT
    /// refuse here. It proceeds — an empty set is a legitimate answer at this step — and the door
    /// draws and RETAINS the slot, exactly as the shipped behaviour charged before its exhaustion
    /// answer. Refusing here would move the charge, and moving a charge is not a refactor.
    pub fn verify(
        &self,
        req: &VerifyRequest<'_>,
        pools: &dyn PoolView,
        facts: &dyn KindFacts,
        breaker: &dyn BreakerView,
        trust: &TrustToken,
        token: &UnitToken<Verify>,
    ) -> Decision<Verify> {
        // The three guards, in their fixed order, all before anything is charged.
        if let Err(refusal) = destination_guard(pools, req.pool, req.unpriced_message) {
            return Decision::refuse(token, Refusal::new(refusal.kind.reason()));
        }

        // The breaker is asked HERE, through the same query the pre-walk's filter asks through, so a
        // lane excluded for an open breaker is excluded once and identically on both paths. Nothing
        // is excluded twice and nothing is excluded two different ways.
        let at = BreakerQuery {
            breaker,
            pool: req.pool,
            now: req.now,
        };

        let sealed: Vec<VerifiedDestination> = req
            .candidates
            .iter()
            .filter(|d| kind_permitted(req.origin, d))
            .filter(|d| kind_rule_passes(d, facts, &at))
            // A destination whose kind carries no lane is not priced on one and does not enter the
            // sealed set. That is not an exclusion and nothing is lost by it: such a destination is
            // reached through the route plan rather than through this pool walk, so a seal here
            // would have to invent a lane name to price it against.
            .filter_map(|d| d.lane())
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();

        Decision::proceed(token, sealed)
    }
}
