// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: the unit the loop calls at the verify step.

use busbar_caps::VerifiedDestination;
use busbar_caps::{Decision, ReasonCode, Refusal, TrustToken, UnitToken, Verify};

use crate::destination::{
    kind_permitted, kind_rule_passes, DestinationFacts, KindFacts, OriginKind,
};
use crate::guard::{destination_guard, PoolView, RefusalKind};

/// Everything the unit is given about one verification.
pub struct VerifyRequest<'a> {
    /// Where the unit came from — which decides which kinds it may reach at all.
    pub origin: OriginKind,
    /// The candidates the plane proposed.
    pub candidates: &'a [DestinationFacts],
    /// The pool the request named.
    pub pool: &'a str,
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
        trust: &TrustToken,
        token: &UnitToken<Verify>,
    ) -> Decision<Verify> {
        // The three guards, in their fixed order, all before anything is charged.
        if let Err(refusal) = destination_guard(pools, req.pool, req.unpriced_message) {
            let reason = match refusal.kind {
                // A caller who may not reach this destination is denied the scope, not the budget.
                RefusalKind::Permission => ReasonCode::ScopeDenied,
                // An unpriced arbitrary name is a bad request, not an exhausted one.
                RefusalKind::InvalidRequest => ReasonCode::Unpriced,
            };
            return Decision::refuse(token, Refusal::new(reason));
        }

        let sealed: Vec<VerifiedDestination> = req
            .candidates
            .iter()
            .filter(|d| kind_permitted(req.origin, d))
            .filter(|d| kind_rule_passes(d, facts))
            // A destination whose kind carries no lane is not priced on one; the seal records
            // that rather than inventing a name for it.
            .filter_map(|d| d.lane())
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();

        Decision::proceed(token, sealed)
    }
}
