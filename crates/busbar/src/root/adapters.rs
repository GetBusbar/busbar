// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams where two units name the same object at two widths.
//!
//! ## Why these exist at all, and why none of them is a defect
//!
//! A unit names no other unit. That is what makes each one testable on its own and what stops a
//! change in one from reaching through into another. The price is that when two units genuinely do
//! talk about the same thing — a pool member, a failure disposition — neither can name the other's
//! type, and something has to hold the mapping. That something is the composition root, and this
//! file is where it holds it.
//!
//! So an adapter here is not a workaround for a mistake in either crate. It is the seam the shape
//! predicted, and each one has a reference in the tree that proved the two real APIs meet.
//!
//! The breaker adapter below is the production binding of the seam that
//! `busbar-unit-egress/tests/breaker_adapter.rs` proved was implementable. That file stays where it
//! is: it lives under the egress unit's own tests so it can never be reached from that crate's
//! source, and it is what keeps the egress unit's port honest if this file ever stops existing. The
//! difference between the two is the one that matters — the reference closes over a default
//! configuration, and this one refuses to.
//!
//! ## The two
//!
//! 1. **Breaker to egress.** The egress unit's port takes no configuration and the breaker unit's
//!    method requires it, because the cooldown ladder is a per-pool declaration and the walk has no
//!    business knowing about ladders. The adapter closes over the configuration. **The one thing it
//!    must not do is close over a default**, which is the hazard the whole adapter exists around:
//!    a default ladder silently applies the wrong cooldowns, a lane recovers early or stays down,
//!    and nothing about the code looks wrong. So the configuration is per-pool, supplied, and
//!    missing-means-refuse rather than missing-means-default.
//!
//! 2. **Trust to breaker.** The trust unit's pre-walk filter keys on a lane's index in the pool's
//!    own table; the breaker and egress units key on a destination. Both name the pool member, from
//!    two sides, and the root holds the one mapping. This is not a width that could have been
//!    unified away: the trust unit's filter runs BEFORE a candidate set exists, so at that point
//!    there is nothing to have a destination identity yet.
//!
//! The metric labels the two units record a disposition under are both read off the contract's
//! one disposition table (`Disposition::label`), so there is no second bank to keep in step.

use busbar_contract::caps::{Pass, Route};
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::classify::Reading;
use busbar_kernel_breaker::{Breaker as BreakerUnitTrait, BreakerUnit, DestinationId, LaneState};
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, Outcome, Unavailable, UpstreamStatus,
};
use std::collections::HashMap;

/// The per-pool breaker configuration the adapter closes over.
///
/// A pool with no entry is a refusal to guess, not a fall back to the defaults. The whole hazard
/// this adapter is written around is a stale or default ladder applying the wrong cooldowns
/// invisibly, so an unconfigured pool is something a reader can see went wrong rather than
/// something that quietly behaves like a configured one.
#[derive(Debug, Default, Clone)]
pub struct BreakerPolicy {
    per_pool: HashMap<String, BreakerCfg>,
    fallback: Option<BreakerCfg>,
}

impl BreakerPolicy {
    #[must_use]
    pub fn new() -> Self {
        BreakerPolicy::default()
    }

    #[must_use]
    pub fn with_pool(mut self, pool: impl Into<String>, cfg: BreakerCfg) -> Self {
        self.per_pool.insert(pool.into(), cfg);
        self
    }

    #[must_use]
    pub fn with_default_cell(mut self, cfg: BreakerCfg) -> Self {
        self.fallback = Some(cfg);
        self
    }

    #[must_use]
    pub fn for_pool(&self, pool: &str) -> Option<&BreakerCfg> {
        if pool.is_empty() {
            self.fallback.as_ref()
        } else {
            self.per_pool.get(pool)
        }
    }
}

pub struct BreakerAdapter {
    unit: BreakerUnit,
    policy: BreakerPolicy,
}

impl BreakerAdapter {
    #[must_use]
    pub fn new(unit: BreakerUnit, policy: BreakerPolicy) -> Self {
        BreakerAdapter { unit, policy }
    }
}

pub(crate) fn try_admit(
    unit: &BreakerUnit,
    pool: &str,
    destination: DestinationId,
    now: u64,
) -> Result<Admit, Unavailable> {
    unit.try_admit(pool, destination, now)
        .map_err(|state| match state {
            LaneState::Suppressed { until } => Unavailable::BreakerOpen { until },
            LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
            LaneState::BudgetExhausted => Unavailable::BudgetExhausted,

            LaneState::Ready => Unavailable::ProbeInFlight,
        })
}

pub(crate) fn unavailable(
    unit: &BreakerUnit,
    pool: &str,
    destination: DestinationId,
    now: u64,
    token: &Pass<Route>,
) -> Option<Unavailable> {
    match busbar_kernel_breaker::Breaker::state(unit, pool, destination, now, token) {
        busbar_kernel_breaker::LaneState::Ready => None,
        busbar_kernel_breaker::LaneState::Suppressed { until } => {
            Some(Unavailable::BreakerOpen { until })
        }
        busbar_kernel_breaker::LaneState::BudgetExhausted => Some(Unavailable::BudgetExhausted),
        busbar_kernel_breaker::LaneState::ProbeInFlight => Some(Unavailable::ProbeInFlight),
    }
}

pub(crate) fn ready(
    unit: &BreakerUnit,
    pool: &str,
    destination: DestinationId,
    now: u64,
    token: &Pass<Route>,
) -> bool {
    matches!(unit.state(pool, destination, now, token), LaneState::Ready)
}

pub(crate) fn admissible(unit: &BreakerUnit, destination: DestinationId) -> bool {
    unit.budget_remaining(destination) != Some(0)
}

pub(crate) fn cooldown_remaining(
    unit: &BreakerUnit,
    pool: &str,
    destination: DestinationId,
    now: u64,
    token: &Pass<Route>,
) -> u64 {
    match unit.state(pool, destination, now, token) {
        LaneState::Suppressed { until } => until.saturating_sub(now),
        _ => 0,
    }
}

pub(crate) fn classify(status: UpstreamStatus) -> Classified {
    busbar_kernel_breaker::port::classify_upstream(busbar_kernel_breaker::port::UpstreamStatus {
        reading: reading(status),
        retry_after: status.retry_after,
    })
}

fn reading(status: UpstreamStatus) -> Reading {
    if status.class.is_none() && status.fault.is_none() {
        return Reading::NoAnswer;
    }
    Reading::Answered(status.fault)
}

impl Breaker for BreakerAdapter {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        try_admit(&self.unit, pool, destination, now)
    }

    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        unavailable(&self.unit, pool, destination, now, token)
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        ready(&self.unit, pool, destination, now, token)
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        admissible(&self.unit, destination)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        cooldown_remaining(&self.unit, pool, destination, now, token)
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        classify(status)
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        let Some(cfg) = self.policy.for_pool(pool) else {
            return false;
        };
        self.unit
            .observe(pool, destination, outcome, cfg, now, token)
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.unit.suppressing(destination, now)
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        self.unit.probed(
            destination,
            outcome,
            &|pool| self.policy.for_pool(pool).cloned(),
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

#[cfg(test)]
#[path = "tests/adapters.rs"]
mod tests;
