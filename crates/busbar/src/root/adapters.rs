// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams where two units name the same object at two widths, and the boot check on two label
//! banks kept in step by hand.
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
//! ## The three
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
//! 3. **The label banks.** Two crates carry the same four metric label strings as separate
//!    literals, deliberately, because they share no dependency to point at one constant. They reach
//!    the scrape as label VALUES, so a drift between them is a wire change nobody would see in a
//!    diff. The check below compares them at boot. It does not introduce a shared constant: the two
//!    crates have no common dependency that could hold one, and putting an open-vocabulary key
//!    where the kernel could compare against it is the thing the lean-core scan exists to catch.

use busbar_contract::caps::{Pass, Route};
use busbar_contract::WireStatusClass;
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::classify::NoopDiagnostics;
use busbar_kernel_breaker::{Breaker as BreakerUnitTrait, BreakerUnit, DestinationId};
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, Outcome, Unavailable, UpstreamStatus,
};
use std::collections::HashMap;
use std::sync::Arc;

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
    /// A policy with no pool configured and no fallback.
    #[must_use]
    pub fn new() -> Self {
        BreakerPolicy::default()
    }

    /// Declare one pool's ladder.
    #[must_use]
    pub fn with_pool(mut self, pool: impl Into<String>, cfg: BreakerCfg) -> Self {
        self.per_pool.insert(pool.into(), cfg);
        self
    }

    /// Declare the ladder for the default cell — direct and ad-hoc routes, which run under the
    /// empty pool name and are not a configured pool at all.
    #[must_use]
    pub fn with_default_cell(mut self, cfg: BreakerCfg) -> Self {
        self.fallback = Some(cfg);
        self
    }

    /// The policy a deployment's `pools:` declare: every configured pool under its own resolved
    /// `breaker:` block (or the defaults, when it declares none), and the default cell under the
    /// defaults — the same ladder each pool's own dispatch resolves, lowered by the kernel's one
    /// lowering so the two cannot disagree.
    #[must_use]
    pub fn from_pools(pools: &HashMap<String, busbar_kernel::config::PoolCfg>) -> Self {
        use busbar_kernel::store::pool_breaker_cfg;
        pools.iter().fold(
            BreakerPolicy::new().with_default_cell(pool_breaker_cfg(None)),
            |policy, (name, pool)| {
                policy.with_pool(name.as_str(), pool_breaker_cfg(pool.breaker.as_ref()))
            },
        )
    }

    /// The ladder in force for one pool, if the configuration declared one.
    ///
    /// The default cell's declaration answers for the default cell and nothing else. A NAMED pool
    /// with no entry is a pool nobody configured — which is the case this whole type is written
    /// around — so it gets no ladder rather than the one declared for the routes that run without a
    /// pool at all.
    #[must_use]
    pub fn for_pool(&self, pool: &str) -> Option<&BreakerCfg> {
        if pool.is_empty() {
            self.fallback.as_ref()
        } else {
            self.per_pool.get(pool)
        }
    }
}

/// The egress unit's breaker port, bound to the breaker unit.
///
/// A thin wrapper with no policy of its own beyond the two folds the module doc names. What it must
/// never do is decide anything: a disposition is the breaker unit's data and a route is the egress
/// unit's walk, and an adapter that split the difference would be a third opinion nobody asked for.
pub struct BreakerAdapter {
    unit: UnitSource,
    policy: BreakerPolicy,
}

/// Where the adapter reaches its breaker unit: asked on every call, so a source that follows the
/// live configuration hands back the unit the node is admitting on NOW, not the one it booted with.
pub type UnitSource = Arc<dyn Fn() -> Arc<BreakerUnit> + Send + Sync>;

impl BreakerAdapter {
    /// Bind the egress port to a breaker unit, under a declared per-pool policy.
    #[must_use]
    pub fn new(unit: Arc<BreakerUnit>, policy: BreakerPolicy) -> Self {
        BreakerAdapter::over(Arc::new(move || Arc::clone(&unit)), policy)
    }

    /// Bind the egress port to whatever unit `source` answers with, under a declared policy.
    #[must_use]
    pub fn over(source: UnitSource, policy: BreakerPolicy) -> Self {
        BreakerAdapter {
            unit: source,
            policy,
        }
    }

    /// Bind the egress port to the kernel's OWN breaker — the unit the live snapshot's lane store is
    /// a handle onto — so there is one cell set on the node: an observation through this port is
    /// the one admission reads, and a trip the kernel records is the one this port answers with.
    /// Read through the handle on every call, because a config apply rebuilds the store (carrying
    /// its learned health over by lane identity) and the unit with it.
    #[must_use]
    pub fn over_kernel(
        handle: Arc<busbar_kernel::state::AppHandle>,
        policy: BreakerPolicy,
    ) -> Self {
        BreakerAdapter::over(Arc::new(move || handle.load().store.breaker_unit()), policy)
    }

    /// Bind the egress port to a fresh breaker unit, under a declared per-pool policy. The
    /// one-call form of [`BreakerAdapter::new`] for a caller with no unit of its own to hand in.
    #[must_use]
    pub fn with_policy(policy: BreakerPolicy) -> Self {
        BreakerAdapter::new(Arc::new(BreakerUnit::new()), policy)
    }

    /// The breaker unit behind the port, as its source answers now.
    #[must_use]
    pub fn unit(&self) -> Arc<BreakerUnit> {
        (self.unit)()
    }

    /// Fold the transport's coarse reading of a frame down to a representative numeric status, for
    /// when no number was reported.
    ///
    /// Success and the catch-all fold to nothing: there is no non-arbitrary number for either, and
    /// the breaker's own "no code" answer — record nothing, relay as-is — is exactly what the
    /// previous release did with an unexpected success reaching the error path.
    fn fold_class(class: Option<WireStatusClass>) -> Option<u16> {
        match class {
            Some(WireStatusClass::ClientError) => Some(400),
            Some(WireStatusClass::ServerError) => Some(500),
            Some(WireStatusClass::Success | WireStatusClass::Other) | None => None,
        }
    }

    /// Narrow the transport contract's namespaced status to the breaker unit's own, carrying the
    /// NAMESPACE across rather than the digits alone.
    ///
    /// Each numbering keeps its own table on the far side: an HTTP number is read against HTTP's
    /// bands, a `grpc-status` against gRPC's codes. Flattening the two into one integer here is
    /// precisely the defect this replaces — a gRPC `UNAVAILABLE` arrived as the number `14`, matched
    /// no HTTP band, and was read as the caller's fault, so the destination that had just declared
    /// itself down got no breaker record and the walk never failed over.
    ///
    /// The class fold is the fallback and only the fallback: it exists for a transport that read a
    /// class but no number at all, and a frame that HAS a number never reaches it. The folded
    /// stand-in is an HTTP one because the coarse class is protocol-neutral and HTTP's bands are the
    /// table the breaker has always read a classless answer through.
    fn narrow_code(status: UpstreamStatus) -> Option<busbar_kernel_breaker::port::UpstreamCode> {
        use busbar_kernel_breaker::port::UpstreamCode;
        // Asked by NAMESPACE, not by arm. The narrowing is this adapter's own — the breaker's
        // enum is closed and names the two numberings it keeps tables for — but the question put
        // to the frame is a keyed one, so a numbering this adapter has no table for is simply not
        // one of these two, and adding a family costs the transport contract nothing here.
        let Some(code) = status.code else {
            return Self::fold_class(status.class).map(UpstreamCode::Http);
        };
        if let Some(http) = code.http().and_then(|n| u16::try_from(n).ok()) {
            return Some(UpstreamCode::Http(http));
        }
        if let Some(grpc) = code.grpc().and_then(|n| u8::try_from(n).ok()) {
            return Some(UpstreamCode::Grpc(grpc));
        }
        None
    }
}

fn to_breaker_outcome(outcome: Outcome) -> busbar_kernel_breaker::Outcome {
    use busbar_kernel_breaker::Outcome as B;
    match outcome {
        Outcome::Success => B::Success,
        Outcome::Transient { retry_after } => B::Transient { retry_after },
        Outcome::HardDown => B::HardDown,
        Outcome::RecordNothing => B::RecordNothing,
    }
}

fn from_breaker_outcome(outcome: busbar_kernel_breaker::Outcome) -> Outcome {
    use busbar_kernel_breaker::Outcome as B;
    match outcome {
        B::Success => Outcome::Success,
        B::Transient { retry_after } => Outcome::Transient { retry_after },
        B::HardDown => Outcome::HardDown,
        B::RecordNothing => Outcome::RecordNothing,
    }
}

impl Breaker for BreakerAdapter {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        match self.unit().try_admit(pool, destination, now) {
            Ok(admit) => Ok(Admit {
                probe_epoch: admit.probe_epoch,
            }),
            Err(state) => Err(match state {
                busbar_kernel_breaker::LaneState::Suppressed { until } => {
                    Unavailable::BreakerOpen { until }
                }
                busbar_kernel_breaker::LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
                busbar_kernel_breaker::LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                // The unit refuses only from a state that would not have admitted, so this arm
                // does not arise. It still answers with a refusal rather than by aborting: a
                // routing step holding a dispatch open is the wrong place to discover that an
                // invariant of another crate has drifted, and the caller has a shed for it.
                busbar_kernel_breaker::LaneState::Ready => Unavailable::ProbeInFlight,
            }),
        }
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        matches!(
            self.unit().state(pool, destination, now, token),
            busbar_kernel_breaker::LaneState::Ready
        )
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        // The destination-scoped fact the breaker unit holds is the lifetime budget. Whether a
        // destination is administratively down is declared configuration, which is the egress and
        // configuration layer's to know and not this unit's. Answered from `budget_remaining`
        // alone, never from the sealed `state`/`observe`, so no token crosses here.
        self.unit().budget_remaining(destination) != Some(0)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        match self.unit().state(pool, destination, now, token) {
            busbar_kernel_breaker::LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        // The status alone, against no operator map: the breaker keeps none. Reading an error body
        // against the operator's `error_map` is the plane's classifier's work, and the unit is told
        // that verdict; this port answers only for the numbered status the walk read off the frame.
        let classified = busbar_kernel_breaker::port::classify_upstream(
            &HashMap::new(),
            busbar_kernel_breaker::port::UpstreamStatus {
                code: Self::narrow_code(status),
                retry_after: status.retry_after,
            },
            &NoopDiagnostics,
        );
        Classified {
            disposition: classified.disposition,
            outcome: from_breaker_outcome(classified.outcome),
            label: classified.label,
        }
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        // THE point of this adapter. The port carries no configuration, the unit requires it, and
        // the ladder is what decides how long a tripped lane stays down. A pool nobody configured
        // gets nothing recorded rather than a default ladder applied in its name: a wrong cooldown
        // is invisible, and a lane that never trips at least shows up as a lane that never trips.
        let Some(cfg) = self.policy.for_pool(pool) else {
            return false;
        };
        self.unit().observe(
            pool,
            destination,
            to_breaker_outcome(outcome),
            cfg,
            now,
            token,
        )
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.unit().release_probe(pool, destination, epoch, now);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.unit().spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.unit().refund_budget(destination);
    }
}

/// The one mapping between a pool member's two names.
///
/// The trust unit's pre-walk filter knows a lane by its index in the pool's own table; the breaker
/// and egress units know a pool member as a destination. The root holds the correspondence because
/// it is the only thing that sees both tables, and it is a `Vec` in table order because that is
/// what the index means.
#[derive(Debug, Default, Clone)]
pub struct LaneMap {
    destinations: Vec<DestinationId>,
}

impl LaneMap {
    /// A map over one pool's members, in the pool's own declaration order.
    #[must_use]
    pub fn new(destinations: Vec<DestinationId>) -> Self {
        LaneMap { destinations }
    }

    /// The destination a lane index names, if the index is in the table.
    ///
    /// An index off the end answers nothing rather than saturating to the last member: a lane the
    /// table does not have is a mistake somewhere upstream, and answering with somebody else's
    /// destination would send a request to the wrong upstream and look like it worked.
    #[must_use]
    pub fn destination(&self, lane: usize) -> Option<DestinationId> {
        self.destinations.get(lane).copied()
    }

    /// The lane index a destination sits at, if it is in this pool.
    #[must_use]
    pub fn lane(&self, destination: DestinationId) -> Option<usize> {
        self.destinations.iter().position(|d| *d == destination)
    }

    /// How many members the pool has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    /// Whether the pool has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }
}

/// A label that appears in one crate's bank and not the other's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelDrift {
    /// What the breaker unit calls it.
    pub breaker: &'static str,
    /// What the egress unit calls it.
    pub egress: &'static str,
}

impl std::fmt::Display for LabelDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "metric label banks drifted: the breaker unit says `{}` where the egress unit says `{}`",
            self.breaker, self.egress
        )
    }
}

impl std::error::Error for LabelDrift {}

/// Check at boot that the two crates' metric label banks still agree.
///
/// The three labels both crates carry are duplicate literals, kept in step by hand and deliberately
/// not shared: the crates have no common dependency that could hold a constant, and a shared one
/// would put an open-vocabulary key somewhere the lean-core scan forbids. What that leaves is a
/// drift nobody would notice — the labels reach the scrape as label VALUES, so a change on one side
/// is a wire change that looks like an ordinary edit in a diff. Comparing them once, at boot, is
/// what turns the hand-kept convention into something mechanical.
///
/// Two labels are not compared and cannot be: the breaker unit's client-fault label has no egress
/// counterpart (the walk short-circuits before it would use one) and the egress unit's
/// attempt-timeout label has no breaker counterpart (a deadline this side of the wire is not a
/// classification of anything upstream). Both are single-sided by design, not by omission.
///
/// # Errors
///
/// A label present in both banks has different text on the two sides.
pub fn check_label_banks() -> Result<(), LabelDrift> {
    use busbar_kernel_breaker::port::label;
    use busbar_kernel_egress::ports::disposition;

    for (breaker, egress) in [
        (label::TRANSIENT_UPSTREAM, disposition::TRANSIENT),
        (label::HARD_DOWN, disposition::HARD_DOWN),
        (label::CONTEXT_LENGTH, disposition::CONTEXT_LENGTH),
    ] {
        if breaker != egress {
            return Err(LabelDrift { breaker, egress });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/adapters.rs"]
mod tests;
