// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The values the units take from configuration rather than from a `Default`, and the one place
//! that is decided.
//!
//! ## Why a default is the wrong answer here, twice, for two different reasons
//!
//! Every value below has a perfectly sensible `Default` or a perfectly sensible empty case. None of
//! them is safe to bind, and the failure modes point in different directions, which is why they
//! share a file: one is a default that silently disputes every posting, and one is an emptiness
//! that silently authorizes everything.
//!
//! **The metering policy.** Its default carries empty lane expansions. An expansion is what turns
//! "this request went to pool `main`" into "this request went to one of `main`'s lanes", and with
//! the map empty that test collapses from set membership to string equality. Every pooled request
//! then reads as a lane mismatch: the posting is disputed, the cheaper reading wins, and the
//! deployment's alarm fires per lane per window until it drains. Nothing about that looks like a
//! configuration problem from the outside — it looks like the meter disagreeing with itself.
//!
//! **The scope view.** Its natural empty case is a policy that says nothing about anything, and the
//! scope unit is explicit that a pair the policy is silent about has NO required scope, which is a
//! REFUSAL and not a pass. An operation nobody wrote a policy entry for has not been authorized. A
//! view that inverted that — answering "read-only is enough" for an unknown pair, or answering
//! `Some` where it meant "I do not know" — would authorize by omission, and every plane's operation
//! classes would open at once. So the type below cannot express the inversion: it holds declared
//! entries and answers `None` for everything else, and the only way to permit something is to have
//! said so.
//!
//! ## What is not here
//!
//! The hook-veto seat. The scope unit does not reach the hook machinery and says so; the
//! composition is the root's, and it is an ordering rather than a value: the scope check runs
//! first, and a veto after it wins regardless of what it returned. That ordering belongs to the
//! step, not to the policy it reads, so it is not a field of anything in this file.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::transport::TransportSettings;
use busbar_contract::{ClaimKey, OpClassId};
use busbar_kernel::config::limits::LimitsResolved;
use busbar_kernel_ledger::usage::MeterPolicy;
use busbar_kernel_scope::{PolicyView, Scope};

/// One pool, as the metering policy needs to know it: its name and the lanes it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolExpansion {
    /// The pool's configured name — the name a request locates.
    pub pool: String,
    /// The lanes it expands to, in the pool's own declaration order.
    pub lanes: Vec<String>,
}

/// One lane's comparable price, off the rate card.
///
/// Used for one thing only: choosing the cheaper entry when the three legs of a lane cross-check
/// disagree. A lane with no entry sorts as cheapest, which is the conservative direction — an
/// unpriced lane cannot be made to look expensive by omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanePrice {
    /// The lane.
    pub lane: String,
    /// Its comparable unit price.
    pub price: u128,
}

/// What the root reads off the parsed rate cards to build the metering policy.
///
/// Named as a struct rather than passed as four arguments because the point of the type is the
/// list: these are the values that must come from configuration, and a reader checking whether
/// something was forgotten wants one place to look.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MeterPolicyConfig {
    /// Every configured pool and the lanes it expands to.
    pub pools: Vec<PoolExpansion>,
    /// Every priced lane.
    pub prices: Vec<LanePrice>,
    /// Per-class tightenings of the variance tolerance. A card may tighten and never loosen; an
    /// entry that would loosen is ignored by the unit, so a card cannot widen its own tolerance by
    /// declaring one.
    pub class_tolerances_bp: BTreeMap<String, u32>,
    /// The general variance tolerance, where the deployment set one.
    pub variance_tolerance_bp: Option<u32>,
    /// The one-sided sanity bound for a located class, where the deployment set one.
    pub locator_floor_ratio: Option<u64>,
}

/// The metering policy the usage unit is handed.
///
/// A newtype rather than the unit's own struct passed around bare, so that "this came from
/// configuration" is visible in the type of every function that takes one. The only way to make one
/// is [`build`], and [`build`] takes the configuration.
#[derive(Debug, Clone)]
pub struct MeterPolicyHandle(MeterPolicy);

impl MeterPolicyHandle {
    /// The policy, as the usage unit reads it.
    #[must_use]
    pub fn policy(&self) -> &MeterPolicy {
        &self.0
    }
}

/// Build the metering policy from the parsed rate cards.
///
/// The two fields that matter are filled from configuration and are the reason this function
/// exists: `lane_expansions` and `lane_prices`. The two tolerances fall back to the unit's own
/// figures, which is correct — those ARE the design's numbers, and a deployment that sets neither
/// is asking for them. Empty expansions are not, which is the difference.
#[must_use]
pub fn build(cfg: &MeterPolicyConfig) -> MeterPolicyHandle {
    let mut lane_expansions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pool in &cfg.pools {
        lane_expansions
            .entry(pool.pool.clone())
            .or_default()
            .extend(pool.lanes.iter().cloned());
    }

    let lane_prices = cfg
        .prices
        .iter()
        .map(|p| (p.lane.clone(), p.price))
        .collect();

    let defaults = MeterPolicy::default();
    MeterPolicyHandle(MeterPolicy {
        variance_tolerance_bp: cfg
            .variance_tolerance_bp
            .unwrap_or(defaults.variance_tolerance_bp),
        class_tolerance_bp: cfg.class_tolerances_bp.clone(),
        locator_floor_ratio: cfg
            .locator_floor_ratio
            .unwrap_or(defaults.locator_floor_ratio),
        lane_expansions,
        lane_prices,
    })
}

/// The settings every linked transport is built from, taken off the deployment's resolved limits
/// rather than from a `Default`.
///
/// Every field of `TransportSettings` is an operator knob that already has a home in `limits:` /
/// `advanced:`, and the legacy serving path builds its upstream client from exactly these six
/// values. The one that matters most is `request_body_max_bytes`: it is the SAME number the served
/// door's inbound body limit is built from, so a transport built from a `Default` would accept a
/// body the door refused (or refuse one the door accepted) on any deployment that set the knob.
/// `request_timeout_secs` is the same shape of hazard for a different knob: a deployment that
/// raised `limits.upstream_request_timeout_secs` for long generations must have the transport's own
/// `client.request()` wait raised with it, not silently re-capped at a transport-crate default.
/// Reading all six off one struct is what makes that impossible to get half-right.
///
/// A deployment that sets nothing gets the config layer's own resolved defaults — which for the
/// body cap is the same 32 MiB `TransportSettings::default()` carries, so an unset limit changes
/// nothing.
///
/// The two deprecated upstream env overrides are read here, as 1.5.5 read them at its client build:
/// `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` and `BUSBAR_UPSTREAM_HTTP1_ONLY`, when set, win over
/// `advanced.upstream_h2_prior_knowledge` / `advanced.upstream_http1_only` (anything but empty or
/// `0` reads as on). The transports these settings open (the http door's prior-knowledge and
/// http1-only keys) are the egress client now, so an existing pin keeps working across the upgrade.
/// The deprecation line itself is the kernel's app build's, in 1.5.5's words, once per boot.
#[must_use]
pub fn client_settings(limits: &LimitsResolved) -> TransportSettings {
    client_settings_under(limits, |name| std::env::var_os(name))
}

/// [`client_settings`] with the process environment read through `env`.
#[must_use]
pub(crate) fn client_settings_under(
    limits: &LimitsResolved,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> TransportSettings {
    use busbar_kernel::appbuild::{
        upstream_bool_env_override, ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE, ENV_UPSTREAM_HTTP1_ONLY,
    };
    TransportSettings {
        pool_max_idle_per_host: limits.pool_max_idle_per_host,
        pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
        upstream_http1_only: upstream_bool_env_override(
            env(ENV_UPSTREAM_HTTP1_ONLY),
            limits.upstream_http1_only,
        ),
        upstream_h2_prior_knowledge: upstream_bool_env_override(
            env(ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE),
            limits.upstream_h2_prior_knowledge,
        ),
        request_body_max_bytes: limits.request_body_max_bytes,
        // The deployment resolves one body limit; the transport holds it against both directions,
        // which is the same posture its own default takes.
        response_body_max_bytes: limits.request_body_max_bytes,
        request_timeout_secs: limits.upstream_request_timeout_secs,
    }
}

/// The scope unit's policy view, over what the deployment's policy actually declared.
///
/// It holds entries and nothing else. There is no default arm, no catch-all and no "unknown means
/// read-only": a pair with no entry answers `None`, and the scope unit reads `None` as a refusal.
/// The type is shaped so that the dangerous answer cannot be given by accident — you cannot
/// construct one that permits something it was not told about.
#[derive(Debug, Default, Clone)]
pub struct ScopePolicy {
    entries: BTreeMap<(&'static str, &'static str), Scope>,
}

impl ScopePolicy {
    /// A policy that permits nothing, because it has been told nothing.
    #[must_use]
    pub fn new() -> Self {
        ScopePolicy::default()
    }

    /// Declare the scope one claim's operation class requires.
    #[must_use]
    pub fn declaring(mut self, claim: ClaimKey, op: OpClassId, scope: Scope) -> Self {
        self.entries.insert((claim.as_str(), op.as_str()), scope);
        self
    }

    /// How many pairs the policy speaks about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the policy speaks about nothing, and therefore permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl PolicyView for ScopePolicy {
    fn required_scope(&self, claim: ClaimKey, op: OpClassId) -> Option<Scope> {
        // `None` here is a refusal, not a pass, and this is the whole of the implementation for
        // exactly that reason: there is nowhere for a fallback to be added by accident.
        self.entries.get(&(claim.as_str(), op.as_str())).copied()
    }
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
