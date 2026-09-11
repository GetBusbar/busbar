// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The values the units take from configuration rather than from a `Default`, and the one place
//! that is decided.
//!
//! ## Why a default is the wrong answer here, three times, for three different reasons
//!
//! Every value below has a perfectly sensible `Default` or a perfectly sensible empty case. None of
//! them is safe to bind, and the failure modes point in different directions, which is why they
//! share a file: one is a default that silently disputes every posting, one is an emptiness that
//! silently authorizes everything, and one is an emptiness that silently enforces nothing.
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
//! **The group table.** Its natural empty case is a node that walks no group at all, and an empty
//! chain is admitted by every cap in it: the `concurrent` gauge is never raised, the budget bucket
//! is never read, the freeze flag is never consulted. An operator who wrote the caps down would
//! have a node that enforces none of them and says nothing about it on any surface, which is worse
//! than a node with no caps configured, because the caps are visibly there. So a leg is given the
//! resolved table or it is not built.
//!
//! ## What is not here
//!
//! The hook-veto seat. The scope unit does not reach the hook machinery and says so; the
//! composition is the root's, and it is an ordering rather than a value: the scope check runs
//! first, and a veto after it wins regardless of what it returned. That ordering belongs to the
//! step, not to the policy it reads, so it is not a field of anything in this file.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::{ClaimKey, OpClassId};
use busbar_substrate::config::groups::{GroupCfg, LimitMetric};
use busbar_substrate::config::limits::LimitsResolved;
use busbar_transport_http::ClientSettings;
use busbar_unit_admission::{GroupBucket, GroupRuntime, GroupTable, STANDARD_TIER_BP};
use busbar_unit_scope::{PolicyView, Scope};
use busbar_unit_usage::MeterPolicy;

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

/// Whether a deployment that configured pools got expansions for all of them.
///
/// The boot check for the hazard above. A configured pool with no expansion is the shape that turns
/// the set-membership test into an equality test for that pool, and the symptom is a disputed
/// posting rather than anything that names the pool, so it is worth catching where the pool is
/// still in scope.
#[must_use]
pub fn pools_without_expansion(cfg: &MeterPolicyConfig, policy: &MeterPolicyHandle) -> Vec<String> {
    cfg.pools
        .iter()
        .filter(|p| {
            policy
                .policy()
                .lane_expansions
                .get(&p.pool)
                .is_none_or(BTreeSet::is_empty)
        })
        .map(|p| p.pool.clone())
        .collect()
}

/// The egress/ingress client settings the http transport is built from, taken off the deployment's
/// resolved limits rather than from the transport crate's `Default`.
///
/// Every field of `ClientSettings` is an operator knob that already has a home in `limits:` /
/// `advanced:`, and the legacy serving path builds its upstream client from exactly these five
/// values. The one that matters most is `request_body_max_bytes`: it is the SAME number the served
/// door's inbound body limit is built from, so a transport built from a `Default` would accept a
/// body the door refused (or refuse one the door accepted) on any deployment that set the knob.
/// Reading all five off one struct is what makes that impossible to get half-right.
///
/// A deployment that sets nothing gets the config layer's own resolved defaults — which for the
/// body cap is the same 32 MiB `ClientSettings::default()` carries, so an unset limit changes
/// nothing.
///
/// The two deprecated upstream env overrides the legacy client build still honors are deliberately
/// not read here: this is the CONFIGURED posture, and the env vars are the legacy path's own
/// compatibility shim.
#[must_use]
pub fn client_settings(limits: &LimitsResolved) -> ClientSettings {
    ClientSettings {
        pool_max_idle_per_host: limits.pool_max_idle_per_host,
        pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
        upstream_http1_only: limits.upstream_http1_only,
        upstream_h2_prior_knowledge: limits.upstream_h2_prior_knowledge,
        request_body_max_bytes: limits.request_body_max_bytes,
        // The deployment resolves one body limit; the transport holds it against both directions,
        // which is the same posture its own default takes.
        response_body_max_bytes: limits.request_body_max_bytes,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The group table — the third configured value, and the third way a default is wrong
// ─────────────────────────────────────────────────────────────────────────────

/// The ledger-bucket prefix every configured group's window bucket is named under.
///
/// The same prefix the shipped release writes, because these are the same rows: a node that
/// resolved its groups through this projection and a node that resolved them through the shipped
/// door must charge the same cell for the same group, or one release's usage would read as another
/// release's silence.
const GROUP_BUCKET_PREFIX: &str = "group:";

/// Resolve the configured `groups:` tree into the table the door walks.
///
/// **Why an empty table is the wrong answer.** The third default this file exists to refuse. A
/// caller handing the door an empty chain gets a yes from every configured cap at once: the group's
/// `concurrent` gauge is never raised, its budget is never read, and its freeze flag is never
/// consulted — a deployment whose operator wrote the caps down and whose node enforces none of
/// them, with nothing on any surface to say so. So the legs take the table from here, and a leg
/// that has no table cannot be built.
///
/// The projection is the shipped release's, metric for metric: groups in name order so two boots on
/// one configuration resolve one table; a windowed metric materialising one bucket per distinct
/// (window, scope) pair in configuration order; a metric written twice for one pair folding to the
/// MOST RESTRICTIVE amount, which is the same AND the chain applies between groups; the most
/// restrictive budget's exhaustion behaviour governing, because that is the cap that actually
/// blocks; and `concurrent` folding to the minimum across repeats, windowless and pool-less by
/// grammar. A parent naming a group this table does not have resolves to no parent rather than a
/// panic — the missing parent is a validation refusal that has already run, and a config that
/// somehow booted past it degrades to a shorter chain.
///
/// `lease_ids` is the boot-interned name per group, from [`Vocabulary::group_ids`]. A group absent
/// from it carries no lease id, which is not an error: the door counts it exactly the same and the
/// slot simply does not name it.
///
/// [`Vocabulary::group_ids`]: crate::root::vocabulary::Vocabulary::group_ids
#[must_use]
pub fn group_table(
    groups: &BTreeMap<String, GroupCfg>,
    lease_ids: &BTreeMap<String, &'static str>,
) -> GroupTable {
    // Name order, so the table one configuration produces is the same table on every boot: the
    // parent indices below are positions in this vector, and a table whose order moved would be a
    // node whose chains moved with it.
    let index_of: BTreeMap<&str, usize> = groups
        .keys()
        .enumerate()
        .map(|(i, name)| (name.as_str(), i))
        .collect();

    let resolved = groups
        .iter()
        .map(|(name, cfg)| {
            let mut buckets: Vec<GroupBucket> = Vec::new();
            let mut concurrent_cap: Option<u64> = None;
            for limit in &cfg.limits {
                let (metric, Some(window)) = (limit.metric, limit.per) else {
                    // `concurrent` is the one metric the grammar gives no window, and it is a
                    // per-group gauge rather than a bucket. Any other windowless limit cannot
                    // deserialize, so there is nothing here to project and nothing to panic over.
                    if limit.metric == LimitMetric::Concurrent {
                        concurrent_cap =
                            Some(concurrent_cap.map_or(limit.amount, |c: u64| c.min(limit.amount)));
                    }
                    continue;
                };
                if metric == LimitMetric::Concurrent {
                    concurrent_cap =
                        Some(concurrent_cap.map_or(limit.amount, |c: u64| c.min(limit.amount)));
                    continue;
                }
                let window = window.as_str();
                // A limit's scope is a kind-tagged reference whose only kind the configuration
                // grammar can produce is the pool one — the YAML key is `pool:` and the parser
                // builds nothing else — and the chain's own scope is the pool name it compares by
                // equality. So the value is the whole of the translation.
                let scope = limit.scope.as_ref().map(|s| s.value.clone());
                let position = buckets
                    .iter()
                    .position(|b| b.window == window && b.scope == scope);
                let bucket = match position {
                    Some(i) => &mut buckets[i],
                    None => {
                        let bucket_id = match &limit.scope {
                            Some(s) => {
                                format!(
                                    "{GROUP_BUCKET_PREFIX}{name}@{window}#{}:{}",
                                    s.kind, s.value
                                )
                            }
                            None => format!("{GROUP_BUCKET_PREFIX}{name}@{window}"),
                        };
                        let mut fresh = GroupBucket::new(bucket_id, window);
                        fresh.scope = scope;
                        buckets.push(fresh);
                        buckets.last_mut().expect("just pushed")
                    }
                };
                let amount = limit.amount;
                let tighter = |cap: Option<u64>| Some(cap.map_or(amount, |c: u64| c.min(amount)));
                match metric {
                    LimitMetric::Requests => bucket.requests_cap = tighter(bucket.requests_cap),
                    LimitMetric::Tokens => bucket.tokens_cap = tighter(bucket.tokens_cap),
                    LimitMetric::TokensInput => {
                        bucket.tokens_input_cap = tighter(bucket.tokens_input_cap);
                    }
                    LimitMetric::TokensOutput => {
                        bucket.tokens_output_cap = tighter(bucket.tokens_output_cap);
                    }
                    LimitMetric::TokensCacheRead => {
                        bucket.tokens_cache_read_cap = tighter(bucket.tokens_cache_read_cap);
                    }
                    LimitMetric::TokensCacheWrite => {
                        bucket.tokens_cache_write_cap = tighter(bucket.tokens_cache_write_cap);
                    }
                    LimitMetric::Budget => {
                        let amount = i64::try_from(amount).unwrap_or(i64::MAX);
                        // The tightest budget is the one that blocks, so its exhaustion behaviour
                        // is the one that fires — including its absence, which is a block.
                        if bucket.budget_cap.is_none_or(|c| amount < c) {
                            bucket.downgrade_to =
                                limit.downgrade_to.as_ref().map(|s| s.value.clone());
                        }
                        bucket.budget_cap =
                            Some(bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)));
                    }
                    LimitMetric::Concurrent => continue,
                }
            }
            GroupRuntime {
                name: name.clone(),
                lease_id: lease_ids.get(name).copied(),
                enabled: cfg.enabled,
                concurrent_cap,
                // THE GROUP'S OWN TIER, as the deployment configured it. A group that declares
                // none is at the standard multiplier, which is one times the price and is what
                // every group in this tree was hardwired to before this key had a source. The
                // door sizes its hold through this; the fee site prices through the root's table
                // built from the same block, so the two are one reading of one configuration.
                tier_bp: cfg.tier_bp.unwrap_or(STANDARD_TIER_BP),
                buckets,
                parent: cfg.parent.as_deref().and_then(|p| index_of.get(p).copied()),
            }
        })
        .collect();

    GroupTable::new(resolved)
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
