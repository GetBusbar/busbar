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
                tier_bp: STANDARD_TIER_BP,
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
mod tests {
    use super::*;
    use busbar_unit_scope::required_scope;

    const POOL: &str = "pool-main";
    const LANE_A: &str = "lane-a";
    const LANE_B: &str = "lane-b";

    fn a_configured_card() -> MeterPolicyConfig {
        MeterPolicyConfig {
            pools: vec![PoolExpansion {
                pool: POOL.into(),
                lanes: vec![LANE_A.into(), LANE_B.into()],
            }],
            prices: vec![
                LanePrice {
                    lane: LANE_A.into(),
                    price: 900,
                },
                LanePrice {
                    lane: LANE_B.into(),
                    price: 100,
                },
            ],
            ..MeterPolicyConfig::default()
        }
    }

    /// **The hazard**, shown as the difference it makes. Under the configured policy a pool name
    /// stands for its member lanes, so a request that went to either of them belongs to the pool.
    /// Under the unit's own default the same lookup answers only the pool's own name, which no lane
    /// is called, so every pooled request reads as a mismatch.
    #[test]
    fn a_pool_expands_to_its_lanes_and_the_default_expands_to_nothing() {
        let configured = build(&a_configured_card());
        let expansion = configured.policy().expansion_of(POOL);
        assert_eq!(expansion, BTreeSet::from([LANE_A, LANE_B]));
        assert!(expansion.contains(LANE_A));

        let defaulted = MeterPolicy::default();
        assert_eq!(defaulted.expansion_of(POOL), BTreeSet::from([POOL]));
        assert!(
            !defaulted.expansion_of(POOL).contains(LANE_A),
            "an empty expansion turns set membership into string equality"
        );
    }

    /// A plain lane name needs no configuration and stands for itself, on either policy. That is
    /// what makes the empty default look harmless until a pool is involved.
    #[test]
    fn a_lane_name_stands_for_itself_without_being_declared() {
        let configured = build(&a_configured_card());
        assert_eq!(
            configured.policy().expansion_of("some-undeclared-lane"),
            BTreeSet::from(["some-undeclared-lane"])
        );
    }

    /// The prices come off the card. They decide only which reading wins when the legs disagree, so
    /// the value that matters is the ordering, not the magnitude.
    #[test]
    fn lane_prices_come_from_the_card() {
        let policy = build(&a_configured_card());
        assert_eq!(policy.policy().lane_prices.get(LANE_A), Some(&900));
        assert_eq!(policy.policy().lane_prices.get(LANE_B), Some(&100));
        assert!(
            !policy.policy().lane_prices.contains_key("unpriced-lane"),
            "an unpriced lane has no entry and sorts as cheapest, which is the conservative way"
        );
    }

    /// The tolerances fall back to the unit's own figures, and that is right: those ARE the design's
    /// numbers, and a deployment that sets neither is asking for them. The expansions are the ones
    /// that must not fall back, which is the distinction this test draws.
    #[test]
    fn the_tolerances_fall_back_but_the_expansions_do_not() {
        let policy = build(&a_configured_card());
        let defaults = MeterPolicy::default();
        assert_eq!(
            policy.policy().variance_tolerance_bp,
            defaults.variance_tolerance_bp
        );
        assert_eq!(
            policy.policy().locator_floor_ratio,
            defaults.locator_floor_ratio
        );
        assert_ne!(policy.policy().lane_expansions, defaults.lane_expansions);
    }

    /// A deployment that sets them gets what it set.
    #[test]
    fn a_declared_tolerance_overrides_the_units_figure() {
        let cfg = MeterPolicyConfig {
            variance_tolerance_bp: Some(25),
            locator_floor_ratio: Some(8),
            ..a_configured_card()
        };
        let policy = build(&cfg);
        assert_eq!(policy.policy().variance_tolerance_bp, 25);
        assert_eq!(policy.policy().locator_floor_ratio, 8);
    }

    /// A card may tighten a tolerance and never widen one. The unit enforces that; this checks that
    /// the entries reach it at all, since a tightening that never arrives is the same as no
    /// tightening.
    #[test]
    fn a_class_tightening_reaches_the_unit_and_a_loosening_is_ignored() {
        let cfg = MeterPolicyConfig {
            variance_tolerance_bp: Some(100),
            class_tolerances_bp: BTreeMap::from([
                ("tight-class".to_string(), 10),
                ("loose-class".to_string(), 500),
            ]),
            ..a_configured_card()
        };
        let policy = build(&cfg);
        assert_eq!(policy.policy().tolerance_bp("tight-class"), 10);
        assert_eq!(
            policy.policy().tolerance_bp("loose-class"),
            100,
            "a card may tighten a tolerance and never widen one"
        );
    }

    /// The boot check: a configured pool with no expansion is nameable while the pool is still in
    /// scope, rather than turning up later as a disputed posting that names nothing.
    #[test]
    fn a_pool_with_no_expansion_is_named_at_boot() {
        let cfg = MeterPolicyConfig {
            pools: vec![
                PoolExpansion {
                    pool: POOL.into(),
                    lanes: vec![LANE_A.into()],
                },
                PoolExpansion {
                    pool: "pool-empty".into(),
                    lanes: vec![],
                },
            ],
            ..MeterPolicyConfig::default()
        };
        let policy = build(&cfg);
        assert_eq!(pools_without_expansion(&cfg, &policy), vec!["pool-empty"]);
    }

    /// And a fully configured deployment names none.
    #[test]
    fn a_configured_deployment_has_no_unexpanded_pool() {
        let cfg = a_configured_card();
        let policy = build(&cfg);
        assert!(pools_without_expansion(&cfg, &policy).is_empty());
    }

    /// **The hazard**, on the transport axis: a client built from the crate's own `Default` ignores
    /// what the operator wrote. A deployment that caps request bodies at 1 KiB gets a transport that
    /// buffers 32 MiB, and the door and the transport then disagree about which bodies exist. Every
    /// field is checked, not just the cap, because the four beside it are operator knobs too and a
    /// mapping that forgot one would be invisible until the deployment that set it.
    #[test]
    fn the_transport_client_reads_the_operators_limits_and_not_a_default() {
        let limits = LimitsResolved {
            request_body_max_bytes: 1024,
            pool_max_idle_per_host: 7,
            pool_idle_timeout_secs: 11,
            upstream_http1_only: true,
            upstream_h2_prior_knowledge: false,
            ..LimitsResolved::default()
        };
        let settings = client_settings(&limits);
        assert_eq!(settings.request_body_max_bytes, 1024);
        assert_eq!(settings.pool_max_idle_per_host, 7);
        assert_eq!(settings.pool_idle_timeout_secs, 11);
        assert!(settings.upstream_http1_only);
        assert!(!settings.upstream_h2_prior_knowledge);
    }

    /// And a deployment that set nothing is left where it was: the resolved default body cap is the
    /// same 32 MiB the transport's own `Default` carries, so wiring the knob through cannot move a
    /// deployment that never touched it.
    #[test]
    fn an_unset_body_cap_resolves_to_the_transport_default() {
        let settings = client_settings(&LimitsResolved::default());
        assert_eq!(
            settings.request_body_max_bytes,
            ClientSettings::default().request_body_max_bytes
        );
        assert_eq!(
            settings.request_body_max_bytes,
            busbar_transport_http::DEFAULT_REQUEST_BODY_MAX_BYTES
        );
    }

    /// **Silence is a refusal.** The pair nobody wrote an entry for answers nothing, and the scope
    /// unit reads nothing as "not authorized". A view that answered a scope here would open every
    /// operation class the policy forgot to mention.
    #[test]
    fn a_pair_the_policy_is_silent_about_is_refused() {
        let policy = ScopePolicy::new();
        assert!(policy.is_empty());
        assert_eq!(
            required_scope(
                ClaimKey::new("some-claim"),
                OpClassId::new("some-op"),
                &policy
            ),
            None
        );
    }

    /// A declared pair answers what it was declared as, and nothing near it answers by association.
    #[test]
    fn only_the_declared_pair_answers() {
        let claim = ClaimKey::new("claim-one");
        let other_claim = ClaimKey::new("claim-two");
        let op = OpClassId::new("op-read");
        let other_op = OpClassId::new("op-write");

        let policy = ScopePolicy::new().declaring(claim, op, Scope::ReadOnly);

        assert_eq!(policy.len(), 1);
        assert_eq!(required_scope(claim, op, &policy), Some(Scope::ReadOnly));
        // The same claim's other operation class, and the other claim's same operation class,
        // are both silent. The lookup key is the PAIR, and neither half implies the other.
        assert_eq!(required_scope(claim, other_op, &policy), None);
        assert_eq!(required_scope(other_claim, op, &policy), None);
    }

    /// Both rungs are expressible, and a mutation declared as full stays full. The two-rung chain
    /// is strict: read-only does not satisfy full.
    #[test]
    fn both_rungs_are_declarable_and_the_chain_is_strict() {
        let claim = ClaimKey::new("claim");
        let read = OpClassId::new("op-read");
        let write = OpClassId::new("op-write");

        let policy = ScopePolicy::new()
            .declaring(claim, read, Scope::ReadOnly)
            .declaring(claim, write, Scope::Full);

        assert_eq!(required_scope(claim, read, &policy), Some(Scope::ReadOnly));
        assert_eq!(required_scope(claim, write, &policy), Some(Scope::Full));
    }

    /// A later declaration of the same pair replaces the earlier one rather than accumulating, so a
    /// policy has one answer per pair and a reload cannot leave two.
    #[test]
    fn redeclaring_a_pair_replaces_it() {
        let claim = ClaimKey::new("claim");
        let op = OpClassId::new("op");
        let policy = ScopePolicy::new()
            .declaring(claim, op, Scope::ReadOnly)
            .declaring(claim, op, Scope::Full);

        assert_eq!(policy.len(), 1);
        assert_eq!(required_scope(claim, op, &policy), Some(Scope::Full));
    }

    // ─────────────────────────────────────────────────────────────────────
    // The group table
    // ─────────────────────────────────────────────────────────────────────

    use busbar_substrate::config::groups::{LimitCfg, LimitWindow};

    fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
        LimitCfg {
            metric,
            amount,
            per,
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    }

    fn configured(name: &str, limits: Vec<LimitCfg>) -> (String, GroupCfg) {
        (
            name.to_string(),
            GroupCfg {
                parent: None,
                enabled: true,
                limits,
                child_default: None,
            },
        )
    }

    /// A group's `concurrent` limit reaches the table as the gauge's cap, and its window limits
    /// reach it as the bucket the ledger already writes. Both halves, because a table carrying one
    /// of them is a table that enforces half of what the operator wrote.
    #[test]
    fn a_configured_group_resolves_to_its_cap_and_its_bucket() {
        let groups = BTreeMap::from([configured(
            "team",
            vec![
                limit(LimitMetric::Concurrent, 1, None),
                limit(LimitMetric::Requests, 40, Some(LimitWindow::Minute)),
            ],
        )]);
        let table = group_table(&groups, &BTreeMap::new());
        let resolved = &table.groups()[0];
        assert_eq!(resolved.concurrent_cap, Some(1));
        assert_eq!(resolved.buckets.len(), 1);
        assert_eq!(resolved.buckets[0].bucket_id, "group:team@minute");
        assert_eq!(resolved.buckets[0].requests_cap, Some(40));
    }

    /// One metric written twice for one window keeps the tighter amount, which is the same
    /// most-restrictive-wins the chain applies between groups. Written loosest-first on purpose: a
    /// projection that simply overwrote would answer with the last one instead.
    #[test]
    fn a_metric_written_twice_keeps_the_tighter_amount() {
        let groups = BTreeMap::from([configured(
            "team",
            vec![
                limit(LimitMetric::Requests, 40, Some(LimitWindow::Minute)),
                limit(LimitMetric::Requests, 10, Some(LimitWindow::Minute)),
                limit(LimitMetric::Concurrent, 8, None),
                limit(LimitMetric::Concurrent, 2, None),
            ],
        )]);
        let table = group_table(&groups, &BTreeMap::new());
        let resolved = &table.groups()[0];
        assert_eq!(resolved.buckets[0].requests_cap, Some(10));
        assert_eq!(resolved.concurrent_cap, Some(2));
    }

    /// A pool-scoped limit accounts on a row of its own and participates only in its own pool's
    /// traffic. Two scoped budgets are two ledger rows, never one shared one.
    #[test]
    fn a_pool_scoped_limit_gets_its_own_row() {
        let mut cheap = limit(LimitMetric::Budget, 500, Some(LimitWindow::Month));
        cheap.scope = Some(busbar_api::ScopeRef::pool("value"));
        let mut dear = limit(LimitMetric::Budget, 500, Some(LimitWindow::Month));
        dear.scope = Some(busbar_api::ScopeRef::pool("frontier"));
        let groups = BTreeMap::from([configured("team", vec![cheap, dear])]);
        let table = group_table(&groups, &BTreeMap::new());
        let buckets = &table.groups()[0].buckets;
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].bucket_id, "group:team@month#pool:value");
        assert_eq!(buckets[1].bucket_id, "group:team@month#pool:frontier");
        let chain = table
            .chain_for("vk_one", Some("team"))
            .expect("the group is in the table");
        assert_eq!(chain.pool_filtered("value").len(), 2, "attribution + value");
        assert_eq!(chain.pool_filtered("other").len(), 1, "attribution alone");
    }

    /// The parent chain is walked by index, and the index is a position in the name-ordered table
    /// rather than in whatever order configuration happened to be written.
    #[test]
    fn a_parent_resolves_to_its_position_in_the_table() {
        let child = GroupCfg {
            parent: Some("zztop".to_string()),
            enabled: true,
            limits: vec![limit(LimitMetric::Concurrent, 3, None)],
            child_default: None,
        };
        let groups = BTreeMap::from([
            ("aaa".to_string(), child),
            configured("zztop", vec![limit(LimitMetric::Concurrent, 1, None)]),
        ]);
        let table = group_table(&groups, &BTreeMap::new());
        let chain = table.chain_for("vk_one", Some("aaa")).expect("configured");
        let names: Vec<&str> = chain.groups().iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["aaa", "zztop"], "innermost first, to the root");
    }

    /// The interned name rides on the group it names, and a group nobody interned carries none —
    /// which the door reads as a group it counts without naming.
    #[test]
    fn the_interned_name_rides_on_the_group_it_names() {
        let groups = BTreeMap::from([
            configured("named", vec![limit(LimitMetric::Concurrent, 1, None)]),
            configured("unnamed", vec![limit(LimitMetric::Concurrent, 1, None)]),
        ]);
        let ids = BTreeMap::from([("named".to_string(), "named")]);
        let table = group_table(&groups, &ids);
        let by_name = |n: &str| table.groups()[table.index_of(n).expect("configured")].lease_id;
        assert_eq!(by_name("named"), Some("named"));
        assert_eq!(by_name("unnamed"), None);
    }

    /// A principal bound to a group this node does not have is fail-closed at the chain, never a
    /// chain that quietly enforces nothing.
    #[test]
    fn a_group_this_node_does_not_have_is_fail_closed() {
        let table = group_table(&BTreeMap::new(), &BTreeMap::new());
        assert!(table.chain_for("vk_one", Some("ghost")).is_err());
        assert!(
            table.chain_for("vk_one", None).is_ok(),
            "a principal bound to no group walks its attribution bucket alone"
        );
    }
}
