// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two values the units take from configuration rather than from a `Default`, and the one place
//! that is decided.
//!
//! ## Why a default is the wrong answer here, twice, for two different reasons
//!
//! Both types below have a perfectly sensible `Default` or a perfectly sensible empty case. Neither
//! is safe to bind, and the failure modes are opposite, which is why they share a file: one is a
//! default that silently disputes every posting, and one is an emptiness that silently authorizes
//! everything.
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

use busbar_contract::{ClaimKey, OpClassId};
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
}
