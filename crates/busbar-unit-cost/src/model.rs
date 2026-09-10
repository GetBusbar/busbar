// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cost model: the card and the group limit topology, bound as one value.
//!
//! A deployment's money is configured in two sections that are enforced together. The `rate_card:`
//! and its flat fee say what a unit of usage COSTS; the `groups:` tree says how much of it a chain
//! of principals may SPEND, per window, per pool. A budget cap is a number in one section compared
//! against a sum derived from the other, so the two are resolved together and held together: a
//! model resolved from one configuration is one reading of that deployment's money, and it is
//! rebuilt whole on apply rather than patched in place.
//!
//! THE PROJECTION IS HERE AND NOWHERE ELSE. The `groups:` section used to be projected into
//! enforcement buckets twice — once by the retiring engine and once by the composition root, into
//! the table the door walks — and two projections of the money topology that must agree exactly is
//! how a deployment comes to be ADMITTED against one set of ledger cells and BILLED against another,
//! silently, because both answers are internally consistent and neither knows the other exists.
//! The root now hands this crate the configured limits as plain values, exactly as it hands the
//! card its raw rates, and takes the resolved table back.
//!
//! The types the projection produces — a bucket, a group, the table — are the shape the admission
//! unit's chain walk chases indices through. They are declared here because the model owns them:
//! the door reads the table, and it never builds one.

use std::collections::BTreeMap;

use crate::posting::STANDARD_TIER_BP;
use crate::rate::RateCard;

/// The prefix every group's window bucket is named under in the ledger.
///
/// A group's per-window buckets are `group:<name>@<window>` — one ledger row per (group, window)
/// — and a scope-qualified bucket appends `#<kind>:<value>`, its own row accounting only the traffic
/// dispatched through that scope. The prefix keeps a group named like a principal's id from ever
/// colliding with that principal's own bucket, and it is the same prefix the previous release
/// wrote, because these are the same rows.
pub const GROUP_BUCKET_PREFIX: &str = "group:";

// ── the configured limits, as the values this crate reads ────────────────────────────────────────

// THE SPEC VOCABULARY IS THE CONTRACT'S, not this crate's.
//
// It was declared here while the crates landed side by side, and that placement forced the RELAY —
// the configured `groups:` section read into these values — to be written somewhere that could name
// both this crate and the configuration grammar's. Only a composition root could, so the relay lived
// in the root, and every engine that resolves a model without a root behind it had to carry its own
// copy of it. Two readings of one `groups:` section that must agree exactly is how a deployment
// comes to be admitted against one set of ledger cells and billed against another.
//
// The vocabulary now sits in `busbar_contract::limits`, which the grammar's crate and this one both
// already name, so the relay is written once against the contract and every reader reaches it. The
// names are re-exported here at their historical paths: this crate still OWNS the projection, and a
// caller that resolves a table names one crate as before.
pub use busbar_contract::limits::{GroupSpec, LimitMetric, LimitSpec, ScopeSpec};

// ── the resolved topology ────────────────────────────────────────────────────────────────────────

/// One group's per-window enforcement bucket, before it is bound to a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBucket {
    /// The ledger bucket id this group's window writes to.
    pub bucket_id: String,
    /// The window word.
    pub window: &'static str,
    /// Request-count cap, if any.
    pub requests_cap: Option<u64>,
    /// Total-token cap, if any.
    pub tokens_cap: Option<u64>,
    /// Uncached-input token cap, if any.
    pub tokens_input_cap: Option<u64>,
    /// Output token cap, if any.
    pub tokens_output_cap: Option<u64>,
    /// Cache-read token cap, if any.
    pub tokens_cache_read_cap: Option<u64>,
    /// Cache-write token cap, if any.
    pub tokens_cache_write_cap: Option<u64>,
    /// Spend cap in minor units, if any.
    pub budget_cap: Option<i64>,
    /// The pool this bucket is qualified to, if any.
    pub scope: Option<String>,
    /// The downgrade target the governing budget limit declared, if any.
    pub downgrade_to: Option<String>,
}

impl GroupBucket {
    /// A bucket for `window` with no caps set, to be filled in by the projection.
    pub fn new(bucket_id: impl Into<String>, window: &'static str) -> Self {
        GroupBucket {
            bucket_id: bucket_id.into(),
            window,
            requests_cap: None,
            tokens_cap: None,
            tokens_input_cap: None,
            tokens_output_cap: None,
            tokens_cache_read_cap: None,
            tokens_cache_write_cap: None,
            budget_cap: None,
            scope: None,
            downgrade_to: None,
        }
    }
}

/// One resolved group: its freeze flag, its in-flight cap, its per-window buckets, and its parent
/// by index, so the chain walk is index-chasing with no hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRuntime {
    /// The group's name.
    pub name: String,
    /// The same name as the composition root interned it, handed over at registration.
    ///
    /// The door works in `String`s because a group name is config-derived, and a caller that
    /// wants to record what the door counted somewhere with a static vocabulary needs the name in
    /// that vocabulary. Interning is the root's job and happens once, at boot; this field is where
    /// the result is handed over. `None` is a group the root did not intern, and it is not an
    /// error: the decision is unaffected either way, and a caller reading the names back simply
    /// does not see this one.
    pub lease_id: Option<&'static str>,
    /// `false` freezes the group and every descendant.
    pub enabled: bool,
    /// The instantaneous in-flight cap, if any.
    pub concurrent_cap: Option<u64>,
    /// The tier multiplier in basis points.
    pub tier_bp: u32,
    /// The group's per-window enforcement buckets, one per distinct window its limits use. Empty
    /// for a group with only a concurrent cap, or none at all.
    pub buckets: Vec<GroupBucket>,
    /// The parent group's index in the table, if any.
    pub parent: Option<usize>,
}

impl GroupRuntime {
    /// An enabled group with no caps and no parent.
    pub fn new(name: impl Into<String>) -> Self {
        GroupRuntime {
            name: name.into(),
            lease_id: None,
            enabled: true,
            concurrent_cap: None,
            tier_bp: STANDARD_TIER_BP,
            buckets: Vec::new(),
            parent: None,
        }
    }
}

/// The resolved group topology: the table the chain walk chases indices through.
#[derive(Debug, Clone, Default)]
pub struct GroupTable {
    groups: Vec<GroupRuntime>,
}

impl GroupTable {
    /// A table from groups already resolved. The parent indices are positions in this vector, and
    /// the walk clamps on a cycle or a dangling index either way.
    pub fn new(groups: Vec<GroupRuntime>) -> Self {
        GroupTable { groups }
    }

    /// Every group.
    pub fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    /// The index of a group by name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.groups.iter().position(|g| g.name == name)
    }

    /// **THE PROJECTION**: the configured `groups:` tree, resolved into the table the door walks.
    ///
    /// Metric for metric it is the previous release's, because the rows it names are the previous
    /// release's rows. Groups resolve in name order so two boots on one configuration resolve one
    /// table; a windowed metric materialises one bucket per distinct (window, scope) pair, in
    /// configuration order; a metric written twice for one pair folds to the MOST RESTRICTIVE
    /// amount, which is the same AND the chain applies between groups; the most restrictive
    /// budget's exhaustion behaviour governs, because that is the cap that actually blocks; and
    /// `concurrent` folds to the minimum across repeats, windowless and pool-less by grammar.
    ///
    /// Defensive and never panicking on what validation should already have refused: a parent
    /// naming a group the table does not have resolves to no parent, so a configuration that
    /// somehow booted past the check degrades to a shorter chain; a windowed metric with no window
    /// cannot deserialize, and is skipped rather than guessed at.
    pub fn resolve(groups: &BTreeMap<String, GroupSpec>) -> Self {
        let index_of: BTreeMap<&str, usize> = groups
            .keys()
            .enumerate()
            .map(|(i, name)| (name.as_str(), i))
            .collect();
        let resolved = groups
            .iter()
            .map(|(name, spec)| {
                let mut buckets: Vec<GroupBucket> = Vec::new();
                let mut concurrent_cap: Option<u64> = None;
                for limit in &spec.limits {
                    let window = match (limit.metric, limit.window) {
                        (LimitMetric::Concurrent, _) => {
                            concurrent_cap = Some(
                                concurrent_cap.map_or(limit.amount, |c: u64| c.min(limit.amount)),
                            );
                            continue;
                        }
                        (_, Some(window)) => window,
                        (_, None) => continue,
                    };
                    let scope = limit.scope.as_ref().map(|s| s.value.clone());
                    let position = buckets
                        .iter()
                        .position(|b| b.window == window && b.scope == scope);
                    let bucket = match position {
                        Some(i) => &mut buckets[i],
                        None => {
                            let bucket_id = match &limit.scope {
                                Some(s) => format!(
                                    "{GROUP_BUCKET_PREFIX}{name}@{window}#{}:{}",
                                    s.kind, s.value
                                ),
                                None => format!("{GROUP_BUCKET_PREFIX}{name}@{window}"),
                            };
                            let mut fresh = GroupBucket::new(bucket_id, window);
                            fresh.scope = scope;
                            buckets.push(fresh);
                            buckets.last_mut().expect("just pushed")
                        }
                    };
                    let amount = limit.amount;
                    let tighter =
                        |cap: Option<u64>| Some(cap.map_or(amount, |c: u64| c.min(amount)));
                    match limit.metric {
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
                            // The tightest budget is the one that blocks, so its exhaustion
                            // behaviour is the one that fires — including its absence, a block.
                            if bucket.budget_cap.is_none_or(|c| amount < c) {
                                bucket.downgrade_to =
                                    limit.downgrade_to.as_ref().map(|s| s.value.clone());
                            }
                            bucket.budget_cap =
                                Some(bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)));
                        }
                        LimitMetric::Concurrent => unreachable!("folded above"),
                    }
                }
                GroupRuntime {
                    name: name.clone(),
                    lease_id: spec.lease_id,
                    enabled: spec.enabled,
                    concurrent_cap,
                    tier_bp: STANDARD_TIER_BP,
                    buckets,
                    parent: spec
                        .parent
                        .as_deref()
                        .and_then(|p| index_of.get(p).copied()),
                }
            })
            .collect();
        GroupTable::new(resolved)
    }
}

// ── the model ────────────────────────────────────────────────────────────────────────────────────

/// The resolved cost model: the card, with its flat fee, and the group limit topology, as one
/// immutable value. Rebuilt with the configuration on apply; never patched.
#[derive(Debug, Clone)]
pub struct CostModel {
    card: RateCard,
    groups: GroupTable,
}

impl CostModel {
    /// Resolve the model from its two configured parts: the card the root built from the rate
    /// section, and the group tree as plain limit values. Assumes configuration validation has
    /// already passed; the projection is defensive on anything it should have caught.
    pub fn resolve_parts(card: RateCard, groups: &BTreeMap<String, GroupSpec>) -> Self {
        CostModel {
            card,
            groups: GroupTable::resolve(groups),
        }
    }

    /// The card: what usage costs, and the flat fee.
    pub fn card(&self) -> &RateCard {
        &self.card
    }

    /// The topology: what a chain may spend.
    pub fn groups(&self) -> &GroupTable {
        &self.groups
    }

    /// Whether a card is configured at all (token pricing active).
    pub fn pricing_enabled(&self) -> bool {
        self.card.pricing_enabled()
    }

    /// Whether a request for `model` must be refused because a card is present and has no entry
    /// for it. A model is a lane, as the card names one. With no card nothing is unpriced, because
    /// there is nothing to be missing from: you either price nothing or price everything.
    pub fn model_unpriced(&self, model: &str) -> bool {
        self.card.lane_unpriced(model)
    }
}
