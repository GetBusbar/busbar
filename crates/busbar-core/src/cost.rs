// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The COST + LIMIT MODEL: rate-card resolution, ledger-to-spend derivation, and the resolved
//! `groups:` limit topology the generic limit engine (governance) enforces. This is the ONE module
//! the engine calls for anything cost- or limit-shaped; the `Store` trait (in `busbar-api`) stays
//! the persistence seam and carries ONLY tokens.
//!
//! Principles (the 1.5.0 redesign):
//! - TOKENS ARE THE LEDGER; dollars are ALWAYS derived, never stored as truth. Every spend figure
//!   is computed here at read time as `ledger x current rate card`, so correcting a rate is a
//!   config edit + reload - past and future derived figures instantly become right. (Honest limit:
//!   repricing cannot un-make PAST admit/reject decisions taken under a wrong rate.)
//! - NO CURRENCY in the core. Rates are ABSTRACT cost units (micro-units per token in config,
//!   integer NANO-units per token internally); `_cents` fields are abstract minor units. Currency
//!   is a display concern owned entirely by the consumer.
//! - ALL-OR-NOTHING pricing: `rate_card` absent => every model prices at 0 (only the flat
//!   per-request fee counts); present => authoritative + complete (validated at boot).
//! - INTEGER MATH ONLY on the hot path: config floats convert ONCE here to nano-units per token;
//!   derivation is a few u128 multiply-adds over the models a bucket actually used.
//! - GROUPS are the ONE limit tree: a group's generic limits (requests / tokens / budget per
//!   window, plus the instantaneous `concurrent` gauge) resolve here into per-(group, window)
//!   ENFORCEMENT BUCKETS; keys are pure auth and contribute no caps of their own.
//!
//! A `CostModel` is resolved from config at boot / config-apply and lives on `App` (rebuilt on
//! apply), while the `GovState` token ledger survives the apply - which is exactly what makes
//! reprice-on-reload work.

use std::collections::{BTreeMap, HashMap};

use busbar_api::{ScopeRef, RESERVED_UNITS};
// The engine's one seam onto the cost unit: every other module in this crate that needs one of the
// unit's constants reads it through here rather than naming the unit itself.
pub(crate) use busbar_unit_cost::{
    CurrencyCode, LaneRates, RateCard, TierRates, NANOS_PER_CENT, NANOS_PER_MICRO,
};

use crate::config::groups::LimitMetric;

/// The prefix namespacing GROUP bucket ids in the store, so a group named like a key id can never
/// collide with a real key's bucket. Key buckets use the bare key id. A group's per-window buckets
/// are `group:<name>@<window>` - one ledger row per (group, window granularity), so a group with
/// limits in several windows never double-counts a flush into one row. A SCOPE-QUALIFIED bucket
/// (limits carrying `pool: <name>`, i.e. `scope: { kind: "pool", value: <name> }`) appends
/// `#<kind>:<value>`: `group:<name>@<window>#pool:<name>` - its own ledger row, accounting only
/// the traffic dispatched through that scope. (Generic-admission-topology generalization: the
/// scheme was `#<pool>` before this widened to carry the kind; safe to change with no migration
/// since no store persists this literal string durably yet.)
pub(crate) const GROUP_BUCKET_PREFIX: &str = "group:";

/// Whether `bucket_id` is a bucket of the group named `group` — an EXACT structural match against
/// the construction `project_groups` uses, NOT a prefix test.
///
/// A GROUP NAME MAY CONTAIN `@` (and `#`). Nothing rejects it: `validate_groups` checks
/// parent-existence / acyclicity / pool refs (the `amount > 0` rule lives in
/// `config_validate::validate`, not here), `build_with_group` checks empty + length, and
/// `sanitize_self_sub` (the SSO auto-provisioning path that mints `user:<sub>` leaves) rejects only
/// empty / `/` / control characters / the reserved prefixes — an IdP subject is normally an EMAIL,
/// so `user:alice@corp.com` is the ORDINARY case, not a pathological one. Any code that splits a
/// bucket id on `@` therefore gets the wrong answer for the most common deployment there is.
///
/// So the test here is anchored at BOTH ends instead: the id must be `group:` + the name VERBATIM +
/// `@` + one of the five [`crate::config::groups::LimitWindow`] spellings + an optional `#<scope>`.
/// `group:user:alice@corp.com@total` therefore does NOT belong to `user:alice` (the window token
/// would have to be `corp.com`), and DOES belong to `user:alice@corp.com`.
pub(crate) fn is_bucket_of_group(bucket_id: &str, group: &str) -> bool {
    let Some(tail) = bucket_id
        .strip_prefix(GROUP_BUCKET_PREFIX)
        .and_then(|rest| rest.strip_prefix(group))
        .and_then(|t| t.strip_prefix('@'))
    else {
        return false;
    };
    // The scope suffix (`#<kind>:<value>`) is everything from the FIRST `#` after the window word;
    // the window word itself can never contain one (it is one of five fixed literals).
    let window = tail.split('#').next().unwrap_or(tail);
    crate::config::groups::LimitWindow::ALL
        .iter()
        .any(|w| w.as_str() == window)
}

/// The nano-unit price of a usage map's RESERVED FOUR at one lane's rates: the four multiply-adds in
/// u128 (a u64 count times a u64 nano rate cannot overflow u128), in canonical reserved order — the
/// enforcement/derive summation, byte-identical to the private rate table it replaced: the map
/// values are the counts, the card's per-class nano rate is the rate, and a class the lane does not
/// price is 0. Opens are NOT priced here; the summation prices only the reserved four.
#[inline]
fn reserved_nanos(lane: &LaneRates<'_>, units: &BTreeMap<String, u64>) -> u128 {
    RESERVED_UNITS.iter().fold(0u128, |acc, u| {
        let n = units.get(*u).copied().unwrap_or(0);
        acc + (n as u128) * (lane.nanos_per_unit(u) as u128)
    })
}

/// One (group, window, pool?) ENFORCEMENT BUCKET, resolved from the group's windowed limits:
/// every limit of the group that shares this window AND pool scope enforces against this one
/// ledger cell. The three windowed metrics are independent caps on the same cell's counters
/// (requests / total tokens / derived spend).
#[derive(Debug, Clone)]
pub(crate) struct GroupBucket {
    /// The store/ledger bucket id: `group:<name>@<window>`, or `group:<name>@<window>#<pool>`
    /// for a pool-scoped bucket.
    pub(crate) bucket_id: String,
    /// The window word (`minute` | `hour` | `day` | `month` | `total`) - the `budget_window`
    /// period sentinel AND the metrics/error vocabulary.
    pub(crate) window: &'static str,
    /// Request-count cap per window (`{ requests: N, per: <window> }`), if any.
    pub(crate) requests_cap: Option<u64>,
    /// Total-token cap per window (`{ tokens: N, per: <window> }`), if any. Best-effort like the
    /// old TPM: tokens land post-response, so the cap blocks the NEXT request once crossed.
    pub(crate) tokens_cap: Option<u64>,
    /// Per-tier token caps (`{ tokens_input: N, per: <window> }` etc.), each best-effort exactly
    /// like `tokens_cap`. Mirror the cost tiers: `tokens_input` = uncached input, `tokens_output`
    /// = output, `tokens_cache_read`, `tokens_cache_write` = cache creation.
    pub(crate) tokens_input_cap: Option<u64>,
    pub(crate) tokens_output_cap: Option<u64>,
    pub(crate) tokens_cache_read_cap: Option<u64>,
    pub(crate) tokens_cache_write_cap: Option<u64>,
    /// Spend cap per window (`{ budget: N, per: <window> }`) in abstract cents, if any. Derived at
    /// check time from the cell's token ledger x the current rate card (+ the flat per-request
    /// fee x requests).
    pub(crate) budget_cap: Option<i64>,
    /// `Some(scope)` = this bucket accounts ONLY traffic dispatched through that scope (limits
    /// carrying `pool: <name>`, i.e. `kind: "pool"`); `None` = group-wide (every request through
    /// the group).
    pub(crate) scope: Option<ScopeRef>,
    /// Where BUDGET-exhausted traffic goes instead of a rejection (`on_exhaust: downgrade,
    /// downgrade_to: <pool>` on the governing budget limit). `None` = block (the default). When
    /// several budget limits merge into this bucket, the MOST RESTRICTIVE (minimum) cap's
    /// behavior governs - it is the one that actually blocks.
    pub(crate) downgrade_to: Option<ScopeRef>,
}

/// One resolved group: its enabled flag, in-flight cap, per-window enforcement buckets, and parent
/// (by index, so the chain walk is index-chasing with zero hashing).
#[derive(Debug, Clone)]
pub(crate) struct GroupRuntime {
    pub(crate) name: String,
    /// `false` FREEZES the group: every request charging through it (its own keys AND every
    /// descendant's) is rejected while history is kept.
    pub(crate) enabled: bool,
    /// The instantaneous in-flight cap (`{ concurrent: N }` - no window), if any.
    pub(crate) concurrent_cap: Option<u64>,
    /// The group's windowed enforcement buckets, one per distinct window its limits use (config
    /// order of first use). Empty for a group with only a `concurrent` limit (or none).
    pub(crate) buckets: Vec<GroupBucket>,
    pub(crate) parent: Option<usize>,
}

/// One bucket of a resolved enforcement chain (borrowed views into the key / the `CostModel`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainBucket<'a> {
    /// The store/ledger bucket id (the key id, or `group:<name>@<window>[#<pool>]`).
    pub(crate) bucket_id: &'a str,
    /// The operator-facing group name for diagnostics; `None` for the key's own bucket.
    pub(crate) group_name: Option<&'a str>,
    /// The bucket's window word - the `budget_window` period sentinel (`total` for the key's own
    /// attribution bucket). `'static`: both sources (the group buckets and the key's `total`) are
    /// compile-time sentinels.
    pub(crate) window: &'static str,
    pub(crate) requests_cap: Option<u64>,
    pub(crate) tokens_cap: Option<u64>,
    pub(crate) tokens_input_cap: Option<u64>,
    pub(crate) tokens_output_cap: Option<u64>,
    pub(crate) tokens_cache_read_cap: Option<u64>,
    pub(crate) tokens_cache_write_cap: Option<u64>,
    pub(crate) budget_cap: Option<i64>,
    /// `Some(scope)` = the bucket is scope-qualified: it checks/charges/accrues ONLY when the
    /// request was dispatched through that scope (today, always `kind: "pool"`). `None` = applies
    /// to every request through the group.
    pub(crate) scope: Option<&'a ScopeRef>,
    /// The budget limit's `downgrade_to` scope, when it declared `on_exhaust: downgrade`.
    pub(crate) downgrade_to: Option<&'a ScopeRef>,
}

impl ChainBucket<'_> {
    /// Whether this bucket participates in a request dispatched through `pool` - group-wide
    /// buckets always do; a pool-scoped bucket only for its own pool. Every enforcement walk
    /// (admit / charge / refund / accrue / headroom) keys off this ONE predicate so the paths
    /// can never disagree on what was charged vs what is refunded. Hardcodes `kind: "pool"`
    /// deliberately - THIS call site is the one that knows it is checking pool admission (see
    /// `ScopeRef`'s doc: each admission site names the kind it expects, `ScopeRef` itself stays
    /// kind-agnostic).
    pub(crate) fn applies_to_pool(&self, pool: &str) -> bool {
        self.scope
            .is_none_or(|s| s.kind == "pool" && s.value == pool)
    }
}

/// A resolved enforcement chain: the key's attribution bucket plus every ancestor group's
/// per-window buckets, innermost group first. Sized by the chain actually walked (the tree is
/// unbounded by policy; a chain can never exceed the number of groups — cycles are a validate
/// error and the walk clamps there defensively). Also carries the GROUP INDICES walked (for the
/// `enabled` freeze check and the `concurrent` gauges, which are per group, not per window
/// bucket).
pub(crate) struct Chain<'a> {
    buckets: Vec<ChainBucket<'a>>,
    groups: Vec<usize>,
}

impl<'a> Chain<'a> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &ChainBucket<'a>> {
        self.buckets.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }

    /// The `CostModel::groups()` indices of the chain's groups, innermost first.
    pub(crate) fn group_indices(&self) -> &[usize] {
        &self.groups
    }
}

/// One resolved group as plain, comparable data. See [`CostModel::resolved_view`].
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGroupView {
    /// The group's name.
    pub name: String,
    /// The freeze flag, verbatim from config.
    pub enabled: bool,
    /// The in-flight gauge, folded to the minimum across repeats.
    pub concurrent_cap: Option<u64>,
    /// The parent's index in the resolved order, or none.
    pub parent: Option<usize>,
    /// The group's windowed enforcement buckets, in the order the projection materialised them.
    pub buckets: Vec<ResolvedBucketView>,
}

/// One resolved enforcement bucket as plain, comparable data. See [`CostModel::resolved_view`].
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBucketView {
    /// The ledger cell this bucket reads and charges.
    pub bucket_id: String,
    /// The window word.
    pub window: &'static str,
    /// The request-count cap, folded to the most restrictive.
    pub requests_cap: Option<u64>,
    /// The total-token cap, folded to the most restrictive.
    pub tokens_cap: Option<u64>,
    /// The uncached-input token cap.
    pub tokens_input_cap: Option<u64>,
    /// The output token cap.
    pub tokens_output_cap: Option<u64>,
    /// The cache-read token cap.
    pub tokens_cache_read_cap: Option<u64>,
    /// The cache-write token cap.
    pub tokens_cache_write_cap: Option<u64>,
    /// The spend cap in abstract cents.
    pub budget_cap: Option<i64>,
    /// The bucket's scope as `(kind, value)`, or none for a group-wide bucket.
    pub scope: Option<(String, String)>,
    /// The governing budget limit's downgrade target as `(kind, value)`, or none for a block.
    pub downgrade_to: Option<(String, String)>,
}

/// A scope reference as the `(kind, value)` pair the comparison is over.
#[cfg(any(test, feature = "test-support"))]
fn scope_pair(s: &ScopeRef) -> (String, String) {
    (s.kind.to_string(), s.value.to_string())
}

/// The resolved cost model: the effective integer rate table + the group limit topology + the
/// flat per-request fee. Immutable once resolved; rebuilt with the config on apply/reload.
pub struct CostModel {
    /// The cost unit's card: absent = token pricing 0 for every model; present = the AUTHORITATIVE
    /// effective table, straight from the top-level `rate_card:` (the ONLY cost source), with the
    /// flat per-request fee. The unit's `nano_rate` is the one micro-to-nano projection.
    card: RateCard,
    groups: Vec<GroupRuntime>,
    group_idx: HashMap<String, usize>,
    /// The ids of every LIVE bucket that still carries at least one windowed cap — the exact set
    /// `project_groups` just emitted, indexed for O(1) membership. This is what makes
    /// "does this ledger cell still back an enforced cap?" an IDENTITY question (is this id one of
    /// the ids the model produces?) instead of a parse of the id's internal structure.
    capped_bucket_ids: std::collections::HashSet<String>,
}

impl CostModel {
    /// Resolve from config. Assumes `config_validate` has already passed (completeness, acyclic
    /// groups, valid limit shapes); this is a pure projection and is defensive, never panicking,
    /// on anything validation should have caught.
    pub fn resolve_parts(
        rate_card: Option<&std::collections::BTreeMap<String, crate::config::RateEntryCfg>>,
        per_request_fee: i64,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        // rate_card is the ONLY cost source - the 1.4.x pool-member tiered-override loop is
        // GONE (cost lives on no pool member; routing derives its scalar from the card).
        // The card's rows are the config's `_utok` micro-floats lifted through their neutral raw
        // view (`raw_tier_rates`), so this names no plane config grammar; the unit rounds once to
        // nano-units and clamps the fee, exactly as the private table did.
        let card = RateCard::from_config(
            rate_card.map(|card| {
                card.iter().map(|(model, r)| {
                    let raw = r.raw_tier_rates();
                    (
                        model.as_str(),
                        TierRates {
                            input: raw.input,
                            output: raw.output,
                            cache_read: raw.cache_read,
                            cache_write: raw.cache_write,
                        },
                    )
                })
            }),
            per_request_fee,
        );
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(&groups),
            card,
            groups,
            group_idx,
        }
    }

    /// Rebuild the model with a NEW groups map, reusing the resolved rate card + flat fee unchanged.
    /// The Admin-API group-mutation seam (`build_with_group` / `build_without_group`): a runtime
    /// group change must reproject enforcement buckets WITHOUT re-parsing the rate card (which the
    /// mutation never touched). Pure — assumes the caller already re-ran `validate_groups`.
    pub(crate) fn with_groups(
        &self,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(&groups),
            card: self.card.clone(),
            groups,
            group_idx,
        }
    }

    /// Index the ids of every projected bucket that carries at least one windowed cap. Built from
    /// the SAME `GroupBucket`s the engine enforces against, so the set can never disagree with the
    /// model about which cells are load-bearing.
    fn capped_bucket_ids(groups: &[GroupRuntime]) -> std::collections::HashSet<String> {
        groups
            .iter()
            .flat_map(|g| g.buckets.iter())
            .filter(|b| {
                b.requests_cap.is_some()
                    || b.tokens_cap.is_some()
                    || b.tokens_input_cap.is_some()
                    || b.tokens_output_cap.is_some()
                    || b.tokens_cache_read_cap.is_some()
                    || b.tokens_cache_write_cap.is_some()
                    || b.budget_cap.is_some()
            })
            .map(|b| b.bucket_id.clone())
            .collect()
    }

    /// Whether `bucket_id` is, RIGHT NOW, the id of a live bucket that still enforces at least one
    /// windowed cap. Pure identity: the id either is one the live model produces or it is not, so
    /// no assumption about `@`/`#` being delimiters (or a group name avoiding them) exists here.
    pub(crate) fn bucket_enforces_a_cap(&self, bucket_id: &str) -> bool {
        self.capped_bucket_ids.contains(bucket_id)
    }

    /// Project a `GroupCfg` map into the runtime enforcement form: sorted `GroupRuntime` vec + a
    /// name→index map (parents resolved to indices). Shared verbatim by `resolve_parts` (boot/apply)
    /// and `with_groups` (runtime group mutation) so the two paths can never drift.
    fn project_groups(
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> (Vec<GroupRuntime>, HashMap<String, usize>) {
        let mut group_names: Vec<&String> = groups_cfg.keys().collect();
        group_names.sort();
        let group_idx: HashMap<String, usize> = group_names
            .iter()
            .enumerate()
            .map(|(i, n)| ((*n).clone(), i))
            .collect();
        let groups: Vec<GroupRuntime> = group_names
            .iter()
            .map(|name| {
                let g = &groups_cfg[name.as_str()];
                // Project the group's generic limits into per-(window, pool) enforcement buckets.
                // A bucket materialises on first use (config order); a metric repeated for the
                // same window + pool scope keeps the MOST RESTRICTIVE (minimum) amount - AND
                // semantics inside one group, same as across the chain. A pool-qualified limit
                // gets its OWN bucket (its own ledger row), so `budget: 5000 pool: frontier` and
                // `budget: 5000 pool: value` account independently.
                let mut buckets: Vec<GroupBucket> = Vec::new();
                let mut concurrent_cap: Option<u64> = None;
                for l in &g.limits {
                    match (l.metric, l.per) {
                        (LimitMetric::Concurrent, _) => {
                            concurrent_cap =
                                Some(concurrent_cap.map_or(l.amount, |c: u64| c.min(l.amount)));
                        }
                        (metric, Some(window)) => {
                            let w = window.as_str();
                            let bucket = match buckets
                                .iter_mut()
                                .find(|b| b.window == w && b.scope == l.scope)
                            {
                                Some(b) => b,
                                None => {
                                    let bucket_id = match &l.scope {
                                        Some(s) => {
                                            format!(
                                                "{GROUP_BUCKET_PREFIX}{name}@{w}#{}:{}",
                                                s.kind, s.value
                                            )
                                        }
                                        None => format!("{GROUP_BUCKET_PREFIX}{name}@{w}"),
                                    };
                                    buckets.push(GroupBucket {
                                        bucket_id,
                                        window: w,
                                        requests_cap: None,
                                        tokens_cap: None,
                                        tokens_input_cap: None,
                                        tokens_output_cap: None,
                                        tokens_cache_read_cap: None,
                                        tokens_cache_write_cap: None,
                                        budget_cap: None,
                                        scope: l.scope.clone(),
                                        downgrade_to: None,
                                    });
                                    buckets.last_mut().expect("just pushed")
                                }
                            };
                            let min_u = |cur: Option<u64>| {
                                Some(cur.map_or(l.amount, |c: u64| c.min(l.amount)))
                            };
                            match metric {
                                LimitMetric::Requests => {
                                    bucket.requests_cap = min_u(bucket.requests_cap)
                                }
                                LimitMetric::Tokens => bucket.tokens_cap = min_u(bucket.tokens_cap),
                                LimitMetric::TokensInput => {
                                    bucket.tokens_input_cap = min_u(bucket.tokens_input_cap)
                                }
                                LimitMetric::TokensOutput => {
                                    bucket.tokens_output_cap = min_u(bucket.tokens_output_cap)
                                }
                                LimitMetric::TokensCacheRead => {
                                    bucket.tokens_cache_read_cap =
                                        min_u(bucket.tokens_cache_read_cap)
                                }
                                LimitMetric::TokensCacheWrite => {
                                    bucket.tokens_cache_write_cap =
                                        min_u(bucket.tokens_cache_write_cap)
                                }
                                LimitMetric::Budget => {
                                    let amount = i64::try_from(l.amount).unwrap_or(i64::MAX);
                                    // The MOST RESTRICTIVE budget's exhaustion behavior governs:
                                    // it is the cap that actually blocks, so its downgrade (or
                                    // its absence = block) is what fires.
                                    if bucket.budget_cap.is_none_or(|c| amount < c) {
                                        bucket.downgrade_to = l.downgrade_to.clone();
                                    }
                                    bucket.budget_cap = Some(
                                        bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)),
                                    );
                                }
                                LimitMetric::Concurrent => unreachable!("matched above"),
                            }
                        }
                        // A windowed metric with no `per` cannot deserialize (LimitCfg enforces the
                        // shape at parse); defensively skip rather than panic.
                        (_, None) => {}
                    }
                }
                GroupRuntime {
                    name: (*name).clone(),
                    enabled: g.enabled,
                    concurrent_cap,
                    buckets,
                    // A missing parent is a validate error; defensively resolve to None here so a
                    // bad config that somehow booted degrades to a shorter chain, never a panic.
                    parent: g.parent.as_deref().and_then(|p| group_idx.get(p).copied()),
                }
            })
            .collect();
        (groups, group_idx)
    }

    /// THE RESOLVED TOPOLOGY AS PLAIN DATA, for the byte-identity cell and nothing else.
    ///
    /// The `groups:` projection lives twice in the tree while the retirement is in flight: here, and
    /// in the composition root's own resolution of the same section into the door's table. Two
    /// projections of the money topology that must agree exactly is how a deployment comes to be
    /// ADMITTED against one set of buckets and BILLED against another — silently, because both
    /// answers are internally consistent and neither knows the other exists.
    ///
    /// Every field the projection decides is here, in the order it decides them, so the comparison
    /// is over the whole resolved value rather than over a summary of it: a divergence this view
    /// cannot express is a divergence the cell cannot catch. The scope and downgrade references
    /// carry their KIND as well as their value, because the kind is the one field the two
    /// projections do not both keep.
    ///
    /// Test-support only, and it dies with this module: nothing shipped reads it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn resolved_view(&self) -> Vec<ResolvedGroupView> {
        self.groups
            .iter()
            .map(|g| ResolvedGroupView {
                name: g.name.clone(),
                enabled: g.enabled,
                concurrent_cap: g.concurrent_cap,
                parent: g.parent,
                buckets: g
                    .buckets
                    .iter()
                    .map(|b| ResolvedBucketView {
                        bucket_id: b.bucket_id.clone(),
                        window: b.window,
                        requests_cap: b.requests_cap,
                        tokens_cap: b.tokens_cap,
                        tokens_input_cap: b.tokens_input_cap,
                        tokens_output_cap: b.tokens_output_cap,
                        tokens_cache_read_cap: b.tokens_cache_read_cap,
                        tokens_cache_write_cap: b.tokens_cache_write_cap,
                        budget_cap: b.budget_cap,
                        scope: b.scope.as_ref().map(scope_pair),
                        downgrade_to: b.downgrade_to.as_ref().map(scope_pair),
                    })
                    .collect(),
            })
            .collect()
    }

    /// The resolved flat per-request fee, for the same cell. The fee is a clamped projection of a
    /// configured number and the clamp is part of what has to agree.
    #[cfg(any(test, feature = "test-support"))]
    pub fn resolved_fee(&self) -> i64 {
        self.price_per_request_cents()
    }

    /// A minimal model for tests / governance-off paths: no card, no groups, the given flat fee.
    #[cfg(any(test, feature = "test-support"))]
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            card: RateCard::absent(price_per_request_cents),
            groups: Vec::new(),
            group_idx: HashMap::new(),
            capped_bucket_ids: std::collections::HashSet::new(),
        }
    }

    /// Resolve a CONFIGURED model name to its rate-card key. 1.5.0: the rate card is keyed by the
    /// CONFIG model name itself (two providers serving one upstream model are two `models:`
    /// entries with two card entries), so this is the identity - kept as the one seam every
    /// consumer resolves through, so a future re-aliasing lands in one place.
    pub(crate) fn resolve_model_alias<'a>(&'a self, model: &'a str) -> &'a str {
        model
    }

    /// Whether a rate card is configured (token pricing active).
    ///
    /// `pub` (was crate-private): the first of the two questions the pre-admission pricing guard
    /// asks, answered for a plane through the
    /// [`BudgetHost::cost_pricing_enabled`](busbar_substrate::plane_host::BudgetHost::cost_pricing_enabled)
    /// seam, which downcasts the opaque cost handle and drives this same read.
    pub fn pricing_enabled(&self) -> bool {
        self.card.pricing_enabled()
    }

    /// The flat per-request fee in abstract cents, clamped at zero by the card.
    pub(crate) fn price_per_request_cents(&self) -> i64 {
        self.card.per_request_fee(CurrencyCode::USD)
    }

    pub(crate) fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    pub(crate) fn group_named(&self, name: &str) -> Option<&GroupRuntime> {
        self.group_idx.get(name).map(|&i| &self.groups[i])
    }

    /// The effective rates for `model` (post-`upstream_model` resolution), read off the card.
    /// Semantics of the three outcomes, which are the card's own:
    /// - card absent: `Some(zero)` - every model prices at 0.
    /// - card present, model priced: `Some(rates)`.
    /// - card present, model UNKNOWN: `None` - fail-closed; the admission path rejects an
    ///   unpriced passthrough model, and the derive paths price it at 0 (it can only arise from
    ///   ledger rows written before a config change).
    #[inline]
    fn lane(&self, model: &str) -> Option<LaneRates<'_>> {
        self.card.lane_rates(model, CurrencyCode::USD)
    }

    /// PRICE a neutral [`busbar_substrate::billing::Usage`] for `model` into nanodollars — the host-side
    /// entry point the [`MeteringHost::price_usage`](busbar_substrate::plane_host::MeteringHost::price_usage)
    /// seam a live carrier (voice) drives folds through. Byte-for-byte the SAME arithmetic the
    /// enforcement/derive summation uses ([`Self::lane`] → [`reserved_nanos`], exactly as
    /// [`Self::derive_spend_cents`]/[`derive_spend_micros`](Self::derive_spend_micros) price each model),
    /// so this is a new READER over the existing pricer — the LLM money path is untouched.
    ///
    /// The three `lane` outcomes carry straight through: card absent ⇒ `Some(0)` (every model prices
    /// at 0); card present + model priced ⇒ `Some(nanos)`; card present + model UNKNOWN ⇒ `None` (the
    /// caller fails closed on an unpriced passthrough model). Only the reserved four price here — the
    /// carrier maps its own unit classes onto the reserved keys before calling, so no open-key
    /// `ExtraRates` lookup (and thus no `CostBreakdown`) is involved.
    pub(crate) fn price_usage_nanos(
        &self,
        model: &str,
        usage: &busbar_substrate::billing::Usage,
    ) -> Option<u128> {
        self.lane(model)
            .map(|lane| reserved_nanos(&lane, &usage.usage_units))
    }

    /// Whether a request for `model` must be REJECTED because the rate card is present but has no
    /// entry (an arbitrary passthrough model string not in any configured lane). Fail-closed and
    /// consistent with the completeness rule: you either price nothing or price everything.
    ///
    /// `pub` (was crate-private): the second of the pricing guard's two questions, answered for a
    /// plane through the
    /// [`BudgetHost::cost_model_unpriced`](busbar_substrate::plane_host::BudgetHost::cost_model_unpriced)
    /// seam over the same opaque handle.
    #[inline]
    pub fn model_unpriced(&self, model: &str) -> bool {
        self.card.lane_unpriced(model)
    }

    /// DERIVE the spend (in cents, abstract minor units) of a ledger view: a few multiply-adds
    /// over the models the bucket actually used, plus - when `include_request_fee` - the flat
    /// per-request fee times the BILLABLE request count (`fee_requests`: admitted minus refunded,
    /// so the fee bills 2xx only). Every enforcement/read path passes `true` (each bucket counts
    /// its own billable requests, so its fee component is its own); the flag exists for callers
    /// that want a tokens-only projection. Pure recompute from tokens x current rates: no spend is
    /// ever cached or stored.
    ///
    /// A model with no rate (card present, entry missing - only possible for ledger rows written
    /// under a previous config) derives at 0; the mismatch is the operator's rate-card edit
    /// taking effect retroactively, which is the designed behavior.
    pub(crate) fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        let mut nanos: u128 = 0;
        for (model, units) in models {
            if let Some(lane) = self.lane(model) {
                nanos = nanos.saturating_add(reserved_nanos(&lane, units));
            }
        }
        // SATURATE into i64 (never `as`-cast): an adversarially large ledger (u64-scale token
        // counts x a large configured rate) can push the cent total past i64::MAX, and a wrapping
        // cast would land NEGATIVE - which `.max(0)` below then floors to 0, i.e. an over-the-top
        // ledger would derive as FREE and bypass every budget cap. Pin at i64::MAX instead (an
        // astronomically over-cap spend that blocks, fail-closed).
        let mut cents = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
        if include_request_fee {
            let fee = self
                .price_per_request_cents()
                .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
            cents = cents.saturating_add(fee);
        }
        cents.max(0)
    }

    /// As [`Self::derive_spend_cents`] but in MICRO-units, for the hook seam / admin projections.
    pub(crate) fn derive_spend_micros<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        let mut nanos: u128 = 0;
        for (model, units) in models {
            if let Some(lane) = self.lane(model) {
                nanos = nanos.saturating_add(reserved_nanos(&lane, units));
            }
        }
        let micros = i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX);
        if include_request_fee {
            // 1 cent = 10_000 micro-units.
            let fee_micros = self
                .price_per_request_cents()
                .saturating_mul(10_000)
                .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
            micros.saturating_add(fee_micros)
        } else {
            micros
        }
    }

    /// Resolve the ENFORCEMENT CHAIN for a key: [key's attribution bucket] -> key.group's window
    /// buckets -> parent's -> ... root, innermost first. Borrows the key + this model's group
    /// table; allocates only the chain vectors themselves.
    ///
    /// `Err(missing)` when the key names a `group` that does not exist in config - the
    /// FAIL-CLOSED outcome (mint validates the group; boot re-checks; this arm covers a shared
    /// durable store whose keys reference a group another node's config no longer has).
    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_api::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let mut buckets: Vec<ChainBucket<'a>> = Vec::with_capacity(8);
        buckets.push(ChainBucket {
            bucket_id: &key.id,
            group_name: None,
            window: crate::governance::WINDOW_TOTAL,
            requests_cap: None,
            tokens_cap: None,
            tokens_input_cap: None,
            tokens_output_cap: None,
            tokens_cache_read_cap: None,
            tokens_cache_write_cap: None,
            budget_cap: None,
            scope: None,
            downgrade_to: None,
        });
        let mut groups: Vec<usize> = Vec::new();
        let mut next = match key.group.as_deref() {
            None => None,
            Some(name) => match self.group_idx.get(name) {
                Some(&i) => Some(i),
                None => return Err(name),
            },
        };
        while let Some(i) = next {
            if groups.len() >= self.groups.len() {
                // A distinct-node walk cannot exceed the group count without revisiting one, i.e.
                // a cycle. Cycles are a validate error; clamp defensively (never loop).
                break;
            }
            let g = &self.groups[i];
            groups.push(i);
            for b in &g.buckets {
                buckets.push(ChainBucket {
                    bucket_id: &b.bucket_id,
                    group_name: Some(&g.name),
                    window: b.window,
                    requests_cap: b.requests_cap,
                    tokens_cap: b.tokens_cap,
                    tokens_input_cap: b.tokens_input_cap,
                    tokens_output_cap: b.tokens_output_cap,
                    tokens_cache_read_cap: b.tokens_cache_read_cap,
                    tokens_cache_write_cap: b.tokens_cache_write_cap,
                    budget_cap: b.budget_cap,
                    scope: b.scope.as_ref(),
                    downgrade_to: b.downgrade_to.as_ref(),
                });
            }
            next = g.parent;
        }
        Ok(Chain { buckets, groups })
    }
}

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod tests;
