// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};

use busbar_contract::records::ScopeRef;

use crate::config::groups::{AdmissionMode, LimitMetric};

pub use busbar_kernel_ledger::cost::{
    budget_remaining, plane_fee_lane, price_ledger, sum_spend, Author, CardEntryDraft, EntryId,
    EntryKey, History, HistorySeq, HistoryView, LedgerEntry, MeteredRow, MoneyError, PlaneFees,
    RateCard, RawRateEra, TierRates, PER_SESSION,
};

pub const GROUP_BUCKET_PREFIX: &str = "group:";

pub(crate) fn group_bucket_id(name: &str, window: &str, scope: Option<&ScopeRef>) -> String {
    match scope {
        Some(scope) => format!(
            "{GROUP_BUCKET_PREFIX}{name}@{window}#{}:{}",
            scope.kind, scope.value
        ),
        None => format!("{GROUP_BUCKET_PREFIX}{name}@{window}"),
    }
}

/// One model's per-token rates in integer NANO-units per token (config micro-units x 1000, rounded
/// once at resolve). All hot-path math is integer over these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateNanos {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl RateNanos {
    pub fn from_raw(raw: &busbar_contract::billing::RawTierRates) -> Self {
        Self {
            input: raw.input.unwrap_or(0),
            output: raw.output.unwrap_or(0),
            cache_read: raw.cache_read.unwrap_or(0),
            cache_write: raw.cache_write.unwrap_or(0),
        }
    }

    pub fn from_cfg(r: &crate::config::RateEntryCfg) -> Self {
        Self::from_raw(&r.raw_tier_rates())
    }
}

fn unit_counts(
    units: &BTreeMap<String, u64>,
) -> impl Iterator<Item = (&str, busbar_kernel_ledger::cost::Count)> + '_ {
    units
        .iter()
        .map(|(class, n)| (class.as_str(), busbar_kernel_ledger::cost::whole(*n)))
}

/// One (group, window, pool?) ENFORCEMENT BUCKET, resolved from the group's windowed limits:
/// every limit of the group that shares this window AND pool scope enforces against this one
/// ledger cell. The three windowed metrics are independent caps on the same cell's counters
/// (requests / total tokens / derived spend).
#[derive(Debug, Clone, Default)]
pub struct GroupBucket {
    /// The store/ledger bucket id: `group:<name>@<window>`, or `group:<name>@<window>#<pool>`
    /// for a pool-scoped bucket.
    pub bucket_id: String,
    /// The window word (`minute` | `hour` | `day` | `month` | `total`) - the `budget_window`
    /// period sentinel AND the metrics/error vocabulary.
    pub window: &'static str,
    /// Request-count cap per window (`{ requests: N, per: <window> }`), if any.
    pub requests_cap: Option<u64>,
    /// Total-token cap per window (`{ tokens: N, per: <window> }`), if any. Best-effort: tokens
    /// land post-response, so the cap blocks the NEXT request once crossed.
    pub tokens_cap: Option<u64>,
    /// Per-class token caps (`{ tokens_<class>: N, per: <window> }`), each best-effort exactly
    /// like `tokens_cap`, one per capped class, in check order ([`LimitMetric`]'s order). The
    /// class is an opaque ledger class name ([`LimitMetric::capped_class`]).
    pub class_caps: Vec<ClassCap>,
    /// Spend cap per window (`{ budget: N, per: <window> }`) in abstract cents, if any. Derived at
    /// check time from the cell's token ledger x the current rate card (+ the flat per-request
    /// fee x requests).
    pub budget_cap: Option<i64>,
    /// `Some(scope)` = this bucket accounts ONLY traffic dispatched through that scope (limits
    /// carrying `pool: <name>`, i.e. `kind: "pool"`); `None` = group-wide (every request through
    /// the group).
    pub scope: Option<ScopeRef>,
    /// Where BUDGET-exhausted traffic goes instead of a rejection (`on_exhaust: downgrade,
    /// downgrade_to: <pool>` on the governing budget limit). `None` = block (the default). When
    /// several budget limits merge into this bucket, the MOST RESTRICTIVE (minimum) cap's
    /// behavior governs - it is the one that actually blocks.
    pub downgrade_to: Option<ScopeRef>,
    /// How the bucket's budget admits (the design's budget modes): `exact` (the default, 1.5.5)
    /// or `estimate` when ANY budget limit merged into this bucket declared it (the
    /// strictest wins, as [`AdmissionMode::governing`] reads it).
    pub budget_admission: AdmissionMode,
}

/// ONE PER-CLASS TOKEN CAP of a bucket: the limit's metric (its config word is the refusal's
/// vocabulary), the ledger class it counts, and the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassCap {
    /// The limit metric the cap was configured under.
    pub metric: LimitMetric,
    /// The ledger class the cap counts ([`LimitMetric::capped_class`]).
    pub class: &'static str,
    /// The cap: the count at which the bucket blocks the next admission.
    pub cap: u64,
}

impl GroupBucket {
    pub fn class_cap(&self, metric: LimitMetric) -> Option<u64> {
        (self.class_caps.iter())
            .find(|c| c.metric == metric)
            .map(|c| c.cap)
    }
}

/// One resolved group: its enabled flag, in-flight cap, per-window enforcement buckets, and parent
/// (by index, so the chain walk is index-chasing with zero hashing).
#[derive(Debug, Clone)]
pub struct GroupRuntime {
    pub name: String,
    /// `false` FREEZES the group: every request charging through it (its own keys AND every
    /// descendant's) is rejected while history is kept.
    pub enabled: bool,
    /// The instantaneous in-flight cap (`{ concurrent: N }` - no window), if any.
    pub concurrent_cap: Option<u64>,
    /// The group's windowed enforcement buckets, one per distinct window its limits use (config
    /// order of first use). Empty for a group with only a `concurrent` limit (or none).
    pub buckets: Vec<GroupBucket>,
    pub parent: Option<usize>,
}

/// One bucket of a resolved enforcement chain (borrowed views into the key / the `CostModel`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ChainBucket<'a> {
    /// The store/ledger bucket id (the key id, or `group:<name>@<window>[#<pool>]`).
    pub bucket_id: &'a str,
    /// The operator-facing group name for diagnostics; `None` for the key's own bucket.
    pub group_name: Option<&'a str>,
    /// The bucket's window word - the `budget_window` period sentinel (`total` for the key's own
    /// attribution bucket). `'static`: both sources (the group buckets and the key's `total`) are
    /// compile-time sentinels.
    pub window: &'static str,
    pub requests_cap: Option<u64>,
    pub tokens_cap: Option<u64>,
    /// The bucket's per-class token caps ([`GroupBucket::class_caps`]).
    pub class_caps: &'a [ClassCap],
    pub budget_cap: Option<i64>,
    /// `Some(scope)` = the bucket is scope-qualified: it checks/charges/accrues ONLY when the
    /// request was dispatched through that scope (today, always `kind: "pool"`). `None` = applies
    /// to every request through the group.
    pub scope: Option<&'a ScopeRef>,
    /// The budget limit's `downgrade_to` scope, when it declared `on_exhaust: downgrade`.
    pub downgrade_to: Option<&'a ScopeRef>,
    /// The bucket's budget admission mode ([`GroupBucket::budget_admission`]).
    pub budget_admission: AdmissionMode,
}

impl ChainBucket<'_> {
    pub fn applies_to_pool(&self, pool: &str) -> bool {
        self.scope
            .is_none_or(|s| s.kind == "pool" && s.value == pool)
    }
}

pub(crate) struct Chain<'a> {
    buckets: Vec<ChainBucket<'a>>,
    groups: Vec<usize>,
}

impl<'a> Chain<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &ChainBucket<'a>> {
        self.buckets.iter()
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn group_indices(&self) -> &[usize] {
        &self.groups
    }
}

pub struct CostModel {
    card: busbar_kernel_ledger::cost::RateCard,

    routing_prices: std::sync::Arc<BTreeMap<String, BTreeMap<String, f64>>>,
    groups: Vec<GroupRuntime>,
    group_idx: HashMap<String, usize>,

    capped_bucket_ids: std::collections::HashSet<String>,

    generation: u64,
}

impl CostModel {
    pub fn resolve_parts(
        rate_card: Option<&std::collections::BTreeMap<String, crate::config::RateEntryCfg>>,
        per_request_fee: i64,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let card = busbar_kernel_ledger::cost::RateCard::from_config(
            rate_card.map(|card| {
                card.iter().map(|(model, r)| {
                    let raw = r.raw_tier_rates();
                    (
                        model.as_str(),
                        busbar_kernel_ledger::cost::TierRates {
                            input: raw.input,
                            output: raw.output,
                            cache_read: raw.cache_read,
                            cache_write: raw.cache_write,
                        },
                    )
                })
            }),
            per_request_fee,
        )
        .with_unit_rates(rate_card.into_iter().flatten().flat_map(|(model, r)| {
            r.units.iter().map(move |(class, rate)| {
                (
                    busbar_kernel_ledger::cost::LaneClass::new(model, class),
                    rate.nanos_per_unit(),
                )
            })
        }));
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(&groups),
            generation: crate::trust::validate::next_generation(),
            card,
            routing_prices: std::sync::Arc::new(
                rate_card
                    .into_iter()
                    .flatten()
                    .map(|(lane, entry)| {
                        let prices = [
                            ("input".to_owned(), entry.input_utok),
                            ("output".to_owned(), entry.output_utok),
                            ("cache_read".to_owned(), entry.cache_read_utok),
                            ("cache_write".to_owned(), entry.cache_write_utok),
                        ]
                        .into_iter()
                        .chain(entry.units.iter().map(|(class, price)| {
                            (class.clone(), price.nanos_per_unit() as f64 / 1_000.0)
                        }))
                        .collect();
                        (lane.clone(), prices)
                    })
                    .collect(),
            ),
            groups,
            group_idx,
        }
    }

    pub fn with_groups(
        &self,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(&groups),
            generation: crate::trust::validate::next_generation(),
            card: self.card.clone(),
            routing_prices: std::sync::Arc::clone(&self.routing_prices),
            groups,
            group_idx,
        }
    }

    fn capped_bucket_ids(groups: &[GroupRuntime]) -> std::collections::HashSet<String> {
        groups
            .iter()
            .flat_map(|g| g.buckets.iter())
            .filter(|b| {
                b.requests_cap.is_some()
                    || b.tokens_cap.is_some()
                    || !b.class_caps.is_empty()
                    || b.budget_cap.is_some()
            })
            .map(|b| b.bucket_id.clone())
            .collect()
    }

    pub fn bucket_enforces_a_cap(&self, bucket_id: &str) -> bool {
        self.capped_bucket_ids.contains(bucket_id)
    }

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
                                    let bucket_id = group_bucket_id(name, w, l.scope.as_ref());
                                    buckets.push(GroupBucket {
                                        bucket_id,
                                        window: w,
                                        scope: l.scope.clone(),
                                        ..GroupBucket::default()
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
                                LimitMetric::TokensInput
                                | LimitMetric::TokensOutput
                                | LimitMetric::TokensCacheRead
                                | LimitMetric::TokensCacheWrite => {
                                    if let Some(class) = metric.capped_class() {
                                        let caps = &mut bucket.class_caps;
                                        match caps.iter_mut().find(|c| c.metric == metric) {
                                            Some(c) => c.cap = c.cap.min(l.amount),
                                            None => caps.push(ClassCap {
                                                metric,
                                                class,
                                                cap: l.amount,
                                            }),
                                        }
                                        caps.sort_by_key(|c| c.metric);
                                    }
                                }
                                LimitMetric::Budget => {
                                    let amount = i64::try_from(l.amount).unwrap_or(i64::MAX);

                                    if bucket.budget_cap.is_none_or(|c| amount < c) {
                                        bucket.downgrade_to = l.downgrade_to.clone();
                                    }
                                    if l.admission == Some(AdmissionMode::Estimate) {
                                        bucket.budget_admission = AdmissionMode::Estimate;
                                    }
                                    bucket.budget_cap = Some(
                                        bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)),
                                    );
                                }
                                LimitMetric::Concurrent => unreachable!("matched above"),
                            }
                        }

                        (_, None) => {}
                    }
                }
                GroupRuntime {
                    name: (*name).clone(),
                    enabled: g.enabled,
                    concurrent_cap,
                    buckets,

                    parent: g.parent.as_deref().and_then(|p| group_idx.get(p).copied()),
                }
            })
            .collect();
        (groups, group_idx)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            card: busbar_kernel_ledger::cost::RateCard::absent(price_per_request_cents),
            routing_prices: std::sync::Arc::default(),
            groups: Vec::new(),
            group_idx: HashMap::new(),
            capped_bucket_ids: std::collections::HashSet::new(),
            generation: crate::trust::validate::next_generation(),
        }
    }

    pub fn resolve_model_alias<'a>(&'a self, model: &'a str) -> &'a str {
        model
    }

    pub fn pricing_enabled(&self) -> bool {
        self.card.pricing_enabled()
    }

    pub fn request_fee_on(&self, plane: &str) -> i64 {
        let lane = busbar_kernel_ledger::cost::plane_fee_lane(plane);
        self.card.plane_lane(&lane).0.fee()
    }

    #[must_use]
    pub fn with_plane_fees(mut self, fees: &crate::config::PlaneFeesMap) -> Self {
        self.card = self
            .card
            .with_plane_fees(fees.iter().map(|(p, f)| (&**p, *f)));
        self.generation = crate::trust::validate::next_generation();
        self
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn card(&self) -> &busbar_kernel_ledger::cost::RateCard {
        &self.card
    }

    pub fn routing_price(&self, lane: &str, class: &str) -> Option<f64> {
        let pricing = self.card.lane_pricing(lane);
        if !pricing.card.pricing_enabled()
            || !matches!(
                pricing.class_price(class),
                busbar_kernel_ledger::cost::ClassPrice::Nanos(_)
            )
        {
            return None;
        }
        self.routing_prices
            .get(lane)?
            .get(class)
            .copied()
            .filter(|price| price.is_finite() && *price >= 0.0)
    }

    pub fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    pub fn group_named(&self, name: &str) -> Option<&GroupRuntime> {
        self.group_idx.get(name).map(|&i| &self.groups[i])
    }

    pub fn price_usage_nanos(
        &self,
        model: &str,
        usage: &busbar_contract::billing::Usage,
    ) -> Option<u128> {
        let mut tally = busbar_kernel_ledger::cost::Tally::at_card(&self.card);
        tally
            .row(
                model,
                0,
                busbar_kernel_ledger::cost::STANDARD_TIER_BP,
                unit_counts(&usage.usage_units),
                busbar_kernel_ledger::cost::whole(0),
            )
            .ok()?;
        busbar_kernel_ledger::cost::nanos_of_exact(tally.exact().ok()?).ok()
    }

    pub fn estimate_minor(&self, models: &[&str], expected: &BTreeMap<String, u64>) -> Option<i64> {
        if expected.values().all(|n| *n == 0) {
            return Some(0);
        }
        let usage = busbar_contract::billing::Usage {
            usage_units: expected.clone(),
        };
        let mut highest: u128 = 0;
        for model in models {
            highest = highest.max(self.price_usage_nanos(model, &usage)?);
        }
        let minor = highest.div_ceil(busbar_kernel_ledger::cost::NANOS_PER_CENT);
        Some(i64::try_from(minor).unwrap_or(i64::MAX))
    }

    #[inline]
    pub fn model_unpriced(&self, model: &str) -> bool {
        self.card.lane_unpriced(model)
    }

    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_contract::records::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let mut buckets: Vec<ChainBucket<'a>> = Vec::with_capacity(8);

        buckets.push(ChainBucket {
            bucket_id: &key.id,
            window: crate::governance::WINDOW_TOTAL,
            ..ChainBucket::default()
        });
        let mut groups: Vec<usize> = Vec::new();
        let group = key.group.as_deref();
        let mut next = group
            .map(|n| self.group_idx.get(n).copied().ok_or(n))
            .transpose()?;
        while let Some(i) = next {
            if groups.len() >= self.groups.len() {
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
                    class_caps: &b.class_caps,
                    budget_cap: b.budget_cap,
                    scope: b.scope.as_ref(),
                    downgrade_to: b.downgrade_to.as_ref(),
                    budget_admission: b.budget_admission,
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
