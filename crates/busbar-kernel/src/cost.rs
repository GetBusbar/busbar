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
//! - INTEGER MATH ONLY on the hot path: config floats convert ONCE, at the config intake
//!   (`RateEntryCfg::raw_tier_rates`), to exact nano-units per token;
//!   derivation is a few u128 multiply-adds over the models a bucket actually used.
//! - GROUPS are the ONE limit tree: a group's generic limits (requests / tokens / budget per
//!   window, plus the instantaneous `concurrent` gauge) resolve here into per-(group, window)
//!   ENFORCEMENT BUCKETS; keys are pure auth and contribute no caps of their own.
//!
//! A `CostModel` is resolved from config at boot / config-apply and lives on `App` (rebuilt on
//! apply), while the `GovState` token ledger survives the apply - which is exactly what makes
//! reprice-on-reload work.

use std::collections::{BTreeMap, HashMap};

use busbar_contract::records::ScopeRef;

use crate::config::groups::{AdmissionMode, LimitMetric};

/// THE KERNEL'S FACADE OVER THE LEDGER'S MONEY TYPES (#36): the cleanliness crates reach the dated
/// rate-card history, the card, the row read and the one pricing function by THIS path, never by
/// naming the ledger crate. Each name is the ledger's own item re-exported as it is: the same type
/// and the same function, so a figure priced through this path is the ledger's figure.
pub use busbar_kernel_ledger::cost::{
    budget_remaining, plane_fee_lane, price_ledger, sum_spend, Author, CardEntryDraft, History,
    HistorySeq, HistoryView, LedgerEntry, MeteredRow, MoneyError, PlaneFees, RateCard, TierRates,
    PER_SESSION,
};

/// The prefix namespacing GROUP bucket ids in the store, so a group named like a key id can never
/// collide with a real key's bucket. Key buckets use the bare key id. A group's per-window buckets
/// are `group:<name>@<window>` - one ledger row per (group, window granularity), so a group with
/// limits in several windows never double-counts a flush into one row. A SCOPE-QUALIFIED bucket
/// (limits carrying `pool: <name>`, i.e. `scope: { kind: "pool", value: <name> }`) appends
/// `#<kind>:<value>`: `group:<name>@<window>#pool:<name>` - its own ledger row, accounting only
/// the traffic dispatched through that scope. (Generic-admission-topology generalization: the
/// scheme was `#<pool>` before this widened to carry the kind; safe to change with no migration
/// since no store persists this literal string durably yet.)
pub const GROUP_BUCKET_PREFIX: &str = "group:";

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
pub fn is_bucket_of_group(bucket_id: &str, group: &str) -> bool {
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
    /// Project the NEUTRAL tier-rate view ([`busbar_contract::billing::RawTierRates`]) — the four
    /// exact nano-per-token rates in canonical reserved order — to this nano-rate. Core reads rates
    /// through this NEUTRAL view so the projection names no plane config type.
    ///
    /// THERE IS NO CONVERSION HERE, AND THAT IS THE POINT. This used to be a SECOND copy of the
    /// decimal-to-money conversion, and the two drifted (a `1e300` rate priced as zero in the book
    /// and as `u64::MAX` nanos here). The view now carries the integers the config intake converted
    /// once (`RateEntryCfg::raw_tier_rates`, the ledger's `representable_nano_rate`), so this is a
    /// copy of four integers: a rate the card cannot hold (`None`) reads as the zero the ledger's
    /// `nano_rate` gives it, exactly as before.
    pub fn from_raw(raw: &busbar_contract::billing::RawTierRates) -> Self {
        Self {
            input: raw.input.unwrap_or(0),
            output: raw.output.unwrap_or(0),
            cache_read: raw.cache_read.unwrap_or(0),
            cache_write: raw.cache_write.unwrap_or(0),
        }
    }

    /// Project a core `RateEntryCfg` by first taking its neutral exact view (the intake), then
    /// [`from_raw`](Self::from_raw). A thin adapter kept while the `rate_card:` grammar
    /// still lives in core (S2a). Once the grammar relocates
    /// to the owning plane (S2b) this adapter goes and callers hand [`from_raw`] the plane-filled view.
    pub fn from_cfg(r: &crate::config::RateEntryCfg) -> Self {
        Self::from_raw(&r.raw_tier_rates())
    }
}

/// The enforcement book's per-model unit map, handed to the one function VERBATIM (item 123, #71):
/// every class the plane declared, the reserved four and the open ones alike, as exact whole counts.
/// The card decides what each prices at — and a present card silent about a class the traffic hit
/// REFUSES (#42) — so no class is filtered out here to be priced as nothing.
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
    /// The cap configured under `metric` on this bucket, if any: the admin view's read of one
    /// per-class cap.
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
    /// Whether this bucket participates in a request dispatched through `pool` - group-wide
    /// buckets always do; a pool-scoped bucket only for its own pool. Every enforcement walk
    /// (admit / charge / refund / accrue / headroom) keys off this ONE predicate so the paths
    /// can never disagree on what was charged vs what is refunded. Hardcodes `kind: "pool"`
    /// deliberately - THIS call site is the one that knows it is checking pool admission (see
    /// `ScopeRef`'s doc: each admission site names the kind it expects, `ScopeRef` itself stays
    /// kind-agnostic).
    pub fn applies_to_pool(&self, pool: &str) -> bool {
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
    pub fn iter(&self) -> impl Iterator<Item = &ChainBucket<'a>> {
        self.buckets.iter()
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// The `CostModel::groups()` indices of the chain's groups, innermost first.
    pub fn group_indices(&self) -> &[usize] {
        &self.groups
    }
}

/// The resolved cost model: the effective integer rate table + the group limit topology + the
/// flat per-request fee. Immutable once resolved; rebuilt with the config on apply/reload.
pub struct CostModel {
    /// THE CARD, in the one function's own type (items 104, 25). ABSENT = `rate_card` absent =
    /// token pricing 0 for every model, fee still posts. PRESENT = the AUTHORITATIVE effective
    /// table, straight from the top-level `rate_card:` (the ONLY cost source). It used to be a
    /// private `HashMap<String, RateNanos>` that this module priced with its own copy of the
    /// arithmetic; every figure is now `busbar_kernel_ledger::cost::Tally` over this card.
    card: busbar_kernel_ledger::cost::RateCard,
    groups: Vec<GroupRuntime>,
    group_idx: HashMap<String, usize>,
    /// The ids of every LIVE bucket that still carries at least one windowed cap — the exact set
    /// `project_groups` just emitted, indexed for O(1) membership. This is what makes
    /// "does this ledger cell still back an enforced cap?" an IDENTITY question (is this id one of
    /// the ids the model produces?) instead of a parse of the id's internal structure.
    capped_bucket_ids: std::collections::HashSet<String>,
    /// This model's GENERATION: unique to each constructed model and moved by every card edit, so
    /// the scrape's money-view memo (`governance::money_view`) knows the card changed without
    /// comparing cards. Never reused, so a new model at a freed address cannot pass as the old one.
    generation: u64,
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
        // rate_card is the ONLY cost source: no per-entry cost override lives anywhere else in
        // config. Each rate was converted ONCE, exactly, at the intake (`raw_tier_rates`); the card is
        // built by the one constructor that owns card-building — the class fan-out, the unpriced
        // placement of an unrepresentable rate (item 22) and the fee's clamp are all
        // `RateCard::from_config`'s, so the door and the bill hold ONE card.
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
        // THE OPEN CLASSES (item 123), exact integer nano-unit rates beside the reserved four.
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
            groups,
            group_idx,
        }
    }

    /// Rebuild the model with a NEW groups map, reusing the resolved rate card + flat fee unchanged.
    /// The Admin-API group-mutation seam (`build_with_group` / `build_without_group`): a runtime
    /// group change must reproject enforcement buckets WITHOUT re-parsing the rate card (which the
    /// mutation never touched). Pure — assumes the caller already re-ran `validate_groups`.
    pub fn with_groups(
        &self,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let (groups, group_idx) = Self::project_groups(groups_cfg);
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(&groups),
            generation: crate::trust::validate::next_generation(),
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
                    || !b.class_caps.is_empty()
                    || b.budget_cap.is_some()
            })
            .map(|b| b.bucket_id.clone())
            .collect()
    }

    /// Whether `bucket_id` is, RIGHT NOW, the id of a live bucket that still enforces at least one
    /// windowed cap. Pure identity: the id either is one the live model produces or it is not, so
    /// no assumption about `@`/`#` being delimiters (or a group name avoiding them) exists here.
    pub fn bucket_enforces_a_cap(&self, bucket_id: &str) -> bool {
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
                                    // The MOST RESTRICTIVE budget's exhaustion behavior governs:
                                    // it is the cap that actually blocks, so its downgrade (or
                                    // its absence = block) is what fires.
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

    /// A minimal model for tests / governance-off paths: no card, no groups, the given flat fee.
    #[cfg(any(test, feature = "test-support"))]
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            card: busbar_kernel_ledger::cost::RateCard::absent(price_per_request_cents),
            groups: Vec::new(),
            group_idx: HashMap::new(),
            capped_bucket_ids: std::collections::HashSet::new(),
            generation: crate::trust::validate::next_generation(),
        }
    }

    /// Resolve a CONFIGURED name to its rate-card key. Today the rate card is keyed by the
    /// caller-supplied name itself, so this is the identity - kept as the one seam every
    /// consumer resolves through, so a future re-aliasing lands in one place.
    pub fn resolve_model_alias<'a>(&'a self, model: &'a str) -> &'a str {
        model
    }

    /// Whether a rate card is configured (token pricing active).
    ///
    /// `pub` (was crate-private): the first of the two questions the pre-admission pricing guard
    /// asks.
    pub fn pricing_enabled(&self) -> bool {
        self.card.pricing_enabled()
    }

    /// The per-request fee of the plane keyed `plane` (#47): its own `fees.per_request`, `0` when it
    /// configured none; the empty key is the pools plane's — `per_request_fee:`.
    pub fn request_fee_on(&self, plane: &str) -> i64 {
        let lane = busbar_kernel_ledger::cost::plane_fee_lane(plane);
        self.card.plane_lane(&lane).0.fee()
    }

    /// Put each other plane's own fees (#47) on the card, by plane registry key.
    #[must_use]
    pub fn with_plane_fees(mut self, fees: &crate::config::PlaneFeesMap) -> Self {
        self.card = self
            .card
            .with_plane_fees(fees.iter().map(|(p, f)| (&**p, *f)));
        self.generation = crate::trust::validate::next_generation();
        self
    }

    /// This model's generation (see the field).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The card every figure this model derives is priced against — the one function's own type.
    pub fn card(&self) -> &busbar_kernel_ledger::cost::RateCard {
        &self.card
    }

    pub fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    pub fn group_named(&self, name: &str) -> Option<&GroupRuntime> {
        self.group_idx.get(name).map(|&i| &self.groups[i])
    }

    /// PRICE a neutral [`busbar_contract::billing::Usage`] for `model` into nano-units — the
    /// kernel's one pricing entry point.
    ///
    /// **THE ONE FUNCTION** over one row at this card: `None` is every refusal it can give — a
    /// present card that does not name the model, a hit class it cannot price (#42), an overflow
    /// (item 28) — and the caller fails closed on it. Card absent ⇒ `Some(0)`. Every class the usage
    /// carries reaches the row (item 123): an open class the card prices is charged, one it does not
    /// refuses.
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

    /// THE `admission: estimate` GUESS (the design's budget modes): the plane's expected units priced by the one money function at each of `models` (the
    /// destinations verify allowed), the HIGHEST of them, in whole minor units rounded UP once.
    /// A guess by design ("It's an estimate. It will never be right."), rounded conservatively because it only ever gates an admission; it is never stored and never bills
    /// (a line carries only far-end-reported units). No model or no expected unit is `Some(0)`.
    /// `None` when a model cannot price an expected class (#42): the caller fails closed.
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

    /// Whether a request for `model` must be REJECTED because the rate card is present but has no
    /// entry (an arbitrary passthrough model string not in the configured rate card). Fail-closed and
    /// consistent with the completeness rule: you either price nothing or price everything.
    ///
    /// `pub` (was crate-private): the second of the pricing guard's two questions, answered for a
    /// plane over the same card.
    #[inline]
    pub fn model_unpriced(&self, model: &str) -> bool {
        self.card.lane_unpriced(model)
    }

    /// DERIVE the spend (in cents, abstract minor units) of a ledger view: every model the bucket
    /// used, plus - when `include_request_fee` - the flat per-request fee times the BILLABLE request
    /// count (`fee_requests`: admitted minus refunded, so the fee bills 2xx only).
    ///
    /// **THE ONE FUNCTION, NOT A COPY OF IT** (items 104, 25, 124, 28, 31). This used to be its own
    /// loop, and its loop answered #42 backwards: `if let Some(rate) = self.rate_for(model)` DROPPED
    /// a model the present card did not name, so its whole consumption derived as nothing — on the
    /// live LLM admission gate (`try_admit`) and on every customer read ("the designed behavior").
    /// It is now `busbar_kernel_ledger::cost::Tally` at this card, so:
    ///
    /// - card ABSENT: tokens price at 0, the fee posts — #42's only silent zero;
    /// - card PRESENT, model or hit class unpriced: `Err` — the door BLOCKS and a read FAILS (#42);
    /// - overflow: `Err(Overflow)` — never pinned at `i64::MAX` (item 28).
    pub fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
        self.tally(models, fee_requests, include_request_fee)?
            .money()?
            .minor_i64()
    }

    /// As [`Self::derive_spend_cents`] but in MICRO-units, for the hook seam / admin projections.
    pub fn derive_spend_micros<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
        self.tally(models, fee_requests, include_request_fee)?
            .money()?
            .micros_i64()
    }

    /// Drive the one function over a bucket view: one row per model (every class it counted, item
    /// 123, at the standard tier — the enforcement book carries no tier), then the bucket's fee row.
    fn tally<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> Result<busbar_kernel_ledger::cost::Tally<'_>, busbar_kernel_ledger::cost::MoneyError> {
        use busbar_kernel_ledger::cost::{whole, Tally, STANDARD_TIER_BP};
        let mut tally = Tally::at_card(&self.card);
        for (model, units) in models {
            tally.row(model, 0, STANDARD_TIER_BP, unit_counts(units), whole(0))?;
        }
        if include_request_fee {
            tally.fee(0, STANDARD_TIER_BP, whole(fee_requests))?;
        }
        Ok(tally)
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
        key: &'a busbar_contract::records::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let mut buckets: Vec<ChainBucket<'a>> = Vec::with_capacity(8);
        // The key's own attribution bucket: uncapped, unscoped, all-time.
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
