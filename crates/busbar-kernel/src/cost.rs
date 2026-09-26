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

use busbar_contract::records::{
    ScopeRef, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
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
    /// Project the NEUTRAL raw-rate view ([`busbar_substrate_values::billing::RawTierRates`]) — the four raw
    /// micro-float-per-token rates in canonical reserved order — to this integer nano-rate. Core
    /// reads rates through this NEUTRAL view so the projection names no plane config type.
    ///
    /// THE CONVERSION IS THE LEDGER'S, NOT A COPY OF IT. `busbar_kernel_ledger::cost::nano_rate` is
    /// the one decimal-to-money conversion in the tree, and this used to be a second copy of its
    /// three lines. The two DID drift, in the way a doc comment is no defence against: the ledger's
    /// clamp refuses a value too large for a `u64` to hold, and this copy tested only finiteness —
    /// so one configured rate with too many zeros (`1e300` micro-units per token) priced as ZERO in
    /// the book and, because a float-to-integer cast SATURATES rather than wrapping, as
    /// `u64::MAX` nanos per token here. A request JUDGED at one rate and BILLED at another is
    /// precisely the failure a duplicate exists to cause, so the duplicate is gone rather than
    /// patched: the clamp, the half-away-from-zero rounding (#44 — card-build quantization) and the
    /// ×1000 are the ledger's, once.
    ///
    /// Every in-range rate projects to the same integer it always did; only the out-of-range ones
    /// move, and they move from a garbage overcharge to the zero that means "nobody can price
    /// this".
    pub fn from_raw(raw: &busbar_substrate_values::billing::RawTierRates) -> Self {
        let nanos = busbar_kernel_ledger::cost::nano_rate;
        Self {
            input: nanos(raw.input),
            output: nanos(raw.output),
            cache_read: nanos(raw.cache_read),
            cache_write: nanos(raw.cache_write),
        }
    }

    /// Project a core `RateEntryCfg` by first taking its neutral raw-rate view, then
    /// [`from_raw`](Self::from_raw). A thin BYTE-IDENTICAL adapter kept while the `rate_card:` grammar
    /// still lives in core (S2a): the map values ARE the raw micro-floats. Once the grammar relocates
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
    /// Per-tier token caps (`{ tokens_input: N, per: <window> }` etc.), each best-effort exactly
    /// like `tokens_cap`. Mirror the cost tiers: `tokens_input` = uncached input, `tokens_output`
    /// = output, `tokens_cache_read`, `tokens_cache_write` = cache creation.
    pub tokens_input_cap: Option<u64>,
    pub tokens_output_cap: Option<u64>,
    pub tokens_cache_read_cap: Option<u64>,
    pub tokens_cache_write_cap: Option<u64>,
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
    pub tokens_input_cap: Option<u64>,
    pub tokens_output_cap: Option<u64>,
    pub tokens_cache_read_cap: Option<u64>,
    pub tokens_cache_write_cap: Option<u64>,
    pub budget_cap: Option<i64>,
    /// `Some(scope)` = the bucket is scope-qualified: it checks/charges/accrues ONLY when the
    /// request was dispatched through that scope (today, always `kind: "pool"`). `None` = applies
    /// to every request through the group.
    pub scope: Option<&'a ScopeRef>,
    /// The budget limit's `downgrade_to` scope, when it declared `on_exhaust: downgrade`.
    pub downgrade_to: Option<&'a ScopeRef>,
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
        // config. The card is built by the one constructor that owns card-building — the class
        // fan-out, the quantisation (#44), the representability refusal (item 22) and the fee's
        // clamp are all `RateCard::from_config`'s, so the door and the bill hold ONE card.
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

    /// A minimal model for tests / governance-off paths: no card, no groups, the given flat fee.
    #[cfg(any(test, feature = "test-support"))]
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            card: busbar_kernel_ledger::cost::RateCard::absent(price_per_request_cents),
            groups: Vec::new(),
            group_idx: HashMap::new(),
            capped_bucket_ids: std::collections::HashSet::new(),
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
    /// asks, answered for a plane through the
    /// [`BudgetHost::cost_pricing_enabled`](busbar_kernel::plane_host::BudgetHost::cost_pricing_enabled)
    /// seam, which downcasts the opaque cost handle and drives this same read.
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
        self
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

    /// The effective rate for `model` (the resolved rate-card key), read off the card. Semantics of
    /// the three outcomes:
    /// - card absent: `Some(zero)` - every model prices at 0.
    /// - card present, model priced: `Some(rate)`.
    /// - card present, model UNKNOWN: `None` - fail-closed.
    ///
    /// A VIEW of the card for callers that size an estimate from per-tier rates; no figure in this
    /// module is priced through it. A class the card could not represent (item 22) reads 0 here
    /// and REFUSES in every figure, because the figures are the one function's.
    #[inline]
    pub fn rate_for(&self, model: &str) -> Option<RateNanos> {
        if !self.card.pricing_enabled() {
            return Some(RateNanos::default());
        }
        self.card.lane_rates(model).map(|r| RateNanos {
            input: r.nanos_per_unit(UNIT_INPUT),
            output: r.nanos_per_unit(UNIT_OUTPUT),
            cache_read: r.nanos_per_unit(UNIT_CACHE_READ),
            cache_write: r.nanos_per_unit(UNIT_CACHE_WRITE),
        })
    }

    /// PRICE a neutral [`busbar_substrate_values::billing::Usage`] for `model` into nano-units — the
    /// host-side entry point the [`MeteringHost::price_usage`](busbar_kernel::plane_host::MeteringHost::price_usage)
    /// seam a live carrier drives folds through.
    ///
    /// **THE ONE FUNCTION** over one row at this card: `None` is every refusal it can give — a
    /// present card that does not name the model, a hit class it cannot price (#42), an overflow
    /// (item 28) — and the caller fails closed on it. Card absent ⇒ `Some(0)`. Every class the usage
    /// carries reaches the row (item 123): an open class the card prices is charged, one it does not
    /// refuses.
    pub fn price_usage_nanos(
        &self,
        model: &str,
        usage: &busbar_substrate_values::billing::Usage,
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

    /// Whether a request for `model` must be REJECTED because the rate card is present but has no
    /// entry (an arbitrary passthrough model string not in the configured rate card). Fail-closed and
    /// consistent with the completeness rule: you either price nothing or price everything.
    ///
    /// `pub` (was crate-private): the second of the pricing guard's two questions, answered for a
    /// plane through the
    /// [`BudgetHost::cost_model_unpriced`](busbar_kernel::plane_host::BudgetHost::cost_model_unpriced)
    /// seam over the same opaque handle.
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
