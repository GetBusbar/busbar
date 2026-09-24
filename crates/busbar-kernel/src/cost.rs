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

use busbar_api::{
    ScopeRef, RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

use crate::config::groups::LimitMetric;

/// The label DOMAIN prefix stamped on every OPEN-unit component so an open unit named like a reserved
/// tier's label (`Prompt`/`Output`/`Cache read`/`Cache write`) or like the `service_tier` surcharge
/// can NEVER collide with them inside [`crate::plane::cost::CostBreakdown::new`] (which rejects
/// duplicate labels). Without this a request carrying an open unit literally named `Prompt` or
/// `service_tier` would fail to price at all — a denial-of-service on the response (fix 2b).
const OPEN_LABEL_PREFIX: &str = "unit:";

/// The operator-facing component label for one reserved tier. The pricer is the ONE place these
/// display names live; the ledger/map speaks only the canonical `input`/`output`/… keys.
fn reserved_label(unit: &str) -> &'static str {
    match unit {
        UNIT_INPUT => "Prompt",
        UNIT_OUTPUT => "Output",
        UNIT_CACHE_READ => "Cache read",
        UNIT_CACHE_WRITE => "Cache write",
        _ => "",
    }
}

/// The service-tier multiplier basis points for the neutral `standard` tier: ×1.0000. A tier's
/// config multiplier resolves to integer basis points (×10_000) at load; the one pricer applies it
/// as `× bp / 10_000` in integer, so no per-key float drift compounds (§7/§10 of `billing-unified.md`).
#[cfg_attr(not(test), allow(dead_code))]
pub const STANDARD_TIER_BP: u32 = 10_000;

/// The OPEN-key nano-rate table for one model: `open key → nano-units per unit`. Rides a separate
/// `Arc<BTreeMap>` on the rate card (never inside the `Copy` [`RateNanos`]), looked up ONLY when a
/// `usage_units` map carries an open key — so `RateNanos` stays `Copy` and the no-extras request
/// allocates nothing (`billing-unified.md` §9.1). In 1.6.0 M1 the pricer accepts this table; config population of the
/// per-model open rates is a designed later-milestone residual (today callers pass an empty table).
#[cfg_attr(not(test), allow(dead_code))]
pub type ExtraRates = std::collections::BTreeMap<String, u64>;

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

    /// The nano rate for one RESERVED tier key (0 for a non-reserved key — opens price via the
    /// separate `ExtraRates` table, never here).
    #[inline]
    pub fn reserved_rate(&self, unit: &str) -> u64 {
        match unit {
            UNIT_INPUT => self.input,
            UNIT_OUTPUT => self.output,
            UNIT_CACHE_READ => self.cache_read,
            UNIT_CACHE_WRITE => self.cache_write,
            _ => 0,
        }
    }
}

/// The enforcement book's per-model unit map, projected onto the row the one function prices: the
/// reserved four keys it CARRIES, as exact whole counts.
///
/// The filter is the enforcement side's existing posture and it is deliberately kept verbatim: an
/// OPEN key in this map was never priced by the enforcement derivations, and converging the open
/// classes onto the card is the keyed-unit convergence (item 123), which builds on this function.
fn reserved_counts(
    units: &BTreeMap<String, u64>,
) -> impl Iterator<Item = (&'static str, busbar_kernel_ledger::cost::Count)> + '_ {
    RESERVED_UNITS.iter().filter_map(|u| {
        units
            .get(*u)
            .map(|n| (*u, busbar_kernel_ledger::cost::whole(*n)))
    })
}

/// THE ONE ENFORCEMENT PRICER every plane's neutral [`busbar_substrate_values::billing::Usage`] reaches
/// (§4.1 of `billing-unified.md`). Since M1b `Usage` is a SINGLE name-keyed map: the reserved four
/// price via the [`RateNanos`] tiers (looked up by canonical key through [`RateNanos::reserved_rate`];
/// the TOTAL is the one function's — `busbar_kernel_ledger::cost::Tally` — as every derivation's is), and
/// every OPEN key prices via an OPAQUE `extras.get(k)` lookup. Each priced key becomes at most one
/// DISJOINT top-level [`CostComponent`], so `Σ top_level == total` holds by [`CostBreakdown::new`]
/// construction — no post-hoc scalar ever touches `total`.
///
/// `tier_bp` is the resolved service-tier multiplier in basis points ([`STANDARD_TIER_BP`] = ×1):
/// a surcharge (`> 10_000`) adds one top-level `service_tier` line (`base × (mult − 1)`); a discount
/// (`< 10_000`) is a SINGLE divide of the summed nanos distributed as per-component marginals
/// (`Σ == floor(base × bp / 10_000)`, never the sum of per-component floors) — both keep exact-sum
/// (`billing-unified.md` §7.1, fix 2a).
///
/// Present-but-unpriced open key ⇒ NEVER a silent $0 (`billing-unified.md` §9.2): a `BUSBAR-3021` WARN, and the key is
/// omitted (fail-closed to VISIBLE, not to hidden free usage), never a zero component. Open-unit
/// labels are namespaced ([`OPEN_LABEL_PREFIX`]) so an adversarial open name can never collide with a
/// reserved/surcharge label and fail the whole breakdown (fix 2b).
#[cfg_attr(not(test), allow(dead_code))]
pub fn price(
    rate: &RateNanos,
    extras: &ExtraRates,
    tier_bp: u32,
    usage: &busbar_substrate_values::billing::Usage,
) -> Result<crate::plane::cost::CostBreakdown, crate::plane::cost::CostError> {
    use crate::plane::cost::{CostAmount, CostBreakdown, CostComponent, CostError};

    // Assemble the UNDISCOUNTED (label, nanos) components in deterministic order: the reserved four
    // first (canonical order, priced via the `RateNanos` tiers), then the OPEN keys (BTreeMap sorted,
    // priced by OPAQUE `extras.get(k)` lookup). Every open label is NAMESPACED under
    // `OPEN_LABEL_PREFIX` so it can never collide with a reserved tier's label or the `service_tier`
    // surcharge label — the duplicate-label DoS fix (2b). A present-but-unpriced open is OMITTED with
    // a WARN, never a silent $0 (`billing-unified.md` §9.2). A zero-nanos component is dropped (no-zero-component
    // invariant).
    let mut raw: Vec<(String, u128)> = Vec::with_capacity(usage.usage_units.len() + 1);
    for u in RESERVED_UNITS {
        let n = usage.usage_units.get(u).copied().unwrap_or(0);
        let amt = u128::from(n).saturating_mul(u128::from(rate.reserved_rate(u)));
        if amt != 0 {
            raw.push((reserved_label(u).to_string(), amt));
        }
    }
    for (k, n) in &usage.usage_units {
        if RESERVED_UNITS.contains(&k.as_str()) {
            continue; // priced above via the tier rates, never as an open
        }
        match extras.get(k) {
            Some(&r) => {
                let amt = u128::from(*n).saturating_mul(u128::from(r));
                if amt != 0 {
                    raw.push((format!("{OPEN_LABEL_PREFIX}{k}"), amt));
                }
            }
            None => {
                tracing::warn!(
                    code = "BUSBAR-3021",
                    usage_key = %k,
                    "present-but-unpriced usage key; omitted (never a silent $0)"
                );
            }
        }
    }

    // **THE TOTAL IS THE ONE FUNCTION'S** (items 104, 27). The components below are the statement's
    // split of it; the figure itself — the multiply, the sum, the tier, the overflow policy — is
    // `busbar_kernel_ledger::cost::Tally`'s, at a card holding exactly the rates this call prices
    // with. For whole counts the tier divide is exact at the one function's scale, so its total is
    // `floor(base × bp / 10_000)`, which is what the marginal split below sums to by construction;
    // `CostBreakdown::new` re-checks that the parts add up to it. An overflow is a refusal.
    let one_total = one_function_total(rate, extras, tier_bp, usage)
        .map_err(|_| CostError::SumOverflow { parent: None })?;
    let base_total: u128 = raw.iter().fold(0u128, |a, (_, amt)| a.saturating_add(*amt));
    let mut components: Vec<CostComponent> = Vec::with_capacity(raw.len() + 1);

    let total: u128 = if tier_bp < STANDARD_TIER_BP {
        // DISCOUNT — SINGLE-DIVIDE (fix 2a). The per-component discounted amounts are the MARGINAL
        // deltas of the cumulative discounted running sum, so `Σ components == floor(base_total × bp
        // / 10_000)` EXACTLY — byte-identical to discounting the summed nanos ONCE, never the sum of
        // per-component integer floors (which under-charges a multi-component discount). The undiscounted
        // running sum keeps advancing even when a marginal amount rounds to 0 (that component is just
        // omitted), so the exact-sum invariant holds regardless.
        let mut running: u128 = 0;
        let mut prev_disc: u128 = 0;
        for (label, amt) in raw {
            running = running.saturating_add(amt);
            let cum_disc =
                running.saturating_mul(u128::from(tier_bp)) / u128::from(STANDARD_TIER_BP);
            let marginal = cum_disc - prev_disc;
            prev_disc = cum_disc;
            if marginal != 0 {
                components.push(CostComponent::top(label, CostAmount(marginal)));
            }
        }
        prev_disc
    } else {
        // STANDARD (×1) or SURCHARGE (×>1): each component bills its undiscounted amount; a surcharge
        // adds ONE top-level `service_tier` line so `Σ = base + surcharge = base × mult = total`.
        for (label, amt) in raw {
            components.push(CostComponent::top(label, CostAmount(amt)));
        }
        let mut t = base_total;
        if tier_bp > STANDARD_TIER_BP {
            let surcharge = base_total.saturating_mul(u128::from(tier_bp - STANDARD_TIER_BP))
                / u128::from(STANDARD_TIER_BP);
            if surcharge != 0 {
                components.push(CostComponent::top("service_tier", CostAmount(surcharge)));
                t = t.saturating_add(surcharge);
            }
        }
        t
    };

    debug_assert_eq!(
        total, one_total,
        "the split sums to the one function's figure"
    );
    CostBreakdown::new(CostAmount(one_total), components)
}

/// The one function's figure for [`price`]'s inputs, in nano-units: a card holding the reserved
/// tier rates and every PRICED open key on one lane, and one row of exactly the keys `price` prices.
///
/// The present-but-unpriced open key is left off the row, as `price` leaves it off the split —
/// that open-class posture is the keyed-unit convergence's (item 123), not this collapse's.
fn one_function_total(
    rate: &RateNanos,
    extras: &ExtraRates,
    tier_bp: u32,
    usage: &busbar_substrate_values::billing::Usage,
) -> Result<u128, busbar_kernel_ledger::cost::MoneyError> {
    use busbar_kernel_ledger::cost::{nanos_of_exact, whole, LaneClass, RateCard, Tally};
    const LANE: &str = "";
    let card = RateCard::from_nano_rates(
        RESERVED_UNITS
            .iter()
            .map(|u| (LaneClass::new(LANE, *u), rate.reserved_rate(u)))
            .chain(
                extras
                    .iter()
                    .map(|(k, r)| (LaneClass::new(LANE, k.as_str()), *r)),
            ),
        0,
    );
    let mut tally = Tally::at_card(&card);
    tally.row(
        LANE,
        0,
        tier_bp,
        usage
            .usage_units
            .iter()
            .filter(|(k, _)| RESERVED_UNITS.contains(&k.as_str()) || extras.contains_key(*k))
            .map(|(k, n)| (k.as_str(), whole(*n))),
        whole(0),
    )?;
    nanos_of_exact(tally.exact()?)
}

/// One (group, window, pool?) ENFORCEMENT BUCKET, resolved from the group's windowed limits:
/// every limit of the group that shares this window AND pool scope enforces against this one
/// ledger cell. The three windowed metrics are independent caps on the same cell's counters
/// (requests / total tokens / derived spend).
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy)]
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

    pub fn price_per_request_cents(&self) -> i64 {
        self.card.fee()
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
    /// (item 28) — and the caller fails closed on it. Card absent ⇒ `Some(0)`. Only the reserved
    /// four reach the row, exactly as before: the open-class convergence is item 123's.
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
                reserved_counts(&usage.usage_units),
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

    /// Drive the one function over a bucket view: one row per model (its reserved-four counts, at
    /// the standard tier — the enforcement book carries no tier), then the bucket's fee row.
    fn tally<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> Result<busbar_kernel_ledger::cost::Tally<'_>, busbar_kernel_ledger::cost::MoneyError> {
        use busbar_kernel_ledger::cost::{whole, Tally, STANDARD_TIER_BP};
        let mut tally = Tally::at_card(&self.card);
        for (model, units) in models {
            tally.row(model, 0, STANDARD_TIER_BP, reserved_counts(units), whole(0))?;
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
