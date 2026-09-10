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

use std::collections::BTreeMap;

// The engine's one seam onto the cost unit: every other module in this crate that needs one of the
// unit's constants reads it through here rather than naming the unit itself.
pub(crate) use busbar_unit_cost::{
    CurrencyCode, GroupRuntime, LaneRates, RateCard, TierRates, NANOS_PER_MICRO,
};
// THE DRAIN EDGE, read rather than restated: the resolved topology is the cost unit's
// (`GroupTable`) and the WALK over it is the admission unit's (`ChainWalk`, which yields a
// `BucketChain`). This module used to declare a second copy of both — its own `GroupBucket`,
// `GroupRuntime`, `project_groups` and `Chain` — and two projections of the money topology that must
// agree exactly is how a deployment comes to be ADMITTED against one set of ledger cells and BILLED
// against another. The copies are gone; what is left here is a CURSOR over the unit's values (see
// [`BucketView`]), which holds no topology of its own.
use busbar_unit_admission::{BucketChain, ChainWalk};
use busbar_unit_cost::GroupTable;

/// The prefix namespacing GROUP bucket ids in the store, so a group named like a key id can never
/// collide with a real key's bucket. Read from the crate that builds the ids rather than restated,
/// so the reader that PARSES one and the projection that WRITES one cannot drift.
pub(crate) use busbar_unit_cost::GROUP_BUCKET_PREFIX;

/// Whether `bucket_id` is a bucket of the group named `group` — an EXACT structural match against
/// the construction the projection uses, NOT a prefix test.
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

/// ONE ENFORCEMENT BUCKET OF A RESOLVED CHAIN, AS A CURSOR — every field is a borrow of, or a `Copy`
/// off, a value the units own; nothing here is a copy of the topology.
///
/// It exists because a chain has TWO sources and the enforcement walks read them uniformly. The
/// group half is [`busbar_unit_admission::ChainBucket`], resolved ONCE per group when the model is
/// built and thereafter only borrowed. The principal's own attribution bucket is the KEY ID, which
/// is per-request and belongs to the key — materialising it as an owned bucket would be one heap
/// allocation on the admission path for a bucket that carries no caps and can never block. So the
/// two are read through this view instead, and the admission path allocates NOTHING to resolve a
/// chain (`cost_tests::chain_read_is_a_borrow_not_a_build` pins that: two keys of one group read
/// the SAME chain, by address).
#[derive(Debug, Clone, Copy)]
pub(crate) struct BucketView<'a> {
    /// The store/ledger bucket id (the key id, or `group:<name>@<window>[#<pool>]`).
    pub(crate) bucket_id: &'a str,
    /// The operator-facing group name for diagnostics; `None` for the key's own bucket.
    pub(crate) group_name: Option<&'a str>,
    /// The bucket's window word - the `budget_window` period sentinel (`total` for the key's own
    /// attribution bucket).
    pub(crate) window: &'static str,
    pub(crate) requests_cap: Option<u64>,
    pub(crate) tokens_cap: Option<u64>,
    pub(crate) tokens_input_cap: Option<u64>,
    pub(crate) tokens_output_cap: Option<u64>,
    pub(crate) tokens_cache_read_cap: Option<u64>,
    pub(crate) tokens_cache_write_cap: Option<u64>,
    pub(crate) budget_cap: Option<i64>,
    /// `Some(pool)` = the bucket is scope-qualified: it checks/charges/accrues ONLY when the
    /// request was dispatched through that pool. `None` = applies to every request through the
    /// group.
    pub(crate) scope: Option<&'a str>,
    /// The budget limit's `downgrade_to` pool, when it declared `on_exhaust: downgrade`.
    pub(crate) downgrade_to: Option<&'a str>,
}

impl<'a> BucketView<'a> {
    /// The principal's own attribution bucket: the key id, no caps, the all-time window. It is
    /// there so every posting is attributed, it is charged on every admission, and it can never
    /// block.
    fn attribution(key_id: &'a str) -> Self {
        BucketView {
            bucket_id: key_id,
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
        }
    }

    /// A cursor onto one of the walk's resolved group buckets. Borrows; copies only the caps,
    /// which are integers.
    fn of(b: &'a busbar_unit_admission::ChainBucket) -> Self {
        BucketView {
            bucket_id: &b.bucket_id,
            group_name: b.group_name.as_deref(),
            window: b.window,
            requests_cap: b.requests_cap,
            tokens_cap: b.tokens_cap,
            tokens_input_cap: b.tokens_input_cap,
            tokens_output_cap: b.tokens_output_cap,
            tokens_cache_read_cap: b.tokens_cache_read_cap,
            tokens_cache_write_cap: b.tokens_cache_write_cap,
            budget_cap: b.budget_cap,
            scope: b.scope.as_deref(),
            downgrade_to: b.downgrade_to.as_deref(),
        }
    }

    /// Whether this bucket participates in a request dispatched through `pool` - group-wide
    /// buckets always do; a pool-scoped bucket only for its own pool. Every enforcement walk
    /// (admit / charge / refund / accrue / headroom) keys off this ONE predicate so the paths
    /// can never disagree on what was charged vs what is refunded.
    pub(crate) fn applies_to_pool(&self, pool: &str) -> bool {
        self.scope.is_none_or(|s| s == pool)
    }
}

/// A resolved enforcement chain for ONE KEY: the key's attribution bucket plus the GROUP HALF, which
/// is a borrow of a chain the model resolved once and holds for its whole life.
///
/// The group half depends only on the group the key is bound to, and the model is immutable once
/// resolved — so it is walked at BOOT, once per group, and every request that arrives on that group
/// thereafter reads the same value. What is per-request is the key id and nothing else.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Chain<'a> {
    key_id: &'a str,
    groups: &'a BucketChain,
}

impl<'a> Chain<'a> {
    /// Every bucket of the chain, innermost first: the key's attribution bucket, then the
    /// innermost group's window buckets, then its parent's, to the root.
    pub(crate) fn iter(&self) -> impl Iterator<Item = BucketView<'a>> {
        std::iter::once(BucketView::attribution(self.key_id))
            .chain(self.groups.buckets().iter().map(BucketView::of))
    }

    pub(crate) fn len(&self) -> usize {
        1 + self.groups.buckets().len()
    }

    /// The chain's groups, innermost first — the `enabled` freeze flag and the `concurrent` gauge
    /// are per GROUP, not per window bucket.
    pub(crate) fn groups(&self) -> &'a [busbar_unit_admission::ChainGroup] {
        self.groups.groups()
    }
}

// THE BYTE-IDENTITY VIEW IS GONE, WITH THE SECOND PROJECTION IT EXISTED TO WATCH.
//
// `ResolvedGroupView`/`ResolvedBucketView`/`resolved_view`/`resolved_fee` were here so a cell could
// drive one `(rate_card, fee, groups)` through this engine's projection AND the composition root's
// and compare every field, because two projections of the money topology that must agree exactly is
// how a deployment comes to be ADMITTED against one set of ledger cells and BILLED against another.
// There is one projection now — `busbar_unit_cost::GroupTable::resolve`, over the values the one
// `GroupCfg` -> `GroupSpec` relay hands it — and both readers drive it. A comparison of a value
// against itself is not a cell, so the view died with the hazard rather than outliving it; what the
// root's cell asserts instead is that the two readers resolve the SAME `GroupRuntime` values, by
// the unit's own equality, which is the claim that is now worth making.

/// The resolved cost model: the cost unit's own model (the effective integer rate table + the
/// resolved `groups:` topology + the flat per-request fee) plus the two things the retiring engine
/// needs on top of it. Immutable once resolved; rebuilt with the config on apply/reload.
pub struct CostModel {
    /// THE MODEL, resolved by the crate that owns money. The card and the group topology are one
    /// value because a budget cap is a number in one configured section compared against a sum
    /// derived from the other.
    inner: busbar_unit_cost::CostModel,
    /// THE CHAIN PER GROUP, WALKED ONCE. The group half of a chain depends only on the group a key
    /// is bound to, and this model is immutable, so the admission unit's walk runs at BOOT — once
    /// per group — and every request on that group thereafter READS the resolved value rather than
    /// rebuilding it. Indexed by the group's position in the table, so the lookup is the same
    /// index-chase the walk itself is.
    chains: Vec<BucketChain>,
    /// The chain of a key bound to NO group: no group buckets and no groups. Held as a value rather
    /// than built per read for the same reason the rest are — an unbound key's chain is one shape,
    /// and a read of it allocates nothing either.
    empty_chain: BucketChain,
    /// The ids of every LIVE bucket that still carries at least one windowed cap — the exact set
    /// the projection just emitted, indexed for O(1) membership. This is what makes
    /// "does this ledger cell still back an enforced cap?" an IDENTITY question (is this id one of
    /// the ids the model produces?) instead of a parse of the id's internal structure.
    capped_bucket_ids: std::collections::HashSet<String>,
}

impl CostModel {
    /// Resolve from config. Assumes `config_validate` has already passed (completeness, acyclic
    /// groups, valid limit shapes); the projection it delegates to is pure and is defensive, never
    /// panicking, on anything validation should have caught.
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
        Self::from_card(card, groups_cfg)
    }

    /// Rebuild the model with a NEW groups map, reusing the resolved rate card + flat fee unchanged.
    /// The Admin-API group-mutation seam (`build_with_group` / `build_without_group`): a runtime
    /// group change must reproject enforcement buckets WITHOUT re-parsing the rate card (which the
    /// mutation never touched). Pure — assumes the caller already re-ran `validate_groups`.
    pub(crate) fn with_groups(
        &self,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        Self::from_card(self.inner.card().clone(), groups_cfg)
    }

    /// The one construction point both entries share: relay the configured tree through the ONE
    /// `GroupCfg` -> `GroupSpec` relay, hand it to the unit that projects it, and walk each group's
    /// chain once.
    ///
    /// THE PROJECTION IS NOT HERE AND IS NOT ANYWHERE ELSE EITHER. It used to be here as well as in
    /// the composition root, and two projections of the money topology that must agree exactly is
    /// how a deployment comes to be ADMITTED against one set of ledger cells and BILLED against
    /// another — silently, because both answers are internally consistent and neither knows the
    /// other exists. Both readers now drive `busbar_unit_cost::GroupTable::resolve` over the values
    /// `busbar_substrate::config::groups::group_specs` relays, so there is one reading of the
    /// section and nothing left to disagree with.
    ///
    /// The relay's lease-id map is EMPTY here: interning a group name into a static vocabulary is
    /// something only a composition root does, the projection is identical either way, and this
    /// engine reads no lease id off the resolved table.
    fn from_card(
        card: RateCard,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        let specs = busbar_substrate::config::groups::group_specs(
            groups_cfg,
            &std::collections::BTreeMap::new(),
        );
        let inner = busbar_unit_cost::CostModel::resolve_parts(card, &specs);
        let table = inner.groups();
        let chains = (0..table.groups().len())
            .map(|i| Self::group_chain(table, i))
            .collect();
        Self {
            capped_bucket_ids: Self::capped_bucket_ids(table.groups()),
            chains,
            empty_chain: BucketChain::unchecked(Vec::new(), Vec::new()),
            inner,
        }
    }

    /// The GROUP HALF of the chain that starts at `index`, walked once by the admission unit and
    /// kept for the model's whole life.
    ///
    /// The walk yields the principal's attribution bucket first and then the groups', and the
    /// attribution bucket is the one part that is NOT shareable — it is the key id, which is
    /// per-request. So it is walked with an empty id and dropped, and each request supplies its own
    /// through [`BucketView::attribution`], which borrows. That is the whole reason a chain read
    /// costs no allocation.
    fn group_chain(table: &GroupTable, index: usize) -> BucketChain {
        let name = table.groups()[index].name.as_str();
        let walked = table
            .chain_for("", Some(name))
            .expect("the name came from the table being walked");
        BucketChain::unchecked(walked.buckets()[1..].to_vec(), walked.groups().to_vec())
    }

    /// Index the ids of every projected bucket that carries at least one windowed cap. Built from
    /// the SAME buckets the engine enforces against, so the set can never disagree with the model
    /// about which cells are load-bearing.
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

    /// A minimal model for tests / governance-off paths: no card, no groups, the given flat fee.
    #[cfg(any(test, feature = "test-support"))]
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self::from_card(
            RateCard::absent(price_per_request_cents),
            &std::collections::BTreeMap::new(),
        )
    }

    /// Whether a rate card is configured (token pricing active).
    ///
    /// `pub` (was crate-private): the first of the two questions the pre-admission pricing guard
    /// asks, answered for a plane through the
    /// [`BudgetHost::cost_pricing_enabled`](busbar_substrate::plane_host::BudgetHost::cost_pricing_enabled)
    /// seam, which downcasts the opaque cost handle and drives this same read.
    pub fn pricing_enabled(&self) -> bool {
        self.inner.pricing_enabled()
    }

    /// The flat per-request fee in abstract cents, clamped at zero by the card.
    pub(crate) fn price_per_request_cents(&self) -> i64 {
        self.inner.card().per_request_fee(CurrencyCode::USD)
    }

    /// THE RESOLVED TOPOLOGY, straight off the unit's table.
    ///
    /// `pub` under test support for the one-projection cell, which asserts that this engine and the
    /// composition root resolve the SAME `GroupRuntime` values off one configuration — the claim
    /// that replaced the field-by-field byte-identity view when the second projection died.
    #[cfg(any(test, feature = "test-support"))]
    pub fn groups(&self) -> &[GroupRuntime] {
        self.inner.groups().groups()
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub(crate) fn groups(&self) -> &[GroupRuntime] {
        self.inner.groups().groups()
    }

    pub(crate) fn group_named(&self, name: &str) -> Option<&GroupRuntime> {
        let table = self.inner.groups();
        table.index_of(name).map(|i| &table.groups()[i])
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
        self.inner.card().lane_rates(model, CurrencyCode::USD)
    }

    /// PRICE a neutral [`busbar_substrate::billing::Usage`] for `model` into nanodollars — the host-side
    /// entry point the [`MeteringHost::price_usage`](busbar_substrate::plane_host::MeteringHost::price_usage)
    /// seam a live carrier (voice) drives folds through.
    ///
    /// A RELAY ONTO THE FACE. The fold this used to run in this file — the reserved four
    /// multiply-adds over a `class -> quantity` map — is now
    /// [`busbar_unit_cost::LaneRates::reserved_units_nanos`], beside the line-shaped fold and against
    /// the same card. It is the same arithmetic on the same values (the unit's cells copied it
    /// verbatim before this one went), with one change that is a fix rather than a difference: the
    /// running sum saturates instead of adding plainly, which is identical below the accumulator's
    /// top and pins rather than wrapping above it.
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
            .map(|lane| lane.reserved_units_nanos(&usage.usage_units))
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
        self.inner.model_unpriced(model)
    }

    /// DERIVE the spend (in cents, abstract minor units) of a ledger view — **A RELAY, AND NO
    /// LONGER A DERIVATION**.
    ///
    /// What used to be here was a second money fold: its own accumulation over the models a bucket
    /// used, its own single divide to cents, its own flat-fee multiply and its own floor at zero,
    /// beside the cost unit's. Every one of those four steps is a decision that must match the
    /// unit's exactly, and nothing made them match — a per-lane floor undercharges every multi-model
    /// bucket, an unclamped fee credits one back toward headroom, and a wrapping cast bills an
    /// over-the-top ledger as free. Two answers to what a bucket has spent, with the ledger unable
    /// to say which one admitted the request.
    ///
    /// So the whole of it is `busbar_unit_cost::derive_spend_minor_units` now, over the card this
    /// model already holds: the same fold, the same divide, the same fee and the same floor as the
    /// line-shaped derivation the composition root drives, because they are literally the same
    /// lines. The semantics are unchanged and are the unit's: `include_request_fee` adds the flat
    /// fee times the BILLABLE request count (`fee_requests`: admitted minus refunded, so the fee
    /// bills 2xx only); every enforcement/read path passes `true`. Pure recompute from tokens x
    /// current rates — no spend is ever cached or stored — and a model with no rate (card present,
    /// entry missing, which only ledger rows written under a previous config can produce) derives at
    /// 0, the operator's rate-card edit taking effect retroactively by design.
    pub(crate) fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        busbar_unit_cost::derive_spend_minor_units(
            self.inner.card(),
            CurrencyCode::USD,
            models,
            fee_requests,
            include_request_fee,
        )
    }

    /// As [`Self::derive_spend_cents`] but in MICRO-units, for the hook seam / admin projections —
    /// the same relay onto the same sum, at the finer scale and with no floor at zero.
    pub(crate) fn derive_spend_micros<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        busbar_unit_cost::derive_spend_micros_units(
            self.inner.card(),
            CurrencyCode::USD,
            models,
            fee_requests,
            include_request_fee,
        )
    }

    /// READ the ENFORCEMENT CHAIN for a key: [key's attribution bucket] -> key.group's window
    /// buckets -> parent's -> ... root, innermost first.
    ///
    /// A READ AND NOT A WALK, WHICH IS THE POINT. The group half of a chain is decided entirely by
    /// the group the key names, and this model is immutable once resolved — so the admission unit's
    /// walk ran at BOOT, once per group, and this is an index-chase into the result. Nothing is
    /// allocated: the group buckets are borrowed from the model and the attribution bucket is the
    /// key's own id, borrowed from the key.
    ///
    /// `Err(missing)` when the key names a `group` that does not exist in config - the
    /// FAIL-CLOSED outcome (mint validates the group; boot re-checks; this arm covers a shared
    /// durable store whose keys reference a group another node's config no longer has).
    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_api::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        let groups = match key.group.as_deref() {
            None => &self.empty_chain,
            Some(name) => match self.inner.groups().index_of(name) {
                Some(i) => &self.chains[i],
                None => return Err(name),
            },
        };
        Ok(Chain {
            key_id: &key.id,
            groups,
        })
    }
}

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod tests;
