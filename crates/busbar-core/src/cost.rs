// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LIMIT MODEL, and the SEAM onto the crate that owns money.
//!
//! **NO MONEY IS DERIVED IN THIS FILE.** It used to be: a private nano-rate table, a fold over a
//! bucket's reserved four, a divide to cents, a flat-fee multiply and a floor at zero, all beside
//! busbar-unit-cost's. Two answers to what a request cost, each internally consistent, with the
//! ledger unable to say which one it recorded. Every one of them is gone. The card and the
//! derivations over it belong to the cost unit, and this module's whole remaining part in pricing
//! is to hold the resolved card and hand it over — which
//! is why the `pub(crate) use` line below is the ONE place in this crate that names the cost unit,
//! and everything else spells `crate::cost::`.
//!
//! What is still here is the resolved `groups:` limit topology the generic limit engine
//! (governance) enforces, as a CURSOR over the units' values, plus the per-group chain walked once
//! at boot. The `Store` trait (in `busbar-api`) stays the persistence seam and carries ONLY tokens.
//!
//! Principles (the 1.5.0 redesign), now upheld by the unit rather than restated here:
//! - TOKENS ARE THE LEDGER; dollars are ALWAYS derived, never stored as truth. Every spend figure
//!   is computed at read time as `ledger x current rate card`, so correcting a rate is a
//!   config edit + reload - past and future derived figures instantly become right. (Honest limit:
//!   repricing cannot un-make PAST admit/reject decisions taken under a wrong rate.)
//! - NO CURRENCY in the core. Rates are ABSTRACT cost units (micro-units per token in config,
//!   integer NANO-units per token internally); `_cents` fields are abstract minor units. Currency
//!   is a display concern owned entirely by the consumer.
//! - ALL-OR-NOTHING pricing: `rate_card` absent => every model prices at 0 (only the flat
//!   per-request fee counts); present => authoritative + complete (validated at boot).
//! - INTEGER MATH ONLY on the hot path: config floats convert ONCE, inside the unit, to nano-units
//!   per unit of quantity; derivation is a few u128 multiply-adds over the lanes a bucket used.
//! - GROUPS are the ONE limit tree: a group's generic limits (requests / tokens / budget per
//!   window, plus the instantaneous `concurrent` gauge) resolve here into per-(group, window)
//!   ENFORCEMENT BUCKETS; keys are pure auth and contribute no caps of their own.
//!
//! A `CostModel` is resolved from config at boot / config-apply and lives on `App` (rebuilt on
//! apply), while the `GovState` token ledger survives the apply - which is exactly what makes
//! reprice-on-reload work.

// The engine's one seam onto the cost unit: every other module in this crate that needs one of the
// unit's constants reads it through here rather than naming the unit itself.
pub(crate) use busbar_unit_cost::{
    derive_spend_micros_units, derive_spend_minor_units, CurrencyCode, GroupRuntime, RateCard,
    TierRates, NANOS_PER_MICRO,
};
// THE DRAIN EDGE, read rather than restated: the resolved topology is the cost unit's
// (`GroupTable`) and both the WALK over it and the MEMO OF THE WALK are the admission unit's
// (`ChainCache`, which yields a `Chain` of `BucketView` cursors). This module used to declare a
// second copy of the topology — its own `GroupBucket`, `GroupRuntime`, `project_groups` and
// `Chain` — and two projections of the money topology that must agree exactly is how a deployment
// comes to be ADMITTED against one set of ledger cells and BILLED against another. The copies are
// gone, and so is the cursor that read them: `BucketView` and `Chain` are the admission unit's,
// spelled here so this crate's readers name one crate as before.
use busbar_unit_admission::ChainCache;
pub(crate) use busbar_unit_admission::{BucketView, Chain};

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
    /// THE CHAINS, WALKED ONCE, and the index of the ids that still carry a cap. The group half of
    /// a chain depends only on the group a key is bound to, and this model is immutable, so the
    /// admission unit's walk runs at BOOT — once per group — and every request on that group
    /// thereafter READS the resolved value rather than rebuilding it.
    chains: ChainCache,
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
        Self::resolve_parts_with_terms(
            rate_card,
            busbar_contract::tariff::FeeTerms::flat(per_request_fee),
            groups_cfg,
        )
    }

    /// [`Self::resolve_parts`] with the deployment's WHOLE fee terms rather than its one flat
    /// figure — what the composition path calls, once the `tariff:` section has been resolved.
    ///
    /// The one-figure spelling above is this, with the previous release's terms: one figure for the
    /// visit and for the transaction, nothing per unit, no floor and no cap. Two entry points, one
    /// card constructor, and no second place that turns a configured amount into a price.
    pub fn resolve_parts_with_terms(
        rate_card: Option<&std::collections::BTreeMap<String, crate::config::RateEntryCfg>>,
        terms: busbar_contract::tariff::FeeTerms,
        groups_cfg: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        // rate_card is the ONLY cost source - the 1.4.x pool-member tiered-override loop is
        // GONE (cost lives on no pool member; routing derives its scalar from the card).
        // The card's rows are the config's `_utok` micro-floats lifted through their neutral raw
        // view (`raw_tier_rates`), so this names no plane config grammar; the unit rounds once to
        // nano-units and clamps the fee, exactly as the private table did.
        let card = RateCard::from_config_in(
            CurrencyCode::USD,
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
            terms,
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
        Self {
            chains: ChainCache::resolve(table),
            inner,
        }
    }

    /// Whether `bucket_id` is, RIGHT NOW, the id of a live bucket that still enforces at least one
    /// windowed cap. Pure identity: the id either is one the live model produces or it is not, so
    /// no assumption about `@`/`#` being delimiters (or a group name avoiding them) exists here.
    pub(crate) fn bucket_enforces_a_cap(&self, bucket_id: &str) -> bool {
        self.chains.bucket_enforces_a_cap(bucket_id)
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
        self.inner
            .card()
            .fee_terms(CurrencyCode::USD)
            .map_or(0, |t| t.transaction)
    }

    /// **THE CARD ITSELF**, for a reader that needs to DERIVE rather than to ask this model a
    /// question.
    ///
    /// It is here so that the engine's remaining spend readers — the budget engine's four in
    /// `governance::state` and the admin projection's one — call
    /// [`busbar_unit_cost::derive_spend_minor_units`] / `derive_spend_micros_units` DIRECTLY, on the
    /// card this model resolved. The alternative is a per-reader method on this type that forwards
    /// to the unit, and a forwarder is a place a fifth reader's slightly different rule can be
    /// added: an extra `.max(0)` here, a fee left out there, and the engine is deriving money again
    /// under a name that says it is only passing it along. With the card handed over, there is
    /// nothing between a reader and the one derivation, and this accessor goes with the crate.
    pub(crate) fn card(&self) -> &RateCard {
        self.inner.card()
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

    /// READ the ENFORCEMENT CHAIN for a key, off the cache the admission unit walked at boot: the
    /// key's own id supplies the attribution bucket and the group name indexes the rest, so this is
    /// an index-chase that allocates nothing.
    ///
    /// `Err(missing)` when the key names a `group` that does not exist in config - the
    /// FAIL-CLOSED outcome (mint validates the group; boot re-checks; this arm covers a shared
    /// durable store whose keys reference a group another node's config no longer has).
    pub(crate) fn chain_for<'a>(
        &'a self,
        key: &'a busbar_api::VirtualKey,
    ) -> Result<Chain<'a>, &'a str> {
        self.chains
            .chain_for(self.inner.groups(), &key.id, key.group.as_deref())
    }
}

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod tests;
