// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `tariff:` SECTION — WHAT A DEPLOYMENT AGREED TO CHARGE, IN ONE PLACE.**
//!
//! A tariff has three nouns and no others. A **visit** is an admitted unit: a caller the node let
//! through its door. A **transaction** is a completed exchange with a destination, or a service the
//! plane declared it performs locally and charges for. **Units** are quantities in a dimension the
//! plane itself declared — there is no list of dimension names here, and there is not going to be
//! one, because a dimension exists exactly when some plane's `METER_CLASSES` says it does.
//!
//! EVERY PLUGIN OF A KIND IS IDENTICAL TO EVERY OTHER OF THAT KIND, and billing a plane is billing
//! a plane. Nothing in this grammar names a dialect, a provider, a model family or a protocol. The
//! scopes are `tier`, `pool`, `plane` and `default`, resolved in that order field by field: an
//! unset field INHERITS the next scope out, it does not reset to the type's zero. So a deployment
//! that wants one number different for one pool writes that one number.
//!
//! ## Absent ⇒ the previous release, exactly
//!
//! A configuration with no `tariff:` block is charged exactly as the previous release charged: no
//! entry fee, and the previous release's own dispute rule is one of the three this section names.
//! Nothing is renamed and nothing is retyped, which is what the frozen config-schema snapshot
//! permits and the only thing it permits.
//!
//! ## What this section decides, and what the card decides
//!
//! **COUNTS HERE, AMOUNTS ON THE CARD.** This section says how many entries and how many
//! transactions a unit owes and whether the meter's quantities are charged for; what one of them is
//! WORTH is `rate_card:` and `per_request_fee:`, which are dated and re-read at settlement. Spend
//! is RE-PRICED at read time by whichever card was in force, so a stored amount would be a second
//! answer to what one unit was charged that no later reader could re-derive. That is why there is no amount
//! in this file: the fields that carry one are the card's, and they are already there.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The whole `tariff:` block: one default cell and three keyed scope maps.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TariffCfg {
    /// The global cell every other scope inherits from, field by field.
    #[serde(default)]
    pub default: TariffScopeCfg,
    /// Overrides keyed by PLANE KIND — the registry key the plane declares, never a dialect, a
    /// provider or a model.
    #[serde(default)]
    pub plane: BTreeMap<String, TariffScopeCfg>,
    /// Overrides keyed by pool name.
    #[serde(default)]
    pub pool: BTreeMap<String, TariffScopeCfg>,
    /// Overrides keyed by group name — the deployment's tier.
    #[serde(default)]
    pub tier: BTreeMap<String, TariffScopeCfg>,
}

/// One scope's cell. EVERY FIELD IS OPTIONAL, and that is the inheritance rule written in the type:
/// `None` means "whatever the next scope out says", and there is no way to spell "reset to zero"
/// except by writing the zero.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TariffScopeCfg {
    /// Whether a VISIT is charged for at the door.
    #[serde(default)]
    pub entry_fee: Option<EntryFeeCfg>,
    /// What a unit whose two endings contradict each other is charged.
    #[serde(default)]
    pub dispute_policy: Option<DisputePolicyCfg>,
}

/// The visit's own fee.
///
/// One field, because the amount is the card's. A deployment that charges for the door says so
/// here; what the door costs is `per_request_fee:`, the same figure a transaction is charged at,
/// until the card carries a second one.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryFeeCfg {
    /// Whether an admitted visit is charged for at all.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// What a contradicted unit is charged. The three answers to one question, generous first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputePolicyCfg {
    /// The visit only: no transaction, and not the units either.
    EntryOnly,
    /// The visit and what was delivered. The default, and the only uniform reading: it is the one
    /// under which the same fault costs the same money on every dialect.
    #[default]
    EntryPlusUnits,
    /// Everything, as though the exchange had completed. What the previous release billed, kept as
    /// a named choice for a deployment that wants it back.
    Full,
}

impl DisputePolicyCfg {
    /// **WHAT THIS POLICY CHARGES**, said as what it charges rather than as which policy it is.
    ///
    /// A policy IS what it charges — that is the whole of its meaning at the site that applies it —
    /// so the seam between the configuration's names and the kernel's carries the two answers and
    /// not the name. This crate is the retiring engine and the kernel is what it retires into; a
    /// type crossing between them would be a dependency in the wrong direction, and a shared
    /// integer code would be a third vocabulary neither side owns. What both sides already agree
    /// on, and always did, is that a contradicted unit either owes a transaction or does not, and
    /// either owes what it consumed or does not.
    #[must_use]
    pub fn charges_transaction(self) -> bool {
        matches!(self, DisputePolicyCfg::Full)
    }

    /// Whether the quantities the meter reported are charged for. See [`Self::charges_transaction`].
    #[must_use]
    pub fn charges_units(self) -> bool {
        !matches!(self, DisputePolicyCfg::EntryOnly)
    }
}

impl TariffCfg {
    /// **RESOLVE ONE UNIT'S CELL: tier, then pool, then plane, then default, field by field.**
    ///
    /// The order is stated once, here, as the scopes that apply to this unit most specific first;
    /// every field then takes the first scope that answers it. A field-wise fold rather than a
    /// whole-cell pick, because a pool that wanted one different number and got a cell of type
    /// defaults for everything else is a deployment silently un-configuring itself.
    ///
    /// `plane` is the plane's registry key and nothing finer. There is no dialect scope and no
    /// model scope, and adding one would be the first line of the tree that said one plugin of a
    /// kind is worth more than another.
    #[must_use]
    pub fn cell(&self, plane: &str, pool: Option<&str>, tier: Option<&str>) -> ResolvedTariff {
        let scopes: Vec<&TariffScopeCfg> = tier
            .and_then(|t| self.tier.get(t))
            .into_iter()
            .chain(pool.and_then(|p| self.pool.get(p)))
            .chain(self.plane.get(plane))
            .chain(std::iter::once(&self.default))
            .collect();
        let dispute_policy = scopes
            .iter()
            .find_map(|s| s.dispute_policy)
            .unwrap_or_default();
        ResolvedTariff {
            entry_enabled: scopes
                .iter()
                .find_map(|s| s.entry_fee.as_ref().and_then(|e| e.enabled))
                .unwrap_or(false),
            disputed_charges_transaction: dispute_policy.charges_transaction(),
            disputed_charges_units: dispute_policy.charges_units(),
        }
    }

    /// Every scope this section names that is keyed by something a deployment defines elsewhere,
    /// as `(what the map is called, the key)`. What validation checks against the pools, the groups
    /// and the registered planes — a scope naming something that does not exist is a schedule
    /// somebody believes is in force and that nothing will ever select.
    #[must_use]
    pub fn named_scopes(&self) -> Vec<(&'static str, &str)> {
        fn each<'a>(
            label: &'static str,
            map: &'a BTreeMap<String, TariffScopeCfg>,
        ) -> Vec<(&'static str, &'a str)> {
            map.keys().map(|k| (label, k.as_str())).collect()
        }
        let mut out = each("plane", &self.plane);
        out.extend(each("pool", &self.pool));
        out.extend(each("tier", &self.tier));
        out
    }
}

/// **ONE SCOPE'S CELL, WITH EVERY FIELD ANSWERED.** What resolution produces.
///
/// Nothing here is optional, because inheritance has already happened: this is the schedule a unit
/// is charged under, and a question it cannot answer is a question the pricing site would have to
/// answer for itself, somewhere nobody can see.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolvedTariff {
    /// Whether an admitted visit is charged for.
    pub entry_enabled: bool,
    /// Whether a unit whose two endings contradict each other owes the transaction.
    pub disputed_charges_transaction: bool,
    /// Whether such a unit owes the quantities its meter reported.
    pub disputed_charges_units: bool,
}

#[cfg(test)]
#[path = "tests/tariff_tests.rs"]
mod tariff_tests;
