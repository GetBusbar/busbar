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
//! ## What this section decides, and where each half of it is applied
//!
//! **COUNTS FOR THE KERNEL, AMOUNTS FOR THE CARD, AND THE TWO NEVER MEET IN A STORED FIGURE.** This
//! section says how many entries and how many transactions a unit owes and whether the meter's
//! quantities are charged for — that half goes to the teller, which counts and never prices. It also says what one of each is WORTH, in the currency's minor units — that half goes
//! onto the dated card, and it is applied at the ONE pricing site, where the card lives, and
//! nowhere else. The ledger stores the counts; the money is what the card in force makes of them at the
//! moment somebody asks, so an amount written here is a figure a later reader re-derives rather
//! than a second answer they cannot.
//!
//! **NEVER TWO NUMBERS FOR ONE FEE.** `per_request_fee:` and `rate_card:` are the previous
//! release's spelling of the transaction fee and of what a unit of a dimension costs, and they stay
//! exactly where they are. An amount left unset here INHERITS them. A deployment that sets both the
//! old spelling and the new one for the same fee, at the same scope, is refused at boot by name:
//! see [`TariffAmountConflict`]. There is no arm anywhere that picks one of two configured numbers.
//!
//! ## Rounding: the teller's rule, and why it is banker's
//!
//! A fee that says `cents per N units` produces a fraction of a minor unit whenever the quantity is
//! not a multiple of N, and SOMEBODY has to decide which way it goes. Rounding up is the house
//! taking a systematic cut of every fraction it ever sees; rounding down is the customer taking the
//! same cut the other way. Half-to-even — banker's rounding — is the rule a teller's till uses
//! precisely because it has no bias over many roundings: the halves split evenly between up and
//! down, so a million small charges sum to the same total whichever side of the counter you are on.
//! It is therefore the DEFAULT, and it is DECLARED rather than implied: `rounding:` is written into
//! the grammar so an operator who wants a different rule names it and an auditor reading a bill can
//! read which one produced it.

// THE FEE TERMS ARE CONTRACT DATA. What a deployment WRITES is this file's, what the figures ARE
// is the contract's, and what they come to is the card's — three questions, three homes, and no
// crate holding a second shape for one set of figures.
use busbar_contract::tariff::{FeeTerms, PerUnitTerm, Rounding, ScopedFeeTerms, TariffScope};
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
    /// Whether a VISIT is charged for at the door, and what the door costs.
    #[serde(default)]
    pub entry_fee: Option<EntryFeeCfg>,
    /// What a completed TRANSACTION costs: a flat amount, a per-dimension amount, or both.
    #[serde(default)]
    pub transaction_fee: Option<TransactionFeeCfg>,
    /// The floor under one unit's tariff charge, in the currency's minor units. A unit that owes
    /// less than this owes this. Unset inherits; the outermost default is nothing, which is a floor
    /// no charge can fall below anyway and therefore the only floor that changes no bill.
    #[serde(default)]
    pub minimum_cents: Option<i64>,
    /// The cap over one unit's tariff charge, in the currency's minor units. Unset at every scope
    /// is UNCAPPED, which is a different statement from a cap of zero and is spelled differently:
    /// omitting the key inherits, writing `0` caps every unit at nothing.
    #[serde(default)]
    pub maximum_cents: Option<i64>,
    /// Which way a fraction of a minor unit goes. See the module header: the default is banker's.
    #[serde(default)]
    pub rounding: Option<Rounding>,
    /// What a unit whose two endings contradict each other is charged.
    #[serde(default)]
    pub dispute_policy: Option<DisputePolicyCfg>,
}

/// **THE VISIT'S OWN FEE**: whether the door is charged for, and what it costs.
///
/// The two are separate because they answer separate questions and a deployment changes them at
/// different times: whether to charge for admission at all is a policy, what admission costs is a
/// price. Collapsing them into "zero means off" would make a deliberate free-admission period
/// indistinguishable from a deployment that never turned the door fee on.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryFeeCfg {
    /// Whether an admitted visit is charged for at all.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// What one visit costs, in the currency's MINOR units. Unset inherits `per_request_fee:` —
    /// the previous release's one fee figure — rather than defaulting to a second number nobody
    /// wrote down.
    #[serde(default)]
    pub amount_cents: Option<i64>,
}

/// **THE TRANSACTION'S FEE**: a flat amount per completed exchange, an amount per N units of a
/// declared dimension, or both.
///
/// Both, summed, is a real schedule and not a hole: a deployment may charge for the exchange AND
/// for what the exchange moved, and the total of the two is the total of the two. There is no arm
/// here that picks one.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionFeeCfg {
    /// The flat amount per completed transaction, in the currency's MINOR units. Unset inherits
    /// `per_request_fee:`.
    #[serde(default)]
    pub flat_cents: Option<i64>,
    /// Per-dimension amounts. Each names a dimension SOME PLANE DECLARED — there is no list of
    /// dimension names in this file and there is not going to be one. Unset inherits; the
    /// outermost default is EMPTY, and empty is what makes `rate_card:` the only thing pricing a
    /// unit of a dimension on a deployment that has not written this key.
    #[serde(default)]
    pub per_units: Option<Vec<PerUnitTerm>>,
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
        let scopes = self.scopes(plane, pool, tier);
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

    /// **WHICH SCOPE THIS UNIT'S AMOUNTS RESOLVE AT** — the innermost one this section actually
    /// WROTE a cell for, and the node's own where it wrote none.
    ///
    /// Configured, not merely applicable: a deployment that scoped nothing for this unit's pool has
    /// not scoped that pool, and a posting recording `pool:<name>` for it would name a schedule the
    /// card carries nothing under and invite a reader to look for one. The order is [`Self::cell`]'s
    /// order, read off the same maps, so the scope a posting records and the scope its amounts were
    /// folded from are one answer rather than two.
    #[must_use]
    pub fn scope_of(&self, plane: &str, pool: Option<&str>, tier: Option<&str>) -> TariffScope {
        if let Some(t) = tier.filter(|t| self.tier.contains_key(*t)) {
            return TariffScope::tier(t);
        }
        if let Some(p) = pool.filter(|p| self.pool.contains_key(*p)) {
            return TariffScope::pool(p);
        }
        if self.plane.contains_key(plane) {
            return TariffScope::plane(plane);
        }
        TariffScope::node()
    }

    /// The scopes that apply to one unit, MOST SPECIFIC FIRST. Stated once, here, so the counts
    /// half and the amounts half cannot resolve a unit against two different orders.
    fn scopes(&self, plane: &str, pool: Option<&str>, tier: Option<&str>) -> Vec<&TariffScopeCfg> {
        tier.and_then(|t| self.tier.get(t))
            .into_iter()
            .chain(pool.and_then(|p| self.pool.get(p)))
            .chain(self.plane.get(plane))
            .chain(std::iter::once(&self.default))
            .collect()
    }

    /// **RESOLVE ONE UNIT'S AMOUNTS**, in the same order and by the same field-wise fold as
    /// [`Self::cell`] resolves its counts.
    ///
    /// `inherited_fee` is the previous release's `per_request_fee:` — the one fee figure a 1.5.5
    /// deployment configured. An amount this section leaves unset at every scope INHERITS it rather
    /// than defaulting to a number nobody wrote, which is what makes a configuration with no
    /// `tariff:` block price exactly as it priced before. A deployment that sets both is refused at
    /// boot, so this fold is never choosing between two configured numbers for one fee — see
    /// [`Self::amount_conflicts`].
    #[must_use]
    pub fn amounts(
        &self,
        plane: &str,
        pool: Option<&str>,
        tier: Option<&str>,
        inherited_fee: i64,
    ) -> FeeTerms {
        let scopes = self.scopes(plane, pool, tier);
        let entry = |f: &dyn Fn(&EntryFeeCfg) -> Option<i64>| {
            scopes.iter().find_map(|s| s.entry_fee.as_ref().and_then(f))
        };
        let txn = |f: &dyn Fn(&TransactionFeeCfg) -> Option<i64>| {
            scopes
                .iter()
                .find_map(|s| s.transaction_fee.as_ref().and_then(f))
        };
        FeeTerms {
            entry: entry(&|e| e.amount_cents).unwrap_or(inherited_fee),
            transaction: txn(&|t| t.flat_cents).unwrap_or(inherited_fee),
            per_units: scopes
                .iter()
                .find_map(|s| {
                    s.transaction_fee
                        .as_ref()
                        .and_then(|t| t.per_units.as_ref())
                })
                .cloned()
                .unwrap_or_default(),
            minimum: scopes.iter().find_map(|s| s.minimum_cents).unwrap_or(0),
            maximum: scopes.iter().find_map(|s| s.maximum_cents),
            rounding: scopes.iter().find_map(|s| s.rounding).unwrap_or_default(),
        }
    }

    /// **THE WHOLE OF A DEPLOYMENT'S AMOUNTS, AT EVERY SCOPE IT WROTE ONE FOR** — what the dated
    /// card carries, and the only shape in which a scoped amount can ever be applied.
    ///
    /// One entry per configured scope, each RESOLVED WHOLE by the same field-wise fold as
    /// [`Self::amounts`], plus the node's own. A card that held unresolved cells would be a card
    /// that had to re-walk a configuration to price a row, and the configuration is exactly the
    /// thing that has moved by the time somebody re-prices.
    ///
    /// **A SCOPED SCHEDULE INHERITS THE NODE'S, AND NOTHING ELSE'S.** A posting records ONE scope —
    /// the innermost that applied — so the chain a reader can re-walk from the row is that scope
    /// and the default. Folding a pool's cell over a plane's as well would charge a unit under a
    /// third schedule its own row does not name, and an auditor holding the postings and the
    /// history could not re-derive the figure. What a scoped cell leaves unset it takes from
    /// `tariff.default` and from the previous release's `per_request_fee:` behind it.
    #[must_use]
    pub fn card_amounts(&self, inherited_fee: i64) -> ScopedFeeTerms {
        let mut out = ScopedFeeTerms::node(self.amounts("", None, None, inherited_fee));
        for (label, name) in self.named_scopes() {
            let (scope, terms) = match label {
                "plane" => (
                    TariffScope::plane(name),
                    self.amounts(name, None, None, inherited_fee),
                ),
                "pool" => (
                    TariffScope::pool(name),
                    self.amounts("", Some(name), None, inherited_fee),
                ),
                _ => (
                    TariffScope::tier(name),
                    self.amounts("", None, Some(name), inherited_fee),
                ),
            };
            out = out.with(scope, terms);
        }
        out
    }

    /// **WHERE ONE FEE IS NAMED TWICE.** Every scope of this section against the previous release's
    /// own two keys.
    ///
    /// A deployment that writes `per_request_fee: 3` and `tariff.default.transaction_fee.flat_cents:
    /// 5` has said two different things about one fee, and there is no honest way for a node to
    /// pick: charging 5 ignores a figure the operator wrote, charging 3 ignores the one they wrote
    /// more recently, and charging 8 invents a schedule neither of them describes. So the node
    /// REFUSES TO BOOT and names both keys. The same reading applies to a dimension `rate_card:`
    /// already prices: a `per_units` entry for it would be a second price for one unit of one thing.
    ///
    /// A zero `per_request_fee:` is not a second number. It is the serde default, it is
    /// indistinguishable from the key's absence in a parsed configuration, and it is the identity
    /// of the sum besides — so a deployment that never mentioned the old key can write the new one.
    #[must_use]
    pub fn amount_conflicts(
        &self,
        per_request_fee: i64,
        card_prices_dimension: &dyn Fn(&str) -> bool,
    ) -> Vec<TariffAmountConflict> {
        let mut out = Vec::new();
        for (scope, cell) in self.every_scope() {
            if per_request_fee != 0 {
                for (key, set) in [
                    (
                        "entry_fee.amount_cents",
                        cell.entry_fee.as_ref().and_then(|e| e.amount_cents),
                    ),
                    (
                        "transaction_fee.flat_cents",
                        cell.transaction_fee.as_ref().and_then(|t| t.flat_cents),
                    ),
                ] {
                    if let Some(new) = set {
                        out.push(TariffAmountConflict {
                            scope: scope.clone(),
                            key: key.to_string(),
                            new_amount: new,
                            old_key: "per_request_fee".to_string(),
                            old_amount: per_request_fee,
                        });
                    }
                }
            }
            for unit in cell
                .transaction_fee
                .as_ref()
                .and_then(|t| t.per_units.as_ref())
                .into_iter()
                .flatten()
            {
                if card_prices_dimension(&unit.dimension) {
                    out.push(TariffAmountConflict {
                        scope: scope.clone(),
                        key: format!("transaction_fee.per_units[{}]", unit.dimension),
                        new_amount: unit.amount,
                        old_key: format!("rate_card (the '{}' rate)", unit.dimension),
                        old_amount: 0,
                    });
                }
            }
        }
        out
    }

    /// Every scope cell this section holds, with the dotted path an operator would have written it
    /// at. Read by the conflict check and by validation, so neither can miss a scope the other sees.
    #[must_use]
    pub fn every_scope(&self) -> Vec<(String, &TariffScopeCfg)> {
        let mut out = vec![("default".to_string(), &self.default)];
        for (label, map) in [
            ("plane", &self.plane),
            ("pool", &self.pool),
            ("tier", &self.tier),
        ] {
            out.extend(map.iter().map(|(k, v)| (format!("{label}.{k}"), v)));
        }
        out
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

/// **ONE FEE NAMED TWICE, AT ONE SCOPE.** What [`TariffCfg::amount_conflicts`] found.
///
/// It carries both spellings and both figures rather than a message, so the boot refusal can say
/// which two keys disagreed and every caller says it the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TariffAmountConflict {
    /// The scope both keys apply to, as the dotted path an operator wrote (`default`, `plane.llm`).
    pub scope: String,
    /// The `tariff:` key, relative to the scope.
    pub key: String,
    /// What the `tariff:` key says.
    pub new_amount: i64,
    /// The previous release's key that says the same thing.
    pub old_key: String,
    /// What that key says.
    pub old_amount: i64,
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
