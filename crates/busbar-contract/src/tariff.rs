// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **WHAT A DEPLOYMENT'S COUNTS ARE WORTH**, as data, in one place every side may name.
//!
//! A tariff has two halves and they live apart on purpose. The COUNTS — how many visits, how many
//! transactions, whether the meter's quantities are charged for — are the teller's, and it holds no
//! amount. The AMOUNTS are the dated card's, and the card holds no count. What crosses between the
//! configuration that declares them and the card that applies them is THIS: a record of figures in
//! a currency's minor units, and the rule for a fraction of one.
//!
//! It is declared HERE, in the contract, for the same reason every other closed grammar in this
//! crate is: the engine that PARSES a deployment's configuration, the seam that CARRIES the result
//! and the unit that APPLIES it may not name each other. A record in the retiring engine would be a
//! name three crates had to learn and then unlearn; a record in the unit that prices would make the
//! seam depend on the card's shape. So the figures are contract data, spoken by everyone, owned by
//! nobody, and they carry no card, no currency and no count.

use serde::Deserialize;

/// **WHICH WAY A FRACTION OF A MINOR UNIT GOES.** Declared by the deployment, never implied.
///
/// A rate of `amount per N units` produces a fraction whenever the quantity is not a multiple of N,
/// and somebody has to decide the direction. The default is [`Rounding::Bankers`] — half to even,
/// the rule a till uses — because it is the only one of the three with no bias: rounding up is the
/// house taking a systematic cut of every fraction it ever sees, and rounding down is the customer
/// taking the same cut back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rounding {
    /// Half to even — the teller's rule, and the default.
    #[default]
    Bankers,
    /// Away from zero. The house takes every fraction.
    Up,
    /// Toward zero. The customer takes every fraction.
    Down,
}

impl Rounding {
    /// Divide, and resolve the remainder the way this rule says.
    ///
    /// The arithmetic lives ON the declaration rather than beside it, because a rule that says which
    /// way a fraction goes and a function that sends it that way are one thing: two readers each
    /// carrying their own division is how one request comes to be judged at one figure and billed
    /// at another. Integer throughout — there is no floating point on any path that decides money.
    ///
    /// A `per` of nothing is refused by configuration validation before a schedule can carry one; if
    /// one arrives anyway the answer is nothing rather than a panic, because a division by zero
    /// inside a settlement would take a node down for a configuration mistake.
    #[must_use]
    pub fn divide(self, numerator: i128, per: u64) -> i128 {
        let per = i128::from(per);
        if per <= 0 {
            return 0;
        }
        let whole = numerator / per;
        let rest = numerator % per;
        if rest == 0 {
            return whole;
        }
        match self {
            Rounding::Down => whole,
            Rounding::Up => whole + 1,
            // Half to even: below half rounds down, above half rounds up, and exactly half goes to
            // whichever of the two neighbours is even — which is what removes the bias.
            Rounding::Bankers => match (rest * 2).cmp(&per) {
                std::cmp::Ordering::Less => whole,
                std::cmp::Ordering::Greater => whole + 1,
                std::cmp::Ordering::Equal => whole + i128::from(whole % 2 != 0),
            },
        }
    }
}

/// **AN AMOUNT PER N UNITS OF ONE DECLARED DIMENSION.**
///
/// `per` is carried rather than folded into the rate, because "3 cents per 1000 tokens" is the
/// schedule operators publish and a rate expressed as a fraction of a cent is a rounding decision
/// taken before anybody could declare one. The division happens once, where the schedule is
/// applied, under [`Rounding`].
///
/// `dimension` is a meter class some PLANE declared. There is no list of dimension names in this
/// file and there is not going to be one: a dimension exists exactly when a plane's own
/// declaration says it does.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerUnitTerm {
    /// The dimension's key, as the plane that declared it spells it.
    pub dimension: String,
    /// How many units one charge covers. At least one.
    pub per: u64,
    /// What one `per` units costs, in the currency's minor units.
    ///
    /// SPELLED `cents` WHERE AN OPERATOR WRITES IT and `amount` where the tree reads it, on purpose.
    /// A deployment's file says cents because that is the word for the figure it is writing; the
    /// type says amount because the figure is in whatever the currency's minor unit is, and `cents`
    /// on a non-USD deployment is a lie — which is the same correction the card already made when
    /// it stopped spelling its own fee `per_request_fee_cents`.
    #[serde(rename = "cents")]
    pub amount: i64,
}

/// **ONE DEPLOYMENT'S FEE TERMS IN ONE CURRENCY.** Every figure in that currency's MINOR units.
///
/// It holds no count, and whatever decides the counts holds no amount: counts and amounts never
/// live in one type, so there is no value anywhere that could be read as either. It names no lane,
/// no plane and no currency — a currency is the card's to know, and these figures are the same
/// figures whichever card carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeTerms {
    /// What one admitted visit costs.
    pub entry: i64,
    /// What one completed transaction costs, flat.
    pub transaction: i64,
    /// What the units cost, per dimension. Empty is the shipped default, and it is what leaves a
    /// card's own per-(lane, class) rates the only thing pricing a unit of a dimension.
    pub per_units: Vec<PerUnitTerm>,
    /// The floor under one unit's tariff charge.
    pub minimum: i64,
    /// The cap over it; `None` is uncapped, which is a different statement from a cap of nothing.
    pub maximum: Option<i64>,
    /// Which way a fraction of a minor unit goes.
    pub rounding: Rounding,
}

impl FeeTerms {
    /// **THE PREVIOUS RELEASE'S TERMS**: one figure, charged for the visit and for the transaction
    /// alike, nothing per unit, no floor and no cap.
    ///
    /// Named so the compatibility claim is a VALUE rather than a comment: a deployment that wrote
    /// only the previous release's one fee key is charged by exactly this, and the cells that prove
    /// it construct it here rather than restating five zeroes each. Clamped at nothing, once, on the
    /// one constructor that makes terms out of a single number: no unit may ever bill a negative
    /// amount, which would credit a budget back toward headroom.
    #[must_use]
    pub fn flat(amount: i64) -> Self {
        FeeTerms {
            entry: amount.max(0),
            transaction: amount.max(0),
            ..FeeTerms::default()
        }
    }
}
