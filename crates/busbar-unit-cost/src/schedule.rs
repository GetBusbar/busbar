// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **WHAT THE COUNTS ARE WORTH.** The amount half of a deployment's tariff, held on the card.
//!
//! Something upstream counts — one entry per admitted visit, one transaction per completed
//! exchange, the meter's quantities admitted or not — and holds no amount at all. This is the other
//! half: what
//! one of each of those costs, in the currency's minor units. It lives HERE, on the dated card,
//! because spend is re-priced at read time by whichever card was in force, and an amount stored
//! anywhere else would be a second answer to what one unit was charged that no later reader could
//! re-derive.
//!
//! It is applied at exactly one site — [`crate::price_at_card`] — and there is nowhere else in the
//! workspace that turns a count into money.

/// **WHICH WAY A FRACTION OF A MINOR UNIT GOES.** Declared by the deployment, never implied.
///
/// A rate of `cents per N units` produces a fraction whenever the quantity is not a multiple of N,
/// and somebody has to decide the direction. The default is [`Rounding::Bankers`] — half to even,
/// the rule a till uses — because it is the only one of the three with no bias: rounding up is the
/// house taking a systematic cut of every fraction it ever sees, and rounding down is the customer
/// taking the same cut back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Rounding {
    /// Half to even.
    #[default]
    Bankers,
    /// Away from zero.
    Up,
    /// Toward zero.
    Down,
}

impl Rounding {
    /// Divide, and resolve the remainder the way this rule says. Integer arithmetic throughout:
    /// there is no floating point on any path that decides money.
    ///
    /// `per` of zero is refused by configuration validation before a schedule can carry one; if one
    /// ever arrives anyway the answer is nothing rather than a panic, because a division by zero
    /// inside the pricing site would take a settlement down for a configuration mistake.
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
                std::cmp::Ordering::Equal => {
                    if whole % 2 == 0 {
                        whole
                    } else {
                        whole + 1
                    }
                }
            },
        }
    }
}

/// **CENTS PER N UNITS OF ONE DECLARED DIMENSION.**
///
/// `per` is carried rather than folded into the rate, because "3 cents per 1000 tokens" is the
/// schedule operators publish and a rate expressed as a fraction of a cent is a rounding decision
/// taken before anybody could declare one. Here the division happens once, under [`Rounding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerUnitFee {
    /// The meter class, spelled as the plane that declared it spells it.
    pub class: String,
    /// How many units one charge covers. At least one.
    pub per: u64,
    /// What one `per` units costs, in the currency's minor units.
    pub minor: i64,
}

/// **ONE DEPLOYMENT'S FEE SCHEDULE IN ONE CURRENCY.** Every field in that currency's minor units.
///
/// It holds no count, and whatever decided the counts holds no amount: counts and amounts never
/// live in one type, so there is no value anywhere that could be read as either.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeSchedule {
    /// What one admitted visit costs.
    pub entry_minor: i64,
    /// What one completed transaction costs, flat.
    pub transaction_minor: i64,
    /// What the units cost, per dimension. Empty is the shipped default, and it is what leaves the
    /// card's own per-(lane, class) rates the only thing pricing a unit of a dimension.
    pub per_units: Vec<PerUnitFee>,
    /// The floor under one unit's tariff charge.
    pub minimum_minor: i64,
    /// The cap over it; `None` is uncapped, which is a different statement from a cap of nothing.
    pub maximum_minor: Option<i64>,
    /// Which way a fraction of a minor unit goes.
    pub rounding: Rounding,
}

impl FeeSchedule {
    /// **THE PREVIOUS RELEASE'S SCHEDULE**: one figure, charged for the visit and for the
    /// transaction alike, nothing per unit, no floor and no cap.
    ///
    /// Named so the compatibility claim is a value rather than a comment: a deployment that wrote
    /// only `per_request_fee:` is charged by exactly this, and the identity cells construct it here
    /// rather than restating five zeroes each.
    #[must_use]
    pub fn flat(minor: i64) -> Self {
        FeeSchedule {
            entry_minor: minor.max(0),
            transaction_minor: minor.max(0),
            ..FeeSchedule::default()
        }
    }

    /// **WHAT ONE UNIT'S COUNTS COST UNDER THIS SCHEDULE**, in minor units, before the tier.
    ///
    /// The order is fixed and is the whole of the law: the visit, the transaction, then each
    /// dimension's quantity divided by its `per` under the declared rounding; those sum; the sum is
    /// held to the floor and the cap. The bound applies to the TARIFF's own charge and to nothing
    /// else — what the metered quantities cost against the card's own per-(lane, class) rates is
    /// the card's answer and is never capped by a fee schedule.
    ///
    /// Returns the lines it charged as well as the total, so the caller can show each one: a total
    /// nobody can decompose is a bill nobody can dispute.
    #[must_use]
    pub fn charge_minor(
        &self,
        entries: u64,
        transactions: u64,
        quantity: &dyn Fn(&str) -> u64,
    ) -> ScheduleCharge {
        let mut lines = Vec::with_capacity(2 + self.per_units.len());
        let entry = i128::from(self.entry_minor).saturating_mul(i128::from(entries));
        let transaction =
            i128::from(self.transaction_minor).saturating_mul(i128::from(transactions));
        lines.push((ENTRY_CLASS.to_string(), entries, entry));
        lines.push((crate::FEE_CLASS.to_string(), transactions, transaction));
        let mut total = entry.saturating_add(transaction);
        for rate in &self.per_units {
            let q = quantity(&rate.class);
            let amount = self.rounding.divide(
                i128::from(rate.minor).saturating_mul(i128::from(q)),
                rate.per,
            );
            lines.push((rate.class.clone(), q, amount));
            total = total.saturating_add(amount);
        }
        let bounded = match self.maximum_minor {
            Some(max) => total.clamp(i128::from(self.minimum_minor), i128::from(max)),
            None => total.max(i128::from(self.minimum_minor)),
        };
        ScheduleCharge {
            lines,
            total_minor: bounded,
            bound_adjustment_minor: bounded - total,
        }
    }
}

/// The meter class the entry fee posts under. A usage line like any other, which is what lets the
/// whole posting be one sum instead of a sum plus two special cases.
pub const ENTRY_CLASS: &str = "entry";

/// The class a floor or a cap posts its own difference under. A bound that moved a total is a line
/// saying so, never a silent adjustment folded into somebody else's figure.
pub const BOUND_CLASS: &str = "tariff_bound";

/// **WHAT A SCHEDULE CHARGED, DECOMPOSED.** Every line that made the total, and the total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleCharge {
    /// `(class, the count or quantity it was charged on, the amount in minor units)`.
    pub lines: Vec<(String, u64, i128)>,
    /// The sum, held to the schedule's floor and cap.
    pub total_minor: i128,
    /// What the floor or the cap moved the sum by; zero when neither applied.
    pub bound_adjustment_minor: i128,
}

#[cfg(test)]
#[path = "tests/schedule_tests.rs"]
mod schedule_tests;
