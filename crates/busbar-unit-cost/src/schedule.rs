// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **APPLYING WHAT THE COUNTS ARE WORTH.** The amount half of a deployment's tariff, on the card.
//!
//! The FIGURES are contract data ([`busbar_contract::tariff::FeeTerms`]): a deployment declares
//! them, a seam carries them, and nobody owns them. This file is what a card DOES with them, and it
//! is the only place in the workspace that turns a count into money. It lives here because the
//! amounts belong to the dated card — spend is re-priced at read time by whichever card was in
//! force, and an amount applied anywhere else would be a second answer to what one unit was charged
//! that no later reader could re-derive.

use busbar_contract::tariff::FeeTerms;

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
    /// The sum, held to the terms' floor and cap.
    pub total_minor: i128,
    /// What the floor or the cap moved the sum by; zero when neither applied.
    pub bound_adjustment_minor: i128,
}

/// **WHAT ONE UNIT'S COUNTS COST UNDER ONE DEPLOYMENT'S TERMS**, in minor units, before the tier.
///
/// The order is fixed and is the whole of the law: the visit, the transaction, then each dimension's
/// quantity divided by its `per` under the declared rounding; those sum; the sum is held to the
/// floor and the cap. The bound applies to the TARIFF's own charge and to nothing else — what the
/// metered quantities cost against the card's own per-(lane, class) rates is the card's answer and
/// is never capped by a fee schedule.
///
/// Returns the lines it charged as well as the total, so the caller can show each one: a total
/// nobody can decompose is a bill nobody can dispute.
///
/// A free function rather than a method on the terms, because a rule about MONEY belongs to the
/// crate that owns the card: the contract declares what a deployment agreed to and this decides
/// what that comes to, and a contract that could add up a bill would be a second pricing site.
#[must_use]
pub fn charge_minor(
    terms: &FeeTerms,
    entries: u64,
    transactions: u64,
    quantity: &dyn Fn(&str) -> u64,
) -> ScheduleCharge {
    let mut lines = Vec::with_capacity(2 + terms.per_units.len());
    let entry = i128::from(terms.entry).saturating_mul(i128::from(entries));
    let transaction = i128::from(terms.transaction).saturating_mul(i128::from(transactions));
    lines.push((ENTRY_CLASS.to_string(), entries, entry));
    lines.push((crate::FEE_CLASS.to_string(), transactions, transaction));
    let mut total = entry.saturating_add(transaction);
    for rate in &terms.per_units {
        let q = quantity(&rate.dimension);
        let amount = terms.rounding.divide(
            i128::from(rate.amount).saturating_mul(i128::from(q)),
            rate.per,
        );
        lines.push((rate.dimension.clone(), q, amount));
        total = total.saturating_add(amount);
    }
    let bounded = match terms.maximum {
        Some(max) => total.clamp(i128::from(terms.minimum), i128::from(max)),
        None => total.max(i128::from(terms.minimum)),
    };
    ScheduleCharge {
        lines,
        total_minor: bounded,
        bound_adjustment_minor: bounded - total,
    }
}

#[cfg(test)]
#[path = "tests/schedule_tests.rs"]
mod schedule_tests;
