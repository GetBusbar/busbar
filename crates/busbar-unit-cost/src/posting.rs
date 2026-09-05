// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stored posting: one priced line per reported quantity, the flat fee as a line of its own,
//! the summed pre-tier amount, and the tier multiplier applied once over that sum.

use busbar_caps::Usage;

use crate::rate::{PinnedCard, RateCardVersion};

/// The neutral tier multiplier, in basis points: one times the price, so no tier at all.
pub const STANDARD_TIER_BP: u32 = 10_000;

/// The meter class the flat per-request fee posts under. It is a usage line like any other, which
/// is what lets the whole posting be one sum instead of a sum plus a special case.
pub const FEE_CLASS: &str = "fee";

/// One priced line of a posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedLine {
    /// The meter class this quantity belongs to.
    pub class: String,
    /// How much of it was reported.
    pub quantity: u64,
    /// The card's rate for this class on the priced lane, in nano-units per unit of quantity.
    pub unit_price_nanos: u128,
    /// Quantity times unit price, in nano-units, before any tier multiplier.
    pub amount_nanos: u128,
    /// Whether the card is present but names no price for this class. Such a line prices at
    /// nothing and says so: never a silent nothing, always a visible one.
    pub unpriced: bool,
}

/// What one settled unit cost, in the layout the ledger stores.
///
/// The pre-tier amount is the sum of every line INCLUDING the fee line. The priced amount is that
/// sum through the tier multiplier, computed with one divide. Both are stored, along with the
/// multiplier and the version of the card that produced them, so the figure can be recomputed and
/// checked without guessing which card was in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    rate_card_version: RateCardVersion,
    tier_bp: u32,
    lines: Vec<PricedLine>,
    pre_tier_amount: u128,
    priced_amount: u128,
    fee_count: u64,
    lane_unpriced: bool,
    estimated: bool,
}

impl Posting {
    /// The card this posting was priced against — the one pinned when the hold opened.
    pub fn rate_card_version(&self) -> &RateCardVersion {
        &self.rate_card_version
    }

    /// The tier multiplier in basis points that produced the priced amount.
    pub fn tier_bp(&self) -> u32 {
        self.tier_bp
    }

    /// Every priced line, in the order the report carried them, with the fee line last.
    pub fn lines(&self) -> &[PricedLine] {
        &self.lines
    }

    /// The sum over every line, including the fee line, in nano-units, before the tier.
    pub fn pre_tier_amount(&self) -> u128 {
        self.pre_tier_amount
    }

    /// The pre-tier amount through the tier multiplier: what the posting actually charges.
    pub fn priced_amount(&self) -> u128 {
        self.priced_amount
    }

    /// How many flat fees this posting carries — one for a billable client request, zero otherwise.
    pub fn fee_count(&self) -> u64 {
        self.fee_count
    }

    /// Whether the lane itself was absent from a present card. Every line prices at nothing when
    /// this is set, and the caller is expected to fail closed rather than serve for free.
    pub fn lane_unpriced(&self) -> bool {
        self.lane_unpriced
    }

    /// Whether the usage behind this posting was the kernel's own floor rather than a figure the
    /// destination reported. The mark travels from the usage report onto the posting.
    pub fn estimated(&self) -> bool {
        self.estimated
    }

    /// Every class the card was present for but silent about.
    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class.as_str())
            .collect()
    }

    /// The posting in whole cents — one truncation over the summed nano-units, floored at zero.
    pub fn cents(&self) -> i64 {
        crate::project::cents_of(self.priced_amount)
    }

    /// The posting in micro-units — one truncation over the summed nano-units, NOT floored.
    pub fn micros(&self) -> i64 {
        crate::project::micros_of(self.priced_amount)
    }
}

/// Apply the tier multiplier: once, over the summed pre-tier amount, with a single divide.
///
/// A sum of per-line floors is the wrong answer and undercharges: two lines of five nano-units at
/// half price are two floors of two, which is four, where the single divide over ten is five.
pub fn apply_tier(pre_tier_amount: u128, tier_bp: u32) -> u128 {
    pre_tier_amount.saturating_mul(u128::from(tier_bp)) / u128::from(STANDARD_TIER_BP)
}

/// Price one settled unit against the card pinned at its hold.
///
/// The order is fixed and is the whole of the law: each reported line prices at quantity times the
/// card's integer rate; the flat fee joins as its own line at the fee's cents lifted to nano-units;
/// those line amounts sum to the pre-tier amount; the tier multiplier applies once to that sum.
/// Nothing is truncated until a projection asks for cents or micro-units.
pub fn price(
    pinned: &PinnedCard<'_>,
    lane: &str,
    usage: &Usage,
    fee_count: u64,
    tier_bp: u32,
) -> Posting {
    let card = pinned.card();
    let rates = card.lane_rates(lane);
    let mut lines: Vec<PricedLine> = Vec::with_capacity(usage.lines().len() + 1);

    for line in usage.lines() {
        let class = line.class.as_str();
        // A lane a present card does not name prices at nothing, and every one of its lines is
        // reported unpriced — the caller decides whether that is a refusal.
        let (unit_price_nanos, priced) = match &rates {
            Some(r) => (u128::from(r.nanos_per_unit(class)), r.class_priced(class)),
            None => (0u128, false),
        };
        lines.push(PricedLine {
            class: class.to_string(),
            quantity: line.quantity,
            unit_price_nanos,
            amount_nanos: u128::from(line.quantity).saturating_mul(unit_price_nanos),
            unpriced: !priced,
        });
    }

    // The fee is a usage line, not a scalar bolted onto the total. Its unit price is an exact
    // multiple of the cent, which is why summing it in before the single truncation gives the same
    // cents as truncating the usage first and adding the fee afterwards.
    let fee_unit_price_nanos = card.fee_unit_price_nanos();
    lines.push(PricedLine {
        class: FEE_CLASS.to_string(),
        quantity: fee_count,
        unit_price_nanos: fee_unit_price_nanos,
        amount_nanos: u128::from(fee_count).saturating_mul(fee_unit_price_nanos),
        unpriced: false,
    });

    let pre_tier_amount = lines
        .iter()
        .fold(0u128, |acc, l| acc.saturating_add(l.amount_nanos));

    Posting {
        rate_card_version: pinned.version().clone(),
        tier_bp,
        lines,
        pre_tier_amount,
        priced_amount: apply_tier(pre_tier_amount, tier_bp),
        fee_count,
        lane_unpriced: rates.is_none(),
        estimated: usage.is_estimated(),
    }
}
