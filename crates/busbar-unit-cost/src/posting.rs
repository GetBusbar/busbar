// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The posting — what happened, and when — and the lookup that prices it.
//!
//! A posting has no money in it. It carries the quantities a unit reported, the lane they were
//! served on, the flat fees it owes, its tier, and the instant it arrived. What it COST is not
//! stored there and is not a property of it: it is [`price`], a pure function of the posting, a
//! rate-card history and a currency. The same posting priced against two snapshots of the history
//! gives two answers, both correct, both reproducible, and neither of them written back.

use busbar_caps::Usage;

use crate::currency::CurrencyCode;
use crate::history::{HistorySeq, HistoryView};
use crate::rate::RateCard;

/// The neutral tier multiplier, in basis points: one times the price, so no tier at all.
pub const STANDARD_TIER_BP: u32 = 10_000;

/// The meter class the flat per-request fee posts under. It is a usage line like any other, which
/// is what lets the whole posting be one sum instead of a sum plus a special case.
pub const FEE_CLASS: &str = "fee";

/// One quantity against one declared class. No rate and no amount: this is layer 0.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Quantity {
    /// The declared meter class the quantity belongs to.
    pub class: String,
    /// How much of it was reported.
    pub amount: u64,
}

impl Quantity {
    /// Name one reported quantity.
    pub fn new(class: impl Into<String>, amount: u64) -> Self {
        Quantity {
            class: class.into(),
            amount,
        }
    }
}

/// **WHAT HAPPENED.** No money in it anywhere.
///
/// The lane is here because the card is keyed by lane, and a lookup over quantities cannot be
/// performed against a record that keeps no lane. The instant is here in both its readings, because
/// they answer two different questions and neither can answer the other's: the wall clock DATES the
/// record — which is what resolves the history — and the monotonic reading ORDERS it, which is what
/// makes two postings in the same millisecond distinguishable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Posting {
    /// The lane the traffic was served on — the card's key for a destination.
    pub lane: String,
    /// Every reported quantity, in the order the report carried them. THE STORED TRUTH.
    pub quantities: Vec<Quantity>,
    /// How many flat fees this posting owes — one for a billable client request, zero otherwise.
    pub fee_count: u64,
    /// The chain's tier multiplier, in basis points.
    pub tier_bp: u32,
    /// The arrival's wall-clock reading, in milliseconds. THE INSTANT THE HISTORY IS RESOLVED AT.
    pub arrived_ms: u64,
    /// The arrival's monotonic reading. Orders two postings that share a millisecond; it can never
    /// date one, and nothing here asks it to.
    pub arrived_mono: u64,
    /// Whether the quantities behind this posting were the kernel's own floor rather than figures a
    /// destination reported. The mark travels from the usage report onto the posting.
    pub estimated: bool,
    /// What the node computed at settlement, if it has settled yet. A CACHE, never a truth: see
    /// [`CachedPrice`].
    pub cached: Option<CachedPrice>,
}

impl Posting {
    /// Build a posting from a usage report: the quantities, the lane, the fees and the instant.
    ///
    /// The report's own estimated mark travels across; nothing else about it does, because nothing
    /// else about it is a quantity.
    pub fn from_usage(
        lane: impl Into<String>,
        usage: &Usage,
        fee_count: u64,
        tier_bp: u32,
        arrived_ms: u64,
        arrived_mono: u64,
    ) -> Self {
        Posting {
            lane: lane.into(),
            quantities: usage
                .lines()
                .iter()
                .map(|line| Quantity::new(line.class.as_str(), line.quantity))
                .collect(),
            fee_count,
            tier_bp,
            arrived_ms,
            arrived_mono,
            estimated: usage.is_estimated(),
            cached: None,
        }
    }

    /// The same posting with a settlement cache attached, taken from a lookup that has just run.
    ///
    /// The cache can only be built from a [`Priced`], so a figure that never came out of the lookup
    /// cannot be written into the cache slot at all.
    pub fn with_cache(mut self, history_seq: HistorySeq, priced: &Priced) -> Self {
        self.cached = Some(CachedPrice {
            history_seq,
            card_seq: priced.card_seq,
            currency: priced.currency,
            pre_tier_nanos: priced.pre_tier_nanos,
            priced_nanos: priced.priced_nanos,
        });
        self
    }
}

/// What the node computed at settlement, kept so that a read is cheap and a recompute has something
/// to compare against.
///
/// **RE-DERIVABLE, AND NEVER AUTHORITATIVE.** It is kept for two reasons and neither of them is
/// truth: a totals read that had to re-price a day of postings on every request is a different
/// performance profile, and a stored figure to compare against is what makes tampering detectable.
/// Where the cache and the lookup disagree, THE LOOKUP WINS and the divergence is a finding — after
/// a back-dated amend it is even an expected one, because the amend is precisely a change to what
/// the lookup says and precisely not a change to what was written down at the time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CachedPrice {
    /// The head of the history at settlement — which snapshot this figure was computed against.
    pub history_seq: HistorySeq,
    /// The entry the lookup resolved the posting's instant to.
    pub card_seq: HistorySeq,
    /// The currency the figure is in.
    pub currency: CurrencyCode,
    /// The summed line amounts before the tier, in nano-units.
    pub pre_tier_nanos: u128,
    /// That sum through the tier multiplier: what the posting charged.
    pub priced_nanos: u128,
}

/// One priced line — an OUTPUT of the lookup, not a stored thing.
///
/// The quantity, the rate and their product all appear together here on purpose: a reader checking
/// an invoice by hand needs all three, and they are consistent by construction because they were
/// produced together, in this function, a moment ago. Stored, the same three fields would be three
/// chances to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedLine {
    /// The meter class this quantity belongs to.
    pub class: String,
    /// How much of it was reported.
    pub quantity: u64,
    /// The card's rate for this class on the priced lane, in this currency's nano-units.
    pub unit_price_nanos: u128,
    /// Quantity times unit price, in nano-units, before any tier multiplier.
    pub amount_nanos: u128,
    /// Whether the card is present but names no price for this class in this currency. Such a line
    /// prices at nothing and says so: never a silent nothing, always a visible one.
    pub unpriced: bool,
}

/// What a posting costs at one snapshot, in one currency.
///
/// Derived, returned, and not stored as truth by anything in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priced {
    /// The history entry the posting's instant resolved to.
    pub card_seq: HistorySeq,
    /// The currency every figure here is in.
    pub currency: CurrencyCode,
    /// Every priced line, in the order the posting carried them, with the fee line last.
    pub lines: Vec<PricedLine>,
    /// The sum over every line, including the fee line, in nano-units, before the tier.
    pub pre_tier_nanos: u128,
    /// The pre-tier sum through the tier multiplier: what the posting charges.
    pub priced_nanos: u128,
}

impl Priced {
    /// Every class the card was present for but silent about.
    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class.as_str())
            .collect()
    }

    /// The figure in this currency's whole minor units — one truncation over the summed nano-units,
    /// floored at zero.
    pub fn minor(&self) -> i64 {
        crate::project::minor_of(self.priced_nanos, self.currency)
    }

    /// The figure in micro-units — one truncation at the finer display scale, NOT floored.
    pub fn micros(&self) -> i64 {
        crate::project::micros_of(self.priced_nanos)
    }
}

/// Why a posting could not be priced.
///
/// Every variant is a REFUSAL and none of them is a zero. A price nobody configured is not free, and
/// reporting it as free is how a node comes to give away its service and record that it meant to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unpriceable {
    /// No entry visible at this snapshot covers the posting's instant. A hole in the history.
    NoCardInForce {
        /// The instant nobody has said the price of.
        at: u64,
    },
    /// The card in force does not name this currency. NEVER converted from another one: there is no
    /// cross-rate in this crate, so the only honest answer to "what is this in a currency you were
    /// never given a rate for" is that there isn't one.
    CurrencyNotPriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency that was asked for.
        currency: CurrencyCode,
    },
    /// A present card names no entry for the lane — the fail-closed rule.
    ///
    /// It carries what only the fee comes to, because the two callers of this need different
    /// things from the same fact and neither may compute it for itself. A door refusing an unpriced
    /// lane refuses and reads nothing else; a settlement that must still post SOMETHING for a unit
    /// already served posts the flat fee, since the fee is owed for a billable request whether or
    /// not the lane is priced. Handing the figure back with the refusal keeps that arithmetic inside
    /// the crate that owns the arithmetic.
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane it did not name.
        lane: String,
        /// The posting priced with every token line at nothing and the fee line as it stands.
        fee_only: Priced,
    },
}

/// Apply the tier multiplier: once, over the summed pre-tier amount, with a single divide.
///
/// A sum of per-line floors is the wrong answer and undercharges: two lines of five nano-units at
/// half price are two floors of two, which is four, where the single divide over ten is five.
pub fn apply_tier(pre_tier_amount: u128, tier_bp: u32) -> u128 {
    pre_tier_amount.saturating_mul(u128::from(tier_bp)) / u128::from(STANDARD_TIER_BP)
}

/// **THE WHOLE OF LAYER 2.** What a posting costs, in a currency, against a snapshot of the history.
///
/// It reads no clock, no store and no config. The view is a borrowed slice of entries; the posting
/// is quantities and an instant. An auditor holding the postings and the history re-derives every
/// invoice from this function by hand, which is the bar the crate is written to.
///
/// The order is fixed and is the whole of the law:
///
/// 1. resolve the entry covering the posting's instant — the highest `seq` that covers it;
/// 2. resolve that card's rates for the posting's lane, in the asked-for currency;
/// 3. each quantity prices at amount times the card's integer rate, saturating;
/// 4. the flat fee joins as a line of its own, at the fee's minor units lifted to nano-units;
/// 5. those line amounts sum to the pre-tier figure;
/// 6. the tier multiplier applies once to that sum, with a single divide;
/// 7. nothing is truncated until a projection asks.
pub fn price(
    view: &HistoryView<'_>,
    posting: &Posting,
    currency: CurrencyCode,
) -> Result<Priced, Unpriceable> {
    let (card_seq, card) = view
        .card_at(posting.arrived_ms)
        .ok_or(Unpriceable::NoCardInForce {
            at: posting.arrived_ms,
        })?;
    price_against(card, card_seq, posting, currency)
}

/// The same lookup against ONE card whose entry number is already known.
///
/// [`price`] is this with the history resolution in front of it, and the resolution is the only
/// difference. It is exposed because the migration path holds a single card and the number it
/// carries is [`HistorySeq::OPENING`] by construction — there is no history to walk, and walking a
/// one-entry history to say so would be ceremony rather than a check.
pub fn price_against(
    card: &RateCard,
    card_seq: HistorySeq,
    posting: &Posting,
    currency: CurrencyCode,
) -> Result<Priced, Unpriceable> {
    if !card.prices_currency(currency) {
        return Err(Unpriceable::CurrencyNotPriced { card_seq, currency });
    }

    let rates = card.lane_rates(&posting.lane, currency);
    let mut lines: Vec<PricedLine> = Vec::with_capacity(posting.quantities.len() + 1);

    for quantity in &posting.quantities {
        let class = quantity.class.as_str();
        // A lane a present card does not name prices at nothing, and every one of its lines is
        // reported unpriced.
        let (unit_price_nanos, priced) = match &rates {
            Some(r) => (u128::from(r.nanos_per_unit(class)), r.class_priced(class)),
            None => (0u128, false),
        };
        lines.push(PricedLine {
            class: class.to_string(),
            quantity: quantity.amount,
            unit_price_nanos,
            amount_nanos: u128::from(quantity.amount).saturating_mul(unit_price_nanos),
            unpriced: !priced,
        });
    }

    // The fee is a usage line, not a scalar bolted onto the total. Its unit price is an exact
    // multiple of one minor unit, which is why summing it in before the single truncation gives the
    // same figure as truncating the usage first and adding the fee afterwards.
    let fee_unit_price_nanos = card.fee_unit_price_nanos(currency);
    lines.push(PricedLine {
        class: FEE_CLASS.to_string(),
        quantity: posting.fee_count,
        unit_price_nanos: fee_unit_price_nanos,
        amount_nanos: u128::from(posting.fee_count).saturating_mul(fee_unit_price_nanos),
        unpriced: false,
    });

    let pre_tier_nanos = lines
        .iter()
        .fold(0u128, |acc, l| acc.saturating_add(l.amount_nanos));

    let priced = Priced {
        card_seq,
        currency,
        lines,
        pre_tier_nanos,
        priced_nanos: apply_tier(pre_tier_nanos, posting.tier_bp),
    };

    if rates.is_none() {
        return Err(Unpriceable::LaneUnpriced {
            card_seq,
            lane: posting.lane.clone(),
            fee_only: priced,
        });
    }
    Ok(priced)
}
