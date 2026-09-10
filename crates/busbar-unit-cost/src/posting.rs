// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happened, and what it costs.
//!
//! Those are two different things and this file keeps them apart. A [`Posting`] is WHAT HAPPENED:
//! quantities per meter class, the lane they were served on, the flat-fee count, the tier and the
//! instant. There is no money in it anywhere. A [`Priced`] is what a lookup ANSWERED: the same
//! quantities against the card in force at that instant, in one currency. It is derived, it is
//! reproducible, and it is never stored as truth.
//!
//! A posting may carry a [`CachedPrice`] — the figure the node computed at settlement, kept so a
//! read is cheap and a recompute has something to compare against. It is not authoritative and
//! nothing in this file will read it to answer a question about money: [`Posting::priced_nanos`]
//! performs the lookup and ignores the cache entirely, so a corrupted cache cannot become a bill.

use busbar_caps::Usage;

use crate::currency::CurrencyCode;
use crate::history::{HistorySeq, HistoryView};
use crate::rate::RateCard;

/// The neutral tier multiplier, in basis points: one times the price, so no tier at all.
pub const STANDARD_TIER_BP: u32 = 10_000;

/// The meter class the flat per-request fee posts under. It is a usage line like any other, which
/// is what lets the whole posting be one sum instead of a sum plus a special case.
pub const FEE_CLASS: &str = "fee";

/// One quantity against one declared class. No money in it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Quantity {
    /// The declared meter class the quantity belongs to.
    pub class: String,
    /// How much of it was reported.
    pub amount: u64,
}

impl Quantity {
    /// Name one measured quantity.
    pub fn new(class: impl Into<String>, amount: u64) -> Self {
        Quantity {
            class: class.into(),
            amount,
        }
    }
}

/// What the node computed at settlement, kept beside the quantities.
///
/// **A CACHED LOOKUP, NEVER A TRUTH.** It is re-derivable from the posting and the history at any
/// time, and where the two disagree the LOOKUP wins and the divergence is a finding. It is kept for
/// two reasons and neither is authority: a totals read that had to re-price a day of postings on
/// every request would be a different performance profile, and a stored figure to compare against is
/// what makes tampering detectable at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CachedPrice {
    /// The head of the history at settlement — which snapshot the figure was computed against.
    pub history_seq: HistorySeq,
    /// The entry `card_at(arrived_ms)` resolved to under that snapshot.
    pub card_seq: HistorySeq,
    /// The currency the figure is in.
    pub currency: CurrencyCode,
    /// The summed line amounts, in nano-units, before the tier.
    pub pre_tier_nanos: u128,
    /// That sum through the tier multiplier.
    pub priced_nanos: u128,
}

/// **WHAT HAPPENED.** Quantities and the instant they happened, and no money anywhere.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Posting {
    /// The lane the traffic was served on — the card is keyed by it, so a posting that kept no lane
    /// could not be priced by a lookup at all.
    pub lane: String,
    /// One entry per reported meter class.
    pub quantities: Vec<Quantity>,
    /// How many flat fees this posting carries — one for a billable client request, zero otherwise.
    pub fee_count: u64,
    /// The chain's tier multiplier, in basis points.
    pub tier_bp: u32,
    /// The instant, as a wall clock reads it, in milliseconds. A wall clock DATES a record and
    /// cannot order one, which is why the monotonic reading is beside it rather than instead of it.
    /// This is the field the history is resolved at.
    pub arrived_ms: u64,
    /// The instant, as a monotonic clock reads it. ORDERS the record and cannot date it.
    pub arrived_mono: u64,
    /// Whether the quantities behind this posting were the kernel's own floor rather than a figure
    /// the destination reported. The mark travels from the usage report onto the posting.
    pub estimated: bool,
    /// The figure computed at settlement, if one was. `None` for a posting nothing has priced yet,
    /// which is a different thing from a cache of zero.
    pub cached: Option<CachedPrice>,
}

impl Posting {
    /// Build a posting from a usage report: the quantities, the lane and the instant.
    ///
    /// The report's lines cross over as quantities with their class names unchanged — the card is
    /// keyed by the same spellings, so no name is translated between a line and the entry that
    /// prices it.
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
                .map(|l| Quantity::new(l.class.as_str(), l.quantity))
                .collect(),
            fee_count,
            tier_bp,
            arrived_ms,
            arrived_mono,
            estimated: usage.is_estimated(),
            cached: None,
        }
    }

    /// **THE FIGURE A READER MUST USE**: the lookup's, always.
    ///
    /// It does not consult [`Self::cached`] and there is no arm here that could. That is the
    /// invariant stated as code rather than as a comment: a posting whose cache has been corrupted
    /// answers exactly what the quantities and the history say, because the cache is not on the
    /// path at all.
    pub fn priced_nanos(
        &self,
        view: &HistoryView<'_>,
        currency: CurrencyCode,
    ) -> Result<u128, Unpriceable> {
        price(view, self, currency).map(|p| p.priced_nanos)
    }

    /// Whether the cache disagrees with a lookup. A posting with no cache never disagrees — there is
    /// nothing to disagree with.
    ///
    /// A divergence is a finding, not a fallback: the caller records that the cache is stale and
    /// corrects it, and the number it reports is the lookup's either way.
    pub fn cache_diverges(&self, priced: &Priced) -> bool {
        match self.cached {
            None => false,
            Some(c) => {
                c.currency != priced.currency
                    || c.card_seq != priced.card_seq
                    || c.pre_tier_nanos != priced.pre_tier_nanos
                    || c.priced_nanos != priced.priced_nanos
            }
        }
    }
}

/// One priced line of a lookup's answer.
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

/// What a lookup answered: the quantities of one posting against one card, in one currency.
///
/// Derived, never stored as truth. Two lookups over the same posting against the same snapshot are
/// the same answer forever, which is what makes an invoice reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priced {
    /// The history entry the instant resolved to.
    pub card_seq: HistorySeq,
    /// The currency the figures are in.
    pub currency: CurrencyCode,
    /// Every priced line, in the order the posting carried them, with the fee line last.
    pub lines: Vec<PricedLine>,
    /// The sum over every line, including the fee line, in nano-units, before the tier.
    pub pre_tier_nanos: u128,
    /// The pre-tier amount through the tier multiplier: what the posting actually charges.
    pub priced_nanos: u128,
    /// Whether the lane itself was absent from a present card. Every token line prices at nothing
    /// when this is set, and the caller decides whether that is a refusal — see [`price_fail_closed`].
    pub lane_unpriced: bool,
    /// Whether the card names no flat fee in this currency. The fee line prices at nothing when
    /// this is set and says so, and the caller decides whether that is a refusal — the same two
    /// postures the lane gets, for the same reason: present but unpriced is never a silent zero.
    pub fee_unpriced: bool,
    /// The tier multiplier in basis points that produced the priced amount.
    pub tier_bp: u32,
    /// How many flat fees the posting carried.
    pub fee_count: u64,
    /// Whether the quantities were the kernel's own floor.
    pub estimated: bool,
}

impl Priced {
    /// The answer in whole minor units of its own currency — one truncation over the summed
    /// nano-units, floored at zero.
    pub fn minor(&self) -> i64 {
        crate::project::minor_of(self.priced_nanos, self.currency)
    }

    /// The answer in micro-units — one truncation over the summed nano-units, NOT floored.
    pub fn micros(&self) -> i64 {
        crate::project::micros_of(self.priced_nanos)
    }

    /// Every class the card was present for but silent about — including [`FEE_CLASS`] when the
    /// card names no flat fee in this currency, because a silent fee is a silent class like any
    /// other and is reported like one.
    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class.as_str())
            .collect()
    }

    /// The cache this answer would be stored as, under a named snapshot.
    pub fn as_cache(&self, history_seq: HistorySeq) -> CachedPrice {
        CachedPrice {
            history_seq,
            card_seq: self.card_seq,
            currency: self.currency,
            pre_tier_nanos: self.pre_tier_nanos,
            priced_nanos: self.priced_nanos,
        }
    }
}

/// Why a posting could not be priced. Every one of these is a refusal, and none of them is a zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unpriceable {
    /// No entry of the snapshot covers the posting's instant. A hole in the record prices at
    /// nothing only if somebody decides it does, and nobody here does.
    NoCardInForce {
        /// The instant that fell in the hole.
        at: u64,
    },
    /// The card in force does not name this currency. NEVER converted from another: there is no
    /// cross-rate in this crate and this variant is what stands where one would have gone.
    CurrencyNotPriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency that was asked for.
        currency: CurrencyCode,
    },
    /// A present card names no entry for the lane — the fail-closed rule, reached through
    /// [`price_fail_closed`].
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the card is silent about.
        lane: String,
    },
    /// The card in force names the currency but no FLAT FEE in it — the fee's half of the same
    /// fail-closed rule, reached through the same [`price_fail_closed`].
    ///
    /// PRESENT BUT UNPRICED IS NEVER A SILENT ZERO. A card that priced its rates in a second
    /// currency and was never given a fee in it would, read as a zero, bill every request's fees at
    /// nothing and report nothing — free service, invisible. Fail closed to VISIBLE instead: the
    /// read posture marks the fee line unpriced and settlement refuses here.
    FeeUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency the card names no fee in.
        currency: CurrencyCode,
    },
}

/// Apply the tier multiplier: once, over the summed pre-tier amount, with a single divide.
///
/// A sum of per-line floors is the wrong answer and undercharges: two lines of five nano-units at
/// half price are two floors of two, which is four, where the single divide over ten is five.
pub fn apply_tier(pre_tier_amount: u128, tier_bp: u32) -> u128 {
    pre_tier_amount.saturating_mul(u128::from(tier_bp)) / u128::from(STANDARD_TIER_BP)
}

/// **THE LOOKUP** — the whole of layer two, and the only place money is computed.
///
/// Resolve the card in force at the posting's instant under this snapshot, then price the
/// quantities against it in the asked-for currency. The order is fixed and is the whole of the law:
/// each quantity prices at amount times the card's integer rate; the flat fee joins as its own line
/// at the fee's minor units lifted to nano-units; those line amounts sum to the pre-tier amount; the
/// tier multiplier applies once to that sum. Nothing is truncated until a projection asks.
///
/// It reads no clock, no store and no configuration. The view is a borrowed slice, so an auditor
/// holding the postings and the history re-derives every invoice by hand.
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
    price_at_card(card_seq, card, posting, currency)
}

/// The lookup with the resolution already done — the same arithmetic, reached by a caller that
/// holds one card rather than a history.
///
/// It exists so that the arithmetic is single-sited: a caller that has pinned one card must not
/// re-derive a price out of the card's parts, because a second copy of the multiply-and-sum is how a
/// request comes to be judged at one figure and billed at another.
pub fn price_at_card(
    card_seq: HistorySeq,
    card: &RateCard,
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
        // reported unpriced — the caller decides whether that is a refusal.
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
    // multiple of one minor unit of its currency, which is why summing it in before the single
    // truncation gives the same answer as truncating the quantities first and adding the fee after.
    //
    // A card that names this currency but no FEE in it prices the fee at nothing AND SAYS SO, on
    // the line, exactly as a class the card is silent about does. Never a silent zero: a fee read
    // as zero out of a map that does not hold it is a request served for free with nothing said.
    let (fee_unit_price_nanos, fee_unpriced) = match card.fee_unit_price_nanos(currency) {
        Some(nanos) => (nanos, false),
        None => (0u128, true),
    };
    lines.push(PricedLine {
        class: FEE_CLASS.to_string(),
        quantity: posting.fee_count,
        unit_price_nanos: fee_unit_price_nanos,
        amount_nanos: u128::from(posting.fee_count).saturating_mul(fee_unit_price_nanos),
        unpriced: fee_unpriced,
    });

    let pre_tier_nanos = lines
        .iter()
        .fold(0u128, |acc, l| acc.saturating_add(l.amount_nanos));

    Ok(Priced {
        card_seq,
        currency,
        lines,
        pre_tier_nanos,
        priced_nanos: apply_tier(pre_tier_nanos, posting.tier_bp),
        lane_unpriced: rates.is_none(),
        fee_unpriced,
        tier_bp: posting.tier_bp,
        fee_count: posting.fee_count,
        estimated: posting.estimated,
    })
}

/// The settlement posture: [`price`], and anything a present card is silent about — a lane, or the
/// flat fee in the currency asked for — is a REFUSAL rather than a figure of nothing.
///
/// A policy wrapper and nothing else — it performs no arithmetic of its own and cannot disagree with
/// [`price`] about a figure, because it either returns that call's answer or returns an error. The
/// two postures exist because reads and settlement want different things from the same lookup: a
/// read reports an unpriced lane or fee per row so an operator can see it, and a settlement that
/// refuses unpriced usage fails closed rather than serving for free. Neither posture is ever a
/// SILENT nothing: the read says it on the line, and settlement says it here.
pub fn price_fail_closed(
    view: &HistoryView<'_>,
    posting: &Posting,
    currency: CurrencyCode,
) -> Result<Priced, Unpriceable> {
    let priced = price(view, posting, currency)?;
    if priced.lane_unpriced {
        return Err(Unpriceable::LaneUnpriced {
            card_seq: priced.card_seq,
            lane: posting.lane.clone(),
        });
    }
    if priced.fee_unpriced {
        return Err(Unpriceable::FeeUnpriced {
            card_seq: priced.card_seq,
            currency,
        });
    }
    Ok(priced)
}
