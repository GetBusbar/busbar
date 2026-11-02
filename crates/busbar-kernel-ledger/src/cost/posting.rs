// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happened, and what it costs.

use busbar_contract::caps::Usage;

use crate::cost::history::{HistorySeq, HistoryView};
use crate::cost::rate::{ClassPrice, RateCard};

/// The neutral tier multiplier, in basis points: one times the price, so no tier at all.
pub const STANDARD_TIER_BP: u32 = 10_000;

/// The meter class the flat per-request fee posts under. It is a usage line like any other, which

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
}

impl Posting {
    /// Build a posting from a usage report: the quantities, the lane and the instant.

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
        }
    }

    /// **THE FIGURE A READER MUST USE**: the lookup's, always.

    pub fn priced_nanos(&self, view: &HistoryView<'_>) -> Result<u128, Unpriceable> {
        price(view, self).map(|p| p.priced_nanos)
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

/// What a lookup answered: the quantities of one posting against one card.
///
/// Derived, never stored as truth. Two lookups over the same posting against the same snapshot are
/// the same answer forever, which is what makes an invoice reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priced {
    /// The history entry the instant resolved to.
    pub card_seq: HistorySeq,
    /// Every priced line, in the order the posting carried them, with the fee line last.
    pub lines: Vec<PricedLine>,
    /// The sum over every line, including the fee line, in nano-units, before the tier.
    pub pre_tier_nanos: u128,
    /// The pre-tier amount through the tier multiplier: what the posting actually charges.
    pub priced_nanos: u128,
    /// Whether the lane itself was absent from a present card. Every token line prices at nothing
    /// when this is set, and the caller decides whether that is a refusal — see [`price_fail_closed`].
    pub lane_unpriced: bool,
    /// The tier multiplier in basis points that produced the priced amount.
    pub tier_bp: u32,
    /// How many flat fees the posting carried.
    pub fee_count: u64,
    /// Whether the quantities were the kernel's own floor.
    pub estimated: bool,
}

impl Priced {
    /// Every class the card was present for but silent about. The flat fee is never among them:

    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class.as_str())
            .collect()
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
    /// A present card names no entry for the lane — the fail-closed rule, reached through
    /// [`price_fail_closed`].
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the card is silent about.
        lane: String,
    },
    /// A present card names the lane but not a class the posting HIT — the fail-closed rule for a
    /// class (#42: *"a hit class not priced ⇒ REFUSE"*), reached through [`price_fail_closed`].
    ClassUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the class was reported on.
        lane: String,
        /// The class the card is silent about.
        class: String,
    },
    /// The priced figure does not fit the arithmetic. A REFUSAL, never a figure pinned at the
    /// ceiling (item 28): the one function is checked, and so is every reader of it.
    Overflow,
}

/// **THE TIER ARITHMETIC — the one implementation in the tree.**

pub fn checked_apply_tier(pre_tier_amount: u128, tier_bp: u32) -> Option<u128> {
    let n = u128::from(STANDARD_TIER_BP);
    let bp = u128::from(tier_bp);

    let (q, r) = (pre_tier_amount / n, pre_tier_amount % n);
    let tail = r * bp;
    let whole = q.checked_mul(bp)?.checked_add(tail / n)?;
    let remainder = tail % n;

    let round_up = match (remainder * 2).cmp(&n) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,

        std::cmp::Ordering::Equal => whole % 2 == 1,
    };
    if round_up {
        whole.checked_add(1)
    } else {
        Some(whole)
    }
}

/// **THE LOOKUP** — the whole of layer two, and the only place money is computed.

pub fn price(view: &HistoryView<'_>, posting: &Posting) -> Result<Priced, Unpriceable> {
    let (card_seq, card) = view
        .card_at(posting.arrived_ms)
        .ok_or(Unpriceable::NoCardInForce {
            at: posting.arrived_ms,
        })?;
    price_at_card(card_seq, card, posting)
}

/// The lookup with the resolution already done — the same arithmetic, reached by a caller that

pub fn price_at_card(
    card_seq: HistorySeq,
    card: &RateCard,
    posting: &Posting,
) -> Result<Priced, Unpriceable> {
    let pricing = card.lane_pricing(&posting.lane);
    let mut lines: Vec<PricedLine> = Vec::with_capacity(posting.quantities.len() + 1);

    for quantity in &posting.quantities {
        let class = quantity.class.as_str();

        let (unit_price_nanos, priced) = match pricing.class_price(class) {
            ClassPrice::FeeMinor(fee_minor) => (
                u128::try_from(fee_minor)
                    .unwrap_or(0)
                    .saturating_mul(crate::cost::NANOS_PER_CENT),
                true,
            ),
            ClassPrice::Nanos(nanos) => (u128::from(nanos), true),
            ClassPrice::Unpriced => (0u128, false),
        };
        let amount_nanos = u128::from(quantity.amount)
            .checked_mul(unit_price_nanos)
            .ok_or(Unpriceable::Overflow)?;
        lines.push(PricedLine {
            class: class.to_string(),
            quantity: quantity.amount,
            unit_price_nanos,
            amount_nanos,
            unpriced: !priced,
        });
    }

    let fee_unit_price_nanos = pricing.card.fee_unit_price_nanos();
    lines.push(PricedLine {
        class: FEE_CLASS.to_string(),
        quantity: posting.fee_count,
        unit_price_nanos: fee_unit_price_nanos,
        amount_nanos: u128::from(posting.fee_count).saturating_mul(fee_unit_price_nanos),
        unpriced: false,
    });

    let mut tally = crate::cost::Tally::at_card_seq(card_seq, card);
    let tallied = if pricing.lane_named() {
        tally.row(
            &posting.lane,
            posting.arrived_ms,
            posting.tier_bp,
            lines
                .iter()
                .take(posting.quantities.len())
                .filter(|l| !l.unpriced)
                .map(|l| (l.class.as_str(), crate::cost::whole(l.quantity))),
            crate::cost::whole(posting.fee_count),
        )
    } else {
        tally.lane_fee(
            &posting.lane,
            posting.arrived_ms,
            posting.tier_bp,
            crate::cost::whole(posting.fee_count),
        )
    };
    let figures = tallied.and_then(|()| {
        let pre = crate::cost::nanos_of_exact(tally.pre_tier_exact()?)?;
        let priced = crate::cost::nanos_of_exact(tally.exact()?)?;
        Ok((pre, priced))
    });
    let (pre_tier_nanos, priced_nanos) = figures.map_err(|_| Unpriceable::Overflow)?;

    Ok(Priced {
        card_seq,
        lines,
        pre_tier_nanos,
        priced_nanos,
        lane_unpriced: !pricing.lane_named(),
        tier_bp: posting.tier_bp,
        fee_count: posting.fee_count,
        estimated: posting.estimated,
    })
}

/// The settlement posture: [`price`], and a lane a present card is silent about is a REFUSAL rather

pub fn price_fail_closed(view: &HistoryView<'_>, posting: &Posting) -> Result<Priced, Unpriceable> {
    let priced = price(view, posting)?;
    if priced.lane_unpriced {
        return Err(Unpriceable::LaneUnpriced {
            card_seq: priced.card_seq,
            lane: posting.lane.clone(),
        });
    }

    if let Some(line) = priced.lines.iter().find(|l| l.unpriced) {
        return Err(Unpriceable::ClassUnpriced {
            card_seq: priced.card_seq,
            lane: posting.lane.clone(),
            class: line.class.clone(),
        });
    }
    Ok(priced)
}
