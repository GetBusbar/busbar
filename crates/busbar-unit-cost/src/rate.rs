// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the pin that
//! freezes a card for the life of one hold.

use std::collections::{BTreeMap, BTreeSet};

use busbar_caps::UsageLine;

/// Convert one configured rate — micro-units per unit of quantity — into the integer nano-unit
/// rate all later arithmetic uses. This is the ONLY place a decimal number turns into money.
///
/// Multiply by a thousand and round to nearest, half away from zero, exactly once. A value that is
/// not finite, or not positive, becomes zero: config validation should already have refused it, and
/// a rate of zero is the safe reading of a value nobody can price. The test that a bare cast would
/// pass is the infinite one — casting a non-finite float to an integer saturates to the largest
/// integer there is, which would be a garbage rate rather than the intended defence.
pub fn nano_rate(micro_per_unit: f64) -> u64 {
    let v = (micro_per_unit * 1000.0).round();
    if v.is_finite() && v > 0.0 {
        v as u64
    } else {
        0
    }
}

/// A price is looked up by the pair (lane, meter class): the same class costs different amounts on
/// different lanes, and a lane prices several classes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneClass {
    /// The lane the traffic was served on — the card's key for a destination.
    pub lane: String,
    /// The declared meter class the quantity belongs to.
    pub class: String,
}

impl LaneClass {
    /// Name one priced cell of the card.
    pub fn new(lane: impl Into<String>, class: impl Into<String>) -> Self {
        LaneClass {
            lane: lane.into(),
            class: class.into(),
        }
    }
}

/// Which card a posting was priced against. Captured when the hold opens and stored on the
/// posting, so a later card edit is visibly a different version rather than an invisible reprice.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RateCardVersion(String);

impl RateCardVersion {
    /// Name a version of the card.
    pub fn new(version: impl Into<String>) -> Self {
        RateCardVersion(version.into())
    }

    /// The version as the posting records it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The resolved rate card: integer nano-unit prices per (lane, class), plus the flat per-request
/// fee, plus the version that identifies it.
///
/// Pricing is all-or-nothing. With no card every class prices at zero and only the flat fee counts.
/// With a card, the card is authoritative: a lane it does not name prices at nothing AND is
/// reported as unpriced, so an unknown lane fails closed instead of quietly serving for free.
#[derive(Debug, Clone)]
pub struct RateCard {
    version: RateCardVersion,
    present: bool,
    prices: BTreeMap<LaneClass, u64>,
    lanes: BTreeSet<String>,
    per_request_fee_cents: i64,
}

impl RateCard {
    /// A card that is not there: every class prices at zero, the flat fee still posts.
    ///
    /// This is the deployment with no pricing configured at all. Nothing is "unpriced" here,
    /// because there is no card to be missing from — attribution only.
    pub fn absent(version: RateCardVersion, per_request_fee_cents: i64) -> Self {
        RateCard {
            version,
            present: false,
            prices: BTreeMap::new(),
            lanes: BTreeSet::new(),
            // A negative configured fee is clamped here, once: no request may ever bill a negative
            // amount, which would credit a budget back toward headroom.
            per_request_fee_cents: per_request_fee_cents.max(0),
        }
    }

    /// Resolve a card from configured micro-unit rates. Each rate converts to nano-units once,
    /// here, and never again.
    pub fn from_micro_rates(
        version: RateCardVersion,
        entries: impl IntoIterator<Item = (LaneClass, f64)>,
        per_request_fee_cents: i64,
    ) -> Self {
        let mut prices = BTreeMap::new();
        let mut lanes = BTreeSet::new();
        for (cell, micro) in entries {
            lanes.insert(cell.lane.clone());
            prices.insert(cell, nano_rate(micro));
        }
        RateCard {
            version,
            present: true,
            prices,
            lanes,
            per_request_fee_cents: per_request_fee_cents.max(0),
        }
    }

    /// Which card this is.
    pub fn version(&self) -> &RateCardVersion {
        &self.version
    }

    /// Whether a card is configured at all (token pricing active).
    pub fn pricing_enabled(&self) -> bool {
        self.present
    }

    /// The flat per-request fee, in cents, clamped at resolve so it is never negative.
    pub fn per_request_fee_cents(&self) -> i64 {
        self.per_request_fee_cents
    }

    /// The flat fee as the unit price of its own usage line: cents lifted to nano-units.
    pub fn fee_unit_price_nanos(&self) -> u128 {
        u128::try_from(self.per_request_fee_cents)
            .unwrap_or(0)
            .saturating_mul(crate::NANOS_PER_CENT)
    }

    /// Whether a request on this lane must be refused because a card is present and has no entry
    /// for it. With no card nothing is unpriced, because there is nothing to be missing from.
    pub fn lane_unpriced(&self, lane: &str) -> bool {
        self.present && !self.lanes.contains(lane)
    }

    /// The rates for one lane. Three outcomes, and they are the whole of the pricing posture:
    ///
    /// - no card: a zero-rate view, so every class prices at nothing;
    /// - card present and the lane is named: that lane's rates;
    /// - card present and the lane is unknown: nothing at all, so the caller fails closed.
    pub fn lane_rates<'a>(&'a self, lane: &'a str) -> Option<LaneRates<'a>> {
        if !self.present {
            return Some(LaneRates { card: None, lane });
        }
        if self.lanes.contains(lane) {
            Some(LaneRates {
                card: Some(self),
                lane,
            })
        } else {
            None
        }
    }

    /// Freeze this card for the life of one hold. The posting a pinned card prices records the
    /// pinned version, so a card edit that lands afterwards can never move it.
    pub fn pin(&self) -> PinnedCard<'_> {
        PinnedCard { card: self }
    }
}

/// One lane's view of the card. Built only by [`RateCard::lane_rates`], so the three outcomes above
/// are the only ways to reach a price.
#[derive(Debug, Clone, Copy)]
pub struct LaneRates<'a> {
    card: Option<&'a RateCard>,
    lane: &'a str,
}

impl LaneRates<'_> {
    /// The nano-unit rate for one meter class on this lane. Zero when there is no card at all, and
    /// zero for a class this lane's card entry does not name.
    pub fn nanos_per_unit(&self, class: &str) -> u64 {
        match self.card {
            None => 0,
            Some(card) => card
                .prices
                .get(&LaneClass::new(self.lane, class))
                .copied()
                .unwrap_or(0),
        }
    }

    /// Whether this class is priced by name. With no card nothing is unpriced — every class is
    /// attribution only, and flagging them all would report a deployment-wide condition per line.
    pub fn class_priced(&self, class: &str) -> bool {
        match self.card {
            None => true,
            Some(card) => card.prices.contains_key(&LaneClass::new(self.lane, class)),
        }
    }

    /// The nano-unit cost of a whole usage report at this lane's rates: one multiply-add per line.
    ///
    /// A quantity times a rate cannot overflow the wide accumulator, and the running sum saturates
    /// rather than wrapping, so an adversarially large report pins at the top instead of landing
    /// back near zero — which is to say, instead of billing as free.
    pub fn nanos(&self, lines: &[UsageLine]) -> u128 {
        lines.iter().fold(0u128, |acc, l| {
            let amount = u128::from(l.quantity)
                .saturating_mul(u128::from(self.nanos_per_unit(l.class.as_str())));
            acc.saturating_add(amount)
        })
    }
}

/// A card frozen for one hold. Everything priced through this pin records the pinned version.
#[derive(Debug, Clone, Copy)]
pub struct PinnedCard<'a> {
    card: &'a RateCard,
}

impl<'a> PinnedCard<'a> {
    /// The frozen card.
    pub fn card(&self) -> &'a RateCard {
        self.card
    }

    /// The version this pin will stamp on every posting it prices.
    pub fn version(&self) -> &'a RateCardVersion {
        &self.card.version
    }
}
