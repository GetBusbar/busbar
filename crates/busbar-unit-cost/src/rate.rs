// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the pin that
//! freezes a card for the life of one hold.

use std::collections::BTreeMap;

use busbar_caps::UsageLine;

/// Convert one configured rate — micro-units per unit of quantity — into the integer nano-unit
/// rate all later arithmetic uses.
///
/// THE ONLY DECIMAL-TO-MONEY CONVERSION IN THE TREE, now. It used to be one of two: the admission
/// unit carried a second copy of the same three lines in its own rate projection, because that crate
/// named nothing here and could not call across. Two copies of a rounding rule that must agree
/// exactly is how a request comes to be JUDGED at one rate by the door and BILLED at another by the
/// ledger — silently, with no error and no refusal, just a bill that does not match the decision
/// that produced it. They did drift, the day a clamp landed on one of them and not the other.
///
/// So the admission unit calls this instead, and the clamp, the rounding rule and the multiply move
/// the decision and the bill together by construction. The agreement test over ten thousand
/// generated rates and every boundary value stays where it was: it is now a guard against the second
/// copy coming back rather than a check that two copies match.
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

/// The uncached-input meter class, as a card entry is keyed.
pub const CLASS_INPUT: &str = "input";
/// The response meter class.
pub const CLASS_OUTPUT: &str = "output";
/// The cache-read meter class — a prompt read back from cache, priced apart from uncached input.
pub const CLASS_CACHE_READ: &str = "cache_read";
/// The cache-write (cache creation) meter class.
pub const CLASS_CACHE_WRITE: &str = "cache_write";

/// ONE LANE'S CONFIGURED RATES, in micro-units per unit of quantity — the neutral raw-value view a
/// card is built from.
///
/// A small record of the section's raw scalars in a canonical order, and deliberately nothing more:
/// the deployment's config GRAMMAR — the field spellings, the validation, which section they live in
/// — belongs to whoever parses it, and only these four numbers cross into the crate that prices
/// them. That is what lets this crate own card construction without owning a config parser, and it
/// is why its dependency closure is still the capability crate and nothing else.
///
/// FLOATS LIVE ONLY HERE. [`RateCard::from_config`] converts each one to an integer nano-unit rate
/// exactly once, and no decimal touches money after that.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TierRates {
    /// Micro-units per uncached input unit.
    pub input: f64,
    /// Micro-units per response unit.
    pub output: f64,
    /// Micro-units per cache-read unit.
    pub cache_read: f64,
    /// Micro-units per cache-write unit.
    pub cache_write: f64,
}

impl TierRates {
    /// The four rates paired with the class each one prices, in the canonical order.
    fn by_class(self) -> [(&'static str, f64); 4] {
        [
            (CLASS_INPUT, self.input),
            (CLASS_OUTPUT, self.output),
            (CLASS_CACHE_READ, self.cache_read),
            (CLASS_CACHE_WRITE, self.cache_write),
        ]
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
///
/// The prices are keyed lane-first and then class, rather than by a composite of the two. That is a
/// lookup shape, not a storage preference: a composite key has to be BUILT before it can be looked
/// up, and building one out of two borrowed strings means two heap allocations per lookup, thrown
/// away immediately, on the hot path of every priced line. Nested, both steps are asked with the
/// borrowed text the caller already holds and neither allocates. The nesting also removes the need
/// to carry the set of priced lanes alongside the prices: the lanes ARE the outer keys, so the two
/// can no longer disagree about which lanes the card names.
#[derive(Debug, Clone)]
pub struct RateCard {
    version: RateCardVersion,
    present: bool,
    prices: BTreeMap<String, BTreeMap<String, u64>>,
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
        let mut prices: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for (cell, micro) in entries {
            prices
                .entry(cell.lane)
                .or_default()
                .insert(cell.class, nano_rate(micro));
        }
        RateCard {
            version,
            present: true,
            prices,
            per_request_fee_cents: per_request_fee_cents.max(0),
        }
    }

    /// **THE CARD A DEPLOYMENT CONFIGURED**, built here and nowhere else.
    ///
    /// The two configured figures a card is made of — the per-lane tier rates and the flat
    /// per-request fee — are read by their owner and handed straight over; what is DONE with them is
    /// this crate's, because a fee or a rate turned into a card outside the crate that owns the card
    /// is a price derived where nobody can see it. So the class fan-out, the absent/present branch
    /// and the fee's clamp all live on this one constructor, and the composition root's binding is a
    /// relay with no arithmetic in it.
    ///
    /// `lanes` is `None` for a deployment that configured no rate card at all. That is an ABSENT
    /// card rather than no card: every class prices at nothing and the flat fee still posts, which is
    /// exactly what such a deployment is billed. Building nothing instead would post nothing for a
    /// node that charges a fee.
    ///
    /// THE CLASS NAMES ARE THIS CRATE'S. A card entry is keyed by the neutral reserved-unit spelling
    /// ([`CLASS_INPUT`] and its three siblings), and the usage report priced against it carries the
    /// same spellings, so no name is translated between the line and the entry that prices it. The
    /// two agreeing is not left to inspection: a card keyed by names a report does not use prices
    /// every line at zero, which the ledger identity reads as a node that delivered value for free.
    pub fn from_config<'a>(
        version: RateCardVersion,
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee_cents: i64,
    ) -> Self {
        let Some(lanes) = lanes else {
            return RateCard::absent(version, per_request_fee_cents);
        };
        let entries = lanes.into_iter().flat_map(|(lane, tiers)| {
            tiers
                .by_class()
                .into_iter()
                .map(move |(class, micro)| (LaneClass::new(lane, class), micro))
        });
        RateCard::from_micro_rates(version, entries, per_request_fee_cents)
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
        self.present && !self.prices.contains_key(lane)
    }

    /// The rates for one lane. Three outcomes, and they are the whole of the pricing posture:
    ///
    /// - no card: a zero-rate view, so every class prices at nothing;
    /// - card present and the lane is named: that lane's rates;
    /// - card present and the lane is unknown: nothing at all, so the caller fails closed.
    pub fn lane_rates(&self, lane: &str) -> Option<LaneRates<'_>> {
        if !self.present {
            return Some(LaneRates { classes: None });
        }
        self.prices.get(lane).map(|classes| LaneRates {
            classes: Some(classes),
        })
    }

    /// Freeze this card for the life of one hold. The posting a pinned card prices records the
    /// pinned version, so a card edit that lands afterwards can never move it.
    pub fn pin(&self) -> PinnedCard<'_> {
        PinnedCard { card: self }
    }
}

/// One lane's view of the card. Built only by [`RateCard::lane_rates`], so the three outcomes above
/// are the only ways to reach a price.
///
/// The lane lookup has already happened by the time this exists: the view borrows that lane's class
/// table directly, so pricing a report is one map lookup per line and no allocation at all. `None`
/// is the no-card deployment, where every class prices at zero and none of them is unpriced.
#[derive(Debug, Clone, Copy)]
pub struct LaneRates<'a> {
    classes: Option<&'a BTreeMap<String, u64>>,
}

impl LaneRates<'_> {
    /// The nano-unit rate for one meter class on this lane. Zero when there is no card at all, and
    /// zero for a class this lane's card entry does not name.
    pub fn nanos_per_unit(&self, class: &str) -> u64 {
        match self.classes {
            None => 0,
            Some(classes) => classes.get(class).copied().unwrap_or(0),
        }
    }

    /// Whether this class is priced by name. With no card nothing is unpriced — every class is
    /// attribution only, and flagging them all would report a deployment-wide condition per line.
    pub fn class_priced(&self, class: &str) -> bool {
        match self.classes {
            None => true,
            Some(classes) => classes.contains_key(class),
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
