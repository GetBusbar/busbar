// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the nested
//! lookup that turns a lane, a class and a currency into that integer with no allocation.

use std::collections::{BTreeMap, BTreeSet};

use busbar_caps::UsageLine;

use crate::currency::CurrencyCode;

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
/// not finite, not positive, or too large for a `u64` to hold becomes zero: config validation should
/// already have refused it, and a rate of zero is the safe reading of a value nobody can price. The
/// test that a bare cast would pass is the infinite one and the finite-but-overflowing one alike —
/// casting a float outside the target range to an integer SATURATES to the largest integer there is,
/// which would be a garbage rate (an astronomical overcharge) rather than the intended defence,
/// whether the float that produced it was infinite or merely a config typo with too many zeros.
///
/// The conversion is per currency and it is the SAME conversion for every currency: a rate is a
/// count of micro-units of the currency it is configured in, so nothing about the scale depends on
/// which currency that is. Where a currency does enter is the projection at the far end
/// ([`CurrencyCode::nanos_per_minor`]), and that is the only place it enters.
pub fn nano_rate(micro_per_unit: f64) -> u64 {
    let v = (micro_per_unit * 1000.0).round();
    if v.is_finite() && v > 0.0 && v <= u64::MAX as f64 {
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
///
/// Four token classes is what a 1.5.5 config can express, so this stays ONE CONSTRUCTOR for a card
/// rather than the card's shape: the card itself is keyed by class NAME, so audio seconds, bytes and
/// any future class price through it with no type change at all.
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

/// One (lane, class) cell of a card, priced in every currency the card names.
///
/// NO PIVOT. Each currency's rate is a first-class configured integer, never a conversion of
/// another one. A cell that names USD and JPY holds two configured numbers, and asking it for yen
/// reads the yen number: there is no dollar figure on the path and therefore no cross-rate to be
/// stale, no rounding of a conversion, and no answer that depends on when the FX table was last
/// refreshed. A currency the cell does not name has no price here at all, which the lookup reports
/// rather than fills in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CellPrices(BTreeMap<CurrencyCode, u64>);

impl CellPrices {
    /// The nano-unit rate in one currency, if this cell names it.
    pub fn nanos_per_unit(&self, currency: CurrencyCode) -> Option<u64> {
        self.0.get(&currency).copied()
    }

    /// Every currency this cell prices, in code order.
    pub fn currencies(&self) -> impl Iterator<Item = CurrencyCode> + '_ {
        self.0.keys().copied()
    }
}

/// The resolved rate card: integer nano-unit prices per (lane, class, currency), plus the flat
/// per-request fee in each currency's minor units.
///
/// Pricing is all-or-nothing. With no card every class prices at zero and only the flat fee counts.
/// With a card, the card is authoritative: a lane it does not name prices at nothing AND is
/// reported as unpriced, so an unknown lane fails closed instead of quietly serving for free.
///
/// The prices are keyed lane-first, then class, then currency, rather than by a composite of the
/// three. That is a lookup shape, not a storage preference: a composite key has to be BUILT before
/// it can be looked up, and building one out of borrowed strings means heap allocations per lookup,
/// thrown away immediately, on the hot path of every priced line. Nested, every step is asked with
/// the borrowed text the caller already holds and the currency it already has by value, and none of
/// them allocates. The nesting also removes the need to carry the set of priced lanes alongside the
/// prices: the lanes ARE the outer keys, so the two can no longer disagree about which lanes the
/// card names.
///
/// A card carries no version of its own. Which card a posting was priced against is the position of
/// the card's ENTRY in the history ([`crate::HistorySeq`]), because a card that could be identified
/// independently of when it was in force is a card that can be pointed at without saying when it
/// applied — which is the thing the dated history exists to stop.
#[derive(Debug, Clone)]
pub struct RateCard {
    present: bool,
    prices: BTreeMap<String, BTreeMap<String, CellPrices>>,
    fees: BTreeMap<CurrencyCode, i64>,
    currencies: BTreeSet<CurrencyCode>,
}

impl RateCard {
    /// A card that is not there: every class prices at zero, the flat fee still posts.
    ///
    /// This is the deployment with no pricing configured at all. Nothing is "unpriced" here,
    /// because there is no card to be missing from — attribution only. The currencies such a card
    /// names are exactly the currencies its fee is quoted in, so a read in a currency it never heard
    /// of is still a refusal rather than a zero.
    pub fn absent(fees: impl IntoIterator<Item = (CurrencyCode, i64)>) -> Self {
        let fees = clamp_fees(fees);
        RateCard {
            present: false,
            prices: BTreeMap::new(),
            currencies: fees.keys().copied().collect(),
            fees,
        }
    }

    /// Resolve a card from configured micro-unit rates, each tagged with the currency it is quoted
    /// in. Each rate converts to nano-units once, here, and never again.
    pub fn from_micro_rates(
        entries: impl IntoIterator<Item = (LaneClass, CurrencyCode, f64)>,
        fees: impl IntoIterator<Item = (CurrencyCode, i64)>,
    ) -> Self {
        let mut prices: BTreeMap<String, BTreeMap<String, CellPrices>> = BTreeMap::new();
        let mut currencies = BTreeSet::new();
        for (cell, currency, micro) in entries {
            currencies.insert(currency);
            prices
                .entry(cell.lane)
                .or_default()
                .entry(cell.class)
                .or_default()
                .0
                .insert(currency, nano_rate(micro));
        }
        let fees = clamp_fees(fees);
        currencies.extend(fees.keys().copied());
        RateCard {
            present: true,
            prices,
            fees,
            currencies,
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
    ///
    /// **A 1.5.5 CONFIG IS A ONE-CURRENCY CARD.** The older release's figures are abstract cost
    /// units with no currency, displayed as `"USD"`, so this constructor builds a card naming
    /// exactly [`CurrencyCode::USD`] — whose minor exponent is 2, whose
    /// [`CurrencyCode::nanos_per_minor`] is therefore [`crate::NANOS_PER_CENT`] exactly, and whose
    /// every projected figure is bit-identical to the one that deployment reads today. That is the
    /// whole of the currency migration.
    pub fn from_config<'a>(
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee: i64,
    ) -> Self {
        let fees = [(CurrencyCode::USD, per_request_fee)];
        let Some(lanes) = lanes else {
            return RateCard::absent(fees);
        };
        let entries = lanes.into_iter().flat_map(|(lane, tiers)| {
            tiers
                .by_class()
                .into_iter()
                .map(move |(class, micro)| (LaneClass::new(lane, class), CurrencyCode::USD, micro))
        });
        RateCard::from_micro_rates(entries, fees)
    }

    /// Whether a card is configured at all (token pricing active).
    pub fn pricing_enabled(&self) -> bool {
        self.present
    }

    /// Exactly the currencies this card prices in, in code order.
    ///
    /// A card must name the same currency set in every priced cell — a cell that priced dollars and
    /// a cell that priced yen would make the answer to "what did this cost in yen" depend on which
    /// classes the traffic happened to use. Whoever validates a config enforces that; this crate
    /// reports the union, and the lookup refuses per cell for anything the cell is silent about.
    pub fn currencies(&self) -> impl Iterator<Item = CurrencyCode> + '_ {
        self.currencies.iter().copied()
    }

    /// Whether this card quotes anything at all in one currency.
    pub fn prices_currency(&self, currency: CurrencyCode) -> bool {
        self.currencies.contains(&currency)
    }

    /// The flat per-request fee in one currency's MINOR units, clamped at build so it is never
    /// negative. Zero for a currency the card does not quote a fee in.
    ///
    /// ONE SPELLING OF THE FEE. Config calls it `per_request_fee`; this crate used to call it
    /// `per_request_fee_cents` and the admission unit called it `price_per_request_cents`, which is
    /// three names for one number and two of them assert a currency that a card in yen does not
    /// have. It is a fee, it is in the currency's minor unit, and it is called the fee.
    pub fn fee_minor(&self, currency: CurrencyCode) -> i64 {
        self.fees.get(&currency).copied().unwrap_or(0)
    }

    /// The flat fee as the unit price of its own usage line: minor units lifted to nano-units.
    ///
    /// The lift is an exact multiple of one minor unit, which is the property that makes the
    /// projection exact — summing the fee in before the single truncation gives the same answer as
    /// truncating the usage first and adding the fee afterwards.
    pub fn fee_unit_price_nanos(&self, currency: CurrencyCode) -> u128 {
        u128::try_from(self.fee_minor(currency))
            .unwrap_or(0)
            .saturating_mul(currency.nanos_per_minor())
    }

    /// Whether a request on this lane must be refused because a card is present and has no entry
    /// for it. With no card nothing is unpriced, because there is nothing to be missing from.
    pub fn lane_unpriced(&self, lane: &str) -> bool {
        self.present && !self.prices.contains_key(lane)
    }

    /// The rates for one lane in one currency. Three outcomes, and they are the whole of the pricing
    /// posture:
    ///
    /// - no card: a zero-rate view, so every class prices at nothing;
    /// - card present and the lane is named: that lane's rates, read in the asked-for currency;
    /// - card present and the lane is unknown: nothing at all, so the caller fails closed.
    ///
    /// The currency is carried INTO the view rather than asked for at each class, so a single line's
    /// price cannot be read in one currency and the next line's in another.
    pub fn lane_rates(&self, lane: &str, currency: CurrencyCode) -> Option<LaneRates<'_>> {
        if !self.present {
            return Some(LaneRates {
                classes: None,
                currency,
            });
        }
        self.prices.get(lane).map(|classes| LaneRates {
            classes: Some(classes),
            currency,
        })
    }
}

/// Clamp every configured fee once, here: no request may ever bill a negative amount, which would
/// credit a budget back toward headroom.
fn clamp_fees(fees: impl IntoIterator<Item = (CurrencyCode, i64)>) -> BTreeMap<CurrencyCode, i64> {
    fees.into_iter()
        .map(|(currency, minor)| (currency, minor.max(0)))
        .collect()
}

/// One lane's view of the card, in one currency. Built only by [`RateCard::lane_rates`], so the
/// three outcomes above are the only ways to reach a price.
///
/// The lane lookup has already happened by the time this exists: the view borrows that lane's class
/// table directly, so pricing a report is one map lookup per line — plus one lookup inside the cell
/// for the currency, over a `Copy` three-byte key — and no allocation at all. `None` is the no-card
/// deployment, where every class prices at zero and none of them is unpriced.
#[derive(Debug, Clone, Copy)]
pub struct LaneRates<'a> {
    classes: Option<&'a BTreeMap<String, CellPrices>>,
    currency: CurrencyCode,
}

impl LaneRates<'_> {
    /// The currency every rate this view returns is quoted in.
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }

    /// The nano-unit rate for one meter class on this lane, in this view's currency. Zero when
    /// there is no card at all, and zero for a class this lane's card entry does not name — or names
    /// only in some other currency.
    pub fn nanos_per_unit(&self, class: &str) -> u64 {
        match self.classes {
            None => 0,
            Some(classes) => classes
                .get(class)
                .and_then(|cell| cell.nanos_per_unit(self.currency))
                .unwrap_or(0),
        }
    }

    /// Whether this class is priced by name IN THIS CURRENCY. With no card nothing is unpriced —
    /// every class is attribution only, and flagging them all would report a deployment-wide
    /// condition per line.
    pub fn class_priced(&self, class: &str) -> bool {
        match self.classes {
            None => true,
            Some(classes) => classes
                .get(class)
                .is_some_and(|cell| cell.nanos_per_unit(self.currency).is_some()),
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
