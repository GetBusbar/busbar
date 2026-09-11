// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the cell that
//! holds one price per currency, natively.

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
/// THE CURRENCY DOES NOT ENTER HERE, and that is the design. A rate is quoted per currency and each
/// quotation is a configured decimal of its own; this function turns one decimal into one integer
/// and knows nothing about which currency it belongs to. A currency-dependent conversion here would
/// be a cross-rate by another name.
///
/// Multiply by a thousand and round to nearest, half away from zero, exactly once. A value that is
/// not finite, not positive, or too large for a `u64` to hold becomes zero: config validation should
/// already have refused it, and a rate of zero is the safe reading of a value nobody can price. The
/// test that a bare cast would pass is the infinite one and the finite-but-overflowing one alike —
/// casting a float outside the target range to an integer SATURATES to the largest integer there is,
/// which would be a garbage rate (an astronomical overcharge) rather than the intended defence,
/// whether the float that produced it was infinite or merely a config typo with too many zeros.
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

/// **THE RESERVED FOUR, IN CANONICAL ORDER** — the one order this crate folds them in.
///
/// It is the order a card's class fan-out writes ([`TierRates::by_class`] reads it) and the order
/// the map-shaped summation adds in ([`LaneRates::reserved_units_nanos`]), so the four names and
/// their sequence exist once rather than once per reader. A sum is commutative and the order does
/// not change the total; what a second list would change is WHICH FOUR are summed, and a
/// constructor fanning out one set of names against a summation folding another prices every line
/// of the difference at zero — which the ledger identity reads as value delivered for free.
pub const RESERVED_CLASSES: [&str; 4] = [
    CLASS_INPUT,
    CLASS_OUTPUT,
    CLASS_CACHE_READ,
    CLASS_CACHE_WRITE,
];

/// ONE LANE'S CONFIGURED RATES, in micro-units per unit of quantity — the neutral raw-value view a
/// card is built from.
///
/// A small record of the section's raw scalars in a canonical order, and deliberately nothing more:
/// the deployment's config GRAMMAR — the field spellings, the validation, which section they live in
/// — belongs to whoever parses it, and only these four numbers cross into the crate that prices
/// them. That is what lets this crate own card construction without owning a config parser, and it
/// is why its dependency closure is still the capability crate and nothing else.
///
/// It is ONE CONSTRUCTOR FOR A CARD RATHER THAN THE CARD'S SHAPE. It can only express the four
/// token classes a 1.5.5 deployment configures, and a card's class map is string-keyed, so audio
/// seconds, bytes and any future class price through the same card with no type change.
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
    /// The four rates paired with the class each one prices, in [`RESERVED_CLASSES`] order — read
    /// off that one list rather than restating it, so the names a card is BUILT with and the names
    /// a usage map is PRICED against cannot come apart.
    fn by_class(self) -> [(&'static str, f64); 4] {
        let micro = [self.input, self.output, self.cache_read, self.cache_write];
        std::array::from_fn(|i| (RESERVED_CLASSES[i], micro[i]))
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
/// another. A card that priced one currency and derived the rest would have to hold an exchange rate
/// somewhere, and an exchange rate is a number that changes without anybody editing the card — which
/// is the exact hazard the dated history exists to remove.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CellPrices(BTreeMap<CurrencyCode, u64>);

impl CellPrices {
    /// A cell priced in one currency.
    pub fn single(currency: CurrencyCode, nanos_per_unit: u64) -> Self {
        let mut prices = BTreeMap::new();
        prices.insert(currency, nanos_per_unit);
        CellPrices(prices)
    }

    /// Add or replace one currency's rate.
    pub fn set(&mut self, currency: CurrencyCode, nanos_per_unit: u64) {
        self.0.insert(currency, nanos_per_unit);
    }

    /// This cell's rate in one currency, if the cell names it. `None` is NOT zero and must never be
    /// read as zero: it is a currency this cell was never priced in, and the answer is a refusal.
    pub fn nanos_per_unit(&self, currency: CurrencyCode) -> Option<u64> {
        self.0.get(&currency).copied()
    }

    /// Every currency this cell names.
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
/// The prices are keyed lane-first, then class, then currency, rather than by a composite. That is a
/// lookup shape, not a storage preference: a composite key has to be BUILT before it can be looked
/// up, and building one out of two borrowed strings means two heap allocations per lookup, thrown
/// away immediately, on the hot path of every priced line. Nested, every step is asked with the
/// borrowed text — or, for the currency, the three-byte `Copy` code — the caller already holds, and
/// none of them allocates. The nesting also removes the need to carry the set of priced lanes
/// alongside the prices: the lanes ARE the outer keys, so the two can no longer disagree about which
/// lanes the card names.
///
/// A card has no version field. Which card this is, is the number of the history entry that holds
/// it, and that number belongs to the history rather than to the card — a card carrying its own name
/// is a second identity that can disagree with the first.
#[derive(Debug, Clone)]
pub struct RateCard {
    present: bool,
    prices: BTreeMap<String, BTreeMap<String, CellPrices>>,
    terms: BTreeMap<CurrencyCode, busbar_contract::tariff::FeeTerms>,
    currencies: BTreeSet<CurrencyCode>,
}

impl RateCard {
    /// A card that is not there: every class prices at zero, the flat fee still posts.
    ///
    /// This is the deployment with no pricing configured at all. Nothing is "unpriced" here,
    /// because there is no card to be missing from — attribution only. The fee is in the given
    /// currency's minor units, and that currency is the one currency such a card names.
    pub fn absent_in(currency: CurrencyCode, terms: busbar_contract::tariff::FeeTerms) -> Self {
        RateCard {
            present: false,
            prices: BTreeMap::new(),
            terms: BTreeMap::from([(currency, terms)]),
            currencies: BTreeSet::from([currency]),
        }
    }

    /// A card that is not there, priced in the currency a 1.5.5 deployment's figures are in.
    ///
    /// The one-currency spelling exists because a 1.5.5 card has no currency at all and the
    /// migration reads it as a card naming exactly [`CurrencyCode::USD`], whose minor unit is the
    /// cent every 1.5.5 figure was already projected through.
    pub fn absent(per_request_fee: i64) -> Self {
        RateCard::absent_in(
            CurrencyCode::USD,
            busbar_contract::tariff::FeeTerms::flat(per_request_fee),
        )
    }

    /// Resolve a card from configured micro-unit rates in ONE currency. Each rate converts to
    /// nano-units once, here, and never again.
    pub fn from_micro_rates_in(
        currency: CurrencyCode,
        entries: impl IntoIterator<Item = (LaneClass, f64)>,
        terms: busbar_contract::tariff::FeeTerms,
    ) -> Self {
        let mut prices: BTreeMap<String, BTreeMap<String, CellPrices>> = BTreeMap::new();
        for (cell, micro) in entries {
            prices
                .entry(cell.lane)
                .or_default()
                .entry(cell.class)
                .or_default()
                .set(currency, nano_rate(micro));
        }
        RateCard {
            present: true,
            prices,
            terms: BTreeMap::from([(currency, terms)]),
            currencies: BTreeSet::from([currency]),
        }
    }

    /// The one-currency spelling, in the currency a 1.5.5 deployment's figures are in.
    pub fn from_micro_rates(
        entries: impl IntoIterator<Item = (LaneClass, f64)>,
        per_request_fee: i64,
    ) -> Self {
        RateCard::from_micro_rates_in(
            CurrencyCode::USD,
            entries,
            busbar_contract::tariff::FeeTerms::flat(per_request_fee),
        )
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
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee: i64,
    ) -> Self {
        RateCard::from_config_in(
            CurrencyCode::USD,
            lanes,
            busbar_contract::tariff::FeeTerms::flat(per_request_fee),
        )
    }

    /// [`RateCard::from_config`], in a named currency.
    ///
    /// The currency-carrying spelling is the real one and [`RateCard::from_config`] is it at
    /// [`CurrencyCode::USD`] — the currency a 1.5.5 deployment's uncurrencied figures are read as.
    /// The composition root calls THIS one, with the currency its node declares, so that the card is
    /// built in the same currency the lookup will be asked for. A card built in one currency and
    /// read in another is not a conversion and must never become one: it is
    /// [`crate::Unpriceable::CurrencyNotPriced`], and the point of naming the currency at the
    /// constructor is that the mismatch is impossible rather than merely refused.
    pub fn from_config_in<'a>(
        currency: CurrencyCode,
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        terms: busbar_contract::tariff::FeeTerms,
    ) -> Self {
        let Some(lanes) = lanes else {
            return RateCard::absent_in(currency, terms);
        };
        let entries = lanes.into_iter().flat_map(|(lane, tiers)| {
            tiers
                .by_class()
                .into_iter()
                .map(move |(class, micro)| (LaneClass::new(lane, class), micro))
        });
        RateCard::from_micro_rates_in(currency, entries, terms)
    }

    /// Add one currency's rate to one cell, and record the currency on the card.
    ///
    /// This is how a multi-currency card is built: each currency's number is configured and set,
    /// never derived. There is no arm here that reads another currency's rate.
    pub fn set_rate(&mut self, cell: LaneClass, currency: CurrencyCode, micro_per_unit: f64) {
        self.present = true;
        self.currencies.insert(currency);
        self.prices
            .entry(cell.lane)
            .or_default()
            .entry(cell.class)
            .or_default()
            .set(currency, nano_rate(micro_per_unit));
    }

    /// Set one currency's whole fee terms — the amounts half of the deployment's tariff.
    pub fn set_terms(&mut self, currency: CurrencyCode, terms: busbar_contract::tariff::FeeTerms) {
        self.currencies.insert(currency);
        self.terms.insert(currency, terms);
    }

    /// Whether a card is configured at all (token pricing active).
    pub fn pricing_enabled(&self) -> bool {
        self.present
    }

    /// Every currency this card names, in code order.
    pub fn currencies(&self) -> impl Iterator<Item = CurrencyCode> + '_ {
        self.currencies.iter().copied()
    }

    /// Whether this card prices in a currency at all.
    ///
    /// A currency it does not name is a REFUSAL, not a conversion and not a zero. There is nothing
    /// in this crate that could turn one currency into another, and this predicate is what says so
    /// at the boundary.
    pub fn prices_currency(&self, currency: CurrencyCode) -> bool {
        self.currencies.contains(&currency)
    }

    /// **THE FEE TERMS THIS CARD CARRIES**, in one currency: what one visit, one transaction
    /// and one unit of each named dimension cost, with the floor, the cap and the rounding the
    /// deployment declared.
    ///
    /// `None` is a currency this card names no terms in, and it is NOT terms of zeroes: a
    /// caller that reaches it charges nothing for the counts and says so, rather than inventing a
    /// free tariff for a currency nobody priced. Every amount on the returned schedule is in that
    /// currency's MINOR units; the lift to nano-units happens once, at the pricing site.
    pub fn fee_terms(&self, currency: CurrencyCode) -> Option<&busbar_contract::tariff::FeeTerms> {
        self.terms.get(&currency)
    }

    /// Whether a request on this lane must be refused because a card is present and has no entry
    /// for it. With no card nothing is unpriced, because there is nothing to be missing from.
    pub fn lane_unpriced(&self, lane: &str) -> bool {
        self.present && !self.prices.contains_key(lane)
    }

    /// The rates for one lane, in one currency. Three outcomes, and they are the whole of the
    /// pricing posture:
    ///
    /// - no card: a zero-rate view, so every class prices at nothing;
    /// - card present and the lane is named: that lane's rates, read in the asked-for currency;
    /// - card present and the lane is unknown: nothing at all, so the caller fails closed.
    ///
    /// The currency is carried into the view rather than resolved here, so the lane step is one map
    /// lookup and the currency step happens per line inside the cell that was going to be read
    /// anyway.
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

/// One lane's view of the card, in one currency. Built only by [`RateCard::lane_rates`], so the
/// three outcomes above are the only ways to reach a price.
///
/// The lane lookup has already happened by the time this exists: the view borrows that lane's class
/// table directly, so pricing a report is one map lookup per line — plus the cell's currency step,
/// which is a lookup on a three-byte `Copy` key — and no allocation at all. `None` is the no-card
/// deployment, where every class prices at zero and none of them is unpriced.
#[derive(Debug, Clone, Copy)]
pub struct LaneRates<'a> {
    classes: Option<&'a BTreeMap<String, CellPrices>>,
    currency: CurrencyCode,
}

impl LaneRates<'_> {
    /// The currency this view reads.
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }

    /// The nano-unit rate for one meter class on this lane. Zero when there is no card at all, zero
    /// for a class this lane's card entry does not name, and zero for a class that is named but
    /// carries no rate in THIS currency — the last of which is reported separately, because a
    /// currency the cell is silent about is a refusal at the card level and never a free line.
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

    /// **THE SAME COST, OFF A MAP-SHAPED REPORT**: the reserved four multiply-adds in
    /// [`RESERVED_CLASSES`] order, over a `class -> quantity` map instead of a line slice.
    ///
    /// ONE ARITHMETIC, TWO REPORT SHAPES. The 1.5.5 ledger stores usage as a name-keyed map and the
    /// 1.6.0 report carries it as lines; the price of either is the same fold at the same rates, and
    /// this is that fold reading the map. It is here, beside [`Self::nanos`] and against the same
    /// card, so the two shapes cannot be priced by two policies — a map priced outside this crate is
    /// a second answer to what a request cost, and the ledger cannot say which one it recorded.
    ///
    /// ONLY THE RESERVED FOUR PRICE HERE, and that is the shape of the map rather than a narrowing:
    /// the reserved names are the only ones a configured card names, because the two constructors a
    /// deployment reaches ([`RateCard::from_config`] and its currency-carrying spelling) fan a lane's
    /// [`TierRates`] out over exactly [`RESERVED_CLASSES`]. A card with an open class is reachable
    /// only through [`RateCard::set_rate`], which nothing in production calls; pin
    /// `open_class_prices_only_through_set_rate` says so and would go red the day one did.
    ///
    /// A quantity times a rate cannot overflow the wide accumulator — a `u64` times a `u64` is
    /// inside a `u128` by a whole bit — but four maximal products summed are past the top of it. So
    /// the running total SATURATES rather than adding plainly: a plain add panics in a debug build
    /// and wraps in a release one, and a wrapped total lands back near zero, which is an
    /// over-the-top ledger deriving as nearly free and escaping every budget cap. Below the
    /// accumulator's top the two are the same number to the byte, which
    /// `saturating_add_matches_plain_add_below_overflow` pins.
    pub fn reserved_units_nanos(&self, units: &BTreeMap<String, u64>) -> u128 {
        RESERVED_CLASSES.iter().fold(0u128, |acc, class| {
            let quantity = units.get(*class).copied().unwrap_or(0);
            let amount =
                u128::from(quantity).saturating_mul(u128::from(self.nanos_per_unit(class)));
            acc.saturating_add(amount)
        })
    }
}
