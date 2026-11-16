// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the cell that

use std::collections::BTreeMap;

/// Convert one configured rate — micro-units per unit of quantity — into the integer nano-unit
pub fn nano_rate(micro_per_unit: f64) -> u64 {
    if !micro_per_unit.is_finite() || micro_per_unit <= 0.0 {
        return 0;
    }
    // The double's shortest decimal text, spelled on the stack. Past 32 bytes it has more than 20
    // whole digits or more than 3 decimals, which is no representable rate either way.
    let mut spelled = crate::cost::spelled::Spelled::<32>::new();
    if std::fmt::Write::write_fmt(&mut spelled, format_args!("{micro_per_unit}")).is_err() {
        return 0;
    }
    let text = spelled.as_str();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if frac.len() > 3 {
        return 0;
    }
    let digit = |i: usize| frac.as_bytes().get(i).map_or(0, |d| u64::from(d - b'0'));
    whole
        .parse::<u64>()
        .ok()
        .and_then(|whole| whole.checked_mul(1000))
        .and_then(|nanos| nanos.checked_add(digit(0) * 100 + digit(1) * 10 + digit(2)))
        .unwrap_or(0)
}

/// **THE CARD-BUILD QUESTION**: can the card hold this configured rate as what it says it is?
pub fn representable_nano_rate(micro_per_unit: f64) -> Option<u64> {
    if micro_per_unit == 0.0 {
        return Some(0);
    }
    match nano_rate(micro_per_unit) {
        0 => None,
        n => Some(n),
    }
}

/// The uncached-input meter class, as a card entry is keyed.
pub const CLASS_INPUT: &str = "input";
/// The response meter class.
pub const CLASS_OUTPUT: &str = "output";
/// The cache-read meter class — input read back from a cache, priced apart from uncached input.
pub const CLASS_CACHE_READ: &str = "cache_read";
/// The cache-write (cache creation) meter class.
pub const CLASS_CACHE_WRITE: &str = "cache_write";

/// ONE LANE'S CONFIGURED RATES, as exact integer nano-units per unit of quantity — the neutral view a
/// card is built from.
///
/// A small record of the section's raw scalars in a canonical order, and deliberately nothing more:
/// the deployment's config GRAMMAR — the field spellings, the validation, which section they live in
/// — belongs to whoever parses it, and only these four numbers cross into the crate that prices
/// them. That is what lets this crate own card construction without owning a config parser, and it
/// is why its dependency closure is still the capability crate and nothing else.
///
/// It is ONE CONSTRUCTOR FOR A CARD RATHER THAN THE CARD'S SHAPE. It can only express the four
/// token classes a 1.5.5 deployment configures, and a card's class map is string-keyed, so seconds,
/// bytes and any other declared class price through the same card with no type change.
///
/// NO FLOAT LIVES HERE (#81, #77(8)). Each configured decimal was converted to its integer nano-unit
/// rate ONCE, at the config intake, by [`representable_nano_rate`]; this record and every hop that
/// carries it hold that integer. `None` is a configured rate the card cannot hold, placed
/// as an UNPRICED cell so a hit refuses (#42) — never a zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierRates {
    /// Nano-units per uncached input unit.
    pub input: Option<u64>,
    /// Nano-units per response unit.
    pub output: Option<u64>,
    /// Nano-units per cache-read unit.
    pub cache_read: Option<u64>,
    /// Nano-units per cache-write unit.
    pub cache_write: Option<u64>,
}

impl Default for TierRates {
    /// Every class configured at zero: an omitted tier prices at 0, as 1.5.5's did.
    fn default() -> Self {
        TierRates {
            input: Some(0),
            output: Some(0),
            cache_read: Some(0),
            cache_write: Some(0),
        }
    }
}

impl TierRates {
    /// The four rates paired with the class each one prices, in the canonical order.
    pub(crate) fn by_class(self) -> [(&'static str, Option<u64>); 4] {
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

/// One (lane, class) cell of a card: ONE configured integer rate, or a silence.
///
/// NO SECOND AXIS. A cell holds one price because a figure in this tree is a unitless abstract cost
/// (#66) — there is no denomination to price it a second time in, and therefore no cross-rate, no
/// exchange table, and no number that could change without somebody editing the card. That absence
/// is the point: an exchange rate is exactly the number the dated history exists to make impossible.
///
/// `None` is NOT zero and must never be read as zero: it is a cell that was never priced, and the
/// answer is a refusal (`class_priced` says so; see [`LaneRates::class_priced`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CellPrices(Option<u64>);

impl CellPrices {
    /// A priced cell.
    pub fn single(nanos_per_unit: u64) -> Self {
        CellPrices(Some(nanos_per_unit))
    }

    /// Set or replace this cell's rate.
    pub fn set(&mut self, nanos_per_unit: u64) {
        self.0 = Some(nanos_per_unit);
    }

    /// This cell's rate, if it has one. `None` is NOT zero — see the type's doc.
    pub fn nanos_per_unit(&self) -> Option<u64> {
        self.0
    }
}

/// The resolved rate card: integer nano-unit prices per (lane, class), plus the flat per-request
/// fee in minor units.
///
/// Pricing is all-or-nothing. With no card every class prices at zero and only the flat fee counts.
/// With a card, the card is authoritative: a lane it does not name prices at nothing AND is
/// reported as unpriced, so an unknown lane fails closed instead of quietly serving for free.
///
/// The prices are keyed lane-first, then class, rather than by a composite. That is a lookup shape,
/// not a storage preference: a composite key has to be BUILT before it can be looked up, and
/// building one out of two borrowed strings means two heap allocations per lookup, thrown away
/// immediately, on the hot path of every priced line. Nested, every step is asked with the borrowed
/// text the caller already holds, and none of them allocates. The nesting also removes the need to
/// carry the set of priced lanes alongside the prices: the lanes ARE the outer keys, so the two can
/// no longer disagree about which lanes the card names.
///
/// A card has no version field. Which card this is, is the number of the history entry that holds
/// it, and that number belongs to the history rather than to the card — a card carrying its own name
/// is a second identity that can disagree with the first.
///
/// **ONE CARD PER PLANE** (#42 "scoped per plane", #47). The card an unqualified lane is priced by is
/// the FLAT card — the card of the plane that owns the unqualified lanes, which is where 1.5.5's
/// top-level `rate_card:` loads, byte-identically. Every other plane's card rides in `planes`, keyed by its plane key, and a lane
/// qualified `"<plane>\u{1f}<lane>"` ([`crate::cost::PLANE_LANE_SEP`]) is priced by THAT plane's card
/// alone ([`Self::plane_lane`]). A plane with no card of its own is billing OFF for that plane (#42:
/// reads 0), whatever any other plane's card says; each plane's presence is its own switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCard {
    pub(crate) present: bool,
    pub(crate) prices: BTreeMap<String, BTreeMap<String, CellPrices>>,
    pub(crate) fee: i64,
    /// Every configured cell the card could not represent (see [`representable_nano_rate`]). Each
    /// is on the card as an UNPRICED cell of a named lane, so a hit on it refuses; the list is kept
    /// so card-build validation can refuse the whole configuration at boot (#77(5)).
    pub(crate) refused: Vec<LaneClass>,
    /// The other planes' cards, by plane key. Each carries ITS OWN fees (#47: `fees` is a reserved
    /// sub-key of every plane's section) and none of the node's: a plane that configured no fees
    /// bills a fee of nothing, whatever another plane charges.
    pub(crate) planes: BTreeMap<String, RateCard>,
    /// Common plugin measurements, keyed by kind; each child prices configured namespaces.
    pub(crate) measurements: BTreeMap<String, RateCard>,
    /// The flat fee per opened SESSION, in minor units (#44 `fees.per_session`). Zero on the flat
    /// card, whose one fee is 1.5.5's `per_request_fee:`.
    pub(crate) session_fee: i64,
}

/// The card a plane with no card of its own resolves to: ABSENT, so its every class reads 0 (#42),
static NO_CARD: RateCard = RateCard {
    present: false,
    prices: BTreeMap::new(),
    fee: 0,
    refused: Vec::new(),
    planes: BTreeMap::new(),
    measurements: BTreeMap::new(),
    session_fee: 0,
};

/// A missing common measurement rate is unpriced, independently of legacy billing switches.
static NO_MEASUREMENT_CARD: RateCard = RateCard {
    present: true,
    prices: BTreeMap::new(),
    fee: 0,
    refused: Vec::new(),
    planes: BTreeMap::new(),
    measurements: BTreeMap::new(),
    session_fee: 0,
};

/// Host-reserved lane prefix. Configured legacy identifiers must not contain control characters.
pub const MEASUREMENT_LANE_PREFIX: &str = "\u{1e}measurement:";

pub use crate::off_path::rate::measurement_lane;

/// Decode a common measurement lane without treating its owner as a plane or provider.
pub fn split_measurement_lane(lane: &str) -> Option<(&str, &str)> {
    let (length, rest) = lane
        .strip_prefix(MEASUREMENT_LANE_PREFIX)?
        .split_once(':')?;
    let length: usize = length.parse().ok()?;
    if length == 0 || length >= rest.len() || !rest.is_char_boundary(length) {
        return None;
    }
    Some(rest.split_at(length))
}

/// The reserved class a plane's REQUEST fee units are counted under, on its fee lane
pub const PER_REQUEST: &str = "per_request";
/// The reserved class a plane's SESSION fee units are counted under — one per opened session (#44
pub const PER_SESSION: &str = "per_session";

/// **A PLANE'S FEE LANE**, `"<plane>\u{1f}"`: the lane its fee units ([`PER_REQUEST`],
pub fn plane_fee_lane(plane: &str) -> String {
    format!("{plane}{}", crate::cost::PLANE_LANE_SEP)
}

/// One plane's configured fees, in minor units (#44: `fees = { per_request | per_session }`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlaneFees {
    /// The fee per billable request.
    pub per_request: i64,
    /// The fee per opened session.
    pub per_session: i64,
}

/// Split a card key (or a ledger row's lane) into `(plane key, lane)`. An unqualified key is the
pub fn split_plane_lane(key: &str) -> (&str, &str) {
    key.split_once(crate::cost::PLANE_LANE_SEP)
        .unwrap_or(("", key))
}

/// Whether the flat card is present, given the PLANE KEY of every key in a composed card map (see
pub fn flat_card_present<'k>(mut planes: impl Iterator<Item = &'k str>) -> bool {
    let mut none = true;
    planes.any(|plane| {
        none = false;
        plane.is_empty()
    }) || none
}

// Composed from configuration once, at boot or on a reload: off the request path.
pub use crate::off_path::rate::compose_plane_cards;

impl RateCard {
    /// A card that is not there: every class prices at zero, the flat fee still posts.
    pub fn absent(per_request_fee: i64) -> Self {
        RateCard {
            present: false,
            prices: BTreeMap::new(),

            fee: per_request_fee.max(0),
            refused: Vec::new(),
            planes: BTreeMap::new(),
            measurements: BTreeMap::new(),
            session_fee: 0,
        }
    }

    /// Every configured cell this card could not represent, in the order it was configured. Empty
    #[cfg(test)]
    pub fn refused_cells(&self) -> &[LaneClass] {
        &self.refused
    }

    /// The fee a reserved fee class ([`PER_REQUEST`], [`PER_SESSION`]) prices at on this card, in
    pub fn fee_of(&self, class: &str) -> Option<i64> {
        match class {
            PER_REQUEST => Some(self.fee),
            PER_SESSION => Some(self.session_fee),
            _ => None,
        }
    }

    /// Resolve a common measurement owner first, otherwise the legacy plane and its local lane.
    pub fn plane_lane<'l>(&self, lane: &'l str) -> (&RateCard, &'l str) {
        if let Some((kind, namespace)) = split_measurement_lane(lane) {
            return (
                self.measurements.get(kind).unwrap_or(&NO_MEASUREMENT_CARD),
                namespace,
            );
        }
        match split_plane_lane(lane) {
            ("", _) => (self, lane),
            (plane, lane) => (self.planes.get(plane).unwrap_or(&NO_CARD), lane),
        }
    }

    /// Whether the legacy flat card is configured (independent of common measurement rates).
    pub fn pricing_enabled(&self) -> bool {
        self.present
    }

    /// **THE FLAT PER-REQUEST FEE**, in MINOR units, clamped at resolve so it is never negative.
    pub fn fee(&self) -> i64 {
        self.fee
    }

    /// The flat fee as the unit price of its own usage line: minor units lifted to nano-units.
    pub fn fee_unit_price_nanos(&self) -> u128 {
        u128::try_from(self.fee)
            .unwrap_or(0)
            .saturating_mul(crate::cost::NANOS_PER_CENT)
    }

    /// Whether a request on this lane must be refused because a card is present and has no entry
    pub fn lane_unpriced(&self, lane: &str) -> bool {
        let (card, lane) = self.plane_lane(lane);
        card.present && !card.prices.contains_key(lane)
    }

    /// The rates for one lane. Three outcomes, and they are the whole of the pricing posture:
    pub fn lane_rates(&self, lane: &str) -> Option<LaneRates<'_>> {
        let (card, lane) = self.plane_lane(lane);
        card.local_lane_rates(lane)
    }

    fn local_lane_rates(&self, lane: &str) -> Option<LaneRates<'_>> {
        if !self.present {
            return Some(LaneRates { classes: None });
        }
        self.prices.get(lane).map(|classes| LaneRates {
            classes: Some(classes),
        })
    }

    /// **HOW A LANE PRICES ON THIS CARD — THE ONE RESOLUTION** (#42, #44, #47). Both the settlement
    pub fn lane_pricing(&self, lane: &str) -> LanePricing<'_> {
        let (card, key) = self.plane_lane(lane);
        let rule = if key.is_empty() && lane.ends_with(crate::cost::PLANE_LANE_SEP) {
            LaneRule::Fees
        } else {
            match card.local_lane_rates(key) {
                Some(rates) => LaneRule::Rates(rates),
                None => LaneRule::Unnamed,
            }
        };
        LanePricing { card, rule }
    }
}

/// A lane as [`RateCard::lane_pricing`] resolved it: the card that prices it, and how.
#[derive(Debug, Clone, Copy)]
pub struct LanePricing<'c> {
    /// The card the lane is priced by — its plane's own (an absent card for a plane with none).
    pub card: &'c RateCard,
    rule: LaneRule<'c>,
}

/// The three ways a lane prices.
#[derive(Debug, Clone, Copy)]
enum LaneRule<'c> {
    /// A plane's fee lane: its reserved fee classes at the plane's own fees.
    Fees,
    /// A lane priced by its card's rates (all zero on an absent card).
    Rates(LaneRates<'c>),
    /// A present card names no entry for the lane.
    Unnamed,
}

/// What one class on a resolved lane prices at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassPrice {
    /// A reserved fee class on a plane's fee lane: this many MINOR units per unit, never rounded and
    /// never divided (#44).
    FeeMinor(i64),
    /// A rate, in nano-units per unit. Zero on an absent card (billing off, #42).
    Nanos(u64),
    /// A present card names no price for the class on this lane: a refusal (#42), never a zero.
    Unpriced,
}

impl LanePricing<'_> {
    /// Whether the lane is priced at all: `false` exactly when a present card names no entry for it.
    pub fn lane_named(&self) -> bool {
        !matches!(self.rule, LaneRule::Unnamed)
    }

    /// What one class prices at on this lane. Every class on an unnamed lane is [`ClassPrice::Unpriced`].
    pub fn class_price(&self, class: &str) -> ClassPrice {
        match self.rule {
            LaneRule::Fees => match self.card.fee_of(class) {
                Some(fee_minor) => ClassPrice::FeeMinor(fee_minor),
                None if self.card.pricing_enabled() => ClassPrice::Unpriced,
                None => ClassPrice::Nanos(0),
            },
            LaneRule::Rates(rates) if rates.class_priced(class) => {
                ClassPrice::Nanos(rates.nanos_per_unit(class))
            }
            LaneRule::Rates(_) | LaneRule::Unnamed => ClassPrice::Unpriced,
        }
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
    classes: Option<&'a BTreeMap<String, CellPrices>>,
}

impl LaneRates<'_> {
    /// The nano-unit rate for one meter class on this lane. Zero when there is no card at all, and
    pub fn nanos_per_unit(&self, class: &str) -> u64 {
        match self.classes {
            None => 0,
            Some(classes) => classes
                .get(class)
                .and_then(CellPrices::nanos_per_unit)
                .unwrap_or(0),
        }
    }

    /// Whether this class is priced by name. With no card nothing is unpriced — every class is
    pub fn class_priced(&self, class: &str) -> bool {
        match self.classes {
            None => true,
            Some(classes) => classes
                .get(class)
                .is_some_and(|cell| cell.nanos_per_unit().is_some()),
        }
    }
}
