// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rate card: the one place a decimal from config becomes an integer rate, and the cell that
//! holds one price.
//!
//! **THE PRICES ARE UNITLESS** (#66 `BUSBAR-1.6.0.md:528`). A cell holds ONE integer, not one per
//! denomination, because there is no denomination here to hold one per: money in this tree is
//! abstract cost and the scale it truncates at is [`crate::cost::NANOS_PER_CENT`], fixed for every
//! card and every reading of one. What a figure is DISPLAYED as is the dashboard's, downstream of
//! this crate and invisible to it.

use std::collections::BTreeMap;

use busbar_contract::caps::UsageLine;

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
/// NO DENOMINATION ENTERS HERE, and that is the design (#66). A rate is a configured decimal and
/// this function turns it into the one integer all later arithmetic uses; there is no second scale
/// it could be quantised at and nothing to choose between. A denomination-dependent conversion would
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
    // REJECT AT THE TRUE BOUNDARY. `u64::MAX` is `2^64 - 1`, which an `f64` cannot represent, so
    // `u64::MAX as f64` rounds UP to exactly `2^64` and a `v <= u64::MAX as f64` guard admits a
    // finite `v == 2^64` — one past the top — which `v as u64` then SATURATES to `u64::MAX`: the
    // astronomical overcharge described above, arriving at the one input the guard was written to
    // stop. Comparing against `2^64` itself is the boundary the cast actually has, so an
    // out-of-range value falls to `0` as the paragraph above promises.
    //
    // BYTE-NEUTRAL for every rate a deployment can hold: the largest `f64` strictly below `2^64` is
    // `2^64 - 2048`, it still passes, and it still converts to itself. Exactly one `f64` changes
    // answer, and it is the one that was never a rate.
    if v.is_finite() && v > 0.0 && v < 2.0_f64.powi(64) {
        v as u64
    } else {
        0
    }
}

/// **THE CARD-BUILD QUESTION**: can the card hold this configured rate as what it says it is?
///
/// `Some(n)` — the rate the card records, which is [`nano_rate`]'s quantisation, unchanged (#44:
/// card-build quantisation stays half-away-from-zero, byte-identical). `Some(0)` only for a rate
/// CONFIGURED at zero, which is #77(5)'s explicit zero row: legitimately free.
///
/// `None` — the card CANNOT represent it, and must not claim to (item 22). [`nano_rate`] maps every
/// value it cannot hold onto `0`, which is the right answer for a conversion with no error channel
/// and the WRONG answer for a card: a configured positive rate below the half-nano-unit quantum
/// (`0.0004` micro-units — `$0.10/GB` is `0.00009313` micro-units a byte) became `0` while the
/// card reported the class PRICED, so every unit of it billed as nothing and #42's refusal could
/// never fire. The same is true of a rate too large for the integer (it was a clamp to `0`), and of
/// a value that is not a rate at all (negative, NaN, infinite — config validation refuses those
/// first; this is the card's own statement of the same rule). Each of those is now an UNPRICED
/// cell, so a hit on it REFUSES (#42) instead of pricing at a zero nobody configured.
pub fn representable_nano_rate(micro_per_unit: f64) -> Option<u64> {
    if micro_per_unit == 0.0 {
        // An explicit zero (`-0.0` included): the operator configured this class free.
        return Some(0);
    }
    match nano_rate(micro_per_unit) {
        // A non-zero configured value that quantises to nothing is a value the card cannot hold.
        0 => None,
        n => Some(n),
    }
}

/// Fold quantity-and-rate pairs into one nano-unit total: multiply each pair, sum the products,
/// and SATURATE at both steps.
///
/// THE ONLY MULTIPLY-AND-SUM ON THE MONEY PATH, now. It used to be three: this crate's own lane
/// fold, the admission unit's reserved-four fold, and a third in the kernel's cost projection that
/// nobody had counted — and the third one guarded nothing. Two copies of a rounding rule drift
/// (which is the incident [`nano_rate`] narrates); three copies of an OVERFLOW rule had already
/// drifted, because the two written down saturated and the one nobody had written down did not.
///
/// BOTH OPERATIONS ARE GUARDED, AND THE SECOND IS THE ONE THAT MATTERS. A single product cannot
/// overflow the accumulator — a `u64` quantity times a `u64` rate is inside a `u128` by a whole bit
/// — and a comment that says only that is TRUE AND BESIDE THE POINT, which is exactly how the
/// unguarded copy read and exactly why it survived review. It is the SUM that overflows: four
/// maximal products reach about 2^130 against a 2^128 ceiling. A plain `+` panics on overflow in a
/// debug build and WRAPS in a release one, and the wrap is the dangerous half because it is silent
/// — a total one past the ceiling wraps to ONE nano-unit, so an astronomical ledger derives as very
/// nearly free and clears every budget cap on the way past. Pinning at the top is the only reading
/// of an over-the-top bill that cannot UNDER-bill, and it is what the caller above then pins into
/// cents.
///
/// Below the ceiling this is ordinary exact integer arithmetic: saturation changes no answer that
/// the unguarded sum was able to give, so every bill a deployment actually produces is unmoved.
///
/// #81 keeps this integer: no `f32`/`f64` touches a quantity or a rate here. The only decimal on
/// the money path is the one [`nano_rate`] converts, once, at card-build time.
pub fn nanos_sum<I>(pairs: I) -> u128
where
    I: IntoIterator<Item = (u64, u64)>,
{
    pairs
        .into_iter()
        .fold(0u128, |acc, (quantity, nanos_per_unit)| {
            acc.saturating_add(u128::from(quantity).saturating_mul(u128::from(nanos_per_unit)))
        })
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
/// the FLAT card — the llm (`pools`) plane's, which is where 1.5.5's top-level `rate_card:` loads,
/// byte-identically. Every other plane's card rides in `planes`, keyed by its plane key, and a lane
/// qualified `"<plane>\u{1f}<lane>"` ([`crate::cost::PLANE_LANE_SEP`]) is priced by THAT plane's card
/// alone ([`Self::plane_lane`]). A plane with no card of its own is billing OFF for that plane (#42:
/// reads 0), whatever any other plane's card says; each plane's presence is its own switch.
#[derive(Debug, Clone)]
pub struct RateCard {
    present: bool,
    prices: BTreeMap<String, BTreeMap<String, CellPrices>>,
    fee: i64,
    /// Every configured cell the card could not represent (see [`representable_nano_rate`]). Each
    /// is on the card as an UNPRICED cell of a named lane, so a hit on it refuses; the list is kept
    /// so card-build validation can refuse the whole configuration at boot (#77(5)).
    refused: Vec<LaneClass>,
    /// The other planes' cards, by plane key. Each carries no fee: the flat fee is one dimension of
    /// the node's card (#44), posted once whatever plane the row is on.
    planes: BTreeMap<String, RateCard>,
}

/// The card a plane with no card of its own resolves to: ABSENT, so its every class reads 0 (#42).
static NO_CARD: RateCard = RateCard {
    present: false,
    prices: BTreeMap::new(),
    fee: 0,
    refused: Vec::new(),
    planes: BTreeMap::new(),
};

/// Split a card key (or a ledger row's lane) into `(plane key, lane)`. An unqualified key is the
/// flat card's, spelt here as the empty plane key; `"<plane>\u{1f}"` with no lane is that plane's
/// PRESENCE — a card configured with no entry yet, which still turns its plane's billing on.
pub fn split_plane_lane(key: &str) -> (&str, &str) {
    key.split_once(crate::cost::PLANE_LANE_SEP)
        .unwrap_or(("", key))
}

/// Whether the flat card is present, given the PLANE KEY of every key in a composed card map (see
/// [`split_plane_lane`]): a map naming no key at all is the 1.5.5 `rate_card: {}` (present), and
/// otherwise the flat card is present only when some key is the flat plane's (the empty plane key).
/// [`RateCard::from_config`] and the config validator both ask this, so they cannot disagree about
/// which card is on.
pub fn flat_card_present<'k>(mut planes: impl Iterator<Item = &'k str>) -> bool {
    let mut none = true;
    planes.any(|plane| {
        none = false;
        plane.is_empty()
    }) || none
}

/// COMPOSE one card map from the flat card and each plane's own card: a plane's lanes are qualified
/// by its key and each present plane card leaves its presence key (see [`split_plane_lane`]). With no
/// plane card this is the flat card, untouched — the 1.5.5 map, byte-identical.
pub fn compose_plane_cards<E: Clone + Default>(
    flat: Option<&BTreeMap<String, E>>,
    planes: &BTreeMap<String, BTreeMap<String, E>>,
) -> Option<BTreeMap<String, E>> {
    if planes.is_empty() {
        return flat.cloned();
    }
    let sep = crate::cost::PLANE_LANE_SEP;
    let mut out = flat.cloned().unwrap_or_default();
    if flat.is_some() {
        out.insert(sep.to_string(), E::default());
    }
    for (plane, card) in planes {
        out.insert(format!("{plane}{sep}"), E::default());
        out.extend(
            card.iter()
                .map(|(lane, e)| (format!("{plane}{sep}{lane}"), e.clone())),
        );
    }
    Some(out)
}

impl RateCard {
    /// A card that is not there: every class prices at zero, the flat fee still posts.
    ///
    /// This is the deployment with no pricing configured at all. Nothing is "unpriced" here,
    /// because there is no card to be missing from — attribution only. The fee is in minor units.
    pub fn absent(per_request_fee: i64) -> Self {
        RateCard {
            present: false,
            prices: BTreeMap::new(),
            // A negative configured fee is clamped here, once: no request may ever bill a negative
            // amount, which would credit a budget back toward headroom.
            fee: per_request_fee.max(0),
            refused: Vec::new(),
            planes: BTreeMap::new(),
        }
    }

    /// Resolve a card from configured micro-unit rates. Each rate converts to nano-units once,
    /// here, and never again.
    ///
    /// A configured value the card cannot represent ([`representable_nano_rate`] answers `None`)
    /// lands as an UNPRICED cell of its lane and is listed in [`Self::refused_cells`] — never as a
    /// cell priced at zero (item 22).
    pub fn from_micro_rates(
        entries: impl IntoIterator<Item = (LaneClass, f64)>,
        per_request_fee: i64,
    ) -> Self {
        let mut card = RateCard {
            present: true,
            prices: BTreeMap::new(),
            fee: per_request_fee.max(0),
            refused: Vec::new(),
            planes: BTreeMap::new(),
        };
        for (cell, micro) in entries {
            card.place_rate(cell, micro);
        }
        card
    }

    /// Resolve a card from rates ALREADY in integer nano-units per unit — for a holder whose rates
    /// were quantised once by [`nano_rate`] and which must not round them a second time. No decimal
    /// enters here. A rate of zero is an explicit zero row, exactly as it is on the micro path.
    pub fn from_nano_rates(
        entries: impl IntoIterator<Item = (LaneClass, u64)>,
        per_request_fee: i64,
    ) -> Self {
        let mut prices: BTreeMap<String, BTreeMap<String, CellPrices>> = BTreeMap::new();
        for (cell, nanos) in entries {
            prices
                .entry(cell.lane)
                .or_default()
                .entry(cell.class)
                .or_default()
                .set(nanos);
        }
        RateCard {
            present: true,
            prices,
            fee: per_request_fee.max(0),
            refused: Vec::new(),
            planes: BTreeMap::new(),
        }
    }

    /// Every configured cell this card could not represent, in the order it was configured. Empty
    /// for every card whose rates are all representable — which is every card config validation
    /// admits (#77(5): an unpriced class is a BOOT refusal when billing is on).
    pub fn refused_cells(&self) -> &[LaneClass] {
        &self.refused
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
    /// ONE CARD PER PLANE: a key qualified by a plane key lands on THAT plane's card (see
    /// [`compose_plane_cards`]); the unqualified keys are the flat card, present by
    /// [`flat_card_present`]'s rule. A map naming no plane builds exactly the card it always did.
    pub fn from_config<'a>(
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee: i64,
    ) -> Self {
        let Some(lanes) = lanes else {
            return RateCard::absent(per_request_fee);
        };
        let mut by_plane: BTreeMap<&str, Vec<(LaneClass, f64)>> = BTreeMap::new();
        for (key, tiers) in lanes {
            let (plane, lane) = split_plane_lane(key);
            let cells = by_plane.entry(plane).or_default();
            if !lane.is_empty() {
                cells.extend(
                    tiers
                        .by_class()
                        .map(|(class, micro)| (LaneClass::new(lane, class), micro)),
                );
            }
        }
        let flat_present = flat_card_present(by_plane.keys().copied());
        let flat = by_plane.remove("").unwrap_or_default();
        let mut card = if flat_present {
            RateCard::from_micro_rates(flat, per_request_fee)
        } else {
            RateCard::absent(per_request_fee)
        };
        card.planes = by_plane
            .into_iter()
            .map(|(plane, cells)| (plane.to_string(), RateCard::from_micro_rates(cells, 0)))
            .collect();
        card
    }

    /// **THE OPEN CLASSES a deployment configured** (item 123): each `(lane, class)` cell set to an
    /// integer nano-unit rate that was parsed EXACTLY at the config boundary, so no decimal and no
    /// second quantisation enters here. The reserved four keep arriving through [`Self::from_config`]
    /// byte-identically; this only ADDS cells beside them, on the lanes the card already names.
    ///
    /// ABSENT STAYS ABSENT. An absent card is billing off (#42): every class prices at nothing, so
    /// open rates configured nowhere have nowhere to land and are ignored rather than switching
    /// billing on by the back door. A card that is PRESENT carries them, and a class the traffic
    /// hits that no cell prices still REFUSES in the one function — never a silent 0.
    ///
    /// A plane-qualified lane lands on that plane's card, under the same rule: a plane with no card
    /// of its own has nowhere for the rate to land.
    pub fn with_unit_rates(mut self, cells: impl IntoIterator<Item = (LaneClass, u64)>) -> Self {
        for (cell, nanos) in cells {
            let (plane, lane) = split_plane_lane(&cell.lane);
            let card = match plane {
                "" => &mut self,
                plane => match self.planes.get_mut(plane) {
                    Some(card) => card,
                    None => continue,
                },
            };
            if card.present && !lane.is_empty() {
                card.prices
                    .entry(lane.to_string())
                    .or_default()
                    .entry(cell.class)
                    .or_default()
                    .set(nanos);
            }
        }
        self
    }

    /// **THE CARD A LANE IS PRICED BY, and the lane as that card keys it** (#42 "scoped per plane",
    /// #47). An unqualified lane is this (the flat) card's; `"<plane>\u{1f}<lane>"` is that plane's
    /// own card's — ABSENT when the plane configured none, so it reads 0 and never borrows another
    /// plane's card, present or not.
    pub fn plane_lane<'l>(&self, lane: &'l str) -> (&RateCard, &'l str) {
        match split_plane_lane(lane) {
            ("", _) => (self, lane),
            (plane, lane) => (self.planes.get(plane).unwrap_or(&NO_CARD), lane),
        }
    }

    /// Set one cell's rate.
    ///
    /// The number is configured and set, never derived: there is no arm here that reads another
    /// cell's rate, and no second denomination a rate could be derived through (#66).
    ///
    /// A value the card cannot represent leaves the cell UNPRICED (and records it in
    /// [`Self::refused_cells`]) — it never sets a zero the operator did not configure (item 22).
    pub fn set_rate(&mut self, cell: LaneClass, micro_per_unit: f64) {
        self.place_rate(cell, micro_per_unit);
    }

    /// The one placement of a configured rate into a cell — the constructor's and the mutator's.
    fn place_rate(&mut self, cell: LaneClass, micro_per_unit: f64) {
        self.present = true;
        let slot = self
            .prices
            .entry(cell.lane.clone())
            .or_default()
            .entry(cell.class.clone())
            .or_default();
        match representable_nano_rate(micro_per_unit) {
            Some(nanos) => {
                slot.set(nanos);
                self.refused.retain(|r| r != &cell);
            }
            None => {
                // UNPRICED, not zero: the lane is named, the class is silent, and #42 refuses a hit.
                *slot = CellPrices::default();
                if !self.refused.contains(&cell) {
                    self.refused.push(cell);
                }
            }
        }
    }

    /// Set the flat per-request fee in minor units, clamped at zero.
    pub fn set_fee(&mut self, per_request_fee: i64) {
        self.fee = per_request_fee.max(0);
    }

    /// Whether a card is configured at all (token pricing active).
    pub fn pricing_enabled(&self) -> bool {
        self.present
    }

    /// **THE FLAT PER-REQUEST FEE**, in MINOR units, clamped at resolve so it is never negative.
    ///
    /// ALWAYS A FIGURE, NEVER A SILENCE — and that is a structural guarantee rather than a
    /// convention. The fee used to be read out of a per-currency map that a caller could leave a
    /// hole in: a card could name a currency for its RATES (`set_rate`) and stay silent about the
    /// fee in it (`set_fee` never called), pass every guard, and then have the missing entry read
    /// as zero. That is silent under-billing — fail-open, the one outcome this module refuses
    /// everywhere else (#42 `BUSBAR-1.6.0.md:367`: *"a hit class not priced ⇒ REFUSE (money-sacred,
    /// never a silent 0)"*). #66 removed the second axis, so the hole is GONE rather than guarded:
    /// every constructor takes the fee by value, `set_fee` replaces it, and there is no key that
    /// could be absent. A fee CONFIGURED at nothing is #77(5)'s (`:420`) explicit zero row —
    /// legitimately free, and distinguishable from a silence because a silence can no longer exist.
    ///
    /// THE SPELLING THAT DEFAULTED IS STILL GONE. `per_request_fee(&self)` used to answer
    /// `unwrap_or(0)` out of that map; this answers the number the card was built with, and the
    /// clamp is the only thing between config and it.
    pub fn fee(&self) -> i64 {
        self.fee
    }

    /// The flat fee as the unit price of its own usage line: minor units lifted to nano-units.
    ///
    /// An exact multiple of one minor unit, which is the property that makes summing the fee in
    /// before the single truncation give the same answer as truncating the usage first and adding
    /// the fee afterwards.
    pub fn fee_unit_price_nanos(&self) -> u128 {
        // The clamp at every constructor and at `set_fee` is what makes this arm dead: a fee held
        // here is already `>= 0`, so the conversion cannot fail and the `0` is a belt-and-braces
        // reading of a negative that cannot arrive.
        u128::try_from(self.fee)
            .unwrap_or(0)
            .saturating_mul(crate::cost::NANOS_PER_CENT)
    }

    /// Whether a request on this lane must be refused because a card is present and has no entry
    /// for it. With no card nothing is unpriced, because there is nothing to be missing from.
    pub fn lane_unpriced(&self, lane: &str) -> bool {
        let (card, lane) = self.plane_lane(lane);
        card.present && !card.prices.contains_key(lane)
    }

    /// The rates for one lane. Three outcomes, and they are the whole of the pricing posture:
    ///
    /// - no card: a zero-rate view, so every class prices at nothing;
    /// - card present and the lane is named: that lane's rates;
    /// - card present and the lane is unknown: nothing at all, so the caller fails closed.
    pub fn lane_rates(&self, lane: &str) -> Option<LaneRates<'_>> {
        let (card, lane) = self.plane_lane(lane);
        if !card.present {
            return Some(LaneRates { classes: None });
        }
        card.prices.get(lane).map(|classes| LaneRates {
            classes: Some(classes),
        })
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
    /// zero for a class this lane's card entry does not name — the latter reported separately,
    /// because a class the card is silent about is a refusal and never a free line.
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
    /// attribution only, and flagging them all would report a deployment-wide condition per line.
    pub fn class_priced(&self, class: &str) -> bool {
        match self.classes {
            None => true,
            Some(classes) => classes
                .get(class)
                .is_some_and(|cell| cell.nanos_per_unit().is_some()),
        }
    }

    /// The nano-unit cost of a whole usage report at this lane's rates: one multiply-add per line.
    ///
    /// The arithmetic is [`nanos_sum`]'s rather than a copy of it — this lane view's job is to say
    /// which rate each line prices at, and the multiply, the sum and the saturation at both steps
    /// belong to the one fold every money path shares.
    pub fn nanos(&self, lines: &[UsageLine]) -> u128 {
        nanos_sum(
            lines
                .iter()
                .map(|l| (l.quantity, self.nanos_per_unit(l.class.as_str()))),
        )
    }
}
