// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`money = f(ledger_slice, card_history)`** — the ONE function, and the only one.
//!
//! The governing design states it in one line: *"money is a read-time view —
//! `price(ledger_slice, card_history) -> Money`, ONE function, called by the admin reads AND the
//! budget gate."* Everything in this module exists so that sentence is literally true of the code
//! rather than approximately true of five crates.
//!
//! # Why this module exists
//!
//! `f` was implemented more than twenty times across five crates. Two admin reads provably answered
//! different money for the same consumption after a rate-card edit, not because either was
//! carelessly written but because each was *separately* written. Two reads cannot disagree when
//! there is one function; they can always disagree when there are twenty. So the remedy is not a
//! better copy, it is one copy.
//!
//! # The shape of the input, and why BOTH books map onto it
//!
//! There are two books in this tree — the metering rows (`MeteringRow`, a UTC-day cell per
//! `(key, model, provider)`) and the enforcement ledger (`UsageLedger`, a cell per
//! `(bucket, window)`). They are different records of the same consumption. A [`LedgerEntry`] is
//! what they have in common and it is the whole of what pricing needs: a LANE, some COUNTS keyed by
//! meter class, a FEE COUNT, a TIER, and the INSTANT the counts arrived. Every row of either book
//! projects onto it without arithmetic, which is the proof that one function can answer for both.
//!
//! # The law, in the order it is applied
//!
//! 1. **Each entry resolves its OWN card** — [`HistoryView::card_at`] at the entry's own
//!    `arrived_ms` (#79). Not the newest card ever authored, not a version stamped into the row.
//!    "Eras" are not a concept here: a window spanning a card edit is simply this loop doing its
//!    job, which is also the only answer that holds for the all-time window, which has no boundary
//!    to apply a card change at.
//! 2. **No card at all is billing OFF** — every line prices at nothing and the entry contributes
//!    zero (#42). This is the one and only circumstance in which a silent zero is the right answer.
//! 3. **A card present but silent is a REFUSAL** (#42). An unnamed lane, an unnamed class, an
//!    unnamed currency: each refuses. Money-sacred means never inventing a zero.
//! 4. **Multiply and add, exactly** — a count at scale 6 times a rate in nano-units per whole unit
//!    accumulates at scale 15, in `i128`, CHECKED. Nothing here saturates: a saturated total is a
//!    wrong total wearing a right total's clothes.
//! 5. **The flat fee is one dimension and is never rounded** (#44) — it joins as its own term at an
//!    exact multiple of one minor unit, so it does not matter whether it is summed before or after
//!    the projection.
//! 6. **The tier applies once per tier, over that tier's summed pre-tier amount** — one divide,
//!    never a sum of per-line floors (#44).
//! 7. **Exactly one truncation, at the very end**, projecting scale 15 to the scale-6 [`Money`].
//!    [`price_exact`] is the same computation with that last step withheld, for a caller that wants
//!    the untruncated figure.
//!
//! # No binary floating point, anywhere on this path
//!
//! There is no `f32` or `f64` in this module (#77(8), #81). Counts arrive as
//! [`busbar_contract::count::Count`] — an `i128` mantissa at a fixed scale of six, parsed from
//! decimal TEXT — because a count that transits an `f64` has already lost the exactness no later
//! conversion can give back.
//!
//! # Order independence
//!
//! The accumulator is integer addition at a fixed scale with no rounding step, so a slice priced in
//! any order is byte-for-byte one number. Asserted, not assumed, in the tests beside this module.

use std::collections::BTreeMap;

use busbar_contract::count::Count;

use crate::cost::currency::CurrencyCode;
use crate::cost::history::{History, HistorySeq, HistoryView};
use crate::cost::posting::STANDARD_TIER_BP;
use crate::cost::NANOS_PER_MICRO;

/// The scale every [`Money`] figure is held at: six decimal places, i.e. micro-units (#81).
///
/// A PRECISION, not a currency and not a denomination — money in this tree is unitless (#66).
pub const MONEY_SCALE: u32 = 6;

/// `10^MONEY_SCALE`: how many mantissa steps make one whole money unit.
const MONEY_SCALE_FACTOR: i128 = 1_000_000;

/// The scale the accumulator runs at, before the single projection to [`MONEY_SCALE`].
///
/// A count is held at scale 6 and a card's rate is nano-units per WHOLE unit, which is scale 9, so
/// their product lands at scale 15. Accumulating there and projecting once at the end is what makes
/// "two lines each worth half a micro-unit make one micro-unit" true, where a per-line projection
/// would floor both to nothing.
pub const EXACT_SCALE: u32 = MONEY_SCALE + 9;

/// The divisor that takes the exact scale-15 accumulator down to [`MONEY_SCALE`]. Applied ONCE.
const EXACT_PER_MONEY: i128 = 1_000_000_000;

/// **A MONEY AMOUNT**: an `i128` mantissa at a fixed scale of six (#81).
///
/// `0.034510` is held as `34_510`. There is no currency in the type and no symbol on it (#66): the
/// currency is an argument to the lookup and a card that does not name it refuses rather than
/// converting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Money(i128);

impl Money {
    /// Nothing — the amount a slice with no priced line comes to.
    pub const ZERO: Money = Money(0);

    /// An amount from its mantissa at [`MONEY_SCALE`]. `34_510` is `0.034510`.
    pub const fn from_micros(micros: i128) -> Money {
        Money(micros)
    }

    /// The mantissa at [`MONEY_SCALE`] — the figure `spend_micros` has always carried.
    pub const fn micros(self) -> i128 {
        self.0
    }

    /// The amount in whole MINOR units of a currency, truncated toward zero.
    ///
    /// The divisor is the currency's and only the currency's, read from the one place a currency's
    /// scale is decided. This is the projection `spend_cents` has always been, for a deployment
    /// whose figures are in the currency 1.5.5 had.
    pub fn minor(self, currency: CurrencyCode) -> i128 {
        let micros_per_minor = i128::try_from(currency.nanos_per_minor() / NANOS_PER_MICRO)
            .expect("a currency's minor scale fits an i128");
        self.0 / micros_per_minor
    }

    /// Whether the amount is nothing.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The exact decimal spelling, always with [`MONEY_SCALE`] places: `34_510` reads `0.034510`.
    ///
    /// Written by integer arithmetic over the mantissa's digits. No float is formatted and none is
    /// parsed back, so what a reader sees is what the book holds.
    pub fn to_decimal_string(self) -> String {
        let negative = self.0 < 0;
        // `unsigned_abs` rather than `abs`, which panics on the minimum.
        let magnitude = self.0.unsigned_abs();
        let whole = magnitude / (MONEY_SCALE_FACTOR as u128);
        let fraction = magnitude % (MONEY_SCALE_FACTOR as u128);
        let sign = if negative { "-" } else { "" };
        format!(
            "{sign}{whole}.{fraction:0width$}",
            width = MONEY_SCALE as usize
        )
    }

    /// Two amounts added, CHECKED. Nothing here wraps and nothing saturates.
    pub fn checked_add(self, rhs: Money) -> Result<Money, MoneyError> {
        self.0
            .checked_add(rhs.0)
            .map(Money)
            .ok_or(MoneyError::Overflow)
    }
}

impl std::fmt::Display for Money {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

/// **ONE ROW OF A LEDGER SLICE** — what either book holds, projected onto what pricing needs.
///
/// A metering row becomes one of these with its four token fields as counts and its
/// `priced_from_ms` (or its own arrival) as the instant. An enforcement-ledger cell becomes one per
/// model, its `usage_units` map as counts — including the OPEN classes a plane declared, which is
/// the part every reserved-four derivation in this tree silently drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The lane the traffic was served on — the card's key for a destination (the model name, for
    /// the LLM plane).
    pub lane: String,
    /// The counts, keyed by the meter class the plane declared. Exact, at scale 6.
    pub counts: BTreeMap<String, Count>,
    /// How many flat fees this row carries — the BILLABLE request count, not the admission count.
    pub fee_count: Count,
    /// The tier multiplier in basis points. [`STANDARD_TIER_BP`] is ×1.
    pub tier_bp: u32,
    /// **THE RESOLUTION KEY** (#79): the instant these counts arrived, in wall-clock MILLISECONDS.
    ///
    /// Milliseconds, and the unit is load-bearing. A history's `effective_from` is in milliseconds;
    /// handing this field a reading in seconds resolves against the from-zero opening entry and
    /// reports it forever — a confident wrong answer that would pass a "reads a history" review.
    pub arrived_ms: u64,
}

impl LedgerEntry {
    /// A row with no counts on it yet.
    pub fn new(lane: impl Into<String>, arrived_ms: u64) -> LedgerEntry {
        LedgerEntry {
            lane: lane.into(),
            counts: BTreeMap::new(),
            fee_count: Count::from_micros(0),
            tier_bp: STANDARD_TIER_BP,
            arrived_ms,
        }
    }

    /// Add one class's count. A repeated class REPLACES rather than accumulating, because two
    /// counts for one class on one row is a caller bug and silently adding them would hide it.
    pub fn with_count(mut self, class: impl Into<String>, count: Count) -> LedgerEntry {
        self.counts.insert(class.into(), count);
        self
    }

    /// Add one class's count from a whole-unit integer — the shape both books hold today.
    pub fn with_whole(mut self, class: impl Into<String>, count: u64) -> LedgerEntry {
        self.counts.insert(
            class.into(),
            Count::from_micros(i128::from(count) * MONEY_SCALE_FACTOR),
        );
        self
    }

    /// Set the number of flat fees this row carries, from a whole-unit request count.
    pub fn with_fee_count(mut self, fee_count: u64) -> LedgerEntry {
        self.fee_count = Count::from_micros(i128::from(fee_count) * MONEY_SCALE_FACTOR);
        self
    }

    /// Set the tier multiplier in basis points.
    pub fn with_tier(mut self, tier_bp: u32) -> LedgerEntry {
        self.tier_bp = tier_bp;
        self
    }
}

/// Why a slice could not be priced. Every variant is a REFUSAL, and none of them is a zero (#42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoneyError {
    /// No entry of the snapshot covers this instant. A hole in the record prices at nothing only if
    /// somebody decides it does, and nobody here does.
    NoCardInForce {
        /// The instant that fell in the hole.
        at: u64,
    },
    /// The card in force does not name this currency. NEVER converted from another — there is no
    /// cross-rate anywhere in this crate and this variant is what stands where one would have gone.
    CurrencyNotPriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency that was asked for.
        currency: CurrencyCode,
    },
    /// A present card names no entry for the lane. Fail-closed: a lane the operator forgot bills at
    /// a refusal, never for free.
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the card is silent about.
        lane: String,
    },
    /// A present card names the lane but not this class. The direct statement of #42: *a hit class
    /// not priced ⇒ REFUSE, never a silent 0*. This is the arm every reserved-four derivation in
    /// the tree is missing, and it is why an open meter class — a2a `hops`, mcp `calls`, streaming
    /// `audio-seconds` — bills as nothing on those paths.
    ClassUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the class was reported on.
        lane: String,
        /// The class the card is silent about.
        class: String,
    },
    /// A product or a sum left the range. Reported rather than saturated: a saturated total is a
    /// wrong total that looks like a right one.
    Overflow,
}

impl std::fmt::Display for MoneyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoneyError::NoCardInForce { at } => {
                write!(f, "no rate-card entry covers the instant {at}")
            }
            MoneyError::CurrencyNotPriced { card_seq, currency } => write!(
                f,
                "rate-card entry {} does not price in {}",
                card_seq.get(),
                currency.as_str()
            ),
            MoneyError::LaneUnpriced { card_seq, lane } => write!(
                f,
                "rate-card entry {} names no price for lane `{lane}`",
                card_seq.get()
            ),
            MoneyError::ClassUnpriced {
                card_seq,
                lane,
                class,
            } => write!(
                f,
                "rate-card entry {} names no price for class `{class}` on lane `{lane}`",
                card_seq.get()
            ),
            MoneyError::Overflow => {
                f.write_str("the money arithmetic left the representable range")
            }
        }
    }
}

impl std::error::Error for MoneyError {}

/// **THE ONE FUNCTION.** `money = f(ledger_slice, card_history)`.
///
/// Prices a whole slice of either book against the history as it currently stands, each entry
/// against the card in force at its own `arrived_ms` (#79). This is what the admin reads call and
/// what the budget gate would call.
///
/// It reads no clock, no store and no configuration. Hand an auditor the slice and the history and
/// they re-derive the figure by hand.
pub fn price(
    ledger: &[LedgerEntry],
    history: &History,
    currency: CurrencyCode,
) -> Result<Money, MoneyError> {
    price_in_view(ledger, &history.current(), currency)
}

/// [`price`] against a PINNED snapshot of the history.
///
/// Pinned rather than re-read per entry: a card appended while a read is in flight must not price
/// half of one response's rows against one history and half against another. It is also the
/// reproducibility primitive — an invoice cut at a snapshot re-derives forever from that snapshot.
pub fn price_in_view(
    ledger: &[LedgerEntry],
    view: &HistoryView<'_>,
    currency: CurrencyCode,
) -> Result<Money, MoneyError> {
    let exact = price_exact(ledger, view, currency)?;
    // THE ONE TRUNCATION, and it is the last thing that happens. Toward zero, matching the
    // projection every 1.5.5 figure was already read through.
    Ok(Money(exact / EXACT_PER_MONEY))
}

/// [`price_in_view`] with the final projection WITHHELD: the exact accumulator at [`EXACT_SCALE`].
///
/// For a caller that must know whether the projection dropped anything — a reconciliation, a
/// property test, an auditor. `price_exact(..) % 1_000_000_000 == 0` is the statement "this figure
/// is exact at scale six", and it is a statement the truncated form cannot make about itself.
pub fn price_exact(
    ledger: &[LedgerEntry],
    view: &HistoryView<'_>,
    currency: CurrencyCode,
) -> Result<i128, MoneyError> {
    // Accumulated PER TIER, because the tier multiplier is one divide over a tier's summed pre-tier
    // amount and never a sum of per-line floors (#44). A slice at one tier — which is every slice
    // this tree produces — has one bucket and one divide.
    let mut pre_tier: BTreeMap<u32, i128> = BTreeMap::new();

    for entry in ledger {
        let (card_seq, card) = view
            .card_at(entry.arrived_ms)
            .ok_or(MoneyError::NoCardInForce {
                at: entry.arrived_ms,
            })?;

        // BILLING OFF (#42): no rate card configured at all. Every class prices at nothing, nothing
        // is "unpriced" because there is no card to be missing from, and the flat fee still posts —
        // which is what such a deployment is actually billed.
        if !card.pricing_enabled() {
            let fee = fee_term(card, currency, entry.fee_count)?;
            add_into(&mut pre_tier, entry.tier_bp, fee)?;
            continue;
        }

        if !card.prices_currency(currency) {
            return Err(MoneyError::CurrencyNotPriced { card_seq, currency });
        }

        // A present card that names no entry for the lane REFUSES. `lane_rates` answers `None` for
        // exactly that case on a present card.
        let rates =
            card.lane_rates(&entry.lane, currency)
                .ok_or_else(|| MoneyError::LaneUnpriced {
                    card_seq,
                    lane: entry.lane.clone(),
                })?;

        let mut amount: i128 = 0;
        for (class, count) in &entry.counts {
            // #42 STATED AS AN ARM: a present card silent about a class the traffic HIT is a
            // refusal. A zero count is still a hit — the row reported the class — so it refuses
            // too; a class the row does not carry is simply not in the map.
            if !rates.class_priced(class) {
                return Err(MoneyError::ClassUnpriced {
                    card_seq,
                    lane: entry.lane.clone(),
                    class: class.clone(),
                });
            }
            let rate = i128::from(rates.nanos_per_unit(class));
            let line = count
                .micros()
                .checked_mul(rate)
                .ok_or(MoneyError::Overflow)?;
            amount = amount.checked_add(line).ok_or(MoneyError::Overflow)?;
        }

        let fee = fee_term(card, currency, entry.fee_count)?;
        amount = amount.checked_add(fee).ok_or(MoneyError::Overflow)?;
        add_into(&mut pre_tier, entry.tier_bp, amount)?;
    }

    let mut total: i128 = 0;
    for (tier_bp, amount) in pre_tier {
        let tiered = if tier_bp == STANDARD_TIER_BP {
            // ×1 exactly. Spelled as its own arm so the standard tier cannot round: a multiply and
            // a divide by the same number is the identity on paper and a truncation in code if the
            // multiply overflows first.
            amount
        } else {
            amount
                .checked_mul(i128::from(tier_bp))
                .ok_or(MoneyError::Overflow)?
                / i128::from(STANDARD_TIER_BP)
        };
        total = total.checked_add(tiered).ok_or(MoneyError::Overflow)?;
    }
    Ok(total)
}

/// The flat fee as a term of the accumulator: minor units lifted to nano-units, times the fee
/// count, at [`EXACT_SCALE`].
///
/// NEVER ROUNDED and never divided (#44) — a fee is one pricing dimension. Its unit price is an
/// exact multiple of one minor unit, which is the property that makes summing it in before the
/// single projection give the same answer as projecting the usage first and adding the fee after.
fn fee_term(
    card: &crate::cost::rate::RateCard,
    currency: CurrencyCode,
    fee_count: Count,
) -> Result<i128, MoneyError> {
    let fee_minor = i128::from(card.per_request_fee(currency));
    let nanos_per_minor =
        i128::try_from(currency.nanos_per_minor()).map_err(|_| MoneyError::Overflow)?;
    let unit_price_nanos = fee_minor
        .checked_mul(nanos_per_minor)
        .ok_or(MoneyError::Overflow)?;
    fee_count
        .micros()
        .checked_mul(unit_price_nanos)
        .ok_or(MoneyError::Overflow)
}

/// Add one entry's pre-tier amount into its tier's bucket, CHECKED.
fn add_into(
    pre_tier: &mut BTreeMap<u32, i128>,
    tier_bp: u32,
    amount: i128,
) -> Result<(), MoneyError> {
    let slot = pre_tier.entry(tier_bp).or_insert(0);
    *slot = slot.checked_add(amount).ok_or(MoneyError::Overflow)?;
    Ok(())
}
