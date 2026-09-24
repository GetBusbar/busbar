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
//! 3. **A card present but silent is a REFUSAL** (#42). An unnamed lane, an unnamed class: each
//!    refuses. Money-sacred means never inventing a zero. The FLAT FEE used to be a third member of
//!    that list — it read its figure out of a per-denomination map with `unwrap_or(0)`, so a card
//!    that priced its rates in one denomination and was never given a fee in it billed every flat
//!    fee at nothing, here, in silence. #66 removed the denomination axis, so the map is a single
//!    field and the hole it could carry no longer exists to be guarded.
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

use crate::cost::history::{History, HistorySeq, HistoryView};
use crate::cost::posting::{checked_apply_tier, STANDARD_TIER_BP};
use crate::cost::{NANOS_PER_CENT, NANOS_PER_MICRO};

/// Joins a plane key to its lane: `"<plane>\u{1f}<lane>"` is a lane priced by THAT plane's own card
/// (#42 "scoped per plane", #47). An unqualified lane is the flat card's — the llm (`pools`) plane's,
/// the only card config can author today — so a qualified lane resolves to an ABSENT card and reads 0
/// until its plane's section can carry one. U+001F is not a character a `models:` key is written with.
pub const PLANE_LANE_SEP: char = '\u{1f}';

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
/// `0.034510` is held as `34_510`. There is no currency in the type, no symbol on it, and no
/// currency ARGUMENT to the lookup that produced it (#66): what a figure is displayed as belongs to
/// the dashboard, downstream of this crate and invisible to it.
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

    /// The amount in whole MINOR units, truncated toward zero.
    ///
    /// The divisor is [`crate::cost::NANOS_PER_CENT`] over [`crate::cost::NANOS_PER_MICRO`] — THE
    /// ONE SCALE (#66), with no second divisor a reader could pick. This is the projection
    /// `spend_cents` has always been.
    pub fn minor(self) -> i128 {
        let micros_per_minor = i128::try_from(NANOS_PER_CENT / NANOS_PER_MICRO)
            .expect("the one minor scale fits an i128");
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
pub fn price(ledger: &[LedgerEntry], history: &History) -> Result<Money, MoneyError> {
    price_in_view(ledger, &history.current())
}

/// [`price`] against a PINNED snapshot of the history.
///
/// Pinned rather than re-read per entry: a card appended while a read is in flight must not price
/// half of one response's rows against one history and half against another. It is also the
/// reproducibility primitive — an invoice cut at a snapshot re-derives forever from that snapshot.
pub fn price_in_view(ledger: &[LedgerEntry], view: &HistoryView<'_>) -> Result<Money, MoneyError> {
    let exact = price_exact(ledger, view)?;
    // THE ONE TRUNCATION, and it is the last thing that happens. Toward zero, matching the
    // projection every 1.5.5 figure was already read through.
    Ok(Money(exact / EXACT_PER_MONEY))
}

/// [`price_in_view`] with the final projection WITHHELD: the exact accumulator at [`EXACT_SCALE`].
///
/// For a caller that must know whether the projection dropped anything — a reconciliation, a
/// property test, an auditor. `price_exact(..) % 1_000_000_000 == 0` is the statement "this figure
/// is exact at scale six", and it is a statement the truncated form cannot make about itself.
pub fn price_exact(ledger: &[LedgerEntry], view: &HistoryView<'_>) -> Result<i128, MoneyError> {
    let mut tally = Tally::in_view(*view);
    for entry in ledger {
        tally.row(
            &entry.lane,
            entry.arrived_ms,
            entry.tier_bp,
            entry
                .counts
                .iter()
                .map(|(class, count)| (class.as_str(), *count)),
            entry.fee_count,
        )?;
    }
    tally.exact()
}

/// A whole-unit count at [`MONEY_SCALE`] — the shape both books hold their counts in today.
///
/// `u64::MAX × 10^6` is about `1.8e25`, inside an `i128` by thirteen orders of magnitude, so this
/// cannot overflow and needs no error arm.
pub fn whole(count: u64) -> Count {
    Count::from_micros(i128::from(count) * MONEY_SCALE_FACTOR)
}

/// The divisor from the exact scale-15 accumulator to NANO-units (scale 9). Applied once, by
/// [`nanos_of_exact`].
const EXACT_PER_NANO: i128 = 1_000_000;

/// An exact scale-15 figure in whole NANO-units, truncated toward zero once — the unit the books
/// and the settlement posting store. `Err(Overflow)` for a figure below zero or past `u128`, which
/// the one function cannot produce from non-negative rates and counts; the arm exists so the
/// narrowing is total rather than a cast.
pub fn nanos_of_exact(exact: i128) -> Result<u128, MoneyError> {
    u128::try_from(exact / EXACT_PER_NANO).map_err(|_| MoneyError::Overflow)
}

impl Money {
    /// The micro-unit mantissa narrowed to the `i64` a served `spend_micros` field carries,
    /// CHECKED: a figure that does not fit is [`MoneyError::Overflow`], never pinned at
    /// `i64::MAX` (item 28 — a saturated bill is a wrong bill wearing a right bill's clothes).
    pub fn micros_i64(self) -> Result<i64, MoneyError> {
        i64::try_from(self.0).map_err(|_| MoneyError::Overflow)
    }

    /// Whole minor units narrowed to the `i64` a served `spend_cents` field carries, CHECKED.
    pub fn minor_i64(self) -> Result<i64, MoneyError> {
        i64::try_from(self.minor()).map_err(|_| MoneyError::Overflow)
    }

    /// A NANO-unit total — a ledger row's summed `priced_amount` — as [`Money`]: one truncation,
    /// toward zero, to scale six, CHECKED. The projection a nano-unit accumulator reads through
    /// (item 28): `Err(Overflow)` for a figure the type cannot hold, never a pin at a ceiling.
    pub fn of_nanos(nanos: u128) -> Result<Money, MoneyError> {
        i128::try_from(nanos / NANOS_PER_MICRO)
            .map(Money)
            .map_err(|_| MoneyError::Overflow)
    }
}

/// Where a [`Tally`] resolves the card a row prices against.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// A dated history snapshot: each row resolves `card_at(row.arrived_ms)` (#79).
    View(HistoryView<'a>),
    /// One card pinned by the caller, answering for every instant.
    Card(HistorySeq, &'a crate::cost::rate::RateCard),
}

/// **THE ONE FUNCTION, AS AN ACCUMULATOR.** `money = f(ledger counts, dated ratecard)`.
///
/// Every spend figure in this tree is this fold. [`price`], [`price_in_view`] and [`price_exact`]
/// drive it over a slice of [`LedgerEntry`]; the read-time derivation
/// ([`crate::cost::derive_spend_micros`]), the settlement lookup ([`crate::cost::price_at_card`]),
/// the kernel's enforcement reads and the budget door drive it over the rows THEY hold — borrowed,
/// with no conversion allocation — because a row is a lane, some counts keyed by class, a fee
/// count, a tier and an instant in every book, and asking the caller to rebuild a `LedgerEntry`
/// first would put a copy of the projection on the hot path of the door. What they may NOT do is
/// multiply, sum, tier, round, narrow, or decide what "unpriced" means: those are this type's,
/// once.
///
/// # The law, per row, in order
///
/// 1. Resolve the row's card — its own instant in a view (#79), or the one pinned card.
/// 2. **Card ABSENT** (billing off, #42): every class prices at nothing; the flat fee still posts.
///    The ONLY silent zero.
/// 3. **Card PRESENT, lane not named**: [`MoneyError::LaneUnpriced`]. **Class not priced** (a hit —
///    a zero count is still a hit): [`MoneyError::ClassUnpriced`]. Never a silent 0 (#42).
/// 4. Per unit, MULTIPLY: count (scale 6) × integer nano-unit rate → scale 15, exact (#44: a
///    per-unit rate is a multiply, never a division, never rounded).
/// 5. The flat fee is one dimension, a straight multiply, never rounded (#44).
/// 6. The tier applies ONCE per tier over that tier's summed pre-tier amount, half-to-even
///    ([`checked_apply_tier`] — #44's per-N-units term), IDENTICALLY for settlement and for every
///    read (item 27): a row carries its tier and this is the only place it is applied.
/// 7. Every operation is CHECKED. Overflow is [`MoneyError::Overflow`] — a refusal, never a pin
///    (item 28).
/// 8. One truncation, in the projection the caller asks for ([`Money`], [`nanos_of_exact`]).
pub struct Tally<'a> {
    source: Source<'a>,
    /// Pre-tier amount per tier, at the exact scale. One element for every slice this tree
    /// produces (every production posting is at the standard tier); a `Vec` so the common case is
    /// one small allocation and a linear scan of length one.
    pre_tier: Vec<(u32, i128)>,
}

impl<'a> Tally<'a> {
    /// A tally resolving each row's card from a dated history snapshot at the row's own instant.
    pub fn in_view(view: HistoryView<'a>) -> Tally<'a> {
        Tally {
            source: Source::View(view),
            pre_tier: Vec::new(),
        }
    }

    /// A tally pricing every row against ONE card — the reads that hold a current card rather than
    /// a history. The card answers for every instant as the opening entry would.
    pub fn at_card(card: &'a crate::cost::rate::RateCard) -> Tally<'a> {
        Tally::at_card_seq(HistorySeq::OPENING, card)
    }

    /// [`Self::at_card`] naming which history entry the pinned card is, for refusals that report it.
    pub fn at_card_seq(card_seq: HistorySeq, card: &'a crate::cost::rate::RateCard) -> Tally<'a> {
        Tally {
            source: Source::Card(card_seq, card),
            pre_tier: Vec::new(),
        }
    }

    /// Resolve the card for an instant.
    fn resolve(&self, at: u64) -> Result<(HistorySeq, &crate::cost::rate::RateCard), MoneyError> {
        match &self.source {
            Source::Card(seq, card) => Ok((*seq, *card)),
            Source::View(view) => view.card_at(at).ok_or(MoneyError::NoCardInForce { at }),
        }
    }

    /// Add one row: a lane, its counts keyed by class, its fee count, its tier and its instant.
    pub fn row<'c>(
        &mut self,
        lane: &str,
        arrived_ms: u64,
        tier_bp: u32,
        counts: impl IntoIterator<Item = (&'c str, Count)>,
        fee_count: Count,
    ) -> Result<(), MoneyError> {
        let (card_seq, card) = self.resolve(arrived_ms)?;

        // Another plane's lane is priced by its own card, never this one (#42/#47): absent, so 0.
        let amount = if card.pricing_enabled() && !lane.contains(PLANE_LANE_SEP) {
            // A present card that names no entry for the lane REFUSES.
            let rates = card
                .lane_rates(lane)
                .ok_or_else(|| MoneyError::LaneUnpriced {
                    card_seq,
                    lane: lane.to_string(),
                })?;
            let mut amount: i128 = 0;
            for (class, count) in counts {
                // #42 STATED AS AN ARM: a present card silent about a class the traffic HIT is a
                // refusal. A zero count is still a hit — the row reported the class.
                if !rates.class_priced(class) {
                    return Err(MoneyError::ClassUnpriced {
                        card_seq,
                        lane: lane.to_string(),
                        class: class.to_string(),
                    });
                }
                let line = count
                    .micros()
                    .checked_mul(i128::from(rates.nanos_per_unit(class)))
                    .ok_or(MoneyError::Overflow)?;
                amount = amount.checked_add(line).ok_or(MoneyError::Overflow)?;
            }
            amount
        } else {
            // BILLING OFF (#42): no rate card configured at all. Every class prices at nothing and
            // nothing is "unpriced" because there is no card to be missing from.
            0
        };

        let fee = fee_term(card, fee_count)?;
        let amount = amount.checked_add(fee).ok_or(MoneyError::Overflow)?;
        self.add(tier_bp, amount)
    }

    /// Add a row that carries the flat fee and no counts — a bucket's billable-request count, which
    /// the enforcement books keep per bucket rather than per lane. No lane is consulted, because
    /// the fee is one plane-agnostic dimension of the card (#44), priced whether the card is
    /// present or absent.
    pub fn fee(
        &mut self,
        arrived_ms: u64,
        tier_bp: u32,
        fee_count: Count,
    ) -> Result<(), MoneyError> {
        let (_card_seq, card) = self.resolve(arrived_ms)?;
        let fee = fee_term(card, fee_count)?;
        self.add(tier_bp, fee)
    }

    /// Add one pre-tier amount into its tier's bucket, CHECKED.
    fn add(&mut self, tier_bp: u32, amount: i128) -> Result<(), MoneyError> {
        match self.pre_tier.iter_mut().find(|(bp, _)| *bp == tier_bp) {
            Some((_, slot)) => *slot = slot.checked_add(amount).ok_or(MoneyError::Overflow)?,
            None => self.pre_tier.push((tier_bp, amount)),
        }
        Ok(())
    }

    /// The summed PRE-TIER amount at [`EXACT_SCALE`], across every tier, CHECKED.
    pub fn pre_tier_exact(&self) -> Result<i128, MoneyError> {
        self.pre_tier.iter().try_fold(0i128, |acc, (_, amount)| {
            acc.checked_add(*amount).ok_or(MoneyError::Overflow)
        })
    }

    /// **THE FIGURE**, at [`EXACT_SCALE`]: each tier's pre-tier sum through the tier once, summed,
    /// CHECKED. No truncation has happened yet.
    pub fn exact(&self) -> Result<i128, MoneyError> {
        let mut total: i128 = 0;
        for (tier_bp, amount) in &self.pre_tier {
            // THE ONE TIER ARITHMETIC, in its refusing form. The magnitude goes through the shared
            // function and the sign is re-applied here, because `checked_` is the one function's
            // overflow policy and the shared arithmetic must not carry a second one.
            let tiered_magnitude =
                checked_apply_tier(amount.unsigned_abs(), *tier_bp).ok_or(MoneyError::Overflow)?;
            let narrowed = i128::try_from(tiered_magnitude).map_err(|_| MoneyError::Overflow)?;
            let tiered = if amount.is_negative() {
                -narrowed
            } else {
                narrowed
            };
            total = total.checked_add(tiered).ok_or(MoneyError::Overflow)?;
        }
        Ok(total)
    }

    /// The figure as [`Money`] — THE ONE TRUNCATION, toward zero, to scale six.
    pub fn money(&self) -> Result<Money, MoneyError> {
        Ok(Money(self.exact()? / EXACT_PER_MONEY))
    }
}

/// The flat fee as a term of the accumulator: minor units lifted to nano-units, times the fee
/// count, at [`EXACT_SCALE`].
///
/// NEVER ROUNDED and never divided (#44) — a fee is one pricing dimension. Its unit price is an
/// exact multiple of one minor unit, which is the property that makes summing it in before the
/// single projection give the same answer as projecting the usage first and adding the fee after.
///
/// **AND NEVER A SILENT NOTHING.** A card carries exactly one fee and every constructor sets it
/// (#66 removed the per-currency map whose absent key used to read as zero), so a fee of nothing
/// can only be a fee an operator CONFIGURED at nothing — #77(5)'s explicit zero row.
///
/// It is the same term whether the card is present or absent, because an absent card still posts
/// its flat fee (#42 `BUSBAR-1.6.0.md:367`: *"rate_card ABSENT ⇒ NOT billed"* for the TOKENS; the
/// fee is what such a deployment is actually billed).
fn fee_term(card: &crate::cost::rate::RateCard, fee_count: Count) -> Result<i128, MoneyError> {
    let fee_minor = i128::from(card.fee());
    let nanos_per_minor = i128::try_from(NANOS_PER_CENT).map_err(|_| MoneyError::Overflow)?;
    let unit_price_nanos = fee_minor
        .checked_mul(nanos_per_minor)
        .ok_or(MoneyError::Overflow)?;
    fee_count
        .micros()
        .checked_mul(unit_price_nanos)
        .ok_or(MoneyError::Overflow)
}
