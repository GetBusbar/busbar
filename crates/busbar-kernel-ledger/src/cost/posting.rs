// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happened, and what it costs.
//!
//! Those are two different things and this file keeps them apart. A [`Posting`] is WHAT HAPPENED:
//! quantities per meter class, the lane they were served on, the flat-fee count, the tier and the
//! instant. There is no money in it anywhere. A [`Priced`] is what a lookup ANSWERED: the same
//! quantities against the card in force at that instant. It is derived, it is reproducible, and it
//! is never stored as truth.
//!
//! A posting may carry a [`CachedPrice`] — the figure the node computed at settlement, kept so a
//! read is cheap and a recompute has something to compare against. It is not authoritative and
//! nothing in this file will read it to answer a question about money: [`Posting::priced_nanos`]
//! performs the lookup and ignores the cache entirely, so a corrupted cache cannot become a bill.

use busbar_contract::caps::Usage;

use crate::cost::history::{HistorySeq, HistoryView};
use crate::cost::rate::RateCard;

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
    pub fn priced_nanos(&self, view: &HistoryView<'_>) -> Result<u128, Unpriceable> {
        price(view, self).map(|p| p.priced_nanos)
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
                c.card_seq != priced.card_seq
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
    /// The answer in whole minor units — one truncation over the summed nano-units, floored at
    /// zero, at the one scale (#66).
    pub fn minor(&self) -> i64 {
        crate::cost::project::minor_of(self.priced_nanos)
    }

    /// The answer in micro-units — one truncation over the summed nano-units, NOT floored.
    pub fn micros(&self) -> i64 {
        crate::cost::project::micros_of(self.priced_nanos)
    }

    /// Every class the card was present for but silent about. The flat fee is never among them:
    /// a card carries exactly one fee and every constructor sets it, so a fee can be an explicit
    /// zero (#77(5) `BUSBAR-1.6.0.md:420`) but never a silence.
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
///
/// Apply the tier multiplier once, over the summed pre-tier amount, with a single divide.
/// A sum of per-line floors is the wrong answer and undercharges: two lines of five nano-units at
/// half price are two floors of two, which is four, where the single divide over ten is five.
///
/// # It rounds HALF-TO-EVEN, because it is a per-N-units division term
///
/// `× tier_bp / 10_000` is a division by N, and #44 (`BUSBAR-1.6.0.md:372`) rules that *"only a
/// 'per-N-units' division term uses banker's (half-to-even) rounding"*. #81 (`:428`) restates it
/// after the exact-count ruling — *"a per-N-units division term still uses banker's rounding (#44),
/// because a DIVISION can genuinely be inexact where a MEASUREMENT cannot"* — so the rule survives
/// the amendment that changed everything around it. Half-away-from-zero is the OTHER rule in #44,
/// and it is reserved for card-build quantisation ([`crate::cost::nano_rate`]); it is not this
/// term's rule and applying it here would be reading the wrong half of the row.
///
/// This used to truncate toward zero, which is not rounding — it is a discount the operator never
/// configured, taken in one direction, forever. Fifteen nano-units at 5,000 bp is `7.5`: truncation
/// billed `7`, half-to-even bills `8`. Five nano-units at 5,000 bp is `2.5`: both give `2`, and
/// that agreement is luck, not policy.
///
/// # The divide comes FIRST, so the saturation cannot under-bill
///
/// The previous implementation was `pre.saturating_mul(bp) / 10_000`, and the saturation it added
/// for safety was the defect: pinning the PRODUCT at `u128::MAX` and then dividing by ten thousand
/// yields a figure ten thousand times too small. It fired at the NEUTRAL tier, which is the tier
/// every posting this node writes actually carries — `apply_tier(u128::MAX, 10_000)` returned
/// `34028236692093846346337460743176821` where `×1` must return `u128::MAX` itself,
/// `340282366920938463463374607431768211455`. A guard that under-bills by four orders of magnitude
/// at the identity multiplier is worse than no guard, because no guard at least panics in debug.
///
/// So the exact quotient is taken apart instead. With `pre = q·N + r`, the value
/// `pre·bp / N` is exactly `q·bp + (r·bp)/N`, and `r·bp` is bounded by `N × u32::MAX` — nowhere
/// near a `u128`. Only `q·bp` can genuinely exceed the type, and when it does the true answer
/// really is past the ceiling, which is the one case where pinning there is the honest reading.
/// Below the ceiling this is exact integer arithmetic and saturation changes no answer.
pub fn apply_tier(pre_tier_amount: u128, tier_bp: u32) -> u128 {
    checked_apply_tier(pre_tier_amount, tier_bp).unwrap_or(u128::MAX)
}

/// [`apply_tier`]'s arithmetic, refusing instead of pinning: `None` exactly when the true tiered
/// amount does not fit a `u128`.
///
/// The exact-money reader (`price_exact`) refuses an overflow rather than billing a ceiling, and it
/// must not carry a second copy of the tier rule to do it. This is the same computation with the
/// same rounding; only the last step differs, which is the only thing the two callers disagree
/// about.
pub fn checked_apply_tier(pre_tier_amount: u128, tier_bp: u32) -> Option<u128> {
    let n = u128::from(STANDARD_TIER_BP);
    let bp = u128::from(tier_bp);

    // `pre = q·N + r`. Splitting before the multiply is what keeps the product inside the type:
    // `r < N`, so `r·bp` is at most ten thousand times a `u32` and cannot overflow, and `q·bp` is
    // the only term big enough to leave the `u128` — and if it does, so does the answer.
    let (q, r) = (pre_tier_amount / n, pre_tier_amount % n);
    let tail = r * bp;
    let whole = q.checked_mul(bp)?.checked_add(tail / n)?;
    let remainder = tail % n;

    // HALF-TO-EVEN over the exact remainder (#44 `:372`, #81 `:428`). Compared as `remainder × 2`
    // against `N` rather than as `remainder` against `N / 2`, so the tie is the exact half and not
    // a half that a divide has already rounded. `remainder < N = 10_000`, so the doubling is safe.
    let round_up = match (remainder * 2).cmp(&n) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Exactly one half: go to the EVEN neighbour. Over many postings that is the property that
        // makes the rounding cost nothing on average, which is the whole reason #44 names it.
        std::cmp::Ordering::Equal => whole % 2 == 1,
    };
    if round_up {
        whole.checked_add(1)
    } else {
        Some(whole)
    }
}

/// [`apply_tier`] over a SIGNED amount — the same arithmetic, on a column that can hold a reversal.
///
/// A reversal is a negative amount (`totals.rs` says why the books are signed), and a tier applies
/// to it exactly as it applies to a charge. The sign is taken off, the one arithmetic runs on the
/// magnitude, and the sign goes back on: half-to-even is symmetric about zero, so `2.5` bills `2`
/// and `-2.5` reverses `-2`, and a customer cannot be moved by choosing which side of the ledger a
/// correction is written on.
///
/// It is a sign adapter and NOT a second implementation: there is no arithmetic decision in it. The
/// tree used to carry a genuine second one — `recompute::apply_tier`, `i128 → i128`, re-exported as
/// `busbar_kernel_ledger::apply_tier` beside this crate's `cost::apply_tier`, so a caller writing
/// `use busbar_kernel_ledger::apply_tier` and one writing `use busbar_kernel_ledger::cost::apply_tier`
/// got different functions. They agreed, which is what made deleting one of them the fix and a test
/// that they still agree the wrong fix: the day either was corrected, the recompute that exists to
/// DETECT a tier divergence would have become the divergence, on every posting in the book at once.
pub fn apply_tier_signed(pre_tier_amount: i128, tier_bp: u32) -> i128 {
    let magnitude = apply_tier(pre_tier_amount.unsigned_abs(), tier_bp);
    if pre_tier_amount.is_negative() {
        // The two halves do NOT narrow to the same bound. `i128::MIN` has no positive twin, so a
        // reversal reaches one nano-unit further than a charge can, and narrowing through
        // `i128::MAX` and negating would lose that one unit at the floor — on the reversal of the
        // largest charge the type can hold, which is the worst place to lose one.
        i128::try_from(magnitude).map_or(i128::MIN, |v| -v)
    } else {
        i128::try_from(magnitude).unwrap_or(i128::MAX)
    }
}

/// **THE LOOKUP** — the whole of layer two, and the only place money is computed.
///
/// Resolve the card in force at the posting's instant under this snapshot, then price the
/// quantities against it. The order is fixed and is the whole of the law:
/// each quantity prices at amount times the card's integer rate; the flat fee joins as its own line
/// at the fee's minor units lifted to nano-units; those line amounts sum to the pre-tier amount; the
/// tier multiplier applies once to that sum. Nothing is truncated until a projection asks.
///
/// It reads no clock, no store and no configuration. The view is a borrowed slice, so an auditor
/// holding the postings and the history re-derives every invoice by hand.
pub fn price(view: &HistoryView<'_>, posting: &Posting) -> Result<Priced, Unpriceable> {
    let (card_seq, card) = view
        .card_at(posting.arrived_ms)
        .ok_or(Unpriceable::NoCardInForce {
            at: posting.arrived_ms,
        })?;
    price_at_card(card_seq, card, posting)
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
) -> Result<Priced, Unpriceable> {
    let rates = card.lane_rates(&posting.lane);
    let mut lines: Vec<PricedLine> = Vec::with_capacity(posting.quantities.len() + 1);

    for quantity in &posting.quantities {
        let class = quantity.class.as_str();
        // A lane a present card does not name prices at nothing, and every one of its lines is
        // reported unpriced — the caller decides whether that is a refusal
        // ([`price_fail_closed`] does).
        let (unit_price_nanos, priced) = match &rates {
            Some(r) => (u128::from(r.nanos_per_unit(class)), r.class_priced(class)),
            None => (0u128, false),
        };
        lines.push(PricedLine {
            class: class.to_string(),
            quantity: quantity.amount,
            unit_price_nanos,
            // A `u64` quantity times a `u64` rate is inside a `u128` by a whole bit: exact, with
            // no saturation to hide behind. The SUM is the one function's, below.
            amount_nanos: u128::from(quantity.amount) * unit_price_nanos,
            unpriced: !priced,
        });
    }

    // The fee is a usage line, not a scalar bolted onto the total. A card carries exactly ONE fee
    // and every constructor sets it, so this line is never a silent zero read out of a map that
    // does not hold the key (#77(5) `BUSBAR-1.6.0.md:420`).
    let fee_unit_price_nanos = card.fee_unit_price_nanos();
    lines.push(PricedLine {
        class: FEE_CLASS.to_string(),
        quantity: posting.fee_count,
        unit_price_nanos: fee_unit_price_nanos,
        amount_nanos: u128::from(posting.fee_count).saturating_mul(fee_unit_price_nanos),
        unpriced: false,
    });

    // **THE FIGURE IS THE ONE FUNCTION'S** (items 104, 27, 28). This lookup used to carry its own
    // multiply-and-sum, its own saturating overflow policy and its own tier call: the sixth copy.
    // It now lists the lines (which is what a statement shows) and hands the SAME quantities to
    // [`crate::cost::Tally`] at the same card, tier and instant — so the settled figure and every
    // read's figure are one arithmetic, one tier rule, one overflow refusal.
    //
    // The READ posture is kept, and stated rather than hidden: a line this card cannot price is
    // FLAGGED (`unpriced`) and contributes nothing to the figure; a lane the card does not name
    // contributes only its fee. [`price_fail_closed`] — the settlement posture — refuses both.
    let mut tally = crate::cost::Tally::at_card_seq(card_seq, card);
    let tallied = match &rates {
        Some(_) => tally.row(
            &posting.lane,
            posting.arrived_ms,
            posting.tier_bp,
            lines
                .iter()
                .take(posting.quantities.len())
                .filter(|l| !l.unpriced)
                .map(|l| (l.class.as_str(), crate::cost::whole(l.quantity))),
            crate::cost::whole(posting.fee_count),
        ),
        None => tally.fee(
            posting.arrived_ms,
            posting.tier_bp,
            crate::cost::whole(posting.fee_count),
        ),
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
        lane_unpriced: rates.is_none(),
        tier_bp: posting.tier_bp,
        fee_count: posting.fee_count,
        estimated: posting.estimated,
    })
}

/// The settlement posture: [`price`], and a lane a present card is silent about is a REFUSAL rather
/// than a figure of nothing.
///
/// A policy wrapper and nothing else — it performs no arithmetic of its own and cannot disagree with
/// [`price`] about a figure, because it either returns that call's answer or returns an error. The
/// two postures exist because reads and settlement want different things from the same lookup: a
/// read reports an unpriced lane per row so an operator can see it, and a settlement that refuses
/// unpriced usage fails closed rather than serving for free. Neither posture is ever a SILENT
/// nothing: the read says it on the line, and settlement says it here.
pub fn price_fail_closed(view: &HistoryView<'_>, posting: &Posting) -> Result<Priced, Unpriceable> {
    let priced = price(view, posting)?;
    if priced.lane_unpriced {
        return Err(Unpriceable::LaneUnpriced {
            card_seq: priced.card_seq,
            lane: posting.lane.clone(),
        });
    }
    // #42 for a CLASS as well as a lane: a present card silent about a class the posting hit
    // refuses here exactly as the one function refuses it (`MoneyError::ClassUnpriced`).
    if let Some(line) = priced.lines.iter().find(|l| l.unpriced) {
        return Err(Unpriceable::ClassUnpriced {
            card_seq: priced.card_seq,
            lane: posting.lane.clone(),
            class: line.class.clone(),
        });
    }
    Ok(priced)
}
