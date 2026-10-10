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
//! A posting may carry a [`CachedPrice`] — the figure the settlement lookup answered. Nothing reads
//! it back: the one production writer sets it on a posting it then drops, no read sums it, and no
//! comparison against it runs. [`Posting::priced_nanos`] performs the lookup and ignores the field
//! entirely, so a corrupted figure there cannot become a bill.

use busbar_contract::caps::Usage;

use crate::cost::history::{HistorySeq, HistoryView};
use crate::cost::rate::{ClassPrice, RateCard};

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

/// What the settlement lookup answered, in the shape a posting can carry beside its quantities.
///
/// **NEVER A TRUTH, AND NEVER READ.** It is re-derivable from the posting and the history at any
/// time, and the lookup is the only figure anything uses. The settlement path sets it on the posting
/// it prices and then drops that posting; no statement, totals read or recompute reads it, and no
/// check compares it with a lookup. A price stored on a row is the stored price #77(3) forbids, so
/// nothing is built on this one.
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
    /// The figure the settlement lookup answered, if one was set. `None` for a posting nothing has
    /// priced yet, which is a different thing from a figure of zero. Nothing reads it back.
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
    /// invariant stated as code rather than as a comment: a posting whose stored figure has been
    /// corrupted answers exactly what the quantities and the history say, because that figure is not
    /// on the path at all.
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
    /// a card carries exactly one fee and every constructor sets it, so a fee can be an explicit
    /// zero (#77(5)) but never a silence.
    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class.as_str())
            .collect()
    }

    /// This answer in the shape a posting carries it, under a named snapshot ([`CachedPrice`]).
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
/// `pre_tier_amount × tier_bp / 10_000`, exactly, rounded HALF-TO-EVEN, or `None` exactly when the
/// true tiered amount does not fit a `u128`. Applied once, over a summed pre-tier amount, with a
/// single divide. A sum of per-line floors is the wrong answer and undercharges: two lines of five
/// at half price are two floors of two, which is four, where the single divide over ten is five.
///
/// Its one caller is the one function's accumulator ([`crate::cost::Tally::exact`]), which refuses
/// an overflow rather than billing a ceiling (item 28). There is no pinning or signed form of this
/// rule: both were wrappers nothing in production called, and they are gone.
///
/// # It rounds HALF-TO-EVEN, because it is a per-N-units division term
///
/// `× tier_bp / 10_000` is a division by N, and #44 rules that *"only a 'per-N-units' division term
/// uses banker's (half-to-even) rounding"*. #81 restates it after the exact-count ruling — *"a
/// per-N-units division term still uses banker's rounding (#44), because a DIVISION can genuinely
/// be inexact where a MEASUREMENT cannot"* — so the rule survives the amendment that changed
/// everything around it. Half-away-from-zero is the OTHER rule in #44, and it is reserved for
/// card-build quantisation ([`crate::cost::nano_rate`]); it is not this term's rule and applying it
/// here would be reading the wrong half of the row.
///
/// # Where the rounding lands on a bill
///
/// The function rounds at whatever scale it is handed, and the accumulator hands it the EXACT
/// scale-15 sum ([`crate::cost::EXACT_SCALE`]), so the division is rounded there, far below one
/// nano-unit. The billed figure is then the single truncation toward zero to nano-units
/// ([`crate::cost::nanos_of_exact`]) or micro-units ([`crate::cost::Money`]) — the projection 1.5.5
/// read every figure through. Fifteen nano-units at 5,000 bp are `7_500_000` at scale 15, exactly
/// half of `15_000_000`, so nothing rounds and the bill truncates to `7`. Handed the whole-nano
/// amount `15` directly, the function would round the `7.5` to the even `8`; no caller hands it
/// one. Every production posting is at [`STANDARD_TIER_BP`], where neither step moves a figure.
///
/// # The divide comes FIRST, so a large amount is exact
///
/// An earlier implementation was `pre.saturating_mul(bp) / 10_000`, and the saturation it added for
/// safety was the defect: pinning the PRODUCT at `u128::MAX` and then dividing by ten thousand
/// yields a figure ten thousand times too small, and it fired at the NEUTRAL tier, which is the tier
/// every posting this node writes actually carries.
///
/// So the exact quotient is taken apart instead. With `pre = q·N + r`, the value `pre·bp / N` is
/// exactly `q·bp + (r·bp)/N`, and `r·bp` is bounded by `N × u32::MAX` — nowhere near a `u128`. Only
/// `q·bp` can genuinely exceed the type, and when it does the true answer really is past the
/// ceiling, which is the one case this refuses.
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

    // HALF-TO-EVEN over the exact remainder (#44, #81). Compared as `remainder × 2`
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
    // THE ONE LANE RESOLUTION, the same one the accumulator takes
    // ([`crate::cost::RateCard::lane_pricing`]): which plane's card prices the lane, whether it is
    // a plane's fee lane, and what each class on it costs. A lane a present card does not name
    // prices at nothing and every one of its lines is reported unpriced — the caller decides
    // whether that is a refusal ([`price_fail_closed`] does).
    let pricing = card.lane_pricing(&posting.lane);
    let mut lines: Vec<PricedLine> = Vec::with_capacity(posting.quantities.len() + 1);

    for quantity in &posting.quantities {
        let class = quantity.class.as_str();
        let (unit_price_nanos, priced) = match pricing.class_price(class) {
            // A plane's fee unit on its fee lane: the plane's own fee, lifted to nano-units (#44).
            ClassPrice::FeeMinor(fee_minor) => (
                u128::try_from(fee_minor)
                    .unwrap_or(0)
                    .saturating_mul(crate::cost::NANOS_PER_CENT),
                true,
            ),
            ClassPrice::Nanos(nanos) => (u128::from(nanos), true),
            ClassPrice::Unpriced => (0u128, false),
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
    // does not hold the key (#77(5)).
    // The lane's OWN plane's fee (#47): the flat card's for an unqualified lane.
    let fee_unit_price_nanos = pricing.card.fee_unit_price_nanos();
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
