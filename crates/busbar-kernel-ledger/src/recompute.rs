// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Booked ledger lines, as the statement reads them, and the one lookup that prices one.
//!
//! A line carries QUANTITIES and the instant they happened, and nothing else about money: what it is
//! worth is the lookup's answer against the dated history at read time (#71, #77(3)). No price is
//! stored, so there is no cached figure to arbitrate: the check that a posted figure still agrees
//! with its counts is the boot reconciliation, which re-derives every settled figure from the
//! journal's counts and compares it with the book.
//!
//! ## The origin rule on the fee line
//!
//! The per-request fee is charged on client-originated work and not on the rest: a line whose origin
//! is not a client prices its fee line at zero. On a deployment with no rate card the fee line is the
//! whole of what a line costs.

use crate::cost::{
    price, HistorySeq, HistoryView, Posting as CostPosting, Priced, Quantity, Unpriceable,
};
use busbar_contract::caps::MeterClassId;

use crate::totals::TotalsKey;

/// Full price in basis points: the standard tier every posting is priced at, defined once.
pub const BASIS_POINTS: u32 = crate::cost::STANDARD_TIER_BP;

/// One quantity, against one declared class. The stored truth: no rate, no product, no money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedLine {
    /// Which class.
    pub class: MeterClassId,
    /// How much of it.
    pub quantity: u64,
}

/// Where a unit came from, as far as the fee line is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingOrigin {
    /// A client asked for this work; the per-request fee applies.
    Client,
    /// The node did this for its own reasons; the fee line prices at zero.
    Internal,
}

/// One booked ledger line, as the journal holds it.
///
/// **A booked line is never rewritten, and carries no price.** Everything on it is what happened:
/// an amendment to the history reprices this line as a dated view (#77(3)), never by editing it and
/// never by booking an adjusting line beside it (#77(2)). What it is worth is [`price_line`]'s
/// answer at read time, never a stored figure (#71).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    /// Which node wrote it.
    pub node: u64,
    /// That node's sequence number for it.
    pub node_seq: u64,
    /// Which balance it belongs to.
    pub key: TotalsKey,
    /// Which window.
    pub window_start: u64,
    /// The serving lane — the key the card is priced by, and the reason the books now keep it.
    pub lane: String,
    /// The quantities. THE STORED TRUTH.
    pub lines: Vec<PricedLine>,
    /// How many request fees the line carries.
    pub fee_count: u64,
    /// The tier applied, in basis points, as the line recorded it. A ledger fact like the
    /// quantities: every path that prices this line prices at THIS tier.
    pub tier_bp: u32,
    /// The instant it happened, in wall-clock milliseconds. The scale the history resolves at.
    pub arrived_ms: u64,
    /// Whether the fee line applies.
    pub origin: PostingOrigin,
}

/// Why a booked line cannot be priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// No entry of the snapshot covers the line's instant. A hole in the history is a refusal and
    /// never a zero: pricing an uncovered instant at nothing is how a gap becomes free service.
    NoCardInForce {
        /// The instant that fell in the hole.
        at: u64,
    },
    /// The card in force names no rate for the line's lane.
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the card is silent about.
        lane: String,
    },
    /// The card in force names the line's lane but not a class the line hit (#42).
    ClassUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the class was reported on.
        lane: String,
        /// The class the card is silent about.
        class: String,
    },
    /// The line's figure does not fit the arithmetic — a refusal, never a pinned figure (item 28).
    Overflow,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Divergence::NoCardInForce { at } => {
                write!(f, "no card is in force at instant {at}")
            }
            Divergence::LaneUnpriced { card_seq, lane } => write!(
                f,
                "the card at history entry {card_seq} names no rate for lane {lane}"
            ),
            Divergence::ClassUnpriced {
                card_seq,
                lane,
                class,
            } => write!(
                f,
                "the card at history entry {card_seq} names no rate for class {class} on lane {lane}"
            ),
            Divergence::Overflow => f.write_str("the line's figure leaves the representable range"),
        }
    }
}

/// The lookup's answer for one line under one snapshot, at `tier_bp` — which every caller passes
/// as the line's own [`Posting::tier_bp`].
///
/// This is the single place the ledger asks what a line costs. It builds the cost unit's posting
/// from the line's own quantities and hands it to the one lookup, rather than re-deriving a product
/// out of a card's parts: a second copy of the multiply-and-sum is how a request comes to be judged
/// at one figure and billed at another, and that has happened here before.
pub fn price_line(
    posting: &Posting,
    view: &HistoryView<'_>,
    tier_bp: u32,
) -> Result<Priced, Unpriceable> {
    let cost = CostPosting {
        lane: posting.lane.clone(),
        quantities: posting
            .lines
            .iter()
            .map(|line| Quantity::new(line.class.as_str(), line.quantity))
            .collect(),
        // The origin rule, applied by charging no fees rather than by a branch further down: a line
        // the node did for its own reasons carries no client request to charge one for.
        fee_count: match posting.origin {
            PostingOrigin::Client => posting.fee_count,
            PostingOrigin::Internal => 0,
        },
        tier_bp,
        arrived_ms: posting.arrived_ms,
        arrived_mono: 0,
        estimated: false,
        cached: None,
    };
    price(view, &cost)
}

/// Name a refusal from the lookup in the statement's own vocabulary: one conversion, in one place.
pub fn divergence_of(why: Unpriceable) -> Divergence {
    match why {
        Unpriceable::NoCardInForce { at } => Divergence::NoCardInForce { at },
        Unpriceable::LaneUnpriced { card_seq, lane } => Divergence::LaneUnpriced { card_seq, lane },
        Unpriceable::ClassUnpriced {
            card_seq,
            lane,
            class,
        } => Divergence::ClassUnpriced {
            card_seq,
            lane,
            class,
        },
        Unpriceable::Overflow => Divergence::Overflow,
    }
}
