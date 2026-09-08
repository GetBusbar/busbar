// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for CostUnit`, in the exemplar's file position.

use busbar_caps::step::Admit;
use busbar_caps::{Unit, UnitToken, Usage};

use crate::posting::{price, Posting};
use crate::rate::PinnedCard;

/// Everything the loop hands this unit inside the admit step.
pub struct PriceInput<'a> {
    /// The rate card, pinned for the length of the decision.
    pub pinned: &'a PinnedCard<'a>,
    /// The lane being priced.
    pub lane: &'a str,
    /// What the unit used.
    pub usage: &'a Usage,
    /// How many fees this unit draws.
    pub fee_count: u64,
    /// The tier, in basis points.
    pub tier_bp: u32,
}

/// The cost unit, as the thing the loop is handed.
///
/// A zero-sized type because pricing is a pure function of its inputs; the crate had no unit struct
/// before, and the kind's shape is one type per crate implementing one trait.
pub struct CostUnit;

/// The cost unit SERVES the admit step: it prices, and the door decides.
///
/// `OWNS_ITS_STEP` is `false` because the root's own table says the admit row is "the admission
/// unit, priced by the cost unit". The admit step's `Facts` are an `Admission` — a hold or a spend
/// against a parent's — and opening one takes the admit token, which is the door's. A cost unit
/// that answered `Decision<Admit>` would have to be lent the token that opens holds in order to
/// report a number.
impl Unit for CostUnit {
    type Step = Admit;
    type Input<'a> = PriceInput<'a>;
    type Answer<'a> = Posting;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(&'a mut self, _token: &'a UnitToken<Admit>, input: PriceInput<'a>) -> Posting {
        price(
            input.pinned,
            input.lane,
            input.usage,
            input.fee_count,
            input.tier_bp,
        )
    }
}
