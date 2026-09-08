// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for CostUnit`, in the exemplar's file position.

use busbar_caps::step::Admit;
use busbar_caps::{Unit, UnitToken};

use crate::currency::CurrencyCode;
use crate::history::HistorySeq;
use crate::posting::{price_at_card, Posting, Priced, Unpriceable};
use crate::rate::RateCard;

/// Everything the loop hands this unit inside the admit step.
pub struct PriceInput<'a> {
    /// The history sequence of the card pinned for the length of the decision — carried so a
    /// refusal names the card that refused rather than "some card".
    pub card_seq: HistorySeq,
    /// The rate card, pinned for the length of the decision.
    pub card: &'a RateCard,
    /// The sealed quantities being priced. The lane, the instant and the fee count are all its
    /// own fields, so nothing is passed twice and nothing can disagree.
    pub posting: &'a Posting,
    /// The currency the answer is asked in.
    pub currency: CurrencyCode,
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
    type Answer<'a> = Result<Priced, Unpriceable>;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Admit>,
        input: PriceInput<'a>,
    ) -> Result<Priced, Unpriceable> {
        price_at_card(input.card_seq, input.card, input.posting, input.currency)
    }
}
