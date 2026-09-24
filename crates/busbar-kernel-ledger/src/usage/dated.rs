// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BUDGET LEDGER, DATED (OWNER RULING Q14, DECISION #79).
//!
//! A budget cell counts what a bucket consumed in its window. Until this module it counted NOTHING
//! ELSE, and a count with no instant can only be priced at one card: the current one. So a card
//! edit in the middle of a window repriced every token the bucket had already consumed, on
//! `GET /keys/{id}/usage`, on `GET /groups/{name}/usage`, on the `/metrics` spend gauges and — the
//! same derivation — at the budget gate that decides who is served. `GET /admin/usage` prices the
//! metering rows of the same consumption at the card in force when each was earned, so the two
//! reads of one consumption disagreed (worked: 1,500 dated against 1,200 served).
//!
//! The owner ruled: DATE EVERYTHING. The cell's counts are SEGMENTED BY THE CARD ERA in force when
//! they were earned — the same `effective_from` boundary a metering row carries as
//! `priced_from_ms` — and every read and the gate price each segment through the one function
//! ([`crate::cost::Tally`]) at the card [`crate::cost::HistoryView::card_at`] resolves for it.
//!
//! **No price is stored (#71).** A segment is counts plus the era it was earned in; what the era's
//! card charges is looked up every time, so a signed back-dated correction still reaches it.
//!
//! **Era zero is "not dated".** A count accrued where no history is installed, or hydrated from a
//! durable row that carries no era, is era zero: the opening entry's own `effective_from`, the card
//! a deployment that never edited a price has always priced at. A cell that is never edited holds
//! nothing but era zero, and prices exactly as the undated derivation did.

use std::collections::BTreeMap;

use crate::cost::{
    nanos_of_exact, whole, History, HistorySeq, HistoryView, Money, MoneyError, RateCard, Tally,
    STANDARD_TIER_BP,
};

/// One bucket's billable-request count (the flat fee's base), SPLIT BY THE ERA each request was
/// admitted under.
///
/// Only DATED eras are recorded: a non-zero era the request was admitted under, one entry per era
/// in the order they were first seen. Whatever of the bucket's billable total these entries do not
/// account for is era zero — so a cell charged where no history is installed records nothing here
/// and costs nothing more than it did, and a cell hydrated from an undated durable row needs no
/// seeding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeEras(Vec<(u64, u64)>);

impl FeeEras {
    /// One request admitted under `era`. Era zero is the implicit remainder and is not recorded.
    pub fn charge(&mut self, era: u64) {
        if era == 0 {
            return;
        }
        match self.0.iter_mut().find(|(e, _)| *e == era) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => self.0.push((era, 1)),
        }
    }

    /// One billable request refunded: taken from the NEWEST dated era still holding one, or from the
    /// undated remainder when none does.
    ///
    /// A refund names no era — the request's own admission instant is not carried to its refund —
    /// and the newest era is where a request that failed just now was most recently admitted. The
    /// caller decrements the bucket's total in the same step, so the remainder never goes negative.
    pub fn refund(&mut self) {
        if let Some((_, n)) = self
            .0
            .iter_mut()
            .filter(|(_, n)| *n > 0)
            .max_by_key(|(e, _)| *e)
        {
            *n -= 1;
        }
    }

    /// The fee base per era, given the bucket's billable total: every dated era, then the undated
    /// remainder at era zero.
    pub fn split(&self, billable_total: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let dated = self
            .0
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        self.0
            .iter()
            .copied()
            .chain(std::iter::once((0, billable_total.saturating_sub(dated))))
    }
}

/// The dated history a budget read resolves each era through, and the instant the read is taken at.
///
/// The instant matters for ONE thing: which entry is IN FORCE NOW. A segment whose era resolves to
/// that entry is priced at the caller's live card — the configuration the gate is enforcing this
/// instant, built by the same constructor from the same figures as the entry, and the only card that
/// also carries the open classes (item 123) a deployment configured. Every OTHER segment is priced at
/// the entry its own instant resolves to.
#[derive(Clone, Copy)]
pub struct DatedHistory<'h> {
    /// The pinned snapshot the whole read resolves through.
    pub view: HistoryView<'h>,
    /// The read's own wall-clock instant, in milliseconds — the history's scale.
    pub now_ms: u64,
}

impl<'h> DatedHistory<'h> {
    /// The history's current snapshot, read at `now_ms`.
    pub fn of(history: &'h History, now_ms: u64) -> Self {
        DatedHistory {
            view: history.current(),
            now_ms,
        }
    }
}

/// **A DATED BUDGET CELL, PRICED.** `money = f(ledger counts, dated ratecard)` over one bucket.
///
/// - `rows`: `(lane, era, counts)` per (model, era) segment the cell holds;
/// - `fees`: `(era, billable requests)` per era, when the fee is to be included;
/// - `window_start_ms`: the start of the cell's window. A segment resolves at
///   `max(window_start_ms, era)` — its OWN first instant, the rule a metering row resolves by, so a
///   back-dated correction over the window reaches the segment and an era that began before the
///   window prices at the card in force when the window opened;
/// - `live`: the caller's current card;
/// - `dated`: the history, or `None` where none is installed — then every segment prices at `live`,
///   exactly the undated derivation.
///
/// Every segment goes through [`Tally`], the one function, at the card resolved for it: an unpriced
/// lane or class REFUSES (#42), an overflow REFUSES (item 28), a hole in the history REFUSES
/// ([`MoneyError::NoCardInForce`]). The segments' exact figures are summed CHECKED and truncated
/// ONCE, toward zero, to [`Money`] — never rounded per era.
pub fn price_dated<'r>(
    rows: impl IntoIterator<Item = (&'r str, u64, &'r BTreeMap<String, u64>)>,
    fees: impl IntoIterator<Item = (u64, u64)>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    let view = dated.map(|d| d.view);
    let in_force = dated.and_then(|d| d.view.card_at(d.now_ms).map(|(seq, _)| seq));
    let resolve = |era: u64| -> Result<(HistorySeq, &RateCard), MoneyError> {
        let Some(view) = view.as_ref() else {
            return Ok((HistorySeq::OPENING, live));
        };
        let at = window_start_ms.max(era);
        let (seq, card) = view.card_at(at).ok_or(MoneyError::NoCardInForce { at })?;
        Ok((seq, if Some(seq) == in_force { live } else { card }))
    };
    // One tally per card resolved — almost always exactly one.
    let mut tallies: Vec<(HistorySeq, Tally<'_>)> = Vec::new();
    let mut tally_for = |era: u64| -> Result<usize, MoneyError> {
        let (seq, card) = resolve(era)?;
        Ok(match tallies.iter().position(|(s, _)| *s == seq) {
            Some(i) => i,
            None => {
                tallies.push((seq, Tally::at_card_seq(seq, card)));
                tallies.len() - 1
            }
        })
    };
    let mut rows_at: Vec<(usize, &str, &BTreeMap<String, u64>)> = Vec::new();
    for (lane, era, counts) in rows {
        rows_at.push((tally_for(era)?, lane, counts));
    }
    let mut fees_at: Vec<(usize, u64)> = Vec::new();
    for (era, n) in fees {
        if n != 0 {
            fees_at.push((tally_for(era)?, n));
        }
    }
    for (i, lane, counts) in rows_at {
        tallies[i].1.row(
            lane,
            0,
            STANDARD_TIER_BP,
            counts.iter().map(|(class, n)| (class.as_str(), whole(*n))),
            whole(0),
        )?;
    }
    for (i, n) in fees_at {
        tallies[i].1.fee(0, STANDARD_TIER_BP, whole(n))?;
    }
    let exact = tallies.iter().try_fold(0i128, |acc, (_, t)| {
        acc.checked_add(t.exact()?).ok_or(MoneyError::Overflow)
    })?;
    // THE ONE TRUNCATION, through the sanctioned projections: exact → nano → money, each toward
    // zero, which for a non-negative figure is one truncation from exact to money.
    Money::of_nanos(nanos_of_exact(exact)?)
}

/// A dated cell's segments folded back to ONE count map per lane, in first-seen order, with `add`
/// combining a lane's eras class by class.
///
/// For the readers that must not see an era: the per-model token gauges and the durable
/// write-behind row, which is per model and carries no era. An undated cell folds to exactly the
/// maps it holds.
pub fn by_lane<'r, V: Copy>(
    segments: impl IntoIterator<Item = (&'r str, BTreeMap<String, V>)>,
    add: impl Fn(V, V) -> V,
) -> Vec<(String, BTreeMap<String, V>)> {
    let mut out: Vec<(String, BTreeMap<String, V>)> = Vec::new();
    for (lane, counts) in segments {
        match out.iter_mut().find(|(name, _)| name == lane) {
            None => out.push((lane.to_string(), counts)),
            Some((_, into)) => {
                for (class, v) in counts {
                    let merged = into.get(&class).map_or(v, |have| add(*have, v));
                    into.insert(class, merged);
                }
            }
        }
    }
    out
}
