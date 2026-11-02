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
//! they were earned. [`RawRateEra`] carries both the entry's `effective_from` and its identity,
//! because an unconfirmed activation can leave the previous entry serving across a later window.
//! Every read and the gate price each segment through the one function ([`crate::cost::Tally`]).
//!
//! **No price is stored (#71).** A segment is counts plus the era it was earned in; what the era's
//! card charges is looked up every time, so a signed back-dated correction still reaches it.
//!
//! **Era zero is "not dated".** A count accrued where no history is installed, or hydrated from a
//! durable row no card-era row dates, is legacy era zero and resolves at the window's start. A
//! known opening entry also starts at zero but carries its own identity; it is recorded explicitly
//! and remains the serving card even when a later configuration is present.

use std::collections::BTreeMap;

use crate::cost::{
    nanos_of_exact, whole, Author, History, HistorySeq, HistoryView, Money, MoneyError, RateCard,
    RawRateEra, Tally, STANDARD_TIER_BP,
};

/// One bucket's billable-request count (the flat fee's base), SPLIT BY THE ERA each request was
/// admitted under.
///
/// Only known eras are recorded: an identity or a nonzero historical timestamp, one entry per era
/// in the order they were first seen. Whatever of the bucket's billable total these entries do not
/// account for is era zero — so a cell charged where no history is installed records nothing here
/// and costs nothing more than it did, and a cell hydrated from an undated durable row needs no
/// seeding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeEras<E = u64>(Vec<(E, u64)>);

impl<E: Copy + Eq + Into<RawRateEra> + From<u64>> FeeEras<E> {
    /// One request admitted under `era`. Legacy zero is the implicit remainder; a known opening
    /// entry dated zero is recorded explicitly.
    pub fn charge(&mut self, era: E) {
        if era.into() == RawRateEra::legacy(0) {
            return;
        }
        match self.0.iter_mut().find(|(e, _)| *e == era) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => self.0.push((era, 1)),
        }
    }

    /// One billable request refunded from the era it was ADMITTED under: `era` is the admission's
    /// own, carried from its charge to its refund, so the fee that comes back is the one that request
    /// was charged — never another era's. Era zero, or an era this split no longer holds a request
    /// of, is the undated remainder. The caller decrements the bucket's total in the same step, so
    /// the remainder never goes negative.
    pub fn refund(&mut self, era: E) {
        if let Some((_, n)) = self.0.iter_mut().find(|(e, n)| *e == era && *n > 0) {
            *n -= 1;
        }
    }

    /// The dated eras and their request counts, as recorded.
    pub fn dated(&self) -> &[(E, u64)] {
        &self.0
    }

    /// A split read back from its dated eras and counts; era zero, the remainder, is dropped.
    #[must_use]
    pub fn of(dated: impl IntoIterator<Item = (E, u64)>) -> Self {
        Self(
            dated
                .into_iter()
                .filter(|(e, n)| (*e).into() != RawRateEra::legacy(0) && *n != 0)
                .collect(),
        )
    }

    /// The fee base per era, given the bucket's billable total: every dated era, then the undated
    /// remainder at era zero.
    pub fn split(&self, billable_total: u64) -> impl Iterator<Item = (E, u64)> + '_ {
        let dated = self
            .0
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        self.0.iter().copied().chain(std::iter::once((
            E::from(0),
            billable_total.saturating_sub(dated),
        )))
    }
}

/// The dated history a budget read resolves each era through, and the instant the read is taken at.
///
/// The instant matters for ONE thing: which entry is IN FORCE NOW. A segment whose era resolves to
/// that entry is priced at the caller's live card — the configuration the gate is enforcing this
/// instant, built by the same constructor from the same figures as the entry, and the only card that
/// also carries the open classes (item 123) a deployment configured. Amendments always retain their
/// own card. Every other segment is priced at its recorded entry, including a voided original.
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
/// - `rows`: `(lane, era, counts)` per (lane, era) segment the cell holds;
/// - `fees`: `(era, billable requests)` per era, when the fee is to be included;
/// - `window_start_ms`: the start of the cell's window. Amendments resolve at
///   `max(window_start_ms, era)`. A nonzero timestamp names its original entry, while legacy zero
///   retains the temporal lookup at the window start. New counts use [`price_dated_raw`] to retain
///   the exact serving identity, including a known opening entry;
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
    price_dated_at(
        rows.into_iter()
            .map(|(lane, era, counts)| (lane, RawRateEra::legacy(era), counts)),
        fees.into_iter()
            .map(|(era, count)| (RawRateEra::legacy(era), count)),
        window_start_ms,
        live,
        dated,
        true,
    )
}

/// Price counts carrying exact serving-entry provenance, while preserving legacy timestamp rows.
/// The window clips only the amendment instant. A configuration published later cannot replace
/// the entry whose identity the counts recorded, including an opening entry dated zero.
/// A history-backed read uses the entry's complete card, even if the caller's live configuration
/// differs from the fleet's current entry. `live` is used only when no history is installed.
pub fn price_dated_raw<'r>(
    rows: impl IntoIterator<Item = (&'r str, RawRateEra, &'r BTreeMap<String, u64>)>,
    fees: impl IntoIterator<Item = (RawRateEra, u64)>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    price_dated_at(rows, fees, window_start_ms, live, dated, false)
}

fn price_dated_at<'r>(
    rows: impl IntoIterator<Item = (&'r str, RawRateEra, &'r BTreeMap<String, u64>)>,
    fees: impl IntoIterator<Item = (RawRateEra, u64)>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
    legacy_live_card: bool,
) -> Result<Money, MoneyError> {
    let view = dated.map(|d| d.view);
    let in_force = dated.and_then(|d| {
        d.view
            .entry_at(d.now_ms)
            .filter(|entry| !matches!(entry.author(), Author::Amend { .. }))
            .map(|entry| entry.seq())
    });
    let resolve = |era: RawRateEra| -> Result<(HistorySeq, &RateCard), MoneyError> {
        let Some(view) = view.as_ref() else {
            return Ok((HistorySeq::OPENING, live));
        };
        let at = window_start_ms.max(era.effective_from);
        let (seq, card) = view
            .card_for_raw_era(era, at)
            .ok_or(MoneyError::NoCardInForce { at })?;
        Ok((
            seq,
            if legacy_live_card && Some(seq) == in_force {
                live
            } else {
                card
            },
        ))
    };
    // One tally per card resolved — almost always exactly one.
    let mut tallies: Vec<(HistorySeq, Tally<'_>)> = Vec::new();
    let mut tally_for = |era: RawRateEra| -> Result<usize, MoneyError> {
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
/// For the readers that must not see an era: the per-lane class gauges and the durable
/// write-behind row, which is per lane and carries no era. An undated cell folds to exactly the
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
