// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The budget ledger segmented by rate-card effective dates.

use std::collections::BTreeMap;

use crate::cost::{
    nanos_of_exact, whole, EntryKey, History, HistoryView, Money, MoneyError, RateCard, RawRateEra,
    Tally, STANDARD_TIER_BP,
};

/// One bucket's billable-request count (the flat fee's base), SPLIT BY THE ERA each request was
/// admitted under.
///
/// Only known eras are recorded: an identity or a nonzero historical timestamp, one entry per era
/// in the order they were first seen. Whatever of the bucket's billable total these entries do not
/// account for is era zero — so a cell charged where no history is installed records nothing here
/// and costs nothing more than it did, and a cell hydrated from an undated durable row needs no
/// seeding.
///
/// Beside the eras rides their request total, kept up to date as they are charged and refunded, so
/// [`FeeEras::split`] never walks them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FeeEras<E = u64>(Vec<(E, u64)>, u64);

/// Spelled as the dated eras alone: the total is derived from them.
impl<E: std::fmt::Debug> std::fmt::Debug for FeeEras<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FeeEras").field(&self.0).finish()
    }
}

impl<E: Copy + Eq + Into<RawRateEra> + From<u64>> FeeEras<E> {
    /// One request admitted under `era`. Legacy zero is the implicit remainder; a known opening
    pub fn charge(&mut self, era: E) {
        if era.into() == RawRateEra::legacy(0) {
            return;
        }
        match self.0.iter_mut().find(|(e, _)| *e == era) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => self.0.push((era, 1)),
        }
        self.1 = self.1.saturating_add(1);
    }

    /// One billable request refunded from the era it was ADMITTED under: `era` is the admission's
    pub fn refund(&mut self, era: E) {
        if let Some((_, n)) = self.0.iter_mut().find(|(e, n)| *e == era && *n > 0) {
            *n -= 1;
            self.1 = self.1.saturating_sub(1);
        }
    }

    /// The dated eras and their request counts, as recorded.
    pub fn dated(&self) -> &[(E, u64)] {
        &self.0
    }

    /// A split read back from its dated eras and counts; era zero, the remainder, is dropped.
    #[must_use]
    pub fn of(dated: impl IntoIterator<Item = (E, u64)>) -> Self {
        let eras: Vec<(E, u64)> = dated
            .into_iter()
            .filter(|(e, n)| (*e).into() != RawRateEra::legacy(0) && *n != 0)
            .collect();
        let total = eras.iter().fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        Self(eras, total)
    }

    /// The fee base per era, given the bucket's billable total: every dated era, then the undated
    pub fn split(&self, billable_total: u64) -> impl Iterator<Item = (E, u64)> + Clone + '_ {
        let dated = self.1;
        self.0.iter().copied().chain(std::iter::once((
            E::from(0),
            billable_total.saturating_sub(dated),
        )))
    }
}

/// The dated history a budget read resolves each era through. Every segment is priced at the
/// entry its era resolves to, including a voided original; amendments retain their own card.
#[derive(Clone, Copy)]
pub struct DatedHistory<'h> {
    /// The pinned snapshot the whole read resolves through.
    pub view: HistoryView<'h>,
}

impl<'h> DatedHistory<'h> {
    /// The history's current snapshot.
    pub fn of(history: &'h History) -> Self {
        DatedHistory {
            view: history.current(),
        }
    }
}

/// Price exact fractional counts through the same dated lookup and final projection.
pub fn price_dated_counts_raw<'r>(
    rows: impl IntoIterator<
        Item = (
            &'r str,
            RawRateEra,
            &'r BTreeMap<String, crate::cost::Count>,
        ),
        IntoIter: Clone,
    >,
    fees: impl IntoIterator<Item = (RawRateEra, u64), IntoIter: Clone>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    price_dated_at(rows, fees, window_start_ms, live, dated)
}

fn price_dated_at<'r, C: Copy + Into<crate::cost::Count> + 'r>(
    rows: impl IntoIterator<Item = (&'r str, RawRateEra, &'r BTreeMap<String, C>), IntoIter: Clone>,
    fees: impl IntoIterator<Item = (RawRateEra, u64), IntoIter: Clone>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    let view = dated.map(|d| d.view);
    let resolve = |era: RawRateEra| -> Result<(Option<EntryKey>, &RateCard), MoneyError> {
        let Some(view) = view.as_ref() else {
            return Ok((None, live));
        };
        let at = window_start_ms.max(era.effective_from);
        let (seq, card) = view
            .card_for_raw_era(era, at)
            .ok_or(MoneyError::NoCardInForce { at })?;
        Ok((Some(seq), card))
    };
    let (rows, fees) = (rows.into_iter(), fees.into_iter());
    // Every era resolves before anything prices, rows then fees, so a hole in the history refuses
    // ahead of any row's own refusal.
    for (_, era, _) in rows.clone() {
        resolve(era)?;
    }
    for (era, n) in fees.clone() {
        if n != 0 {
            resolve(era)?;
        }
    }
    // Each row and fee prices against its era's card at the standard tier, which is the identity,
    // so the per-era sums need no table of their own: one checked total of the per-row figures.
    let tally_at = |era: RawRateEra| -> Result<Tally<'_>, MoneyError> {
        Ok(match resolve(era)? {
            (Some(key), card) => Tally::at_card_seq(key, card),
            (None, card) => Tally::at_card(card),
        })
    };
    let mut exact = 0i128;
    for (lane, era, counts) in rows {
        let mut tally = tally_at(era)?;
        tally.row(
            lane,
            0,
            STANDARD_TIER_BP,
            counts
                .iter()
                .map(|(class, n)| (class.as_str(), (*n).into())),
            whole(0),
        )?;
        exact = exact
            .checked_add(tally.exact()?)
            .ok_or(MoneyError::Overflow)?;
    }
    for (era, n) in fees {
        if n != 0 {
            let mut tally = tally_at(era)?;
            tally.fee(0, STANDARD_TIER_BP, whole(n))?;
            exact = exact
                .checked_add(tally.exact()?)
                .ok_or(MoneyError::Overflow)?;
        }
    }

    Money::of_nanos(nanos_of_exact(exact)?)
}

/// A dated cell's segments folded back to ONE count map per lane, in first-seen order, with `add`
pub fn by_lane<'r, V: Copy>(
    segments: impl IntoIterator<Item = (&'r str, BTreeMap<String, V>), IntoIter: Clone>,
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
