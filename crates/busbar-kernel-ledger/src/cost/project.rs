// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read-time derivation the legacy usage endpoint still performs.
//!
//! The pinning projections that used to live here — `minor_of`, `cents_of`, `micros_of` — answered
//! `i64::MAX` for a figure past the served range: a bill nobody posted (item 28). They are deleted.
//! A nano-unit total projects through the one money type, [`crate::cost::Money::of_nanos`] and its
//! checked narrowings, which REFUSE instead. What is left reprices a token ledger against a card at
//! read time — the card the history says was in force, rather than whatever is configured at the
//! moment of the read.

use std::collections::BTreeMap;

use busbar_contract::caps::UsageLine;

use crate::cost::rate::RateCard;
use crate::cost::{
    plane_fee_lane, price_in_view, split_plane_lane, whole, HistoryView, LedgerEntry, MoneyError,
    Tally, PER_REQUEST, STANDARD_TIER_BP,
};

/// Derive what a ledger view costs, in minor units, against one card: every lane the bucket used,
/// plus — when asked for — the flat fee times the billable request count.
///
/// **THE ONE FUNCTION'S, NOT A COPY OF IT** (items 104, 25). This used to be its own
/// multiply-and-sum with its own posture on every question the one function answers: a lane the
/// card did not name was SKIPPED (priced free), a class the card was silent about priced at zero,
/// and a sum past the range pinned at `i64::MAX`. Each of those is now the one function's answer,
/// because this is [`crate::cost::Tally`] at the card:
///
/// - card ABSENT: tokens price at nothing, the fee posts (#42's only silent zero);
/// - card PRESENT and the lane or a hit class unpriced: `Err` — a refusal, never a free line (#42);
/// - overflow: `Err(Overflow)` — a refusal, never a pinned bill (item 28).
///
/// One truncation, at the very end: two lanes each worth half a minor unit make a whole one.
pub fn derive_spend_cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<i64, MoneyError> {
    tally(card, lanes, fee_requests, include_request_fee)?
        .money()?
        .minor_i64()
}

/// As [`derive_spend_cents`] but in micro-units, for the finer projections.
///
/// The fee is a minor unit lifted by the one scale ([`crate::cost::MICROS_PER_CENT`] micro-units
/// each), inside the one function, so a deployment's figures are unchanged to the byte.
pub fn derive_spend_micros<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<i64, MoneyError> {
    tally(card, lanes, fee_requests, include_request_fee)?
        .money()?
        .micros_i64()
}

/// Drive the one function over a bucket's lanes at one card: one row per lane at the standard tier
/// (a bucket view carries no tier), then the bucket's fee row.
fn tally<'a, 'c>(
    card: &'c RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<Tally<'c>, MoneyError> {
    let mut t = Tally::at_card(card);
    for (lane, lines) in lanes {
        t.row(
            lane,
            0,
            STANDARD_TIER_BP,
            lines.iter().map(|l| (l.class.as_str(), whole(l.quantity))),
            whole(0),
        )?;
    }
    if include_request_fee {
        t.fee(0, STANDARD_TIER_BP, whole(fee_requests))?;
    }
    Ok(t)
}

/// ONE METERING ROW, AS ITS READER HOLDS IT: the lane it was metered on, its counts by class, its
/// request count and its ledgered classes. The reader names its own columns and does nothing else.
/// Which lane a count prices on, whether the requests are the pools plane's flat fee or a plane's
/// own fee units, and where a plane's session count goes is decided HERE, in the cost unit, next
/// to the price (ARCHITECT ruling 2026-09-30, one-pricing-site): a reader that projected the row
/// itself and handed the slice in would be choosing the price's inputs beside the one function.
///
/// The two reads below price the same projection two ways: in the dated history at the row's own
/// instant (#79), and at one card when no history is installed (the previous release's reading).
pub struct MeteredRow<'r> {
    lane: &'r str,
    counts: BTreeMap<String, u64>,
    requests: u64,
    classes: &'r BTreeMap<String, u64>,
}

impl<'r> MeteredRow<'r> {
    /// `lane` is the row's configured model name after alias resolution, or a plane's
    /// `"<plane>\u{1f}<subject>"` lane. `counts` is the row's token split under the reserved class
    /// spellings, a zero left off. `classes` are its other ledgered counts.
    pub fn new(
        lane: &'r str,
        counts: BTreeMap<String, u64>,
        requests: u64,
        classes: &'r BTreeMap<String, u64>,
    ) -> MeteredRow<'r> {
        MeteredRow {
            lane,
            counts,
            requests,
            classes,
        }
    }

    /// The row as the lanes the one function prices, with no arithmetic: each lane with its counts
    /// per class, and the flat fee count when the requests are the pools plane's (`None` for a
    /// plane's row, whose requests are its own fee units).
    ///
    /// A PLANE'S ROW prices its requests the way the budget book does (#47): one PER_REQUEST each
    /// on that plane's FEE LANE, at the plane's own `fees.per_request` (0 when it configured none),
    /// never at the pools plane's flat fee. Its other counts price on its plane-qualified lane, and
    /// the plane's FEE LANE row (`("", <plane>)`) carries its session count on the fee lane itself.
    #[allow(clippy::type_complexity)]
    fn lanes(&self) -> (Vec<(String, BTreeMap<String, u64>)>, Option<u64>) {
        let mut counts = self.counts.clone();
        let (plane, subject) = split_plane_lane(self.lane);
        if plane.is_empty() {
            add_classes(&mut counts, self.classes);
            return (vec![(self.lane.to_string(), counts)], Some(self.requests));
        }
        let mut fees = BTreeMap::from([(PER_REQUEST.to_string(), self.requests)]);
        add_classes(
            if subject.is_empty() {
                &mut fees
            } else {
                &mut counts
            },
            self.classes,
        );
        let mut lanes = vec![(plane_fee_lane(plane), fees)];
        if !counts.is_empty() {
            lanes.push((self.lane.to_string(), counts));
        }
        (lanes, None)
    }

    /// What the row cost, in micro-units, against the card in force at `arrived_ms` (#79): the row
    /// as a ledger slice, priced by the one function, [`price_in_view`]. A refusal is the answer
    /// (#42): an unnamed lane or class, no card in force, or a total past the range is an `Err`.
    pub fn spend_micros_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i64, MoneyError> {
        let (lanes, fee_count) = self.lanes();
        let entries: Vec<LedgerEntry> = lanes
            .iter()
            .map(|(lane, counts)| {
                let entry = counts.iter().fold(
                    LedgerEntry::new(lane.as_str(), arrived_ms),
                    |e, (class, quantity)| e.with_whole(class, *quantity),
                );
                match fee_count {
                    Some(n) => entry.with_fee_count(n),
                    None => entry,
                }
            })
            .collect();
        price_in_view(&entries, view)?.micros_i64()
    }

    /// What the row cost, in micro-units, at one `card`: the reading when no dated history is
    /// installed. [`Tally`] at that card, one row per lane at the standard tier (a metering row
    /// carries no tier), then the pools fee row.
    pub fn spend_micros_at_card(&self, card: &RateCard) -> Result<i64, MoneyError> {
        let (lanes, fee_count) = self.lanes();
        let mut t = Tally::at_card(card);
        for (lane, counts) in &lanes {
            t.row(
                lane,
                0,
                STANDARD_TIER_BP,
                counts.iter().map(|(class, n)| (class.as_str(), whole(*n))),
                whole(0),
            )?;
        }
        if let Some(n) = fee_count {
            t.fee(0, STANDARD_TIER_BP, whole(n))?;
        }
        t.money()?.micros_i64()
    }
}

/// Fold a row's ledgered classes into a lane's counts, additively (never overwriting a token tier).
fn add_classes(into: &mut BTreeMap<String, u64>, classes: &BTreeMap<String, u64>) {
    for (class, n) in classes.iter().filter(|(_, n)| **n != 0) {
        let cur = into.entry(class.clone()).or_insert(0);
        *cur = cur.saturating_add(*n);
    }
}
