// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read-time derivation the legacy usage endpoint still performs.

use std::collections::BTreeMap;

use crate::cost::rate::RateCard;
use crate::cost::{
    plane_fee_lane, price_exact, price_in_view, split_plane_lane, whole, HistorySeq, HistoryView,
    LedgerEntry, MoneyError, Tally, PER_REQUEST, STANDARD_TIER_BP,
};

/// ONE METERING ROW, AS ITS READER HOLDS IT: the lane it was metered on, its counts by class, its
pub struct MeteredRow<'r> {
    lane: &'r str,
    counts: BTreeMap<String, u64>,
    requests: u64,
    classes: &'r BTreeMap<String, u64>,
}

impl<'r> MeteredRow<'r> {
    /// `lane` is the row's configured lane name after alias resolution, or a plane's
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
    pub fn spend_micros_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i64, MoneyError> {
        price_in_view(&self.entries(arrived_ms), view)?.micros_i64()
    }

    /// [`MeteredRow::spend_micros_in_view`] with the final projection WITHHELD: the exact figure
    pub fn exact_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i128, MoneyError> {
        price_exact(&self.entries(arrived_ms), view)
    }

    /// The row as the ledger slice the one function prices, at `arrived_ms`.
    fn entries(&self, arrived_ms: u64) -> Vec<LedgerEntry> {
        let (lanes, fee_count) = self.lanes();
        lanes
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
            .collect()
    }

    /// What the row cost, in micro-units, at one `card`: the reading when no dated history is
    pub fn spend_micros_at_card(&self, card: &RateCard) -> Result<i64, MoneyError> {
        self.spend_micros_at_card_seq(HistorySeq::OPENING, card)
    }

    /// The row at an already resolved card and its snapshot sequence. A reader resolving exact
    pub fn spend_micros_at_card_seq(
        &self,
        seq: HistorySeq,
        card: &RateCard,
    ) -> Result<i64, MoneyError> {
        let (lanes, fee_count) = self.lanes();
        let mut t = Tally::at_card_seq(seq, card);
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
