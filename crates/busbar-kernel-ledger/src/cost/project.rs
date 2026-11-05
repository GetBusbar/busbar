// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read-time derivation the legacy usage endpoint still performs.

use busbar_contract::count::Count;
use std::collections::BTreeMap;

use crate::cost::rate::RateCard;
use crate::cost::{
    plane_fee_lane, price_exact, price_in_view, split_plane_lane, whole, EntryKey, HistoryView,
    LedgerEntry, Money, MoneyError, Tally, PER_REQUEST, STANDARD_TIER_BP,
};

/// ONE METERING ROW, AS ITS READER HOLDS IT: the lane it was metered on, its counts by class, its
pub struct MeteredRow<'r> {
    lane: &'r str,
    counts: BTreeMap<String, Count>,
    requests: u64,
    classes: BTreeMap<String, Count>,
}

impl<'r> MeteredRow<'r> {
    /// `lane` is the row's configured lane name after alias resolution, or a plane's
    pub fn new(
        lane: &'r str,
        counts: BTreeMap<String, u64>,
        requests: u64,
        classes: &'r BTreeMap<String, u64>,
    ) -> MeteredRow<'r> {
        Self::exact(
            lane,
            counts.into_iter().map(|(k, v)| (k, whole(v))).collect(),
            requests,
            classes
                .iter()
                .map(|(k, v)| (k.clone(), whole(*v)))
                .collect(),
        )
    }

    /// Construct a read-time row without projecting fractional quantities to whole units.
    pub fn exact(
        lane: &'r str,
        counts: BTreeMap<String, Count>,
        requests: u64,
        classes: BTreeMap<String, Count>,
    ) -> Self {
        Self {
            lane,
            counts,
            requests,
            classes,
        }
    }

    /// The row as the lanes the one function prices, with no arithmetic: each lane with its counts
    #[allow(clippy::type_complexity)]
    fn lanes(&self) -> Result<(Vec<(String, BTreeMap<String, Count>)>, Option<u64>), MoneyError> {
        let mut counts = self.counts.clone();
        let (plane, subject) = split_plane_lane(self.lane);
        if plane.is_empty() {
            add_classes(&mut counts, &self.classes)?;
            return Ok((vec![(self.lane.to_string(), counts)], Some(self.requests)));
        }
        let mut fees = BTreeMap::from([(PER_REQUEST.to_string(), whole(self.requests))]);
        add_classes(
            if subject.is_empty() {
                &mut fees
            } else {
                &mut counts
            },
            &self.classes,
        )?;
        let mut lanes = vec![(plane_fee_lane(plane), fees)];
        if !counts.is_empty() {
            lanes.push((self.lane.to_string(), counts));
        }
        Ok((lanes, None))
    }

    /// What the row cost, in micro-units, against the card in force at `arrived_ms` (#79): the row
    pub fn spend_micros_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i64, MoneyError> {
        price_in_view(&self.entries(arrived_ms)?, view)?.micros_i64()
    }

    /// [`MeteredRow::spend_micros_in_view`] with the final projection WITHHELD: the exact figure
    pub fn exact_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i128, MoneyError> {
        price_exact(&self.entries(arrived_ms)?, view)
    }

    /// The row as the ledger slice the one function prices, at `arrived_ms`.
    fn entries(&self, arrived_ms: u64) -> Result<Vec<LedgerEntry>, MoneyError> {
        let (lanes, fee_count) = self.lanes()?;
        Ok(lanes
            .iter()
            .map(|(lane, counts)| {
                let entry = counts.iter().fold(
                    LedgerEntry::new(lane.as_str(), arrived_ms),
                    |e, (class, quantity)| e.with_count(class, *quantity),
                );
                match fee_count {
                    Some(n) => entry.with_fee_count(n),
                    None => entry,
                }
            })
            .collect())
    }

    /// What the row cost, in micro-units, at one `card`: the reading when no dated history is
    pub fn spend_micros_at_card(&self, card: &RateCard) -> Result<i64, MoneyError> {
        Money::of_exact(self.exact_at_card(card)?).micros_i64()
    }

    /// The row at an already resolved card and its actual history-entry key.
    pub fn spend_micros_at_card_seq(
        &self,
        seq: EntryKey,
        card: &RateCard,
    ) -> Result<i64, MoneyError> {
        Money::of_exact(self.exact_at_card_seq(seq, card)?).micros_i64()
    }

    /// Retain the exact scale-15 figure for aggregation across rows.
    pub fn exact_at_card(&self, card: &RateCard) -> Result<i128, MoneyError> {
        self.exact_with_tally(Tally::at_card(card))
    }

    /// Retain the exact figure at the resolved historical entry.
    pub fn exact_at_card_seq(&self, seq: EntryKey, card: &RateCard) -> Result<i128, MoneyError> {
        self.exact_with_tally(Tally::at_card_seq(seq, card))
    }

    fn exact_with_tally(&self, mut t: Tally<'_>) -> Result<i128, MoneyError> {
        let (lanes, fee_count) = self.lanes()?;
        for (lane, counts) in &lanes {
            t.row(
                lane,
                0,
                STANDARD_TIER_BP,
                counts.iter().map(|(class, n)| (class.as_str(), *n)),
                whole(0),
            )?;
        }
        if let Some(n) = fee_count {
            t.fee(0, STANDARD_TIER_BP, whole(n))?;
        }
        t.exact()
    }
}

/// Fold a row's ledgered classes into a lane's counts, additively (never overwriting a token tier).
fn add_classes(
    into: &mut BTreeMap<String, Count>,
    classes: &BTreeMap<String, Count>,
) -> Result<(), MoneyError> {
    for (class, n) in classes.iter().filter(|(_, n)| !n.is_zero()) {
        let cur = into.entry(class.clone()).or_default();
        *cur = cur.checked_add(*n).map_err(|_| MoneyError::Overflow)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{History, LaneClass};

    #[test]
    fn exact_row_prices_fractional_token_and_open_class_with_the_same_tally() {
        let card = RateCard::from_micro_rates(
            [
                (LaneClass::new("lane", "input"), 16.0),
                (LaneClass::new("lane", "seconds"), 4.0),
            ],
            0,
        );
        let counts = BTreeMap::from([("input".into(), Count::parse("27.5").unwrap())]);
        let classes = BTreeMap::from([("seconds".into(), Count::parse("0.25").unwrap())]);
        let row = MeteredRow::exact("lane", counts.clone(), 0, classes.clone());
        let mut tally = Tally::at_card(&card);
        tally
            .row(
                "lane",
                0,
                STANDARD_TIER_BP,
                counts
                    .iter()
                    .chain(classes.iter())
                    .map(|(k, v)| (k.as_str(), *v)),
                Count::ZERO,
            )
            .unwrap();
        let expected = tally.money().unwrap().micros_i64().unwrap();
        assert_eq!(expected, 441);
        assert_eq!(row.spend_micros_at_card(&card).unwrap(), expected);
        let history = History::opening(card, 0);
        assert_eq!(
            row.spend_micros_in_view(0, &history.current()).unwrap(),
            expected
        );
    }

    #[test]
    fn whole_constructor_keeps_legacy_units_and_duplicate_classes_refuse_overflow() {
        let card = RateCard::from_micro_rates([(LaneClass::new("lane", "input"), 16.0)], 0);
        let empty = BTreeMap::new();
        let legacy = MeteredRow::new("lane", BTreeMap::from([("input".into(), 27)]), 0, &empty);
        assert_eq!(legacy.spend_micros_at_card(&card).unwrap(), 432);
        let overflow = MeteredRow::exact(
            "lane",
            BTreeMap::from([("input".into(), Count::from_micros(i128::MAX))]),
            0,
            BTreeMap::from([("input".into(), Count::EPSILON)]),
        );
        assert_eq!(
            overflow.spend_micros_at_card(&card),
            Err(MoneyError::Overflow)
        );
    }
}
