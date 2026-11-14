// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read-time derivation the legacy usage endpoint still performs.

use busbar_contract::count::Count;
use std::collections::BTreeMap;

use crate::cost::rate::RateCard;
use crate::cost::{
    split_plane_lane, whole, EntryKey, HistoryView, Money, MoneyError, Tally, PER_REQUEST,
    PLANE_LANE_SEP, STANDARD_TIER_BP,
};

/// ONE METERING ROW, AS ITS READER HOLDS IT: the lane it was metered on, its counts by class, its
pub struct MeteredRow<'r> {
    lane: &'r str,
    counts: BTreeMap<String, Count>,
    requests: u64,
    classes: BTreeMap<String, Count>,
}

/// One lane of a row as the one function prices it: its name, its counts by class, and the row's
/// fee count when the lane carries it.
type LaneVisit<'v> = dyn FnMut(&str, &mut dyn Iterator<Item = (&str, Count)>, Option<u64>) -> Result<(), MoneyError>
    + 'v;

impl<'r> MeteredRow<'r> {
    /// `lane` is the row's configured lane name after alias resolution, or a plane's
    #[cfg(test)]
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

    /// Walk the row as the lanes the one function prices, with no arithmetic and nothing copied:
    /// each lane with its counts by class — the row's counts with its ledgered classes folded in
    /// additively (never overwriting a token tier), key by key — and the row's fee count on the one
    /// lane that carries it. A fold that overflows refuses before any lane is visited.
    fn each_lane(&self, visit: &mut LaneVisit<'_>) -> Result<(), MoneyError> {
        if crate::cost::split_measurement_lane(self.lane).is_some() {
            // Common measurement facts live exclusively in open classes. Legacy token fields
            // are placeholders, including when a declared common class is named `input`.
            return visit(self.lane, &mut counted(&self.classes), None);
        }
        let (plane, subject) = split_plane_lane(self.lane);
        if plane.is_empty() {
            folded(counted(&self.counts), Some(&self.classes)).try_for_each(|n| n.map(drop))?;
            return visit(
                self.lane,
                &mut folded(counted(&self.counts), Some(&self.classes)).map_while(Result::ok),
                Some(self.requests),
            );
        }
        let per_request = [(PER_REQUEST, whole(self.requests))];
        let (fee_classes, lane_classes) = if subject.is_empty() {
            (Some(&self.classes), None)
        } else {
            (None, Some(&self.classes))
        };
        folded(per_request.into_iter(), fee_classes).try_for_each(|n| n.map(drop))?;
        folded(counted(&self.counts), lane_classes).try_for_each(|n| n.map(drop))?;
        // The plane's fee lane, `"<plane>\u{1f}"`, is this row's own lane up to its separator.
        let fee_lane = &self.lane[..plane.len() + PLANE_LANE_SEP.len_utf8()];
        visit(
            fee_lane,
            &mut folded(per_request.into_iter(), fee_classes).map_while(Result::ok),
            None,
        )?;
        if folded(counted(&self.counts), lane_classes).next().is_some() {
            visit(
                self.lane,
                &mut folded(counted(&self.counts), lane_classes).map_while(Result::ok),
                None,
            )?;
        }
        Ok(())
    }

    /// What the row cost, in micro-units, against the card in force at `arrived_ms` (#79): the row
    pub fn spend_micros_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i64, MoneyError> {
        Money::of_exact(self.exact_in_view(arrived_ms, view)?).micros_i64()
    }

    /// [`MeteredRow::spend_micros_in_view`] with the final projection WITHHELD: the exact figure
    pub fn exact_in_view(
        &self,
        arrived_ms: u64,
        view: &HistoryView<'_>,
    ) -> Result<i128, MoneyError> {
        let mut t = Tally::in_view(*view);
        self.each_lane(&mut |lane, counts, fee| {
            t.row(
                lane,
                arrived_ms,
                STANDARD_TIER_BP,
                counts,
                fee.map_or(Count::from_micros(0), whole),
            )
        })?;
        t.exact()
    }

    /// What the row cost, in micro-units, at one `card`: the reading when no dated history is
    pub fn spend_micros_at_card(&self, card: &RateCard) -> Result<i64, MoneyError> {
        Money::of_exact(self.exact_at_card(card)?).micros_i64()
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
        self.each_lane(&mut |lane, counts, fee| {
            t.row(lane, 0, STANDARD_TIER_BP, counts, whole(0))?;
            match fee {
                Some(n) => t.fee(0, STANDARD_TIER_BP, whole(n)),
                None => Ok(()),
            }
        })?;
        t.exact()
    }
}

/// A class map's counts, borrowed, in key order.
fn counted(map: &BTreeMap<String, Count>) -> impl Iterator<Item = (&str, Count)> + Clone {
    map.iter().map(|(class, n)| (class.as_str(), *n))
}

/// `base` (in key order) with `extra`'s non-zero counts folded in additively, key by key, in key
/// order: the map a fold of `extra` into `base` would build, walked rather than built. A class in
/// both answers its CHECKED sum, so an overflow surfaces as an `Err` item.
fn folded<'m>(
    base: impl Iterator<Item = (&'m str, Count)>,
    extra: Option<&'m BTreeMap<String, Count>>,
) -> impl Iterator<Item = Result<(&'m str, Count), MoneyError>> {
    let mut base = base.peekable();
    let mut extra = extra
        .into_iter()
        .flatten()
        .filter(|(_, n)| !n.is_zero())
        .map(|(class, n)| (class.as_str(), *n))
        .peekable();
    std::iter::from_fn(move || {
        let pick = match (base.peek(), extra.peek()) {
            (None, None) => return None,
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some((b, _)), Some((e, _))) => b.cmp(e),
        };
        Some(match pick {
            std::cmp::Ordering::Less => Ok(base.next()?),
            std::cmp::Ordering::Greater => Ok(extra.next()?),
            std::cmp::Ordering::Equal => {
                let (class, have) = base.next()?;
                let (_, add) = extra.next()?;
                have.checked_add(add)
                    .map(|sum| (class, sum))
                    .map_err(|_| MoneyError::Overflow)
            }
        })
    })
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
