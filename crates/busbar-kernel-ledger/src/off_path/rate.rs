// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Building a rate card: from configuration once, at boot or on a reload, and a signed correction of
//! one on an operator's edit; never per request. The request path only prices with the card built
//! here.

use std::collections::BTreeMap;

use crate::cost::{
    flat_card_present, representable_nano_rate, split_measurement_lane, split_plane_lane,
    CellPrices, LaneClass, PlaneFees, RateCard, TierRates,
};

/// COMPOSE one card map from the flat card and each plane's own card: a plane's lanes are qualified
pub fn compose_plane_cards<E: Clone + Default>(
    flat: Option<&BTreeMap<String, E>>,
    planes: &BTreeMap<String, BTreeMap<String, E>>,
) -> Option<BTreeMap<String, E>> {
    if planes.is_empty() {
        return flat.cloned();
    }
    let sep = crate::cost::PLANE_LANE_SEP;
    let mut out = flat.cloned().unwrap_or_default();
    if flat.is_some() {
        out.insert(sep.to_string(), E::default());
    }
    for (plane, card) in planes {
        out.insert(format!("{plane}{sep}"), E::default());
        out.extend(
            card.iter()
                .map(|(lane, e)| (format!("{plane}{sep}{lane}"), e.clone())),
        );
    }
    Some(out)
}

impl RateCard {
    /// Resolve a card from configured micro-unit rates. Each rate converts to nano-units once, by
    pub fn from_micro_rates(
        entries: impl IntoIterator<Item = (LaneClass, f64)>,
        per_request_fee: i64,
    ) -> Self {
        RateCard::from_cells(
            entries
                .into_iter()
                .map(|(cell, micro)| (cell, representable_nano_rate(micro))),
            per_request_fee,
        )
    }

    /// A present card from cells ALREADY converted at the intake: `Some` an integer nano-unit rate,
    fn from_cells(
        entries: impl IntoIterator<Item = (LaneClass, Option<u64>)>,
        per_request_fee: i64,
    ) -> Self {
        let mut card = RateCard {
            present: true,
            prices: BTreeMap::new(),
            fee: per_request_fee.max(0),
            refused: Vec::new(),
            planes: BTreeMap::new(),
            measurements: BTreeMap::new(),
            session_fee: 0,
        };
        for (cell, nanos) in entries {
            card.place_rate(cell, nanos);
        }
        card
    }

    /// Resolve a card from rates ALREADY in integer nano-units per unit — for a holder whose rates
    pub fn from_nano_rates(
        entries: impl IntoIterator<Item = (LaneClass, u64)>,
        per_request_fee: i64,
    ) -> Self {
        RateCard::from_cells(
            entries.into_iter().map(|(cell, nanos)| (cell, Some(nanos))),
            per_request_fee,
        )
    }

    /// **THE CARD A DEPLOYMENT CONFIGURED**, built here and nowhere else.
    pub fn from_config<'a>(
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee: i64,
    ) -> Self {
        let Some(lanes) = lanes else {
            return RateCard::absent(per_request_fee);
        };
        let mut by_plane: BTreeMap<&str, Vec<(LaneClass, Option<u64>)>> = BTreeMap::new();
        let mut has_measurements = false;
        for (key, tiers) in lanes {
            if split_measurement_lane(key).is_some() {
                has_measurements = true;
                continue;
            }
            let (plane, lane) = split_plane_lane(key);
            let cells = by_plane.entry(plane).or_default();
            if !lane.is_empty() {
                cells.extend(
                    tiers
                        .by_class()
                        .map(|(class, nanos)| (LaneClass::new(lane, class), nanos)),
                );
            }
        }
        let flat_present = flat_card_present(by_plane.keys().copied())
            && (!by_plane.is_empty() || !has_measurements);
        let flat = by_plane.remove("").unwrap_or_default();
        let mut card = if flat_present {
            RateCard::from_cells(flat, per_request_fee)
        } else {
            RateCard::absent(per_request_fee)
        };
        let planes = by_plane
            .into_iter()
            .map(|(plane, cells)| (plane.to_string(), RateCard::from_cells(cells, 0)))
            .collect();
        card.planes = planes;
        card
    }

    /// **THE OPEN CLASSES a deployment configured**: each `(lane, class)` cell set to an
    pub fn with_unit_rates(mut self, cells: impl IntoIterator<Item = (LaneClass, u64)>) -> Self {
        for (cell, nanos) in cells {
            if split_measurement_lane(&cell.lane).is_some() {
                self.place_rate(cell, Some(nanos));
                continue;
            }
            let (plane, lane) = split_plane_lane(&cell.lane);
            let card = match plane {
                "" => &mut self,
                plane => match self.planes.get_mut(plane) {
                    Some(card) => card,
                    None => continue,
                },
            };
            if card.present && !lane.is_empty() {
                card.prices
                    .entry(lane.to_string())
                    .or_default()
                    .entry(cell.class)
                    .or_default()
                    .set(nanos);
            }
        }
        self
    }

    /// **EACH PLANE'S OWN FEES** (#47), by plane key: set on that plane's card, or on an ABSENT card
    pub fn with_plane_fees<'p>(
        mut self,
        fees: impl IntoIterator<Item = (&'p str, PlaneFees)>,
    ) -> Self {
        for (plane, f) in fees {
            let card = self
                .planes
                .entry(plane.to_string())
                .or_insert_with(|| RateCard::absent(0));
            card.fee = f.per_request.max(0);
            card.session_fee = f.per_session.max(0);
        }
        self
    }

    /// **A SIGNED CORRECTION OF THIS CARD** (#79): this card with the named cells set to the
    pub fn corrected(
        &self,
        cells: impl IntoIterator<Item = (LaneClass, u64)>,
        fee: Option<i64>,
    ) -> Option<RateCard> {
        let mut card = self.clone();
        if let Some(fee) = fee {
            card.fee = fee.max(0);
        }
        for (cell, nanos) in cells {
            if let Some((kind, namespace)) = split_measurement_lane(&cell.lane) {
                card.measurements
                    .entry(kind.to_string())
                    .or_insert_with(|| RateCard::from_cells([], 0))
                    .place_rate(LaneClass::new(namespace, &cell.class), Some(nanos));
                continue;
            }
            let (plane, lane) = split_plane_lane(&cell.lane);
            if lane.is_empty() {
                return None;
            }
            let target = match plane {
                "" => &mut card,
                plane => card.planes.get_mut(plane)?,
            };
            if !target.present {
                return None;
            }

            target
                .refused
                .retain(|r| !(r.lane == lane && r.class == cell.class));
            target
                .prices
                .entry(lane.to_string())
                .or_default()
                .entry(cell.class)
                .or_default()
                .set(nanos);
        }
        Some(card)
    }

    /// **THE CARD'S DIGEST**: `sha256` over every figure the card prices with, in one fixed order.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = b"busbar/rate-card-digest/v1\0".to_vec();
        self.digest_into(&mut bytes);
        busbar_contract::abi::sdk::digest::sha256(&bytes)
    }

    /// The bytes [`Self::digest`] hashes: length-prefixed, every map in its own (sorted) order.
    fn digest_into(&self, out: &mut Vec<u8>) {
        fn count(out: &mut Vec<u8>, n: usize) {
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
        fn text(out: &mut Vec<u8>, s: &str) {
            count(out, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        out.push(u8::from(self.present));
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.session_fee.to_le_bytes());
        count(out, self.prices.len());
        for (lane, classes) in &self.prices {
            text(out, lane);
            count(out, classes.len());
            for (class, cell) in classes {
                text(out, class);
                match cell.nanos_per_unit() {
                    None => out.push(0),
                    Some(nanos) => {
                        out.push(1);
                        out.extend_from_slice(&nanos.to_le_bytes());
                    }
                }
            }
        }
        count(out, self.planes.len());
        for (plane, card) in &self.planes {
            text(out, plane);
            card.digest_into(out);
        }
        // Preserve every historical legacy digest when no common measurement rates exist.
        if !self.measurements.is_empty() {
            out.extend_from_slice(b"busbar/measurement-rates/v1\0");
            count(out, self.measurements.len());
            for (kind, card) in &self.measurements {
                text(out, kind);
                card.digest_into(out);
            }
        }
    }

    /// The one placement of a configured rate into a cell, used by the constructor alone. A card is
    fn place_rate(&mut self, cell: LaneClass, nanos_per_unit: Option<u64>) {
        if let Some((kind, namespace)) = split_measurement_lane(&cell.lane) {
            self.measurements
                .entry(kind.to_string())
                .or_insert_with(|| RateCard::from_cells([], 0))
                .place_rate(LaneClass::new(namespace, &cell.class), nanos_per_unit);
            return;
        }
        self.present = true;
        let slot = self
            .prices
            .entry(cell.lane.clone())
            .or_default()
            .entry(cell.class.clone())
            .or_default();
        match nanos_per_unit {
            Some(nanos) => {
                slot.set(nanos);
                self.refused.retain(|r| r != &cell);
            }
            None => {
                *slot = CellPrices::default();
                if !self.refused.contains(&cell) {
                    self.refused.push(cell);
                }
            }
        }
    }
}

/// Encode a host-bound plugin kind and configured namespace without delimiter collisions. Spelled
/// when a card or a measurement binding is configured, never per request.
pub fn measurement_lane(kind: &str, namespace: &str) -> String {
    format!(
        "{}{}:{kind}{namespace}",
        crate::cost::MEASUREMENT_LANE_PREFIX,
        kind.len()
    )
}
