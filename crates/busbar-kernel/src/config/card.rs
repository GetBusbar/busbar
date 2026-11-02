// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DeployCfg, PlaneFeesMap, PlaneRateCards, RateEntryCfg, RootCfg};

/// The card, as the configuration spells it: the flat `rate_card:` and `per_request_fee:`, and each
/// other plane's own `rate_card:` and `fees:` by plane registry key (#47).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CardFields {
    /// The flat card (the pools plane's), `None` when no `rate_card:` is configured.
    pub rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    /// The flat per-request fee, in minor units.
    pub per_request_fee: i64,
    /// Each other plane's own card.
    pub plane_rate_cards: PlaneRateCards,
    /// Each other plane's own fees.
    pub plane_fees: PlaneFeesMap,
}

/// One plane's card and fees, as the stored form spells them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaneCardFields {
    /// The plane's card, replaced whole when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    /// The plane's fees, replaced whole when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fees: Option<PlaneFeesForm>,
}

/// A plane's fees, in minor units, as the stored form spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PlaneFeesForm {
    /// Charged once per billable request of the plane.
    pub per_request: i64,
    /// Charged once per session the plane opens.
    pub per_session: i64,
}

impl From<busbar_kernel_ledger::cost::PlaneFees> for PlaneFeesForm {
    fn from(f: busbar_kernel_ledger::cost::PlaneFees) -> Self {
        PlaneFeesForm {
            per_request: f.per_request,
            per_session: f.per_session,
        }
    }
}

impl From<PlaneFeesForm> for busbar_kernel_ledger::cost::PlaneFees {
    fn from(f: PlaneFeesForm) -> Self {
        busbar_kernel_ledger::cost::PlaneFees {
            per_request: f.per_request,
            per_session: f.per_session,
        }
    }
}

/// The stored spelling of a [`CardFields`]: JSON, every map ordered, so equal cards are equal bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCard {
    #[serde(default)]
    rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    #[serde(default)]
    per_request_fee: i64,
    #[serde(default)]
    planes: BTreeMap<String, PlaneCardFields>,
}

impl CardFields {
    #[must_use]
    pub fn of_deploy(deploy: &DeployCfg) -> Self {
        CardFields {
            rate_card: deploy.rate_card.clone(),
            per_request_fee: deploy.per_request_fee,
            plane_rate_cards: deploy.plane_rate_cards.clone(),
            plane_fees: deploy.plane_fees.clone(),
        }
    }

    #[must_use]
    pub fn with_overlay(mut self, root: Option<&super::overlay::RootSettings>) -> Self {
        if let Some(root) = root {
            if let Some(card) = root.rate_card.as_ref() {
                self.rate_card = Some(card.clone());
            }
            if let Some(fee) = root.per_request_fee {
                self.per_request_fee = fee;
            }
        }
        self
    }

    pub fn apply_to(&self, cfg: &mut RootCfg) {
        cfg.rate_card = busbar_kernel_ledger::cost::compose_plane_cards(
            self.rate_card.as_ref(),
            &self.plane_rate_cards,
        );
        cfg.per_request_fee = self.per_request_fee;
        cfg.plane_fees = self.plane_fees.clone();
    }

    #[must_use]
    pub fn of_root(cfg: &RootCfg) -> Self {
        Self::from_composed(
            cfg.rate_card.as_ref(),
            cfg.per_request_fee,
            cfg.plane_fees.clone(),
        )
    }

    #[must_use]
    pub fn from_composed(
        composed: Option<&BTreeMap<String, RateEntryCfg>>,
        per_request_fee: i64,
        plane_fees: PlaneFeesMap,
    ) -> Self {
        let sep = busbar_kernel_ledger::cost::PLANE_LANE_SEP;
        let mut flat: Option<BTreeMap<String, RateEntryCfg>> = None;
        let mut planes: PlaneRateCards = BTreeMap::new();
        match composed {
            None => {}
            Some(map) if map.keys().all(|k| !k.contains(sep)) => flat = Some(map.clone()),
            Some(map) => {
                for (key, entry) in map {
                    let (plane, lane) = busbar_kernel_ledger::cost::split_plane_lane(key);
                    match (plane.is_empty(), lane.is_empty()) {
                        (true, true) => {
                            flat.get_or_insert_with(BTreeMap::new);
                        }
                        (true, false) => {
                            flat.get_or_insert_with(BTreeMap::new)
                                .insert(lane.to_string(), entry.clone());
                        }

                        (false, true) => {
                            planes.entry(plane.to_string()).or_default();
                        }
                        (false, false) => {
                            planes
                                .entry(plane.to_string())
                                .or_default()
                                .insert(lane.to_string(), entry.clone());
                        }
                    }
                }
            }
        }
        CardFields {
            rate_card: flat,
            per_request_fee,
            plane_rate_cards: planes,
            plane_fees,
        }
    }

    #[must_use]
    pub fn composed(&self) -> Option<BTreeMap<String, RateEntryCfg>> {
        busbar_kernel_ledger::cost::compose_plane_cards(
            self.rate_card.as_ref(),
            &self.plane_rate_cards,
        )
    }

    #[must_use]
    pub fn differing_fields(&self, other: &CardFields) -> Vec<String> {
        let mut out = Vec::new();
        if self.rate_card != other.rate_card {
            out.push("rate_card".to_string());
        }
        if self.per_request_fee != other.per_request_fee {
            out.push("per_request_fee".to_string());
        }
        let planes: std::collections::BTreeSet<&String> = self
            .plane_rate_cards
            .keys()
            .chain(other.plane_rate_cards.keys())
            .chain(self.plane_fees.keys())
            .chain(other.plane_fees.keys())
            .collect();
        for plane in planes {
            if self.plane_rate_cards.get(plane) != other.plane_rate_cards.get(plane) {
                out.push(format!("planes.{plane}.rate_card"));
            }
            if self.plane_fees.get(plane) != other.plane_fees.get(plane) {
                out.push(format!("planes.{plane}.fees"));
            }
        }
        out
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut planes: BTreeMap<String, PlaneCardFields> = BTreeMap::new();
        for (plane, card) in &self.plane_rate_cards {
            planes.entry(plane.clone()).or_default().rate_card = Some(card.clone());
        }
        for (plane, fees) in &self.plane_fees {
            planes.entry(plane.clone()).or_default().fees = Some((*fees).into());
        }
        let stored = StoredCard {
            rate_card: self.rate_card.clone(),
            per_request_fee: self.per_request_fee,
            planes,
        };
        serde_json::to_vec(&stored).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let stored: StoredCard =
            serde_json::from_slice(bytes).map_err(|e| format!("not a stored rate card: {e}"))?;
        let mut card = CardFields {
            rate_card: stored.rate_card,
            per_request_fee: stored.per_request_fee,
            ..CardFields::default()
        };
        for (plane, p) in stored.planes {
            if let Some(rc) = p.rate_card {
                card.plane_rate_cards.insert(plane.clone(), rc);
            }
            if let Some(fees) = p.fees {
                card.plane_fees.insert(plane, fees.into());
            }
        }
        Ok(card)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.to_bytes())
    }

    #[must_use]
    pub fn rates(&self) -> CardRates {
        let composed = busbar_kernel_ledger::cost::compose_plane_cards(
            self.rate_card.as_ref(),
            &self.plane_rate_cards,
        );
        let (mut lanes, mut units) = (Vec::new(), Vec::new());
        for (lane, e) in composed.iter().flatten() {
            lanes.push((lane.clone(), e.raw_tier_rates()));
            for (class, rate) in &e.units {
                units.push((lane.clone(), class.clone(), rate.nanos_per_unit()));
            }
        }
        CardRates {
            lanes,
            units,
            flat_minor: self.per_request_fee,
            present: composed.is_some(),
            plane_fees: self.plane_fees.clone(),
        }
    }
}

#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// A card's rates, owned: what [`crate::rate_apply::RawRates`] borrows.
#[derive(Debug, Clone)]
pub struct CardRates {
    /// `(lane, its four tier rates)`.
    pub lanes: Vec<(String, busbar_contract::billing::RawTierRates)>,
    /// `(lane, open class, nano-units per unit)`.
    pub units: Vec<(String, String, u64)>,
    /// The flat per-request figure.
    pub flat_minor: i64,
    /// Whether a rate card is configured at all.
    pub present: bool,
    /// Each other plane's fees.
    pub plane_fees: PlaneFeesMap,
}

impl CardRates {
    #[must_use]
    pub fn raw(&self) -> crate::rate_apply::RawRates<'_> {
        crate::rate_apply::RawRates {
            lanes: &self.lanes,
            units: &self.units,
            flat_minor: self.flat_minor,
            present: self.present,
            plane_fees: &self.plane_fees,
        }
    }
}

pub(crate) mod origin {
    use std::cell::RefCell;

    thread_local! {
        static ORIGIN: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub(crate) fn with<T>(origin: &str, f: impl FnOnce() -> T) -> T {
        let previous = ORIGIN.with(|o| o.replace(Some(origin.to_string())));
        let out = f();
        ORIGIN.with(|o| *o.borrow_mut() = previous);
        out
    }

    pub(crate) fn current() -> String {
        ORIGIN
            .with(|o| o.borrow().clone())
            .unwrap_or_else(|| "a configuration change".to_string())
    }
}

#[cfg(test)]
#[path = "tests/card_tests.rs"]
mod tests;
