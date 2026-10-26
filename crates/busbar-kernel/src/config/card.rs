// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE CARD AS THE CONFIGURATION SPELLS IT: the four fields a deployment prices with, lifted
//! out of the rest of the configuration so the card can be held, compared and stored on its own
//! (MONEY-DESIGN section 3a, owner ruling 2026-10-25).
//!
//! After first boot the card in force is the fleet-shared history's, never the configuration's: the
//! history holds a [`CardFields`] per entry, every build of a generation prices with the card in
//! force ([`CardFields::apply_to`]), and `PUT /config/settings` is the one path that writes a new
//! one. A configuration file's card is read once, to seed an empty history; after that a file card
//! that differs from both the seed and the card in force is an EDIT, refused by name.

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

/// One plane's card and fees as `PUT /config/settings` names them under its request-only `planes`
/// key, and as the stored form spells them.
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

/// A plane's fees, in minor units, as the stored form and the `planes` key spell them.
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

/// The fields `PUT /config/settings` SETS, each a whole value (MONEY-DESIGN section 3a): a field left
/// `None` is kept from the card in force.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CardSet {
    /// A new flat card, replacing the flat card whole.
    pub rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    /// A new flat per-request fee.
    pub per_request_fee: Option<i64>,
    /// Each named plane's card and fees, each replacing that plane's own whole.
    pub planes: BTreeMap<String, PlaneCardFields>,
}

impl CardSet {
    /// Whether the request sets no card field at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rate_card.is_none()
            && self.per_request_fee.is_none()
            && self
                .planes
                .values()
                .all(|p| p.rate_card.is_none() && p.fees.is_none())
    }

    /// The names of the fields it sets, as an operator reads them.
    #[must_use]
    pub fn field_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.rate_card.is_some() {
            out.push("rate_card".to_string());
        }
        if self.per_request_fee.is_some() {
            out.push("per_request_fee".to_string());
        }
        for (plane, p) in &self.planes {
            if p.rate_card.is_some() {
                out.push(format!("planes.{plane}.rate_card"));
            }
            if p.fees.is_some() {
                out.push(format!("planes.{plane}.fees"));
            }
        }
        out
    }
}

impl CardFields {
    /// The card a deployment document configures.
    #[must_use]
    pub fn of_deploy(deploy: &DeployCfg) -> Self {
        CardFields {
            rate_card: deploy.rate_card.clone(),
            per_request_fee: deploy.per_request_fee,
            plane_rate_cards: deploy.plane_rate_cards.clone(),
            plane_fees: deploy.plane_fees.clone(),
        }
    }

    /// This card with an overlay root section's card fields laid over it, as boot merges them.
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

    /// PRICE A GENERATION WITH THIS CARD: the resolved configuration's three card fields are
    /// replaced by this card's, composed as [`super::resolve`] composes them.
    pub fn apply_to(&self, cfg: &mut RootCfg) {
        cfg.rate_card = busbar_kernel_ledger::cost::compose_plane_cards(
            self.rate_card.as_ref(),
            &self.plane_rate_cards,
        );
        cfg.per_request_fee = self.per_request_fee;
        cfg.plane_fees = self.plane_fees.clone();
    }

    /// The card a resolved configuration prices with, read back off its composed fields.
    #[must_use]
    pub fn of_root(cfg: &RootCfg) -> Self {
        Self::from_composed(
            cfg.rate_card.as_ref(),
            cfg.per_request_fee,
            cfg.plane_fees.clone(),
        )
    }

    /// The card a COMPOSED card map spells (`compose_plane_cards`'s form: plane-qualified lanes and
    /// presence keys), with its flat fee and plane fees, split back into the flat and plane cards.
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
                        // `"<sep>"`: the flat card's presence key.
                        (true, true) => {
                            flat.get_or_insert_with(BTreeMap::new);
                        }
                        (true, false) => {
                            flat.get_or_insert_with(BTreeMap::new)
                                .insert(lane.to_string(), entry.clone());
                        }
                        // `"<plane><sep>"`: that plane's presence key.
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

    /// The composed card map a generation prices with.
    #[must_use]
    pub fn composed(&self) -> Option<BTreeMap<String, RateEntryCfg>> {
        busbar_kernel_ledger::cost::compose_plane_cards(
            self.rate_card.as_ref(),
            &self.plane_rate_cards,
        )
    }

    /// The card with `set`'s fields replaced, each as a whole value.
    #[must_use]
    pub fn with_set(&self, set: &CardSet) -> Self {
        let mut next = self.clone();
        if let Some(card) = set.rate_card.as_ref() {
            next.rate_card = Some(card.clone());
        }
        if let Some(fee) = set.per_request_fee {
            next.per_request_fee = fee;
        }
        for (plane, p) in &set.planes {
            if let Some(card) = p.rate_card.as_ref() {
                next.plane_rate_cards.insert(plane.clone(), card.clone());
            }
            if let Some(fees) = p.fees {
                next.plane_fees.insert(plane.clone(), fees.into());
            }
        }
        next
    }

    /// The fields on which `self` and `other` differ, as an operator reads them.
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

    /// The stored bytes: canonical JSON, so two equal cards are two equal byte strings.
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

    /// The card from its stored bytes.
    ///
    /// # Errors
    ///
    /// The bytes are not a stored card.
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

    /// The card's digest: SHA-256 of its stored bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.to_bytes())
    }

    /// The card's rates as the rate-apply seam carries them, owned.
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

    /// The flat card and fee, and each plane's, as `GET /config/settings` renders them.
    #[must_use]
    pub fn rendered_planes(&self) -> BTreeMap<String, PlaneCardFields> {
        let mut planes: BTreeMap<String, PlaneCardFields> = BTreeMap::new();
        for (plane, card) in &self.plane_rate_cards {
            planes.entry(plane.clone()).or_default().rate_card = Some(card.clone());
        }
        for (plane, fees) in &self.plane_fees {
            planes.entry(plane.clone()).or_default().fees = Some((*fees).into());
        }
        planes
    }
}

/// SHA-256 of `bytes`: the one digest the card history's records carry.
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
    pub lanes: Vec<(String, crate::billing::RawTierRates)>,
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
    /// The neutral view the rate-apply seam carries.
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

/// The sentence every refused card edit carries.
pub const ONLY_PUT: &str = "the rate card changes only through PUT /config/settings";

/// The audit action of a configuration file edited back to its first-boot seed after a PUT.
pub const FILE_DIFFERS_ACTION: &str = "card.file_differs";

/// The audit action of a refused card edit.
pub const EDIT_REFUSED_ACTION: &str = "card.edit_refused";

/// The prefix a refused card edit's message opens with, so the admin surface answers it 409.
pub const EDIT_REFUSED_PREFIX: &str = "card edit refused: ";

/// A REFUSED CARD EDIT: the path that tried it and the fields it would have changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditRefused {
    /// The path, as an operator names it (`config/reload`, `config/apply`, `boot`, ...).
    pub path: String,
    /// The fields that differ from the card in force.
    pub fields: Vec<String>,
}

impl std::fmt::Display for EditRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{EDIT_REFUSED_PREFIX}{} would change {} of the rate card in force; {ONLY_PUT}",
            self.path,
            self.fields.join(", ")
        )
    }
}

impl EditRefused {
    /// Record the refusal on the audit chain, under [`EDIT_REFUSED_ACTION`].
    pub fn audit(&self) {
        crate::audit_ring::AUDIT.record_by(
            EDIT_REFUSED_ACTION,
            &format!(
                "rate_card path={} fields={} ({ONLY_PUT})",
                self.path,
                self.fields.join(",")
            ),
            crate::audit_ring::OUTCOME_REJECTED,
            "busbar",
        );
    }
}

/// Whether `message` is a refused card edit's ([`EDIT_REFUSED_PREFIX`]).
#[must_use]
pub fn is_edit_refusal(message: &str) -> bool {
    message.contains(EDIT_REFUSED_PREFIX)
}

/// The per-thread scope of one card check: a candidate card a build prices with, PUT's lenient
/// disk re-read, and the notes the checks leave for the response being built. Thread-local because
/// a config transaction's whole apply phase runs on one blocking thread.
pub(crate) mod scope {
    use super::CardFields;
    use std::cell::{Cell, RefCell};

    thread_local! {
        /// The card a build on this thread prices with in place of the card in force.
        static OVERRIDE: RefCell<Option<CardFields>> = const { RefCell::new(None) };
        /// Set while a `PUT /config/settings` re-reads the disk.
        static LENIENT: Cell<bool> = const { Cell::new(false) };
        /// The notes card checks left on this thread.
        static NOTES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn with_override<T>(card: &CardFields, f: impl FnOnce() -> T) -> T {
        let previous = OVERRIDE.with(|o| o.replace(Some(card.clone())));
        let out = f();
        OVERRIDE.with(|o| *o.borrow_mut() = previous);
        out
    }

    pub(crate) fn override_card() -> Option<CardFields> {
        OVERRIDE.with(|o| o.borrow().clone())
    }

    pub(crate) fn lenient<T>(f: impl FnOnce() -> T) -> T {
        let previous = LENIENT.with(|l| l.replace(true));
        let out = f();
        LENIENT.with(|l| l.set(previous));
        out
    }

    pub(crate) fn is_lenient() -> bool {
        LENIENT.with(Cell::get)
    }

    pub(crate) fn note(text: String) {
        tracing::warn!("{text}");
        NOTES.with(|n| n.borrow_mut().push(text));
    }

    pub(crate) fn take_notes() -> Vec<String> {
        NOTES.with(|n| std::mem::take(&mut *n.borrow_mut()))
    }
}

#[cfg(test)]
#[path = "tests/card_tests.rs"]
mod tests;
