// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPOOL'S RECORDS (MONEY-DESIGN §3c, "The spool"). Counts only: a contribution is a unit's
//! final 1.5.5 bill as RAM `cur` applied it, per (bucket, window, segment), plus its metering
//! rows. Nothing here is a price.
//!
//! The store batch bodies are DERIVED from the contributions an op lists, deterministically
//! ([`usage_body`], [`metering_body`]), so a replay after a restart sends the identical body under
//! the identical op id.

use std::collections::BTreeMap;

use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, ModelTokensDelta, UsageDelta};
use serde::{Deserialize, Serialize};

/// The pseudo-model separator of a sibling row and a metering provider prefix.
pub const SEP: char = '\u{1f}';

/// The unit the fee count of a segment is keyed under in a sibling row.
pub const FEE_UNIT: &str = "fee";

/// A unit's random id (CSPRNG, never the per-boot `UnitKey` counter).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnitId(pub [u8; 16]);

impl UnitId {
    /// A fresh id from the OS CSPRNG. Entropy failure is not survivable for an id that must never
    /// repeat, so it falls back to the op-id allocator's unique bits.
    #[must_use]
    pub fn mint() -> Self {
        let mut raw = [0u8; 16];
        if getrandom::fill(&mut raw).is_err() {
            raw = crate::door::op_id().0;
        }
        UnitId(raw)
    }
}

impl std::fmt::Debug for UnitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::fmt::Display for UnitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Serialize for UnitId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for UnitId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        <[u8; 16]>::try_from(bytes.as_slice())
            .map(UnitId)
            .map_err(|_| serde::de::Error::custom("a unit id is 16 bytes"))
    }
}

/// An op id as the spool spells it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Op(pub OpId);

impl Op {
    /// A fresh op id from the node's one allocator.
    #[must_use]
    pub fn mint() -> Self {
        Op(crate::door::op_id())
    }
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0 .0))
    }
}

impl Serialize for Op {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0 .0))
    }
}

impl<'de> Deserialize<'de> for Op {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        <[u8; 16]>::try_from(bytes.as_slice())
            .map(|b| Op(OpId(b)))
            .map_err(|_| serde::de::Error::custom("an op id is 16 bytes"))
    }
}

/// A unit's two op ids, minted at its ADMISSION: one for its usage op, one for its metering op
/// (the stores' dedupe table is one namespace across slots). A single post of the unit, from RAM
/// while the spool is failed or as its crash bill at boot, always uses this pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ops {
    /// The usage op.
    pub usage: Op,
    /// The metering op.
    pub metering: Op,
}

impl Ops {
    /// A fresh pair.
    #[must_use]
    pub fn mint() -> Self {
        Ops {
            usage: Op::mint(),
            metering: Op::mint(),
        }
    }
}

/// Which of a unit's two ops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    /// `add_usage_batch`.
    Usage,
    /// `add_metering_batch`.
    Metering,
}

/// A segment: the 24-hex id of the card-history entry that priced the counts, or `""` for the
/// legacy remainder (counts with no entry: no history installed).
pub type Seg = String;

/// ONE (bucket, window) CELL of a contribution, as RAM `cur` applied it, by segment. Every count
/// is non-negative (MONEY-DESIGN §3c): net of the unit's own refunds, parks included.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCount {
    /// The bucket id (a key id, or `group:<name>@<window>#<scope>`).
    pub bucket: String,
    /// The window start the counts were applied to.
    pub window: u64,
    /// Admission count.
    pub requests: u64,
    /// The flat fee base, by segment.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub billable: BTreeMap<Seg, u64>,
    /// Unit counts: segment, then model (lane), then class.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub units: BTreeMap<Seg, BTreeMap<String, BTreeMap<String, u64>>>,
}

impl CellCount {
    /// An empty cell of `bucket` in `window`.
    #[must_use]
    pub fn new(bucket: &str, window: u64) -> Self {
        CellCount {
            bucket: bucket.to_string(),
            window,
            ..CellCount::default()
        }
    }

    /// Whether the cell counts nothing.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.requests == 0
            && self.billable.values().all(|n| *n == 0)
            && self
                .units
                .values()
                .flat_map(|m| m.values())
                .flat_map(|c| c.values())
                .all(|n| *n == 0)
    }

    /// The total billable count over every segment.
    #[must_use]
    pub fn billable_total(&self) -> u64 {
        self.billable
            .values()
            .fold(0u64, |a, n| a.saturating_add(*n))
    }

    /// Add `other` (same bucket and window) into this cell.
    pub fn merge(&mut self, other: &CellCount) {
        self.requests = self.requests.saturating_add(other.requests);
        for (seg, n) in &other.billable {
            let slot = self.billable.entry(seg.clone()).or_insert(0);
            *slot = slot.saturating_add(*n);
        }
        for (seg, models) in &other.units {
            let into = self.units.entry(seg.clone()).or_default();
            for (model, classes) in models {
                let into = into.entry(model.clone()).or_default();
                for (class, n) in classes {
                    let slot = into.entry(class.clone()).or_insert(0);
                    *slot = slot.saturating_add(*n);
                }
            }
        }
    }
}

/// Fold `cells` into one cell per (bucket, window), in (bucket, window) order.
#[must_use]
pub fn merged<'c>(cells: impl IntoIterator<Item = &'c CellCount>) -> Vec<CellCount> {
    let mut by: BTreeMap<(String, u64), CellCount> = BTreeMap::new();
    for c in cells {
        by.entry((c.bucket.clone(), c.window))
            .or_insert_with(|| CellCount::new(&c.bucket, c.window))
            .merge(c);
    }
    by.into_values().filter(|c| !c.is_zero()).collect()
}

/// A unit's METERING row counts, keyed as the store's row is, its entry id prefixing the provider
/// on the wire ([`metering_body`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterCount {
    /// The key.
    pub key_id: String,
    /// The metering day bucket.
    pub bucket: u64,
    /// The model (lane).
    pub model: String,
    /// The provider, unprefixed.
    pub provider: String,
    /// The entry that priced the row, `""` for none.
    #[serde(default)]
    pub seg: Seg,
    /// The instant the card the row was served under started.
    pub priced_from_ms: u64,
    /// Requests.
    pub requests: u64,
    /// Input tokens.
    #[serde(default)]
    pub tokens_input: u64,
    /// Output tokens.
    #[serde(default)]
    pub tokens_output: u64,
    /// Cache-read tokens.
    #[serde(default)]
    pub tokens_cache_read: u64,
    /// Cache-write tokens.
    #[serde(default)]
    pub tokens_cache_write: u64,
    /// Every other class.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub usage_units: BTreeMap<String, u64>,
}

impl MeterCount {
    fn row_key(&self) -> (String, u64, String, String, String, u64) {
        (
            self.key_id.clone(),
            self.bucket,
            self.model.clone(),
            self.provider.clone(),
            self.seg.clone(),
            self.priced_from_ms,
        )
    }

    fn merge(&mut self, o: &MeterCount) {
        self.requests = self.requests.saturating_add(o.requests);
        self.tokens_input = self.tokens_input.saturating_add(o.tokens_input);
        self.tokens_output = self.tokens_output.saturating_add(o.tokens_output);
        self.tokens_cache_read = self.tokens_cache_read.saturating_add(o.tokens_cache_read);
        self.tokens_cache_write = self.tokens_cache_write.saturating_add(o.tokens_cache_write);
        for (k, n) in &o.usage_units {
            let slot = self.usage_units.entry(k.clone()).or_insert(0);
            *slot = slot.saturating_add(*n);
        }
    }

    /// The provider column as it is written: `"<id>\u{1f}<provider>"` for a row with an entry.
    #[must_use]
    pub fn wire_provider(&self) -> String {
        if self.seg.is_empty() {
            self.provider.clone()
        } else {
            format!("{}{SEP}{}", self.seg, self.provider)
        }
    }
}

/// A unit's ONE contribution: its final bill, handed to the poster at its close.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contrib {
    /// The unit.
    pub unit: UnitId,
    /// Its own op pair, minted at admission.
    pub ops: Ops,
    /// Its per-window net counts.
    pub cells: Vec<CellCount>,
    /// Its metering rows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metering: Vec<MeterCount>,
    /// When it was handed off, wall-clock ms.
    pub at_ms: u64,
}

/// A unit's ADMISSION MARK: the charge its admission recorded, posted as its crash bill when no
/// contribution retires it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    /// The unit.
    pub unit: UnitId,
    /// Its own op pair.
    pub ops: Ops,
    /// The charge: `requests +1` and `billable +1`, or the plane lane fee unit, per bucket.
    pub cells: Vec<CellCount>,
    /// When it was appended, wall-clock ms.
    pub at_ms: u64,
}

/// One op's dead-letter state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadState {
    /// REFUSED alone: never applied.
    Refused,
    /// Applied-unknown past the op-id retention margin.
    LandedUnknown,
}

/// A spool record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
pub enum Rec {
    /// An admission mark.
    Admitted(Mark),
    /// A contribution.
    Contrib(Contrib),
    /// A batch: `op` of `kind` carries exactly these units' contributions (the body is derived).
    Sent {
        /// The op.
        op: Op,
        /// Which body.
        kind: Kind,
        /// The units, in body order.
        units: Vec<UnitId>,
        /// When the op was first sent, wall-clock ms (the retention clock).
        at_ms: u64,
    },
    /// A unit's crash bill, posted under its own usage op.
    CrashBill {
        /// The unit.
        unit: UnitId,
        /// When, wall-clock ms.
        at_ms: u64,
    },
    /// `op` answered applied.
    Ready {
        /// The op.
        op: Op,
    },
    /// `op` was REFUSED; its units go on alone, each under a NEW op.
    Superseded {
        /// The refused op.
        op: Op,
        /// Which body.
        kind: Kind,
        /// Each unit and its new op.
        pieces: Vec<(UnitId, Op)>,
        /// When, wall-clock ms.
        at_ms: u64,
    },
    /// The unit's `kind` op was dead-lettered (the dead-letter file holds its counts).
    Dead {
        /// The unit.
        unit: UnitId,
        /// Which body.
        kind: Kind,
    },
}

/// The bucket id of `bucket`'s sibling era row: `"e:" ++ hex32(SHA-256(bucket))`, 34 ASCII bytes.
#[must_use]
pub fn sibling_bucket(bucket: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bucket.as_bytes());
    format!("e:{}", hex::encode(&digest.as_ref()[..16]))
}

/// THE USAGE BODY of the contributions `cells`: per (bucket, window) the PLAIN row (every
/// segment's total, exactly the 1.5.5 row) and, when any count carries an entry, the SIBLING row
/// with per-entry pseudo-models. Cells merged per (bucket, window, sibling) and sorted that way.
#[must_use]
pub fn usage_body<'c>(cells: impl IntoIterator<Item = &'c CellCount>) -> Vec<(String, u64, UsageDelta)> {
    let mut out: Vec<(String, u64, bool, UsageDelta)> = Vec::new();
    for cell in merged(cells) {
        let mut plain: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        let mut sib: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        for (seg, models) in &cell.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    let v = i64::try_from(*n).unwrap_or(i64::MAX);
                    let slot = plain
                        .entry(model.clone())
                        .or_default()
                        .entry(class.clone())
                        .or_insert(0);
                    *slot = slot.saturating_add(v);
                    if !seg.is_empty() {
                        let slot = sib
                            .entry(format!("{seg}{SEP}{model}"))
                            .or_default()
                            .entry(class.clone())
                            .or_insert(0);
                        *slot = slot.saturating_add(v);
                    }
                }
            }
        }
        for (seg, n) in &cell.billable {
            if !seg.is_empty() && *n > 0 {
                let slot = sib
                    .entry(format!("{seg}{SEP}"))
                    .or_default()
                    .entry(FEE_UNIT.to_string())
                    .or_insert(0);
                *slot = slot.saturating_add(i64::try_from(*n).unwrap_or(i64::MAX));
            }
        }
        let models = |m: BTreeMap<String, BTreeMap<String, i64>>| {
            m.into_iter()
                .map(|(model, mut usage_units)| {
                    usage_units.retain(|_, v| *v != 0);
                    ModelTokensDelta { model, usage_units }
                })
                .filter(|d| !d.usage_units.is_empty())
                .collect::<Vec<_>>()
        };
        out.push((
            cell.bucket.clone(),
            cell.window,
            false,
            UsageDelta {
                requests: i64::try_from(cell.requests).unwrap_or(i64::MAX),
                billable_requests: i64::try_from(cell.billable_total()).unwrap_or(i64::MAX),
                models: models(plain),
            },
        ));
        let sib = models(sib);
        if !sib.is_empty() {
            out.push((
                sibling_bucket(&cell.bucket),
                cell.window,
                true,
                UsageDelta {
                    requests: 0,
                    billable_requests: 0,
                    models: sib,
                },
            ));
        }
    }
    out.sort_by(|a, b| (&a.0, a.1, a.2).cmp(&(&b.0, b.1, b.2)));
    out.into_iter()
        .filter(|(_, _, _, d)| !d.is_zero())
        .map(|(b, w, _, d)| (b, w, d))
        .collect()
}

/// THE METERING BODY of `rows`: merged per row key, sorted, the provider prefixed by the entry id.
#[must_use]
pub fn metering_body<'m>(rows: impl IntoIterator<Item = &'m MeterCount>) -> Vec<MeteringDelta> {
    let mut by: BTreeMap<(String, u64, String, String, String, u64), MeterCount> = BTreeMap::new();
    for r in rows {
        by.entry(r.row_key())
            .and_modify(|m| m.merge(r))
            .or_insert_with(|| r.clone());
    }
    by.into_values()
        .map(|m| MeteringDelta {
            key_id: m.key_id.clone(),
            bucket: m.bucket,
            model: m.model.clone(),
            provider: m.wire_provider(),
            tokens_input: m.tokens_input,
            tokens_output: m.tokens_output,
            tokens_cache_read: m.tokens_cache_read,
            tokens_cache_write: m.tokens_cache_write,
            requests: m.requests,
            billable_requests: m.requests,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: m.priced_from_ms,
            usage_units: m.usage_units.clone(),
        })
        .collect()
}

/// A record's bytes.
#[must_use]
pub fn encode(rec: &Rec) -> Vec<u8> {
    serde_json::to_vec(rec).unwrap_or_default()
}

/// A record from its bytes; `None` for bytes no build of this record set wrote.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Rec> {
    serde_json::from_slice(bytes).ok()
}
