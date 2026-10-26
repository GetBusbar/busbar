// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPOOL'S RECORDS (MONEY-DESIGN §3c, "The spool"). Counts only: a batch is the net deltas RAM
//! `cur` applied during one or more flush windows, per (bucket, window, segment), plus the metering
//! rows accumulated over the same windows. Nothing here is a price.
//!
//! A batch's store bodies are DERIVED from its cells, deterministically ([`usage_body`]), so a
//! replay after a restart sends the identical body under the identical op id.

use std::collections::BTreeMap;

use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, ModelTokensDelta, UsageDelta};
use serde::{Deserialize, Serialize};

/// The pseudo-model separator of a sibling row and a metering provider prefix.
pub const SEP: char = '\u{1f}';

/// The unit the fee count of a segment is keyed under in a sibling row.
pub const FEE_UNIT: &str = "fee";

/// An op id as the spool spells it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Op(pub OpId);

impl Op {
    /// A fresh op id from the node's one allocator (its node half is a per-boot CSPRNG draw, so a
    /// restart never mints a previous boot's id).
    #[must_use]
    pub fn mint() -> Self {
        Op(crate::door::op_id())
    }
}

impl PartialOrd for Op {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Op {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0 .0.cmp(&other.0 .0)
    }
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0 .0))
    }
}

impl std::fmt::Display for Op {
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

/// Which of a batch's two ops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    /// `add_usage_batch`.
    Usage,
    /// `add_metering_batch`.
    Metering,
}

/// A segment as a record spells it: the 24-hex id of the card-history entry that priced the counts,
/// or `""` for the legacy remainder (counts written with no entry).
pub type Seg = String;

/// ONE (bucket, window) CELL's net delta, by segment, exactly as RAM `cur` applied it. Signed: a
/// refund after the charge's window was swapped is a `-1` on that window. Batches reach the store
/// one at a time, in order, so a `-1` never lands before the `+1` it cancels.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCount {
    /// The bucket id (a key id, or `group:<name>@<window>#<scope>`).
    pub bucket: String,
    /// The window start the counts were applied to.
    pub window: u64,
    /// Admission count.
    #[serde(default)]
    pub requests: i64,
    /// The flat fee base, by segment.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub billable: BTreeMap<Seg, i64>,
    /// Unit counts: segment, then model (lane), then class.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub units: BTreeMap<Seg, BTreeMap<String, BTreeMap<String, i64>>>,
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
    pub fn billable_total(&self) -> i64 {
        self.billable
            .values()
            .fold(0i64, |a, n| a.saturating_add(*n))
    }

    /// Add `n` to `seg`'s billable count.
    pub fn add_billable(&mut self, seg: &str, n: i64) {
        if n == 0 {
            return;
        }
        let slot = self.billable.entry(seg.to_string()).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// Add `n` to `seg`'s `model` `class` count.
    pub fn add_unit(&mut self, seg: &str, model: &str, class: &str, n: i64) {
        if n == 0 {
            return;
        }
        let slot = self
            .units
            .entry(seg.to_string())
            .or_default()
            .entry(model.to_string())
            .or_default()
            .entry(class.to_string())
            .or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// Add `other` (same bucket and window) into this cell, dropping what nets to zero.
    pub fn merge(&mut self, other: &CellCount) {
        self.requests = self.requests.saturating_add(other.requests);
        for (seg, n) in &other.billable {
            self.add_billable(seg, *n);
        }
        for (seg, models) in &other.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    self.add_unit(seg, model, class, *n);
                }
            }
        }
        self.tidy();
    }

    /// Drop every zero count.
    pub fn tidy(&mut self) {
        self.billable.retain(|_, n| *n != 0);
        for models in self.units.values_mut() {
            for classes in models.values_mut() {
                classes.retain(|_, n| *n != 0);
            }
            models.retain(|_, c| !c.is_empty());
        }
        self.units.retain(|_, m| !m.is_empty());
    }

    /// The same cell with every count's sign flipped.
    #[must_use]
    pub fn negated(&self) -> CellCount {
        let mut out = CellCount::new(&self.bucket, self.window);
        out.requests = self.requests.saturating_neg();
        for (seg, n) in &self.billable {
            out.add_billable(seg, n.saturating_neg());
        }
        for (seg, models) in &self.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    out.add_unit(seg, model, class, n.saturating_neg());
                }
            }
        }
        out
    }

    /// Only the counts of the given sign (`positive`: above zero; else below zero).
    #[must_use]
    pub fn signed_part(&self, positive: bool) -> CellCount {
        let keep = |n: i64| if positive { n > 0 } else { n < 0 };
        let mut out = CellCount::new(&self.bucket, self.window);
        if keep(self.requests) {
            out.requests = self.requests;
        }
        for (seg, n) in &self.billable {
            if keep(*n) {
                out.add_billable(seg, *n);
            }
        }
        for (seg, models) in &self.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    if keep(*n) {
                        out.add_unit(seg, model, class, *n);
                    }
                }
            }
        }
        out
    }
}

/// Fold `cells` into one cell per (bucket, window), in (bucket, window) order, zero cells dropped.
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

/// A dead letter's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadState {
    /// REFUSED alone: never applied.
    Refused,
    /// Applied-unknown past the op-id retention margin: the operator says whether it landed.
    LandedUnknown,
}

/// A CARVE: cells taken out of the unsent accumulator (each cell's whole net), sealed under a new
/// SEQUENCE and two op ids. Its `carve` record both consumes the cells and records `sent`: nothing
/// can fold into it afterwards, so one op id always has one body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// Its SEQUENCE: monotonic per node; bisect children keep it, and the sender resolves the
    /// lowest unresolved sequence first, one in flight.
    pub seq: u64,
    /// The usage op.
    pub usage_op: Op,
    /// The metering op.
    pub metering_op: Op,
    /// The cells, in the accumulator's stable order.
    pub cells: Vec<CellCount>,
    /// The metering rows (the provider already carries the entry-id prefix).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metering: Vec<MeteringDelta>,
    /// When it was carved and first sent, wall-clock ms (the 24 h retention clock).
    pub t_sent: u64,
}

/// One PART of a REFUSED op: the cells (usage) or rows (metering) `lo..hi` of the batch, sent
/// alone under its own new op id. A refused part is BISECTED into two halves; a single cell refused
/// alone is dead-lettered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// The part's op.
    pub op: Op,
    /// First index, inclusive.
    pub lo: usize,
    /// Last index, exclusive.
    pub hi: usize,
}

/// A spool record (MONEY-DESIGN §3c, "The spool").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
pub enum Rec {
    /// One window's take, added into the unsent accumulator.
    Fold {
        /// The window's sequence (diagnostic).
        window_seq: u64,
        /// The take's cells.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cells: Vec<CellCount>,
        /// The take's metering rows.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        metering: Vec<MeteringDelta>,
    },
    /// A carve: consumes its cells from the accumulator and records them sent.
    Carve(Batch),
    /// `op` answered applied.
    Ready {
        /// The op.
        op: Op,
    },
    /// `op` first answered applied-unknown at `t_first`.
    Failing {
        /// The op.
        op: Op,
        /// The first failure, wall-clock ms.
        t_first: u64,
    },
    /// Batch `seq`'s `kind` body now stands as `parts` (a REFUSED op bisected), written before any
    /// new part is sent. The parts keep the batch's sequence.
    Split {
        /// The batch.
        seq: u64,
        /// Which body.
        kind: Kind,
        /// Every part of the body, the done ones included.
        parts: Vec<Part>,
    },
    /// The `kind` body of batch `seq`, from index `lo` to `hi`, was dead-lettered. For a usage
    /// body it also moves those cells' current accumulator entries into the dead letter.
    Dead {
        /// The batch.
        seq: u64,
        /// Which body.
        kind: Kind,
        /// First index.
        lo: usize,
        /// Last index, exclusive.
        hi: usize,
        /// `refused` moves the cells' whole accumulator entries into the letter; `landed-unknown`
        /// only their negative fields.
        #[serde(default = "refused")]
        state: DeadState,
    },
}

fn refused() -> DeadState {
    DeadState::Refused
}

/// The bucket id of `bucket`'s sibling era row: `"e:" ++ hex32(SHA-256(bucket))`, 34 ASCII bytes.
#[must_use]
pub fn sibling_bucket(bucket: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bucket.as_bytes());
    format!("e:{}", hex::encode(&digest.as_ref()[..16]))
}

/// THE USAGE BODY of `cells`: per (bucket, window) the PLAIN row (every segment's total, exactly
/// the 1.5.5 row) and, when any count carries an entry, the SIBLING row with per-entry
/// pseudo-models (`"<id>\u{1f}<model>"`, and `"<id>\u{1f}"` with unit `fee` for the fee base). Cells
/// merged per (bucket, window, sibling) and sorted that way.
#[must_use]
pub fn usage_body<'c>(
    cells: impl IntoIterator<Item = &'c CellCount>,
) -> Vec<(String, u64, UsageDelta)> {
    let mut out: Vec<(String, u64, bool, UsageDelta)> = Vec::new();
    for cell in merged(cells) {
        let mut plain: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        let mut sib: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        let add = |into: &mut BTreeMap<String, BTreeMap<String, i64>>,
                       model: String,
                       class: &str,
                       n: i64| {
            let slot = into
                .entry(model)
                .or_default()
                .entry(class.to_string())
                .or_insert(0);
            *slot = slot.saturating_add(n);
        };
        for (seg, models) in &cell.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    add(&mut plain, model.clone(), class, *n);
                    if !seg.is_empty() {
                        add(&mut sib, format!("{seg}{SEP}{model}"), class, *n);
                    }
                }
            }
        }
        for (seg, n) in &cell.billable {
            if !seg.is_empty() {
                add(&mut sib, format!("{seg}{SEP}"), FEE_UNIT, *n);
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
                requests: cell.requests,
                billable_requests: cell.billable_total(),
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

/// The provider column a metering row is written with: `"<id>\u{1f}<provider>"` when an entry
/// priced it (MONEY-DESIGN §3d, `/admin/usage`: `provider` is in the metering primary key, so
/// rows of two entries never merge, and 1.5.5 still prices the row by its unprefixed `model`).
#[must_use]
pub fn prefixed_provider(seg: &str, provider: &str) -> String {
    if seg.is_empty() {
        provider.to_string()
    } else {
        format!("{seg}{SEP}{provider}")
    }
}

/// A stored provider column split into its entry id (`""` for a legacy row) and the provider.
#[must_use]
pub fn split_provider(stored: &str) -> (&str, &str) {
    match stored.split_once(SEP) {
        Some((id, provider))
            if id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            (id, provider)
        }
        _ => ("", stored),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: u8) -> String {
        hex::encode([n; 12])
    }

    #[test]
    fn the_plain_row_is_the_1_5_5_total_and_the_sibling_row_carries_each_entry() {
        let mut a = CellCount::new("group:g@day", 100);
        a.requests = 2;
        a.add_billable(&seg(1), 1);
        a.add_billable("", 1);
        a.add_unit(&seg(1), "gpt", "input", 10);
        a.add_unit("", "gpt", "input", 5);
        let body = usage_body([&a]);
        assert_eq!(body.len(), 2);
        let (_, w, plain) = body
            .iter()
            .find(|(b, _, _)| b == "group:g@day")
            .expect("the plain row");
        assert_eq!(*w, 100);
        assert_eq!(plain.requests, 2);
        assert_eq!(plain.billable_requests, 2);
        assert_eq!(plain.models[0].usage_units["input"], 15);
        let (sib_id, _, sib) = body
            .iter()
            .find(|(b, _, _)| *b == sibling_bucket("group:g@day"))
            .expect("the sibling row");
        assert_eq!(sib_id.len(), 34);
        assert_eq!(sib.requests, 0);
        let fee = sib
            .models
            .iter()
            .find(|m| m.model == format!("{}{SEP}", seg(1)))
            .expect("fee key");
        assert_eq!(fee.usage_units[FEE_UNIT], 1);
        let tok = sib
            .models
            .iter()
            .find(|m| m.model == format!("{}{SEP}gpt", seg(1)))
            .expect("model key");
        assert_eq!(tok.usage_units["input"], 10);
    }

    #[test]
    fn a_cell_that_nets_to_zero_writes_nothing() {
        let mut a = CellCount::new("k", 0);
        a.add_billable(&seg(2), 1);
        let b = a.negated();
        assert!(usage_body([&a, &b]).is_empty());
    }

    #[test]
    fn the_body_is_deterministic_whatever_the_cell_order() {
        let mut a = CellCount::new("b", 1);
        a.requests = 1;
        let mut c = CellCount::new("a", 1);
        c.add_unit(&seg(3), "m", "output", 4);
        assert_eq!(usage_body([&a, &c]), usage_body([&c, &a]));
    }

    #[test]
    fn a_provider_prefix_round_trips() {
        let p = prefixed_provider(&seg(4), "openai");
        assert_eq!(split_provider(&p), (seg(4).as_str(), "openai"));
        assert_eq!(split_provider("openai"), ("", "openai"));
        assert_eq!(split_provider("a\u{1f}b"), ("", "a\u{1f}b"));
    }
}
