// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound tables, each keyed by what its retire event names (EXTRACT-IF-SWEEPS S3, S4).
//!
//! A stream end names `(owner, framing, stream)` and a connection end names `framing`; no table
//! is keyed that way round, so each used to be swept in full under its mutex. Here each table
//! is nested by the key its retire event names, and the retired rows leave in one move. Each
//! table stays behind its own mutex and these types are the only mutators of their indexes.

use super::{PendingAdoption, UnitState};
use foldhash::HashMap;
use smallvec::SmallVec;

/// Rows keyed `(key, framing)`, held by framing. Framing ids come from one global counter, so a
/// framing nearly always has one row and the inline slot holds it.
pub(super) struct ByFraming<K, V> {
    rows: HashMap<u64, SmallVec<[(K, V); 1]>>,
    len: usize,
}

impl<K, V> Default for ByFraming<K, V> {
    fn default() -> Self {
        Self {
            rows: HashMap::default(),
            len: 0,
        }
    }
}

impl<K: Copy + PartialEq, V> ByFraming<K, V> {
    pub(super) fn get(&self, key: K, framing: u64) -> Option<&V> {
        self.rows
            .get(&framing)?
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }

    pub(super) fn get_mut(&mut self, key: K, framing: u64) -> Option<&mut V> {
        self.rows
            .get_mut(&framing)?
            .iter_mut()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }

    pub(super) fn contains_key(&self, key: K, framing: u64) -> bool {
        self.get(key, framing).is_some()
    }

    /// Insert, replacing and answering a row already at `(key, framing)`.
    pub(super) fn insert(&mut self, key: K, framing: u64, value: V) -> Option<V> {
        let row = self.rows.entry(framing).or_default();
        if let Some(slot) = row.iter_mut().find(|(k, _)| *k == key) {
            return Some(std::mem::replace(&mut slot.1, value));
        }
        row.push((key, value));
        self.len += 1;
        None
    }

    /// The row at `(key, framing)`, made by `make` when absent.
    pub(super) fn or_insert_with(&mut self, key: K, framing: u64, make: impl FnOnce() -> V) {
        if !self.contains_key(key, framing) {
            self.insert(key, framing, make());
        }
    }

    pub(super) fn remove(&mut self, key: K, framing: u64) -> Option<V> {
        let row = self.rows.get_mut(&framing)?;
        let at = row.iter().position(|(k, _)| *k == key)?;
        let (_, value) = row.swap_remove(at);
        if row.is_empty() {
            self.rows.remove(&framing);
        }
        self.len -= 1;
        Some(value)
    }

    /// Every row of `framing`, moved out whole.
    pub(super) fn take(&mut self, framing: u64) -> SmallVec<[(K, V); 1]> {
        let row = self.rows.remove(&framing).unwrap_or_default();
        self.len -= row.len();
        row
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// Every row as `(key, framing, value)`: the test adapter's way back to a flat map.
    #[cfg(test)]
    pub(super) fn into_flat(self) -> impl Iterator<Item = (K, u64, V)> {
        self.rows
            .into_iter()
            .flat_map(|(framing, row)| row.into_iter().map(move |(k, v)| (k, framing, v)))
    }
}

/// One framing's units, keyed by `(owner, stream)`.
type StreamUnits = HashMap<(u64, u64), SmallVec<[u64; 1]>>;

/// The live units by id, and by the `(owner, stream)` of the framing each belongs to.
#[derive(Default)]
pub(super) struct Units {
    by_id: HashMap<u64, UnitState>,
    by_stream: HashMap<u64, StreamUnits>,
}

impl Units {
    pub(super) fn get(&self, id: &u64) -> Option<&UnitState> {
        self.by_id.get(id)
    }

    /// A unit's `owner` and `binding` key it in the index; a caller must not rewrite them
    /// through this borrow (a unit that changes owner or binding is removed and inserted).
    pub(super) fn get_mut(&mut self, id: &u64) -> Option<&mut UnitState> {
        self.by_id.get_mut(id)
    }

    pub(super) fn contains_key(&self, id: &u64) -> bool {
        self.by_id.contains_key(id)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.by_id.len()
    }

    pub(super) fn insert(&mut self, id: u64, unit: UnitState) -> Option<UnitState> {
        let old = self.remove(&id);
        if let Some(framing) = unit.binding.framing {
            self.by_stream
                .entry(framing)
                .or_default()
                .entry((unit.owner, unit.binding.stream))
                .or_default()
                .push(id);
        }
        self.by_id.insert(id, unit);
        old
    }

    pub(super) fn remove(&mut self, id: &u64) -> Option<UnitState> {
        let unit = self.by_id.remove(id)?;
        if let Some(framing) = unit.binding.framing {
            if let Some(streams) = self.by_stream.get_mut(&framing) {
                let key = (unit.owner, unit.binding.stream);
                if let Some(ids) = streams.get_mut(&key) {
                    if let Some(at) = ids.iter().position(|i| i == id) {
                        ids.swap_remove(at);
                    }
                    if ids.is_empty() {
                        streams.remove(&key);
                    }
                }
                if streams.is_empty() {
                    self.by_stream.remove(&framing);
                }
            }
        }
        Some(unit)
    }

    /// The units of one stream, moved out.
    pub(super) fn take_stream(
        &mut self,
        owner: u64,
        framing: u64,
        stream: u64,
    ) -> SmallVec<[UnitState; 2]> {
        let mut taken = SmallVec::new();
        let Some(streams) = self.by_stream.get_mut(&framing) else {
            return taken;
        };
        let ids = streams.remove(&(owner, stream));
        if streams.is_empty() {
            self.by_stream.remove(&framing);
        }
        for id in ids.into_iter().flatten() {
            taken.extend(self.by_id.remove(&id));
        }
        taken
    }

    /// The units of one framing, moved out.
    pub(super) fn take_framing(&mut self, framing: u64) -> SmallVec<[UnitState; 2]> {
        let mut taken = SmallVec::new();
        for ids in self
            .by_stream
            .remove(&framing)
            .into_iter()
            .flat_map(HashMap::into_values)
        {
            for id in ids {
                taken.extend(self.by_id.remove(&id));
            }
        }
        taken
    }

    /// The units of one stream, by id.
    pub(super) fn in_stream(
        &self,
        owner: u64,
        framing: u64,
        stream: u64,
    ) -> impl Iterator<Item = (u64, &UnitState)> + '_ {
        self.by_stream
            .get(&framing)
            .and_then(|streams| streams.get(&(owner, stream)))
            .into_iter()
            .flatten()
            .filter_map(|id| self.by_id.get(id).map(|unit| (*id, unit)))
    }

    /// The units of one framing, by id.
    pub(super) fn in_framing(&self, framing: u64) -> impl Iterator<Item = (u64, &UnitState)> + '_ {
        self.by_stream
            .get(&framing)
            .into_iter()
            .flat_map(HashMap::values)
            .flatten()
            .filter_map(|id| self.by_id.get(id).map(|unit| (*id, unit)))
    }
}

/// The pending session adoptions, by destination framing, and the destination of each source
/// leg (one pending adoption per leg), so the duplicate check reads the leg by key.
#[derive(Default)]
pub(super) struct Adoptions {
    by_destination: ByFraming<u64, PendingAdoption>,
    by_source: HashMap<u64, (u64, u64)>,
}

impl Adoptions {
    pub(super) fn contains_key(&self, owner: u64, framing: u64) -> bool {
        self.by_destination.contains_key(owner, framing)
    }

    pub(super) fn has_leg(&self, leg: u64) -> bool {
        self.by_source.contains_key(&leg)
    }

    pub(super) fn get(&self, owner: u64, framing: u64) -> Option<&PendingAdoption> {
        self.by_destination.get(owner, framing)
    }

    pub(super) fn insert(&mut self, owner: u64, framing: u64, stage: PendingAdoption) {
        self.by_source.insert(stage.source.leg, (owner, framing));
        self.by_destination.insert(owner, framing, stage);
    }

    pub(super) fn remove(&mut self, owner: u64, framing: u64) -> Option<PendingAdoption> {
        let stage = self.by_destination.remove(owner, framing)?;
        self.by_source.remove(&stage.source.leg);
        Some(stage)
    }

    /// Every adoption a framing's end retires: the ones headed to it and the one leaving it.
    pub(super) fn take_framing(&mut self, framing: u64) -> SmallVec<[PendingAdoption; 1]> {
        let mut taken: SmallVec<[PendingAdoption; 1]> = SmallVec::new();
        taken.extend(
            self.by_destination
                .take(framing)
                .into_iter()
                .map(|(_, stage)| stage),
        );
        for stage in &taken {
            self.by_source.remove(&stage.source.leg);
        }
        if let Some((owner, destination)) = self.by_source.remove(&framing) {
            taken.extend(self.by_destination.remove(owner, destination));
        }
        taken
    }
}
