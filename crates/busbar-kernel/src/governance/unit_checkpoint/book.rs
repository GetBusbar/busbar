// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit-checkpoint custody book. It owns its derived answers: the recovered-target index that
//! admission reads without the book's lock, and the `unit -> checkpoint id` index. Both are exact
//! functions of the map, kept in step by the only methods that change it.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

use busbar_contract::abi::sdk::expiry::Counted;

use super::{RecoveryEvent, UnitCheckpoint, UnitTarget};

type Id = [u8; 16];
/// bucket -> window -> number of recovered-entry targets naming it.
type TargetIndex = BTreeMap<Box<str>, BTreeMap<u64, NonZeroUsize>>;

#[derive(Default)]
pub(super) struct PendingBook {
    /// The one map lock, as before.
    inner: Mutex<Inner>,
    /// Read by admission without `inner`.
    blocked: RecoveredTargets,
    /// `note_unit_audit` calls that matched no single live entry.
    audit_misses: AtomicU64,
}

#[derive(Default)]
pub(super) struct Inner {
    entries: Counted<BTreeMap<Id, Pending>>,
    /// `(unit, id)` for every entry. Same lock as `entries`.
    by_unit: Counted<BTreeSet<(u64, Id)>>,
}

#[derive(Default)]
struct RecoveredTargets {
    /// Number of recovered entries. 0 implies `index` is empty.
    live: AtomicUsize,
    /// bucket -> window -> number of recovered-entry targets naming it.
    index: RwLock<Counted<TargetIndex>>,
}

pub(super) struct Pending {
    snapshot: UnitCheckpoint,
    persisted: Option<u64>,
    recovered: bool,
    audit_seq: Option<u64>,
}

/// `note_unit_audit` matched zero or several live entries for the unit; the caller falls back to
/// its cold lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitAuditMiss;

impl Pending {
    /// A running unit's report.
    pub(super) fn live(snapshot: UnitCheckpoint) -> Self {
        Self::new(snapshot, None, false)
    }

    /// A finished unit whose hot accounting applied.
    pub(super) fn terminal(snapshot: UnitCheckpoint, persisted: Option<u64>) -> Self {
        Self::new(snapshot, persisted, false)
    }

    /// A unit replayed at boot, or one whose hot accounting failed: its targets refuse admission
    /// until its durable custody settles.
    pub(super) fn recovered(snapshot: UnitCheckpoint, persisted: Option<u64>) -> Self {
        Self::new(snapshot, persisted, true)
    }

    fn new(snapshot: UnitCheckpoint, persisted: Option<u64>, recovered: bool) -> Self {
        Self {
            snapshot,
            persisted,
            recovered,
            audit_seq: None,
        }
    }

    pub(super) fn snapshot(&self) -> &UnitCheckpoint {
        &self.snapshot
    }

    pub(super) fn persisted(&self) -> Option<u64> {
        self.persisted
    }

    #[cfg(test)]
    pub(super) fn is_recovered(&self) -> bool {
        self.recovered
    }

    pub(super) fn audit_seq(&self) -> Option<u64> {
        self.audit_seq
    }
}

impl RecoveredTargets {
    fn blocks(&self, bucket: &str, window: u64) -> bool {
        if self.live.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.index
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(bucket)
            .is_some_and(|windows| windows.contains_key(&window))
    }

    fn add(&self, targets: &[UnitTarget]) {
        let mut index = self.index.write().unwrap_or_else(|p| p.into_inner());
        for target in targets {
            match index.get_mut(target.bucket.as_str()) {
                Some(windows) => {
                    windows
                        .entry(target.window)
                        .and_modify(|n| *n = n.saturating_add(1))
                        .or_insert(NonZeroUsize::MIN);
                }
                None => {
                    index.insert(
                        target.bucket.as_str().into(),
                        BTreeMap::from([(target.window, NonZeroUsize::MIN)]),
                    );
                }
            }
        }
        self.live.fetch_add(1, Ordering::Release);
    }

    fn drop_targets(&self, targets: &[UnitTarget]) {
        let mut index = self.index.write().unwrap_or_else(|p| p.into_inner());
        for target in targets {
            let Some(windows) = index.get_mut(target.bucket.as_str()) else {
                continue;
            };
            if let Some(n) = windows.get_mut(&target.window) {
                match NonZeroUsize::new(n.get() - 1) {
                    Some(left) => *n = left,
                    None => {
                        windows.remove(&target.window);
                    }
                }
            }
            if windows.is_empty() {
                index.remove(target.bucket.as_str());
            }
        }
        self.live.fetch_sub(1, Ordering::Release);
    }
}

impl PendingBook {
    /// The only way to reach the map and its unit index.
    pub(super) fn lock(&self) -> PendingGuard<'_> {
        PendingGuard {
            inner: self.inner.lock().unwrap_or_else(|p| p.into_inner()),
            blocked: &self.blocked,
            audit_misses: &self.audit_misses,
        }
    }

    /// Whether a recovered unit still blocks admission to `(bucket, window)`. It never takes the
    /// book's lock and never touches live entries: O(1) with no recovered unit, else O(log R) for
    /// R recovered targets.
    pub(super) fn blocks(&self, bucket: &str, window: u64) -> bool {
        self.blocked.blocks(bucket, window)
    }

    pub(super) fn audit_misses(&self) -> u64 {
        self.audit_misses.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn hold(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Entries visited so far across all three counted structures.
    #[cfg(test)]
    pub(super) fn visits(&self) -> u64 {
        let inner = self.hold();
        inner.entries.visits()
            + inner.by_unit.visits()
            + self
                .blocked
                .index
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .visits()
    }

    #[cfg(test)]
    pub(super) fn recovered_live(&self) -> usize {
        self.blocked.live.load(Ordering::Acquire)
    }

    /// Rebuilds every derived structure from the map and asserts it equals the kept one.
    #[cfg(test)]
    pub(super) fn check(&self) {
        let inner = self.hold();
        let mut live = 0;
        let mut index: BTreeMap<Box<str>, BTreeMap<u64, usize>> = BTreeMap::new();
        let mut by_unit = BTreeSet::new();
        for (id, entry) in inner.entries.iter() {
            by_unit.insert((entry.snapshot.unit, *id));
            if entry.recovered {
                live += 1;
                for target in &entry.snapshot.targets {
                    *index
                        .entry(target.bucket.as_str().into())
                        .or_default()
                        .entry(target.window)
                        .or_default() += 1;
                }
            }
        }
        assert_eq!(self.blocked.live.load(Ordering::Acquire), live, "live");
        let kept: BTreeMap<Box<str>, BTreeMap<u64, usize>> = self
            .blocked
            .index
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(bucket, windows)| {
                (
                    bucket.clone(),
                    windows.iter().map(|(w, n)| (*w, n.get())).collect(),
                )
            })
            .collect();
        assert_eq!(kept, index, "recovered index");
        let kept: BTreeSet<_> = inner.by_unit.iter().copied().collect();
        assert_eq!(kept, by_unit, "unit index");
    }
}

pub(super) struct PendingGuard<'a> {
    inner: MutexGuard<'a, Inner>,
    blocked: &'a RecoveredTargets,
    audit_misses: &'a AtomicU64,
}

impl PendingGuard<'_> {
    pub(super) fn get(&self, id: &Id) -> Option<&Pending> {
        self.inner.entries.get(id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.inner.entries.is_empty()
    }

    pub(super) fn insert(&mut self, id: Id, entry: Pending) -> Option<Pending> {
        // Index the new entry before unindexing the one it replaces, so a target that stays
        // recovered never reads as unblocked in between.
        if entry.recovered {
            self.blocked.add(&entry.snapshot.targets);
        }
        let unit = entry.snapshot.unit;
        let old = self.inner.entries.insert(id, entry);
        if let Some(old) = &old {
            self.inner.by_unit.remove(&(old.snapshot.unit, id));
            if old.recovered {
                self.blocked.drop_targets(&old.snapshot.targets);
            }
        }
        self.inner.by_unit.insert((unit, id));
        old
    }

    pub(super) fn remove(&mut self, id: &Id) -> Option<Pending> {
        let old = self.inner.entries.remove(id)?;
        self.inner.by_unit.remove(&(old.snapshot.unit, *id));
        if old.recovered {
            self.blocked.drop_targets(&old.snapshot.targets);
        }
        Some(old)
    }

    pub(super) fn edit(&mut self, id: &Id) -> Option<PendingEdit<'_>> {
        let inner = &mut *self.inner;
        let entry = inner.entries.get_mut(id)?;
        Some(PendingEdit {
            id: *id,
            entry,
            by_unit: &mut inner.by_unit,
            blocked: self.blocked,
        })
    }

    /// Records the live audit line for `unit` on its single live entry. Zero or several live
    /// entries is a counted miss, never a guess.
    pub(super) fn note_unit_audit(&mut self, unit: u64, seq: u64) -> Result<(), UnitAuditMiss> {
        let mut found = None;
        let mut several = false;
        for (_, id) in self
            .inner
            .by_unit
            .range((unit, [0; 16])..=(unit, [u8::MAX; 16]))
        {
            if self
                .inner
                .entries
                .get(id)
                .is_some_and(|entry| !entry.recovered)
            {
                several |= found.replace(*id).is_some();
            }
        }
        match found {
            Some(id) if !several => {
                if let Some(entry) = self.inner.entries.get_mut(&id) {
                    entry.audit_seq = Some(seq);
                }
                Ok(())
            }
            _ => {
                self.audit_misses.fetch_add(1, Ordering::Relaxed);
                Err(UnitAuditMiss)
            }
        }
    }

    /// Every id. A cold walk: the flusher's pass and shutdown only.
    pub(super) fn ids(&self) -> Vec<Id> {
        self.inner.entries.keys().copied().collect()
    }

    /// Whether every entry satisfies `f`. A cold walk: boot only.
    pub(super) fn all(&self, f: impl FnMut(&Pending) -> bool) -> bool {
        self.inner.entries.values().all(f)
    }
}

pub(super) struct PendingEdit<'a> {
    id: Id,
    entry: &'a mut Pending,
    by_unit: &'a mut Counted<BTreeSet<(u64, Id)>>,
    blocked: &'a RecoveredTargets,
}

impl PendingEdit<'_> {
    pub(super) fn snapshot(&self) -> &UnitCheckpoint {
        &self.entry.snapshot
    }

    pub(super) fn persisted(&self) -> Option<u64> {
        self.entry.persisted
    }

    pub(super) fn is_recovered(&self) -> bool {
        self.entry.recovered
    }

    /// Replaces the snapshot, re-keying the unit index and, for a recovered entry, its targets.
    pub(super) fn replace_snapshot(&mut self, snapshot: UnitCheckpoint) {
        if self.entry.recovered {
            self.blocked.add(&snapshot.targets);
            self.blocked.drop_targets(&self.entry.snapshot.targets);
        }
        if snapshot.unit != self.entry.snapshot.unit {
            self.by_unit.remove(&(self.entry.snapshot.unit, self.id));
            self.by_unit.insert((snapshot.unit, self.id));
        }
        self.entry.snapshot = snapshot;
    }

    /// Selects the terminal operations. Neither the unit nor the targets change.
    pub(super) fn set_terminal(&mut self, events: Vec<RecoveryEvent>, revision: u64) {
        self.entry.snapshot.terminal = Some(events);
        self.entry.snapshot.revision = revision;
    }

    pub(super) fn set_persisted(&mut self, revision: u64) {
        self.entry.persisted = Some(revision);
    }
}
