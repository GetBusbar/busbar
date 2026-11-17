// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit-checkpoint custody book. It owns its derived answers: the recovered-target index that
//! admission reads without the book's lock, and the `unit -> checkpoint id` index. Both are exact
//! functions of the map, kept in step by the only methods that change it.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use busbar_contract::abi::sdk::expiry::Counted;

use super::{RecoveryEvent, UnitCheckpoint, UnitTarget};
use crate::persistence::journal::runtime::Carried;

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
    /// The number of `ended` entries: the admission gate's terminal backlog (SHUTDOWN-HANG
    /// F4a). Changed only under `inner`, by the methods that change an entry's `ended`.
    terminal: Arc<AtomicU64>,
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
    /// The unit's live audit line, carried from the root's seal (SHUTDOWN-HANG F1a). RAM only.
    audit: Option<Carried>,
    memory_selected: bool,
    fee_completion: Option<Arc<dyn super::partitions::SelectedFeeCompletion>>,
    awaiting_terminal_reader: bool,
    terminal_signal: Option<Arc<super::TerminalSignal>>,
}

/// One entry's custody facts at a non-retired exit (SHUTDOWN-HANG §5).
#[derive(Clone, Debug)]
pub(crate) struct UnitCustody {
    pub(crate) id: Id,
    pub(crate) ended: bool,
    pub(crate) persisted: Option<u64>,
    pub(crate) revision: u64,
    pub(crate) principal: String,
    pub(crate) group: String,
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
            audit: None,
            memory_selected: false,
            fee_completion: None,
            awaiting_terminal_reader: false,
            terminal_signal: None,
        }
    }

    pub(super) fn selected(snapshot: UnitCheckpoint, durable: bool, pending_hot: bool) -> Self {
        let mut entry = Self::new(snapshot, None, pending_hot);
        entry.memory_selected = !durable;
        entry
    }

    pub(super) fn is_memory_selected(&self) -> bool {
        self.memory_selected
    }

    pub(super) fn with_fee_completion(
        mut self,
        completion: Option<Arc<dyn super::partitions::SelectedFeeCompletion>>,
    ) -> Self {
        self.fee_completion = completion;
        self.awaiting_terminal_reader = true;
        self
    }

    pub(super) fn require_terminal_reader(mut self) -> Self {
        self.awaiting_terminal_reader = true;
        self
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
        self.audit.map(|line| line.seq)
    }

    /// The audit line hint the flusher's removal carries into the audit confirmation.
    pub(super) fn audit_hint(&self) -> Option<Carried> {
        self.audit
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
                    let mut windows = BTreeMap::new();
                    windows.insert(target.window, NonZeroUsize::MIN);
                    index.insert(target.bucket.as_str().into(), windows);
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
            terminal: &self.terminal,
        }
    }

    /// The terminal-backlog counter the admission gate reads without the lock.
    pub(super) fn terminal_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.terminal)
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
        let ended = inner.entries.values().filter(|e| e.snapshot.ended).count();
        assert_eq!(
            self.terminal.load(Ordering::Relaxed),
            u64::try_from(ended).unwrap_or(u64::MAX),
            "terminal mirror"
        );
    }
}

pub(super) struct PendingGuard<'a> {
    inner: MutexGuard<'a, Inner>,
    blocked: &'a RecoveredTargets,
    audit_misses: &'a AtomicU64,
    terminal: &'a AtomicU64,
}

impl PendingGuard<'_> {
    pub(super) fn get(&self, id: &Id) -> Option<&Pending> {
        self.inner.entries.get(id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.inner.entries.is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.inner.entries.len()
    }

    /// The lowest audit line `node_seq` noted on any entry (SEALING-FIX §3.9 floor (b)).
    pub(super) fn oldest_audit_seq(&self) -> Option<u64> {
        self.inner
            .entries
            .values()
            .filter_map(Pending::audit_seq)
            .min()
    }

    pub(super) fn insert(&mut self, id: Id, entry: Pending) -> Option<Pending> {
        // Index the new entry before unindexing the one it replaces, so a target that stays
        // recovered never reads as unblocked in between.
        if entry.recovered {
            self.blocked.add(&entry.snapshot.targets);
        }
        let unit = entry.snapshot.unit;
        if entry.snapshot.ended {
            self.terminal.fetch_add(1, Ordering::Relaxed);
        }
        let old = self.inner.entries.insert(id, entry);
        if let Some(old) = &old {
            if old.snapshot.ended {
                self.terminal.fetch_sub(1, Ordering::Relaxed);
            }
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
        if old.snapshot.ended {
            self.terminal.fetch_sub(1, Ordering::Relaxed);
        }
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
            terminal: self.terminal,
        })
    }

    /// Records the live audit line for `unit` on its single live entry. Zero or several live
    /// entries is a counted miss, never a guess.
    pub(super) fn note_unit_audit(
        &mut self,
        unit: u64,
        line: Carried,
    ) -> Result<(), UnitAuditMiss> {
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
                && found.replace(*id).is_some()
            {
                several = true;
            }
        }
        match found {
            Some(id) if !several => {
                if let Some(entry) = self.inner.entries.get_mut(&id) {
                    entry.audit = Some(line);
                }
                Ok(())
            }
            _ => {
                self.audit_misses.fetch_add(1, Ordering::Relaxed);
                Err(UnitAuditMiss)
            }
        }
    }

    /// The flush pass's snapshot (SHUTDOWN-HANG F3.3): every `ended` entry first, then the
    /// running entries whose revision moved since their last persist, each group in id order.
    /// A running entry whose revision is persisted needs no store call and is skipped.
    pub(super) fn flush_order(&self) -> Vec<Id> {
        crate::off_path::governance::runtime::unit_checkpoint_book_flush_order(
            self.inner
                .entries
                .iter()
                .filter(|(_, entry)| !entry.memory_selected),
            |e: &Pending| e.snapshot.ended,
            |e: &Pending| !e.snapshot.ended && e.persisted != Some(e.snapshot.revision),
        )
    }

    pub(super) fn memory_order(&self) -> Vec<Id> {
        self.inner
            .entries
            .iter()
            .filter(|(_, entry)| entry.memory_selected && entry.snapshot.ended)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Every entry's custody facts at exit: id, ended, persisted revision, staged revision,
    /// principal and group. A cold walk: a non-retired exit only.
    pub(super) fn custody_states(&self) -> Vec<UnitCustody> {
        crate::off_path::governance::runtime::unit_checkpoint_book_map(
            self.inner.entries.iter(),
            |(id, e): (&Id, &Pending)| UnitCustody {
                id: *id,
                ended: e.snapshot.ended,
                persisted: e.persisted,
                revision: e.snapshot.revision,
                principal: e.snapshot.principal.clone(),
                group: e.snapshot.group.clone(),
            },
        )
    }

    /// Whether every entry satisfies `f`. A cold walk: boot only.
    pub(super) fn all(&self, f: impl FnMut(&Pending) -> bool) -> bool {
        crate::off_path::governance::runtime::unit_checkpoint_book_all(
            self.inner.entries.values(),
            f,
        )
    }
}

pub(super) struct PendingEdit<'a> {
    id: Id,
    entry: &'a mut Pending,
    by_unit: &'a mut Counted<BTreeSet<(u64, Id)>>,
    blocked: &'a RecoveredTargets,
    terminal: &'a AtomicU64,
}

impl PendingEdit<'_> {
    pub(super) fn terminal_signal(&mut self) -> Arc<super::TerminalSignal> {
        self.entry
            .terminal_signal
            .get_or_insert_with(Default::default)
            .clone()
    }
    pub(super) fn matches_terminal_signal(
        &self,
        expected: Option<&Arc<super::TerminalSignal>>,
    ) -> bool {
        match expected {
            Some(expected) => self
                .entry
                .terminal_signal
                .as_ref()
                .is_some_and(|actual| Arc::ptr_eq(actual, expected)),
            None => self
                .entry
                .terminal_signal
                .as_ref()
                .is_none_or(|signal| !signal.claimed.load(Ordering::Acquire)),
        }
    }
    pub(super) fn notify_terminal(&self) {
        if let Some(signal) = &self.entry.terminal_signal {
            signal.notify();
        }
    }
    pub(super) fn awaiting_terminal_reader(&self) -> bool {
        self.entry.awaiting_terminal_reader
    }
    pub(super) fn terminal_reader_accepted(&mut self) {
        self.entry.awaiting_terminal_reader = false;
    }
    pub(super) fn is_memory_selected(&self) -> bool {
        self.entry.memory_selected
    }
    pub(super) fn resolve_fee(&mut self) -> Result<bool, super::RecordStoreError> {
        let result = self.resolve_fee_inner();
        if !matches!(result, Ok(false)) {
            self.notify_terminal();
        }
        result
    }
    fn resolve_fee_inner(&mut self) -> Result<bool, super::RecordStoreError> {
        let Some(parts) = self.entry.snapshot.partitions.as_ref() else {
            return Ok(true);
        };
        if !parts.fee.pending() {
            return Ok(true);
        }
        let Some(result) = self
            .entry
            .fee_completion
            .as_ref()
            .and_then(|observer| observer.observe())
        else {
            return Ok(false);
        };
        let mut snapshot = self.entry.snapshot.clone();
        snapshot.revision = snapshot
            .revision
            .checked_add(1)
            .ok_or_else(|| super::error("selected fee revision exhausted"))?;
        let parts = snapshot.partitions.as_mut().expect("selected fee owner");
        parts.fee = super::partitions::CapturedFee::ResolvedOwner {
            basis: parts.fee.basis().clone(),
            result,
        };
        super::partitions::validate_successor(&self.entry.snapshot, &snapshot)?;
        self.replace_snapshot(snapshot);
        self.entry.fee_completion = None;
        Ok(true)
    }
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
        match (self.entry.snapshot.ended, snapshot.ended) {
            (false, true) => {
                self.terminal.fetch_add(1, Ordering::Relaxed);
            }
            (true, false) => {
                self.terminal.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
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
