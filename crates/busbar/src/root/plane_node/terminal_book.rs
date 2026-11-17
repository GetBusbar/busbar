// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Node's terminal custody records, backed by class-isolated process storage.
//! The pinned Rust 1.98 RawVec/Global cohort requests the exact array layout for
//! a fresh `try_reserve_exact`. Revalidate that contract when changing toolchains.

use std::alloc::Layout;

use busbar_contract::storage::{StorageCredit, StorageSource};
use busbar_contract::UnitKey;
use busbar_kernel::limits::process_admission::AdmissionClass;

use super::RetainedUnit;

#[cfg(test)]
#[path = "terminal_book_tests.rs"]
mod tests;

struct Entry {
    key: UnitKey,
    unit: RetainedUnit,
}

struct Partition {
    // Storage must be destroyed before its credit, including ordinary Drop.
    entries: Vec<Entry>,
    credit: Option<StorageCredit>,
    source: StorageSource,
}

impl Partition {
    fn new(source: StorageSource) -> Self {
        Self {
            entries: Vec::new(),
            credit: None,
            source,
        }
    }

    fn position(&self, key: UnitKey) -> Result<usize, usize> {
        self.entries
            .binary_search_by_key(&key.get(), |entry| entry.key.get())
    }

    fn reserve_slot(&mut self) -> bool {
        if self.entries.len() < self.entries.capacity() {
            return true;
        }
        let Some(capacity) = self
            .entries
            .capacity()
            .max(1)
            .checked_mul(if self.entries.capacity() == 0 { 1 } else { 2 })
        else {
            return false;
        };
        let Ok(layout) = Layout::array::<Entry>(capacity) else {
            return false;
        };
        let Ok(credit) = self.source.try_reserve(layout.size()) else {
            return false;
        };
        // Declare backing after credit: even unwinding destroys backing first.
        let mut replacement = Vec::new();
        if replacement.try_reserve_exact(capacity).is_err() {
            return false;
        }
        assert_eq!(
            replacement.capacity(),
            capacity,
            "pinned allocation cohort changed"
        );
        // The new allocation and old allocation remain charged during movement.
        for entry in self.entries.drain(..) {
            replacement.push(entry);
        }
        let old = std::mem::replace(&mut self.entries, replacement);
        drop(old);
        self.credit = Some(credit);
        true
    }

    fn remove(&mut self, key: UnitKey) -> Option<RetainedUnit> {
        let position = self.position(key).ok()?;
        let entry = self.entries.remove(position);
        if self.entries.is_empty() {
            drop(std::mem::take(&mut self.entries));
            drop(self.credit.take());
        }
        Some(entry.unit)
    }

    fn next(&self, after: Option<u64>, upper: u64) -> Option<UnitKey> {
        let position = after.map_or(0, |last| {
            self.entries
                .partition_point(|entry| entry.key.get() <= last)
        });
        self.entries
            .get(position)
            .filter(|entry| entry.key.get() <= upper)
            .map(|entry| entry.key)
    }
}

pub(super) struct TerminalBook {
    data: Partition,
    operator: Partition,
}

impl TerminalBook {
    pub(super) fn new(data: StorageSource, operator: StorageSource) -> Self {
        Self {
            data: Partition::new(data),
            operator: Partition::new(operator),
        }
    }

    fn partition(&self, class: AdmissionClass) -> &Partition {
        match class {
            AdmissionClass::Data => &self.data,
            AdmissionClass::Operator => &self.operator,
        }
    }

    fn partition_mut(&mut self, class: AdmissionClass) -> &mut Partition {
        match class {
            AdmissionClass::Data => &mut self.data,
            AdmissionClass::Operator => &mut self.operator,
        }
    }

    /// Install before effects. Every refusal returns the original custody intact.
    #[expect(
        clippy::result_large_err,
        reason = "refusal must return inline custody without allocating an uncharged error box"
    )]
    pub(super) fn insert(
        &mut self,
        class: AdmissionClass,
        key: UnitKey,
        unit: RetainedUnit,
    ) -> Result<(), RetainedUnit> {
        if self.data.position(key).is_ok() || self.operator.position(key).is_ok() {
            return Err(unit);
        }
        let partition = self.partition_mut(class);
        let position = partition.position(key).unwrap_err();
        if !partition.reserve_slot() {
            return Err(unit);
        }
        partition.entries.insert(position, Entry { key, unit });
        Ok(())
    }

    pub(super) fn get(&self, class: AdmissionClass, key: UnitKey) -> Option<&RetainedUnit> {
        let partition = self.partition(class);
        Some(&partition.entries[partition.position(key).ok()?].unit)
    }

    pub(super) fn get_mut(
        &mut self,
        class: AdmissionClass,
        key: UnitKey,
    ) -> Option<&mut RetainedUnit> {
        let partition = self.partition_mut(class);
        let position = partition.position(key).ok()?;
        Some(&mut partition.entries[position].unit)
    }

    /// The caller verifies the original call/slot/binding before taking custody.
    pub(super) fn remove(&mut self, class: AdmissionClass, key: UnitKey) -> Option<RetainedUnit> {
        self.partition_mut(class).remove(key)
    }

    pub(super) fn len(&self) -> usize {
        self.data.entries.len() + self.operator.entries.len()
    }

    pub(super) fn max_key(&self) -> u64 {
        self.data
            .entries
            .last()
            .map_or(0, |entry| entry.key.get())
            .max(
                self.operator
                    .entries
                    .last()
                    .map_or(0, |entry| entry.key.get()),
            )
    }

    pub(super) fn next(&self, last: Option<u64>, upper: u64) -> Option<(AdmissionClass, UnitKey)> {
        match (self.data.next(last, upper), self.operator.next(last, upper)) {
            (Some(data), Some(operator)) if operator.get() < data.get() => {
                Some((AdmissionClass::Operator, operator))
            }
            (Some(data), _) => Some((AdmissionClass::Data, data)),
            (None, Some(operator)) => Some((AdmissionClass::Operator, operator)),
            (None, None) => None,
        }
    }

    /// Drain accounting only; page and driver pulses use bounded `next` instead.
    pub(super) fn values(&self) -> impl Iterator<Item = &RetainedUnit> {
        self.data
            .entries
            .iter()
            .chain(self.operator.entries.iter())
            .map(|entry| &entry.unit)
    }
}
