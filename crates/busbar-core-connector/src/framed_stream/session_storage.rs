// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Requested callback backing, retained through the actual consumer rather than logical progress.

use std::ops::Deref;

use busbar_contract::secure::SecureVec;
use busbar_contract::storage::{StorageCredit, StorageDenied, StorageSource};

/// Secure bytes together with the exact allocation credit. Logical consumption wipes bytes but
/// retains the full backing reservation; moving into an action, input or upgrade moves both.
pub struct Payload {
    bytes: SecureVec,
    credit: StorageCredit,
}

impl Payload {
    /// Reserve destination backing before allocating or copying a borrowed callback slice.
    pub fn copy(source: &StorageSource, bytes: &[u8]) -> Result<Self, StorageDenied> {
        let credit = source.try_reserve(bytes.len())?;
        let mut owned = SecureVec::with_capacity(bytes.len()).map_err(|_| StorageDenied)?;
        if owned.capacity() > credit.len() {
            return Err(StorageDenied);
        }
        owned.extend(bytes).map_err(|_| StorageDenied)?;
        Ok(Self {
            bytes: owned,
            credit,
        })
    }

    /// Borrow only the remaining logical bytes; ownership and credit stay together.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Wipe a successfully consumed prefix without refunding still-allocated backing capacity.
    pub(crate) fn consume(&mut self, count: usize) {
        self.bytes.consume(count);
    }

    #[cfg(test)]
    pub(crate) fn allocation(&self) -> &[u8] {
        self.bytes.allocation()
    }
    #[cfg(test)]
    pub(crate) fn live_range(&self) -> std::ops::Range<usize> {
        self.bytes.live_range()
    }

    /// Replacement reserves its full extent while the original remains live.
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), StorageDenied> {
        if bytes.is_empty() {
            return Ok(());
        }
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(StorageDenied)?;
        let credit = self.credit.source().try_reserve(length)?;
        let mut next = SecureVec::with_capacity(length).map_err(|_| StorageDenied)?;
        if next.capacity() > credit.len() {
            return Err(StorageDenied);
        }
        next.extend(self.bytes.as_slice())
            .map_err(|_| StorageDenied)?;
        next.extend(bytes).map_err(|_| StorageDenied)?;
        let old_bytes = std::mem::replace(&mut self.bytes, next);
        let old_credit = std::mem::replace(&mut self.credit, credit);
        drop(old_bytes);
        drop(old_credit);
        Ok(())
    }
}

impl Deref for Payload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// An upgrade protocol name whose separately allocated text retains its original credit.
pub struct Name {
    value: Box<str>,
    _credit: StorageCredit,
}

impl Name {
    pub(crate) fn copy(source: &StorageSource, value: &str) -> Result<Self, StorageDenied> {
        let credit = source.try_reserve(value.len())?;
        Ok(Self {
            value: value.into(),
            _credit: credit,
        })
    }
}

impl Deref for Name {
    type Target = str;
    fn deref(&self) -> &str {
        &self.value
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Name")
            .field("len", &self.value.len())
            .finish_non_exhaustive()
    }
}

/// A callback action or scratch array. Its actual backing retires before its allocation credit.
#[derive(Debug)]
pub struct Items<T> {
    values: Vec<T>,
    credit: StorageCredit,
}

impl<T> Items<T> {
    pub(crate) fn new(source: &StorageSource) -> Result<Self, StorageDenied> {
        Ok(Self {
            values: Vec::new(),
            credit: source.try_reserve(0)?,
        })
    }

    pub(crate) fn push(&mut self, value: T) -> Result<(), StorageDenied> {
        if self.values.len() == self.values.capacity() {
            let capacity = self
                .values
                .len()
                .checked_mul(2)
                .unwrap_or(usize::MAX)
                .max(1);
            let bytes = capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(StorageDenied)?;
            let credit = self.credit.source().try_reserve(bytes)?;
            let mut next = Vec::new();
            next.try_reserve_exact(capacity)
                .map_err(|_| StorageDenied)?;
            if next
                .capacity()
                .checked_mul(std::mem::size_of::<T>())
                .is_none_or(|n| n > credit.len())
            {
                return Err(StorageDenied);
            }
            next.append(&mut self.values);
            let old_values = std::mem::replace(&mut self.values, next);
            let old_credit = std::mem::replace(&mut self.credit, credit);
            drop(old_values);
            drop(old_credit);
        }
        self.values.push(value);
        Ok(())
    }

    pub(crate) fn take(&mut self) -> Result<Self, StorageDenied> {
        let empty = Self::new(self.credit.source())?;
        Ok(std::mem::replace(self, empty))
    }

    pub(crate) fn append(&mut self, other: Self) -> Result<(), StorageDenied> {
        for value in other {
            self.push(value)?;
        }
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
    pub(crate) fn last_mut(&mut self) -> Option<&mut T> {
        self.values.last_mut()
    }
    /// Read the captured items without exposing a mutable vector or detaching its backing credit.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.values.capacity()
    }
}

impl<T> Deref for Items<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

/// The original array credit survives iterator construction, partial consumption and cancellation.
pub struct OwnedIter<T> {
    values: std::vec::IntoIter<T>,
    _credit: StorageCredit,
}

impl<T> IntoIterator for Items<T> {
    type Item = T;
    type IntoIter = OwnedIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        OwnedIter {
            values: self.values.into_iter(),
            _credit: self.credit,
        }
    }
}

impl<'a, T> IntoIterator for &'a Items<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<T> Iterator for OwnedIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
}

#[cfg(test)]
fn test_source() -> StorageSource {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    ProcessAdmission::new(1).connection_storage(AdmissionClass::Data)
}

#[cfg(test)]
impl From<&[u8]> for Payload {
    fn from(bytes: &[u8]) -> Self {
        Self::copy(&test_source(), bytes).expect("test backing")
    }
}

#[cfg(test)]
impl<T: PartialEq> PartialEq<Vec<T>> for Items<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        self.as_slice() == other
    }
}

#[cfg(test)]
impl<T: PartialEq> PartialEq for Items<T> {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

#[cfg(test)]
impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[cfg(test)]
impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for Items<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        self.as_slice() == other
    }
}

#[cfg(test)]
#[path = "../tests/session_storage_tests.rs"]
mod tests;
