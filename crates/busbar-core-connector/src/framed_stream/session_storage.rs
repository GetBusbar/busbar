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
    /// Encode directly into a fixed loan of already funded secure backing. The canonical writer
    /// cannot grow; errors and unwind wipe the entire abandoned loan before its credit is released.
    pub fn encode(
        source: &StorageSource,
        extent: usize,
        encode: impl FnOnce(
            &mut busbar_plugin_abi::records::Fixed<'_>,
        ) -> Result<(), busbar_plugin_abi::records::Full>,
    ) -> Result<Self, StorageDenied> {
        let credit = source.try_reserve(extent)?;
        let mut bytes = SecureVec::with_capacity(extent).map_err(|_| StorageDenied)?;
        bytes
            .read_into(extent, busbar_contract::secure::Tail::Wipe, |loan| {
                let mut writer = busbar_plugin_abi::records::Fixed::new(loan);
                encode(&mut writer)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
                Ok(writer.len())
            })
            .map_err(|_| StorageDenied)?
            .map_err(|_| StorageDenied)?;
        Ok(Self { bytes, credit })
    }

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

/// The most an emptied output buffer keeps: four read chunks. One that grew past it (an answer that
/// wrote more at once) is let go with its charge when it empties, not held for the connection's life.
const OUTPUT_KEPT: usize = 4 * 16 * 1024;

/// The smallest output buffer made: a response head and a small body piece fit without a second growth.
const OUTPUT_MIN: usize = 1024;

/// Where one WRITE's or WIRE_PART's bytes are in the session's output buffer: two offsets counted from the
/// buffer's last clear, never a pointer into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    start: usize,
    end: usize,
}

impl Span {
    /// The bytes the record carried.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the record carried no byte.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// THE SESSION'S OUTPUT: the socket-bound bytes of the answer being applied, in one wiped buffer that the
/// session owns. It is allocated when the session first has output, grows only when an answer needs more
/// room (the larger charge reserved before it grows), wipes each byte as the socket takes it, is cleared
/// (wiped) when the answer is done or abandoned, and goes with the session: its drop wipes what is left,
/// then returns the charge. A buffer grown past [`OUTPUT_KEPT`] is let go as soon as it is empty.
///
/// SPANS STAY VALID: bytes are only appended at the end, or taken (wiped) from the front in span order,
/// and growth copies them in order to the new block's front, so no offset moves; only [`Output::clear`]
/// ends spans, and it runs whenever the actions naming them are cleared.
pub(crate) struct Output {
    /// The live bytes; `None` until the first byte and after a release. Declared before the credit: the
    /// backing retires (wiped) before its charge is let go.
    bytes: Option<SecureVec>,
    /// The offset of the first live byte: how many bytes the socket took since the last clear.
    taken: usize,
    /// The charge for the buffer's whole capacity.
    credit: StorageCredit,
}

impl Output {
    /// No buffer yet: nothing is allocated or charged until the first byte.
    pub(crate) fn new(source: &StorageSource) -> Result<Self, StorageDenied> {
        Ok(Self {
            bytes: None,
            taken: 0,
            credit: source.try_reserve(0)?,
        })
    }

    /// Append a record's borrowed bytes after everything held and return where they are. On denial
    /// nothing is appended and what is held is unchanged.
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<Span, StorageDenied> {
        let held = self.bytes.as_ref().map_or(0, SecureVec::len);
        let start = self.taken.checked_add(held).ok_or(StorageDenied)?;
        let end = start.checked_add(bytes.len()).ok_or(StorageDenied)?;
        if bytes.is_empty() {
            return Ok(Span { start, end });
        }
        let need = held.checked_add(bytes.len()).ok_or(StorageDenied)?;
        let capacity = self.bytes.as_ref().map_or(0, SecureVec::capacity);
        // An answer's appends all come before the socket takes any of it, so the live bytes start at
        // the block's front and a `need` within the capacity extends in place, never allocating outside
        // the charge. Were bytes taken and some still held, they are first moved to a charged block.
        if need > capacity || (self.taken != 0 && held != 0) {
            self.grow(need)?;
        }
        let buffer = self.bytes.as_mut().ok_or(StorageDenied)?;
        buffer.extend(bytes).map_err(|_| StorageDenied)?;
        Ok(Span { start, end })
    }

    /// A block for at least `need` live bytes, charged before it is made; the held bytes are copied to
    /// its front and the old block is wiped and freed, then its charge let go.
    fn grow(&mut self, need: usize) -> Result<(), StorageDenied> {
        let capacity = self.bytes.as_ref().map_or(0, SecureVec::capacity);
        let target = if need > capacity {
            need.max(capacity.saturating_mul(2)).max(OUTPUT_MIN)
        } else {
            capacity
        };
        if self.bytes.as_ref().is_none_or(SecureVec::is_empty) {
            // Nothing held: the old block and its charge go before the larger one is charged.
            self.release();
        }
        let credit = self.credit.source().try_reserve(target)?;
        let mut next = SecureVec::with_capacity(target).map_err(|_| StorageDenied)?;
        if next.capacity() > credit.len() {
            return Err(StorageDenied);
        }
        if let Some(held) = &self.bytes {
            next.extend(held.as_slice()).map_err(|_| StorageDenied)?;
        }
        let old_bytes = std::mem::replace(&mut self.bytes, Some(next));
        let old_credit = std::mem::replace(&mut self.credit, credit);
        drop(old_bytes);
        drop(old_credit);
        Ok(())
    }

    /// The block (wiped by its drop) and then its charge go; the empty credit keeps the origin.
    fn release(&mut self) {
        drop(self.bytes.take());
        let all = self.credit.len();
        if let Ok(freed) = self.credit.split(all) {
            drop(freed);
        }
    }

    /// The bytes of `span` the socket has not taken yet.
    pub(crate) fn unwritten(&self, span: Span) -> &[u8] {
        let Some(bytes) = &self.bytes else {
            return &[];
        };
        let from = span.start.max(self.taken) - self.taken;
        let to = span.end.saturating_sub(self.taken);
        bytes.as_slice().get(from..to).unwrap_or(&[])
    }

    /// The socket took the first `count` unwritten bytes: they are wiped now. Only the tests take
    /// from the front today: the session hands the whole answer to the connection's queue
    /// (`Actions::handed_over`), which wipes as the connection takes.
    #[cfg(test)]
    pub(crate) fn take(&mut self, count: usize) {
        if let Some(bytes) = &mut self.bytes {
            let count = count.min(bytes.len());
            bytes.consume(count);
            self.taken += count;
        }
    }

    /// The answer is done or abandoned: every byte held is wiped and every span ends. A block grown past
    /// [`OUTPUT_KEPT`] goes now, with its charge; a smaller one stays for the session's next answer.
    pub(crate) fn clear(&mut self) {
        if let Some(bytes) = &mut self.bytes {
            bytes.clear();
            if bytes.capacity() > OUTPUT_KEPT {
                self.release();
            }
        }
        self.taken = 0;
    }

    /// The whole block, written or not (tests only: the wipe proofs read it).
    #[cfg(test)]
    pub(crate) fn allocation(&self) -> Option<&[u8]> {
        self.bytes.as_ref().map(SecureVec::allocation)
    }
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output")
            .field("len", &self.bytes.as_ref().map_or(0, SecureVec::len))
            .field(
                "capacity",
                &self.bytes.as_ref().map_or(0, SecureVec::capacity),
            )
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

    /// Grows the owner's own array in place: the larger extent is charged while the smaller one is still
    /// charged, then the old charge is let go. Nothing is copied into a second array.
    pub(crate) fn push(&mut self, value: T) -> Result<(), StorageDenied> {
        if self.values.len() == self.values.capacity() {
            let held = self.values.capacity();
            let capacity = self.values.len().saturating_mul(2).max(1);
            let bytes = capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(StorageDenied)?;
            let credit = self.credit.source().try_reserve(bytes)?;
            self.values
                .try_reserve_exact(capacity - self.values.len())
                .map_err(|_| StorageDenied)?;
            if self
                .values
                .capacity()
                .checked_mul(std::mem::size_of::<T>())
                .is_none_or(|n| n > credit.len())
            {
                self.values.shrink_to(held);
                return Err(StorageDenied);
            }
            let old = std::mem::replace(&mut self.credit, credit);
            drop(old);
        }
        self.values.push(value);
        Ok(())
    }

    /// The items, taken out in order; the array and its charge stay with the owner for its next use.
    pub(crate) fn drain(&mut self) -> std::vec::Drain<'_, T> {
        self.values.drain(..)
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
impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[cfg(test)]
#[path = "../tests/session_storage_tests.rs"]
mod tests;
