// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read storage whose consumers cannot bypass wiping by resizing a raw vector.

use std::ops::{Bound, Deref, DerefMut, RangeBounds};

use zeroize::{Zeroize, Zeroizing};

/// Unread connection bytes. Slice access borrows the storage; consuming or clearing bytes wipes
/// their old positions. Growth retires the previous allocation through its wiping owner.
#[derive(Default)]
pub struct Input(Zeroizing<Vec<u8>>);

impl Input {
    /// Borrow the unread bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Erase all unread bytes and retain the allocation for the next read.
    pub fn clear(&mut self) {
        self.0.zeroize();
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let len = self
            .0
            .len()
            .checked_add(bytes.len())
            .expect("wire input length");
        if len > self.0.capacity() {
            let capacity = len.max(self.0.capacity().saturating_mul(2));
            let mut next = Zeroizing::new(Vec::with_capacity(capacity));
            next.extend_from_slice(&self.0);
            self.0 = next;
        }
        self.0.extend_from_slice(bytes);
        #[cfg(test)]
        crate::abi::sdk::secret_bytes::watch(&self.0);
    }

    /// Remove a range, yielding its bytes. Dropping the iterator erases any bytes not yielded.
    /// The source range and any vacated tail are erased before this method returns.
    pub fn drain(&mut self, range: impl RangeBounds<usize>) -> Drain {
        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("wire input range start"),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("wire input range end"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.0.len(),
        };
        assert!(start <= end && end <= self.0.len(), "wire input range");
        let bytes = Zeroizing::new(self.0[start..end].to_vec());
        #[cfg(test)]
        crate::abi::sdk::secret_bytes::watch(&bytes);
        let old_len = self.0.len();
        let new_len = old_len - (end - start);
        self.0[start..end].zeroize();
        self.0.copy_within(end..old_len, start);
        self.0[new_len..old_len].zeroize();
        self.0.truncate(new_len);
        Drain {
            bytes,
            front: 0,
            back: end - start,
        }
    }
}

impl Deref for Input {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Input {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Zeroize for Input {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Bytes removed from [`Input`], with a wiping owner for the not-yet-yielded contents.
pub struct Drain {
    bytes: Zeroizing<Vec<u8>>,
    front: usize,
    back: usize,
}

impl Iterator for Drain {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.front == self.back {
            return None;
        }
        let byte = std::mem::take(&mut self.bytes[self.front]);
        self.front += 1;
        Some(byte)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.back - self.front;
        (len, Some(len))
    }
}

impl DoubleEndedIterator for Drain {
    fn next_back(&mut self) -> Option<u8> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(std::mem::take(&mut self.bytes[self.back]))
    }
}

impl ExactSizeIterator for Drain {}
impl std::iter::FusedIterator for Drain {}

impl std::fmt::Debug for Drain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Drain")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
