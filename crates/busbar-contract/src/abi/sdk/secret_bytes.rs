// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Private encoder storage: growth retires the previous initialized bytes through a wiping owner.

use std::io::{self, Write};
use std::ops::Deref;

use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let len = self
            .0
            .len()
            .checked_add(bytes.len())
            .expect("encoder length");
        if len > self.0.capacity() {
            let capacity = len.max(self.0.capacity().saturating_mul(2)).max(8);
            let mut next = Zeroizing::new(Vec::with_capacity(capacity));
            next.extend_from_slice(&self.0);
            // Assignment drops and wipes the old allocation before it is freed. Calling reserve
            // on the live credential buffer would instead free an unwiped previous allocation.
            self.0 = next;
        }
        self.0.extend_from_slice(bytes);
        #[cfg(test)]
        watch(&self.0);
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Transfer the complete allocation to an existing caller-owned wire API. No copy is made.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        let mut bytes = self.0;
        std::mem::take(&mut *bytes)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Write for SecretBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn watch(bytes: &[u8]) {
    // SAFETY: all callers own this allocation's initialized base prefix and retain it on the
    // observing thread until it is wiped/freed or the probe finishes. No spare capacity is read.
    unsafe { crate::alloc_counter::watch_initialized_payload(bytes) }
}
