// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Private encoder storage: growth moves the initialized bytes into a fresh block and wipes the
//! old one; drop wipes the whole allocation. Every wipe goes through the unmarked
//! [`crate::abi::sdk::wipe::wipe_bytes`] (SECURE-TYPES, core #164).

use std::io::{self, Write};
use std::ops::Deref;

use crate::abi::sdk::wipe::wipe_bytes;
use crate::secure::SecureVec;

#[derive(Default)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let len = self
            .0
            .len()
            .checked_add(bytes.len())
            .expect("wiping buffer length");
        if len > self.0.capacity() {
            let mut next = Vec::with_capacity(len.max(self.0.capacity().saturating_mul(2)));
            next.extend_from_slice(&self.0);
            let mut old = std::mem::replace(&mut self.0, next);
            wipe_bytes(&mut old);
        }
        self.0.extend_from_slice(bytes);
        #[cfg(test)]
        watch(&self.0);
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    /// The bytes, still in custody, without a copy.
    pub(crate) fn into_secure(mut self) -> SecureVec {
        SecureVec::from(std::mem::take(&mut self.0))
    }

    /// Transfer the complete allocation to an existing caller-owned wire API. No copy is made.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
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
