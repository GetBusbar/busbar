// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector's per-thread wiping scratch slots over [`SecureVec`]. The buffer itself lives in
//! `busbar_contract::secure` (one home for the wiping logic, reachable by plugins); this module
//! re-exports it under its old path.

use std::cell::Cell;
use std::thread::LocalKey;

#[cfg(any(test, feature = "test-support"))]
pub use busbar_contract::secure::refuse_growth;
pub use busbar_contract::secure::{Overflow, SecureVec, Tail};

/// One per-thread scratch slot: `Some` while no taker holds it.
pub(crate) type Slot = Cell<Option<SecureVec>>;

thread_local! {
    /// The carrier read's scratch (T11-dev): taken only in `Connection::read`, held until `feed`
    /// returns.
    pub(crate) static READ_SCRATCH: Slot = Cell::new(Some(SecureVec::new()));
    /// The TLS plaintext's scratch (T6): taken only in `feed`, after the `process_new_packets`
    /// loop, held until `ingest` returns. It nests inside `READ_SCRATCH` and never contends.
    pub(crate) static TLS_PLAIN: Slot = Cell::new(Some(SecureVec::new()));
}

/// A slot's buffer, taken for one read. Drop wipes what it holds and puts it back, so the slot is
/// all zero between reads. A slot found empty is a re-entrant take on this thread: the guard uses a
/// fresh buffer (never an alias) and, on Drop, the slot keeps the larger of the two.
pub(crate) struct Scratch {
    key: &'static LocalKey<Slot>,
    buf: Option<SecureVec>,
}

impl Scratch {
    /// Take `key`'s buffer.
    pub(crate) fn take(key: &'static LocalKey<Slot>) -> Self {
        let buf = key.with(Cell::take).unwrap_or_else(|| {
            scratch_missed();
            SecureVec::new()
        });
        Self {
            key,
            buf: Some(buf),
        }
    }
}

impl std::ops::Deref for Scratch {
    type Target = SecureVec;
    fn deref(&self) -> &SecureVec {
        self.buf.as_ref().expect("held until drop")
    }
}

impl std::ops::DerefMut for Scratch {
    fn deref_mut(&mut self) -> &mut SecureVec {
        self.buf.as_mut().expect("held until drop")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let Some(mut buf) = self.buf.take() else {
            return;
        };
        buf.clear();
        let _ = self.key.try_with(move |slot| {
            let keep = match slot.take() {
                Some(other) if other.capacity() >= buf.capacity() => other,
                _ => buf,
            };
            slot.set(Some(keep));
        });
    }
}

#[cfg(test)]
thread_local! {
    /// Re-entrant takes that found their slot empty, on this thread.
    static SCRATCH_MISSES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn scratch_missed() {
    SCRATCH_MISSES.with(|m| m.set(m.get() + 1));
}

#[cfg(not(test))]
const fn scratch_missed() {}

#[cfg(test)]
#[path = "tests/secure_vec_tests.rs"]
mod tests;
