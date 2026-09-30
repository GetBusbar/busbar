// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLUSH EPOCH: how many times the kernel's one flush tick has run. The composition root's
//! 1 s flush tick bumps it once per tick, right after the host services' flush; the money seam
//! reads it to write a unit's accrual checkpoint at most once per tick. It is the only cadence:
//! nothing else in the kernel keeps a second timer for it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A shared handle on the flush epoch. Clones read and bump the same counter.
#[derive(Debug, Clone, Default)]
pub struct FlushEpoch(Arc<AtomicU64>);

impl FlushEpoch {
    /// A new epoch, at `0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current epoch: the number of flush ticks run so far.
    pub fn now(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// One flush tick ran. Called by the composition root's flush tick alone.
    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
