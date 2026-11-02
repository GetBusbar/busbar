// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::caps::ReasonCode;

pub use busbar_contract::{Direction, StreamId};

/// The bounded pool nested units run in, and the depth bound on nesting.
///
/// A parent's route blocks on its child's end, so a node with more parents than child permits is a
/// node that has stopped. The permit count is what keeps that from happening: parents wait for a
/// permit rather than deadlocking on each other, and the count of parents waiting is a number the
/// battery can read.
#[derive(Debug)]
pub struct NestedPool {
    permits: AtomicUsize,
    refusals: AtomicUsize,
    size: usize,
    max_depth: usize,
}

/// A nested child's place in the pool. Give it back when the child ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a permit that is never given back shrinks the pool for good"]
pub struct NestedPermit {
    /// How deep the child is.
    pub depth: usize,
}

impl NestedPool {
    pub fn new(size: usize, max_depth: usize) -> Self {
        NestedPool {
            permits: AtomicUsize::new(size),
            refusals: AtomicUsize::new(0),
            size,
            max_depth,
        }
    }

    pub fn available(&self) -> usize {
        self.permits.load(Ordering::Acquire)
    }

    pub fn refusals(&self) -> usize {
        self.refusals.load(Ordering::Acquire)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn enter(&self, depth: usize) -> Result<NestedPermit, ReasonCode> {
        if depth >= self.max_depth {
            return Err(ReasonCode::ScopeDenied);
        }
        match self
            .permits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        {
            Ok(_) => Ok(NestedPermit { depth }),
            Err(_) => {
                self.refusals.fetch_add(1, Ordering::AcqRel);
                Err(ReasonCode::InFlightCap)
            }
        }
    }

    pub fn leave(&self, _permit: NestedPermit) {
        self.permits.fetch_add(1, Ordering::AcqRel);
    }
}

/// Whether frames on this transport can be held back, or only dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// A stream: an overrun becomes backpressure on whatever is producing.
    Stream,
    /// A datagram: there is nowhere to push back to, so an overrun is a dropped frame.
    Datagram,
}
