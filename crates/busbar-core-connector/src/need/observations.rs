// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded network facts retained before a store exists and for the lifetime of boot leases.

use std::sync::{Mutex, PoisonError};

/// Maximum retained network observations per immutable network generation.
const CAPACITY: usize = 256;

/// A fixed outcome, without plugin/server messages or credential material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Destination policy refused the operation (the existing DEST_* verdict).
    Denied(u64),
    /// TLS configuration or peer verification refused the operation.
    Tls,
    /// The selected proxy receives unresolved target DNS responsibility.
    Delegated,
}

/// One redacted fact. Retention in memory does not claim durable persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    /// Bounded logical host only; paths, userinfo and query values are excluded.
    pub host: String,
    /// Reserved runtime instance, if this operation belongs to one.
    pub owner: Option<u64>,
    /// Checked egress class, if admission completed.
    pub class: Option<u32>,
    /// Fixed outcome classification.
    pub outcome: Outcome,
}

/// A drained prefix and the number omitted because the bounded buffer was full.
#[derive(Debug, Default)]
pub struct Batch {
    /// Facts in occurrence order.
    pub facts: Vec<Fact>,
    /// Omitted facts since the last drain.
    pub overflow: u64,
}

/// Generation-owned observation writer/reader, independent of process or store globals.
#[derive(Debug, Default)]
pub struct Observations(Mutex<Batch>);

impl Observations {
    /// Record bounded redacted metadata; never accepts a free-form error or credential payload.
    pub fn record(&self, host: &str, owner: Option<u64>, class: Option<u32>, outcome: Outcome) {
        let mut batch = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if batch.facts.len() == CAPACITY {
            batch.overflow = batch.overflow.saturating_add(1);
            return;
        }
        batch.facts.push(Fact {
            host: crate::egress_audit::shown(host).to_owned(),
            owner,
            class,
            outcome,
        });
    }

    /// Transfer the retained prefix to the generation's consumer; persistence is its concern.
    pub fn drain(&self) -> Batch {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_prefix_has_explicit_overflow_and_remains_writable_after_drain() {
        let observations = Observations::default();
        for _ in 0..CAPACITY + 3 {
            observations.record(
                "https://user:password@secret.example/path?token=value",
                Some(7),
                Some(2),
                Outcome::Tls,
            );
        }
        let batch = observations.drain();
        assert_eq!(batch.facts.len(), CAPACITY);
        assert_eq!(batch.overflow, 3);
        assert!(batch.facts.iter().all(|fact| fact.host == "secret.example"));
        observations.record("late.example", Some(7), Some(2), Outcome::Delegated);
        let late = observations.drain();
        assert_eq!(late.facts.len(), 1);
        assert_eq!(late.overflow, 0);
    }
}
