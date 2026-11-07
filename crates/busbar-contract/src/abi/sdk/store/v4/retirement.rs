// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Receipt age proof that survives wall-clock jumps by delaying collection.
//!
//! An adapter observes a durably retired execution floor under its native
//! serialization guard. Every receipt covered by that floor already existed at
//! observation: a fenced epoch cannot apply a new unseen operation. Waiting a full
//! monotonic horizon therefore establishes a minimum receipt age without trusting
//! persisted wall time. Restart discards this cache and starts a new grace period.
//! This is transport receipt maintenance, not domain-record retention policy.

use std::time::{Duration, Instant};

use crate::persistence::Failure;

/// Mandatory minimum transport receipt retention, in actual elapsed time.
pub const MIN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Process-local observation for one persistent writer identity in one dataset.
/// Never transfer this value to another dataset/authority or serialize its clock.
#[derive(Debug)]
pub struct Horizon {
    collectible: u64,
    pending: u64,
    observed: Instant,
}

impl Horizon {
    /// Begin observing a floor already proven durably retired by this backend.
    #[must_use]
    pub fn new(retired_floor: u64, now: Instant) -> Self {
        Self {
            collectible: 0,
            pending: retired_floor,
            observed: now,
        }
    }

    /// Return the highest floor whose receipts have existed for a full horizon.
    ///
    /// The caller rereads the durable floor in the transaction that will collect
    /// receipts and supplies that exact value. Lowered authority is corruption,
    /// not permission to reset the timer. Later retirements cannot extend the
    /// grace period of already observed work indefinitely.
    pub fn observe(&mut self, retired_floor: u64, now: Instant) -> Result<u64, Failure> {
        if retired_floor < self.pending {
            return Err(Failure::Corrupt);
        }
        if self.pending > self.collectible
            && now
                .checked_duration_since(self.observed)
                .is_some_and(|elapsed| elapsed >= MIN_RETENTION)
        {
            self.collectible = self.pending;
        }
        if self.pending == self.collectible && retired_floor > self.pending {
            self.pending = retired_floor;
            self.observed = now;
        }
        Ok(self.collectible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_retirements_do_not_reset_old_work_and_restart_delays_collection() {
        let start = Instant::now();
        let mut horizon = Horizon::new(1, start);
        assert_eq!(horizon.observe(2, start + MIN_RETENTION / 2), Ok(0));
        assert_eq!(
            horizon.observe(3, start + MIN_RETENTION - Duration::from_nanos(1)),
            Ok(0)
        );
        assert_eq!(horizon.observe(3, start + MIN_RETENTION), Ok(1));
        assert_eq!(horizon.observe(4, start + MIN_RETENTION * 2), Ok(3));
        assert_eq!(
            horizon.observe(2, start + MIN_RETENTION * 3),
            Err(Failure::Corrupt)
        );
        let mut restarted = Horizon::new(4, start + MIN_RETENTION * 2);
        assert_eq!(restarted.observe(4, start + MIN_RETENTION * 2), Ok(0));
        assert_eq!(restarted.observe(4, start + MIN_RETENTION * 3), Ok(4));
    }

    #[test]
    fn zero_floor_is_not_an_age_proof_for_future_retirement() {
        let start = Instant::now();
        let mut horizon = Horizon::new(0, start);
        assert_eq!(horizon.observe(7, start + MIN_RETENTION * 10), Ok(0));
        assert_eq!(horizon.observe(7, start + MIN_RETENTION * 11), Ok(7));
    }
}
