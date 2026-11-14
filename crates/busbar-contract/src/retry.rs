// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S RETRY BACKOFF: exponential, capped, with full jitter and a floor.
//!
//! One shape for every timer-driven retry the host makes (a credential refresh, a plugin's tick).
//! The random draw is a parameter (`unit`, uniform in `[0, 1)`), so a schedule is a pure function a
//! test can pin; [`unit`] is the production draw.

use std::time::Duration;

/// An exponential backoff: failure `n` waits up to `min(base · 2^(n-1), cap)`, never under `floor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The first failure's ceiling.
    pub base: Duration,
    /// The ceiling every later failure stops doubling at.
    pub cap: Duration,
    /// The least any wait is, so a schedule can never spin.
    pub floor: Duration,
}

/// The least wait a host retry schedules.
pub const FLOOR: Duration = Duration::from_millis(100);

impl Backoff {
    /// `base` and `cap` with the host's [`FLOOR`].
    #[must_use]
    pub const fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            floor: FLOOR,
        }
    }

    /// Failure `failures`' (1-based) ceiling: `min(base · 2^(failures-1), cap)`.
    #[must_use]
    pub fn ceiling(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(31);
        self.base
            .checked_mul(1_u32 << doublings)
            .unwrap_or(self.cap)
            .min(self.cap)
            .max(self.floor)
    }

    /// Failure `failures`' wait under FULL JITTER: uniform in `[0, ceiling]`, at least `floor`.
    #[must_use]
    pub fn delay(&self, failures: u32, unit: f64) -> Duration {
        self.ceiling(failures)
            .mul_f64(clamp_unit(unit))
            .max(self.floor)
    }

    /// A steady retry at the cap: uniform in `[cap/2, cap]`, at least `floor`.
    #[must_use]
    pub fn steady(&self, unit: f64) -> Duration {
        let half = self.cap / 2;
        (half + half.mul_f64(clamp_unit(unit))).max(self.floor)
    }
}

/// `every` spread by ±`spread` (a fraction, `0.1` = ±10 %), at least [`FLOOR`].
#[must_use]
pub fn spread(every: Duration, spread: f64, unit: f64) -> Duration {
    let factor = 1.0 - spread + 2.0 * spread * clamp_unit(unit);
    every.mul_f64(factor.max(0.0)).max(FLOOR)
}

fn clamp_unit(unit: f64) -> f64 {
    if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// One uniform draw in `[0, 1)` from the OS's random source (`0.5` if it cannot answer: a
/// schedule is still bounded by `floor` and `cap`).
#[must_use]
pub fn unit() -> f64 {
    let mut bytes = [0_u8; 8];
    if crate::crypto::fill(&mut bytes).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1_u64 << 53) as f64
}

#[cfg(test)]
#[path = "tests/retry_tests.rs"]
mod tests;
