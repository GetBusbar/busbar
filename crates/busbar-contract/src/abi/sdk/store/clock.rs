// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE'S CLOCKS. A store's own code reads elapsed and wall time only here, so the store
//! case's clock jump (`v4::conformance::JUMP`, LR-118) reaches every clock that code reads.
//! A server-side clock (SQL `now()`, a Valkey `TIME`) is the server's, not this one.

use std::time::{Duration, Instant, SystemTime};

#[cfg(any(test, feature = "test-support"))]
static JUMPED_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(any(test, feature = "test-support"))]
fn jumped() -> Duration {
    Duration::from_secs(JUMPED_SECS.load(std::sync::atomic::Ordering::Relaxed))
}

#[cfg(not(any(test, feature = "test-support")))]
const fn jumped() -> Duration {
    Duration::ZERO
}

/// Elapsed time, for anything a store measures between two of its own observations.
#[must_use]
pub fn monotonic() -> Instant {
    let now = Instant::now();
    now.checked_add(jumped()).unwrap_or(now)
}

/// Wall time, for a store whose dataset clock is its own process.
#[must_use]
pub fn wall() -> SystemTime {
    let now = SystemTime::now();
    now.checked_add(jumped()).unwrap_or(now)
}

/// Move both clocks forward by whole seconds of `by`, for every store in this process.
#[cfg(any(test, feature = "test-support"))]
pub fn jump(by: Duration) {
    JUMPED_SECS.fetch_add(by.as_secs(), std::sync::atomic::Ordering::Relaxed);
}
