// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector's host clock: one monotonic reading, as nanoseconds or as an instant, counted from the
//! epoch [`crate::off_path::framing`] fixes once per process.

use std::time::Instant;

/// The host's monotonic clock, nanoseconds since this process first read it, plus one (never `0`:
/// `0` names no reading).
#[must_use]
pub fn now_ns() -> u64 {
    u64::try_from(crate::off_path::framing::since_epoch().as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// The host's monotonic clock as an instant: one [`now_ns`] reading, named as [`instant_of`] names
/// it. An op takes it once and passes it down.
#[must_use]
pub fn now() -> Instant {
    instant_of(now_ns())
}

/// ONE OPERATION'S CLOCK: `now`, read the first time the operation needs it and kept for the rest of
/// it, so an operation reads the clock at most once, and not at all when nothing asks.
pub(crate) fn memo(now: &mut Option<Instant>) -> Instant {
    *now.get_or_insert_with(|| {
        busbar_contract::work_count::tally(busbar_contract::work_count::Work::ClockRead);
        #[cfg(test)]
        reads::read();
        self::now()
    })
}

/// How often [`memo`] read the clock on this thread (tests only).
#[cfg(test)]
pub(crate) mod reads {
    use std::cell::Cell;

    thread_local! {
        static READS: Cell<u64> = const { Cell::new(0) };
    }

    /// [`super::memo`] read the clock.
    pub(crate) fn read() {
        READS.with(|n| n.set(n.get() + 1));
    }

    /// The reads since the last call, starting the count again from zero.
    pub(crate) fn take() -> u64 {
        READS.with(|n| n.replace(0))
    }
}

/// The host's monotonic instant `ns` names: the exact inverse of [`now_ns`], so one reading names
/// one instant.
#[must_use]
pub fn instant_of(ns: u64) -> Instant {
    crate::off_path::framing::epoch() + std::time::Duration::from_nanos(ns.saturating_sub(1))
}
