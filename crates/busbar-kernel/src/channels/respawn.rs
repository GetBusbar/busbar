// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Respawn and trip for a CARRIER_STDIO channel (IF §12.19, round 6). Core owns the stdio carrier, so
//! the supervisor the retired stdio plugin carried lives here.
//!
//! A child that exits or cannot be spawned ends its generation. The next attach respawns it no sooner
//! than 100 ms × 2^(n−1) after the n-th end counted inside a sliding 60 s window (100, 200, 400,
//! 800 ms, from `backon::ExponentialBuilder`). The 5th end inside 60 s trips the channel until the
//! upstream is declared anew. Counters are per channel key and survive generations, not restarts.

use backon::BackoffBuilder;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The sliding window ends are counted in.
pub const WINDOW: Duration = Duration::from_secs(60);

/// The end inside [`WINDOW`] that trips the channel.
pub const TRIP_AT: usize = 5;

/// The schedule: 100 ms doubling, one delay per end before the trip (no jitter, no cap below 800 ms).
const SCHEDULE: backon::ExponentialBuilder = backon::ExponentialBuilder::new()
    .with_min_delay(Duration::from_millis(100))
    .with_factor(2.0)
    .without_max_delay()
    .with_max_times(TRIP_AT - 1);

/// The wait after the n-th end inside the window (1-based); `None` once the channel trips.
#[must_use]
pub fn delay(n: usize) -> Option<Duration> {
    if n == 0 {
        return Some(Duration::ZERO);
    }
    // backon multiplies in `f32`, so its 200 ms comes out as 200.000003 ms: the schedule is whole milliseconds.
    SCHEDULE.build().nth(n - 1).map(|d| {
        Duration::from_millis(
            u64::try_from((d.as_nanos() + 500_000) / 1_000_000).unwrap_or(u64::MAX),
        )
    })
}

/// What the next attach may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spawn {
    /// Spawn the child now.
    Now,
    /// Not before this much longer.
    After(Duration),
    /// The channel tripped: the attach fails at once with RecordsDenied::Unavailable.
    Tripped,
}

/// One channel key's ends.
#[derive(Debug, Clone, Default)]
pub struct Respawn {
    ends: VecDeque<Instant>,
    tripped: bool,
}

impl Respawn {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The child of this generation exited or could not be spawned at `at`. True when this end trips
    /// the channel (the caller audits `upstream_child_tripped` once).
    pub fn ended(&mut self, at: Instant) -> bool {
        if self.tripped {
            return false;
        }
        while self
            .ends
            .front()
            .is_some_and(|e| at.saturating_duration_since(*e) > WINDOW)
        {
            self.ends.pop_front();
        }
        self.ends.push_back(at);
        if self.ends.len() >= TRIP_AT {
            self.tripped = true;
            return true;
        }
        false
    }

    /// What an attach at `now` may do.
    #[must_use]
    pub fn next(&self, now: Instant) -> Spawn {
        if self.tripped {
            return Spawn::Tripped;
        }
        let counted = self
            .ends
            .iter()
            .filter(|e| now.saturating_duration_since(**e) <= WINDOW)
            .count();
        let Some(last) = self.ends.back().filter(|_| counted > 0) else {
            return Spawn::Now;
        };
        let Some(wait) = delay(counted) else {
            return Spawn::Tripped;
        };
        let due = *last + wait;
        if now >= due {
            Spawn::Now
        } else {
            Spawn::After(due - now)
        }
    }

    /// The upstream was declared anew (config reload or admin reconfigure): the trip and the counted
    /// ends are cleared.
    pub fn redeclared(&mut self) {
        self.ends.clear();
        self.tripped = false;
    }

    #[must_use]
    pub fn is_tripped(&self) -> bool {
        self.tripped
    }
}
