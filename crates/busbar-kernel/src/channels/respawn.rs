// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Respawn and trip for a CARRIER_STDIO channel (IF §12.19, round 6; today's transport-stdio
//! supervisor.rs, moved into core with the carrier).
//!
//! A child that exits or cannot be spawned ends its generation. The next attach respawns it no sooner
//! than 100 ms × 2^(n−1) after the n-th end counted inside a sliding 60 s window (100, 200, 400,
//! 800 ms, from `backon::ExponentialBuilder`). The 5th end inside 60 s trips the channel until the
//! upstream is declared anew. Counters are per channel key and survive generations, not restarts.

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
    let _ = (n, SCHEDULE);
    todo!()
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
        let _ = (at, &mut self.ends, &mut self.tripped);
        todo!()
    }

    /// What an attach at `now` may do.
    #[must_use]
    pub fn next(&self, now: Instant) -> Spawn {
        let _ = now;
        todo!()
    }

    /// The upstream was declared anew (config reload or admin reconfigure): the trip and the counted
    /// ends are cleared.
    pub fn redeclared(&mut self) {
        todo!()
    }

    #[must_use]
    pub fn is_tripped(&self) -> bool {
        self.tripped
    }
}
