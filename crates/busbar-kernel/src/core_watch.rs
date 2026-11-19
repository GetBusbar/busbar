// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which data cores the core watch nudges, stops and resumes, one housekeeping tick at a time.

/// What the watch does at one tick: the cores to nudge (run one beat task on their own runtime), to stop (their
/// listener leaves the group) and to resume (a new listener joins it).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub nudge: Vec<usize>,
    pub stop: Vec<usize>,
    pub resume: Vec<usize>,
}

/// The watch's reading of the cores, one tick at a time.
#[derive(Default)]
pub struct Verdicts {
    _cores: Vec<u64>,
}

impl Verdicts {
    /// One tick: each core's beat now, and the watchdog's count of hung entries.
    pub fn check(&mut self, _beats: &[u64], _hung_total: u64) -> Step {
        Step::default()
    }
}

/// The housekeeping tick's hook: run once per tick on the control runtime, never awaited.
pub type Tick = Box<dyn FnMut() + Send>;

/// The housekeeping tick for `tick` alone, when the engine runs no budget flusher (no governance): the same
/// configured interval (`advanced.usage_flush_interval_ms`), read on every wait as the flusher reads it.
pub async fn tick_alone(mut tick: Tick) {
    loop {
        let interval = std::time::Duration::from_millis(crate::limits::usage_flush_interval_ms());
        tokio::time::sleep(interval).await;
        tick();
    }
}

#[cfg(test)]
#[path = "tests/core_watch_tests.rs"]
mod tests;
