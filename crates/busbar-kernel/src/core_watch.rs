// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which data cores the core watch stops (the root's `core_watch` reads the beats and stops the listeners).

/// The watch's reading of the cores, one check at a time.
#[derive(Default)]
pub struct Verdicts {
    _cores: Vec<u64>,
}

impl Verdicts {
    /// One check: each core's beat now, and the watchdog's count of hung entries. The cores to stop.
    pub fn check(&mut self, _beats: &[u64], _hung_total: u64) -> Vec<usize> {
        Vec::new()
    }
}

#[cfg(test)]
#[path = "tests/core_watch_tests.rs"]
mod tests;
