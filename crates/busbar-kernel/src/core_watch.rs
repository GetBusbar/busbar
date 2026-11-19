// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which data cores the core watch stops (the root's `core_watch` reads the beats and stops the listeners).
//!
//! A core whose beat stood still for [`STILL`] checks while a hung plugin entry, reported in the last
//! [`ATTRIBUTE`] checks, was open is the one holding that entry. A beating core is never stopped, and a still core
//! with no hung entry is left alone (it is slow, not held). A core is stopped once.

/// Checks a core's beat must stand still to be the one holding a hung entry.
const STILL: u32 = 3;
/// Checks a reported hang stays open for a still core to be found: an entry is reported once, at its ceiling,
/// which can come before its core has stood still for [`STILL`] checks.
const ATTRIBUTE: u32 = 50;

/// One core as the watch last read it.
#[derive(Clone, Copy, Default)]
struct Read {
    beat: u64,
    still: u32,
    stopped: bool,
}

/// The watch's reading of the cores, one check at a time.
#[derive(Default)]
pub struct Verdicts {
    cores: Vec<Read>,
    hung_seen: u64,
    open: u32,
}

impl Verdicts {
    /// One check: each core's beat now, and the watchdog's count of hung entries. The cores to stop.
    pub fn check(&mut self, beats: &[u64], hung_total: u64) -> Vec<usize> {
        let known = self.cores.len();
        for (read, &beat) in self.cores.iter_mut().zip(beats) {
            if read.beat == beat {
                read.still = read.still.saturating_add(1);
            } else {
                read.beat = beat;
                read.still = 0;
            }
        }
        self.cores
            .extend(beats.iter().skip(known).map(|&beat| Read {
                beat,
                ..Read::default()
            }));
        if hung_total > self.hung_seen {
            self.hung_seen = hung_total;
            self.open = ATTRIBUTE;
        }
        if self.open == 0 {
            return Vec::new();
        }
        self.open -= 1;
        let mut stop = Vec::new();
        for (core, read) in self.cores.iter_mut().enumerate() {
            if read.still >= STILL && !read.stopped {
                read.stopped = true;
                stop.push(core);
            }
        }
        stop
    }
}

#[cfg(test)]
#[path = "tests/core_watch_tests.rs"]
mod tests;
