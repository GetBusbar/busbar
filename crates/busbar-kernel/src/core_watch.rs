// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which data cores the core watch nudges, stops and resumes, one housekeeping tick at a time.
//!
//! The watch has no clock and no count of its own. Its only time is the housekeeping tick it rides, and its only
//! threshold is the plugin watchdog's: an entry is reported hung once it passed its own ceiling.
//!
//! - A hang reported: every core with no nudge outstanding is nudged (one beat task on its own runtime).
//! - At a later tick, a core that has not run its nudge is held. One hung entry holds one thread, so the held
//!   cores are stopped only when they are no more than the hangs not yet placed on a core; while they are more
//!   (a core busy, not held, has not reached its nudge yet), the watch waits for them to run it, tick by tick.
//! - Every nudged core ran its nudge and none is stopped: the hang is on no data core (a blocking or control
//!   thread); it is closed.
//! - A stopped core that runs its nudge is free: the entry it held returned (a held thread runs nothing). It
//!   resumes, and that hang is closed. The rejoin is that event, not a timer: a core cannot flap faster than its
//!   entries hang and return.

/// What the watch does at one tick: the cores to nudge (run one beat task on their own runtime), to stop (their
/// listener leaves the group) and to resume (a new listener joins it).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub nudge: Vec<usize>,
    pub stop: Vec<usize>,
    pub resume: Vec<usize>,
}

/// One core as the watch holds it: the beat it had when nudged (a nudge outstanding), and whether it is stopped.
#[derive(Clone, Copy, Default)]
struct Core {
    nudged: Option<u64>,
    stopped: bool,
}

/// The watch's reading of the cores, one tick at a time.
#[derive(Default)]
pub struct Verdicts {
    cores: Vec<Core>,
    /// The watchdog's count of hung entries at the last tick.
    hung_seen: u64,
    /// Hangs reported and not yet closed (placed on a stopped core, or found on no data core).
    open: u64,
}

impl Verdicts {
    /// One tick: each core's beat now, and the watchdog's count of hung entries.
    pub fn check(&mut self, beats: &[u64], hung_total: u64) -> Step {
        let mut step = Step::default();
        self.cores.resize(beats.len(), Core::default());
        let new = hung_total.saturating_sub(self.hung_seen);
        self.hung_seen = self.hung_seen.max(hung_total);
        self.open += new;
        let mut held = Vec::new();
        let mut nudged_any = false;
        for (i, (core, &beat)) in self.cores.iter_mut().zip(beats).enumerate() {
            let Some(at) = core.nudged else { continue };
            nudged_any = true;
            if beat != at {
                core.nudged = None;
                if core.stopped {
                    core.stopped = false;
                    self.open = self.open.saturating_sub(1);
                    step.resume.push(i);
                }
            } else if !core.stopped {
                held.push(i);
            }
        }
        let stopped = self.cores.iter().filter(|core| core.stopped).count() as u64;
        let unplaced = self.open.saturating_sub(stopped);
        if !held.is_empty() && held.len() as u64 <= unplaced {
            for &i in &held {
                self.cores[i].stopped = true;
            }
            step.stop = held;
        } else if nudged_any && held.is_empty() && stopped == 0 && new == 0 {
            self.open = 0;
        }
        if new > 0 {
            for (i, (core, &beat)) in self.cores.iter_mut().zip(beats).enumerate() {
                if core.nudged.is_none() {
                    core.nudged = Some(beat);
                    step.nudge.push(i);
                }
            }
        }
        step
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
