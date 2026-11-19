// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outcome window's counts, against the walk they replaced.

use super::OutcomeWindow;

/// The window as it was: every entry visited, in push order, bounded by the capacity.
struct Model {
    entries: std::collections::VecDeque<(u64, bool)>,
    capacity: usize,
}

impl Model {
    fn push(&mut self, ts: u64, is_error: bool) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ts, is_error));
    }

    fn outcomes_in_window(&self, now: u64, window_s: u64) -> (usize, usize) {
        let start = now.saturating_sub(window_s);
        let (mut total, mut errors) = (0, 0);
        for (ts, is_error) in &self.entries {
            if *ts >= start {
                total += 1;
                errors += usize::from(*is_error);
            }
        }
        (total, errors)
    }
}

/// A fixed pseudo-random sequence (xorshift): no clock, no entropy.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn counts_equal_the_walk_for_non_decreasing_seconds() {
    // Capacity 1,024 is crossed several times, so the drop of the oldest entry is covered.
    let mut window = OutcomeWindow::new(1024);
    let mut model = Model {
        entries: std::collections::VecDeque::new(),
        capacity: 1024,
    };
    let (mut state, mut second) = (0x9E37_79B9_7F4A_7C15_u64, 1_000_u64);
    for step in 0..5_000 {
        let roll = next(&mut state);
        // Several outcomes in one second, and now and then a pause.
        second += (roll >> 8) % 3 / 2 + u64::from(roll.is_multiple_of(97)) * 40;
        let is_error = roll % 5 < 2;
        window.push(second, is_error);
        model.push(second, is_error);
        if step % 7 == 0 {
            for window_s in [1, 30, 60, 600] {
                assert_eq!(
                    window.outcomes_in_window(second, window_s),
                    model.outcomes_in_window(second, window_s),
                    "step {step}, window {window_s}"
                );
                // A read a little later than the newest outcome, and one far later.
                for later in [3, 1_000] {
                    assert_eq!(
                        window.outcomes_in_window(second + later, window_s),
                        model.outcomes_in_window(second + later, window_s),
                        "step {step}, window {window_s}, later {later}"
                    );
                }
            }
        }
    }
}

#[test]
fn clear_forgets_every_outcome_and_the_counts_start_again() {
    let mut window = OutcomeWindow::new(8);
    for second in 0..20 {
        window.push(second, second % 2 == 0);
    }
    window.clear();
    assert_eq!(window.outcomes_in_window(20, 600), (0, 0));
    window.push(21, true);
    window.push(21, false);
    assert_eq!(window.outcomes_in_window(21, 600), (2, 1));
    assert_eq!(window.outcomes_in_window(21, 0), (2, 1));
}

/// The one named change: an outcome stamped earlier than the newest entry is held at the newest
/// entry's second (the binary search needs the ring in time order). Before, it kept its own earlier
/// second and so left the window sooner.
#[test]
fn an_outcome_stamped_earlier_is_held_at_the_newest_second() {
    let mut window = OutcomeWindow::new(1024);
    window.push(100, false);
    window.push(90, true);
    // Window of 5 seconds ending at 100: both are inside (the late one counts at second 100).
    assert_eq!(window.outcomes_in_window(100, 5), (2, 1));
}
