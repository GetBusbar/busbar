// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which cores the watch stops: a core whose beat stood still while the watchdog reported a hung entry, once.

use super::Verdicts;

/// Runs `checks` of (beats, hung total) and returns, per check, the cores stopped.
fn run(checks: &[(&[u64], u64)]) -> Vec<Vec<usize>> {
    let mut verdicts = Verdicts::default();
    checks
        .iter()
        .map(|(beats, hung)| verdicts.check(beats, *hung))
        .collect()
}

#[test]
fn a_core_that_stands_still_while_an_entry_hangs_is_stopped_once() {
    // Core 0 stops beating at the first check; core 1 keeps beating. The watchdog reports a hang at check 2.
    let stopped = run(&[
        (&[1, 1], 0),
        (&[1, 2], 1),
        (&[1, 3], 1),
        (&[1, 4], 1),
        (&[1, 5], 1),
        (&[1, 6], 1),
    ]);
    let all: Vec<usize> = stopped.iter().flatten().copied().collect();
    assert_eq!(all, [0], "the still core alone, and only once: {stopped:?}");
}

#[test]
fn a_still_core_with_no_hung_entry_is_left_alone() {
    let checks: Vec<(&[u64], u64)> = (0..20).map(|_| (&[7u64, 7][..], 0)).collect();
    assert!(run(&checks).iter().all(Vec::is_empty));
}

#[test]
fn a_hang_reported_after_the_core_resumed_stops_nothing() {
    let stopped = run(&[
        (&[1], 0),
        (&[1], 0),
        (&[1], 0),
        (&[2], 0),
        (&[3], 1),
        (&[4], 1),
        (&[5], 1),
    ]);
    assert!(stopped.iter().all(Vec::is_empty), "{stopped:?}");
}
