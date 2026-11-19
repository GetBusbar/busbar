// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which cores the watch nudges, stops and resumes, one housekeeping tick at a time: no clock, no count of its own.

use super::{Step, Verdicts};

/// Runs ticks of (beats, hung total) and returns each tick's step.
fn run(ticks: &[(&[u64], u64)]) -> Vec<Step> {
    let mut verdicts = Verdicts::default();
    ticks
        .iter()
        .map(|(beats, hung)| verdicts.check(beats, *hung))
        .collect()
}

#[test]
fn with_no_hung_entry_the_watch_does_nothing_at_all() {
    let ticks: Vec<(&[u64], u64)> = (0..10).map(|_| (&[0u64, 0][..], 0)).collect();
    assert!(run(&ticks).iter().all(|step| *step == Step::default()));
}

#[test]
fn the_core_that_did_not_run_its_nudge_after_a_hang_is_stopped_then_resumed_when_it_runs_it() {
    let steps = run(&[
        // The watchdog reports a hang: every core is nudged.
        (&[0, 0], 1),
        // Core 1 ran its nudge, core 0 did not: core 0 holds the hung entry.
        (&[0, 1], 1),
        // Core 0 is still held: nothing more (its nudge is still queued; nobody is nudged again).
        (&[0, 1], 1),
        // Core 0 ran its nudge: its entry returned, it rejoins.
        (&[1, 1], 1),
        (&[1, 1], 1),
    ]);
    assert_eq!(
        steps[0],
        Step {
            nudge: vec![0, 1],
            ..Step::default()
        }
    );
    assert_eq!(
        steps[1],
        Step {
            stop: vec![0],
            ..Step::default()
        }
    );
    assert_eq!(steps[2], Step::default());
    assert_eq!(
        steps[3],
        Step {
            resume: vec![0],
            ..Step::default()
        }
    );
    assert_eq!(steps[4], Step::default());
}

#[test]
fn a_hang_off_the_data_cores_stops_nothing_and_closes() {
    let steps = run(&[(&[0, 0], 1), (&[1, 1], 1), (&[1, 1], 1)]);
    assert_eq!(steps[0].nudge, [0, 1]);
    assert_eq!(steps[1], Step::default(), "every core ran its nudge");
    assert_eq!(
        steps[2],
        Step::default(),
        "the hang is closed: no more nudges"
    );
}

#[test]
fn no_more_cores_are_stopped_than_hangs_were_reported() {
    // One hang, two cores that did not run their nudge yet: which one holds it is not known; neither is stopped.
    let steps = run(&[(&[0, 0, 0], 1), (&[0, 0, 1], 1), (&[0, 1, 1], 1)]);
    assert_eq!(steps[1], Step::default());
    // Core 1 ran it a tick later: core 0 is the one.
    assert_eq!(steps[2].stop, [0]);
}
