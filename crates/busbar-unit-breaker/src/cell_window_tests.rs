// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sliding outcome window, counted directly.
//!
//! Declared from `cell.rs` itself (`#[cfg(test)] #[path = "cell_window_tests.rs"] mod
//! cell_window_tests;`) because `OutcomeWindow` is private to that module and is not widened to
//! `pub(crate)` just to be looked at. Everything the error-rate trip reads comes out of this one
//! type — how many outcomes fall inside the window and how many of those were errors — and the pair
//! is only ever read together, so it is asserted together, at counts no small constant stands in
//! for.

use super::OutcomeWindow;

/// The pair is the count of what is inside the window and the count of the errors among them, and
/// neither is a constant: they are asserted at three different pairs from three different windows.
#[test]
fn the_window_counts_what_is_inside_it_and_the_errors_among_them() {
    let mut window = OutcomeWindow::new(16);
    window.push(100, false);
    window.push(101, true);
    window.push(102, true);
    window.push(103, false);
    window.push(104, true);

    // The whole window: five outcomes, three of them errors.
    assert_eq!(window.outcomes_in_window(104, 30), (5, 3));
    // A narrower window that reaches back to 103: two outcomes, one error.
    assert_eq!(window.outcomes_in_window(104, 1), (2, 1));
    // A window of zero width still sees the outcome recorded at this very second.
    assert_eq!(window.outcomes_in_window(104, 0), (1, 1));
}

/// A window with no errors in it reports none, and one with nothing but errors reports all of them.
/// Both directions, so a counter that reported the total as the error count would fail one of them.
#[test]
fn a_clean_window_and_a_wholly_failing_one_are_told_apart() {
    let mut clean = OutcomeWindow::new(16);
    for ts in 0..4 {
        clean.push(ts, false);
    }
    assert_eq!(clean.outcomes_in_window(3, 30), (4, 0));

    let mut failing = OutcomeWindow::new(16);
    for ts in 0..4 {
        failing.push(ts, true);
    }
    assert_eq!(failing.outcomes_in_window(3, 30), (4, 4));
}

/// The cut is `ts >= start`, at the exact second: an outcome recorded at the window's own start
/// instant is inside it, and the one a second earlier is not.
#[test]
fn the_window_edge_is_exact() {
    let mut window = OutcomeWindow::new(16);
    window.push(69, true); // one second before the start
    window.push(70, true); // exactly at the start
    window.push(71, false); // inside

    // now = 100, width = 30 → start = 70.
    assert_eq!(
        window.outcomes_in_window(100, 30),
        (2, 1),
        "the entry at the start instant counts; the one before it does not"
    );
}

/// A window start that would run before the epoch saturates at zero rather than wrapping — which
/// would otherwise put every entry outside a window that reaches back past time zero.
#[test]
fn a_window_reaching_back_past_the_epoch_saturates_rather_than_wrapping() {
    let mut window = OutcomeWindow::new(16);
    window.push(0, true);
    window.push(1, false);
    assert_eq!(window.outcomes_in_window(2, u64::MAX), (2, 1));
}

/// At capacity the oldest entry is dropped, not the newest: the window slides. Asserted on the
/// COUNTS, because that is the only thing the trip condition reads.
#[test]
fn the_window_drops_the_oldest_entry_at_capacity() {
    let mut window = OutcomeWindow::new(3);
    window.push(1, true);
    window.push(2, true);
    window.push(3, true);
    assert_eq!(window.outcomes_in_window(3, 30), (3, 3), "full, all errors");

    // A fourth outcome evicts the first. The bound holds and the evicted entry was the oldest.
    window.push(4, false);
    assert_eq!(
        window.outcomes_in_window(4, 30),
        (3, 2),
        "the count is still the capacity, and the entry that left was one of the errors"
    );

    // Two more successes push the remaining errors out entirely, one at a time.
    window.push(5, false);
    assert_eq!(window.outcomes_in_window(5, 30), (3, 1));
    window.push(6, false);
    assert_eq!(window.outcomes_in_window(6, 30), (3, 0));
}

/// The bound is never exceeded, however many outcomes arrive.
#[test]
fn the_window_never_grows_past_its_capacity() {
    let mut window = OutcomeWindow::new(4);
    for ts in 0..64 {
        window.push(ts, ts % 2 == 0);
    }
    let (total, errors) = window.outcomes_in_window(63, u64::MAX);
    assert_eq!(total, 4, "the deque is bounded by its capacity");
    assert_eq!(errors, 2, "and it kept the four most recent outcomes");
}

/// A recovery clears the window: the outcomes that argued for the trip are not evidence against the
/// cell that has since recovered.
#[test]
fn clearing_the_window_leaves_nothing_behind() {
    let mut window = OutcomeWindow::new(16);
    window.push(1, true);
    window.push(2, true);
    window.push(3, false);
    assert_eq!(window.outcomes_in_window(3, 30), (3, 2));

    window.clear();
    assert_eq!(
        window.outcomes_in_window(3, 30),
        (0, 0),
        "a cleared window argues neither way"
    );

    // And it is still usable afterwards.
    window.push(4, true);
    assert_eq!(window.outcomes_in_window(4, 30), (1, 1));
}
