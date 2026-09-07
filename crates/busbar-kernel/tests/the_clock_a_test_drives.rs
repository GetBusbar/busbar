// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The clock a test drives by hand, driven by hand.
//!
//! Every deadline in this crate is a difference between two readings of a clock, and every cell
//! that proves a deadline drives THIS one. That makes it an instrument: a clock whose hand does not
//! move, or that answers the same figure whatever was asked of it, turns every idle bound, lease
//! lifetime and tick interval in the batteries green by measuring nothing. So the instrument is
//! read against figures of its own here, before anything is measured with it.

use busbar_kernel::{Clock, ManualClock};

/// A fresh clock reads zero, the hand moves by exactly what it is given, and the moves accumulate.
#[test]
fn the_hand_moves_by_what_it_is_given_and_stays_where_it_was_put() {
    let clock = ManualClock::new();
    assert_eq!(clock.now(), 0, "a fresh clock reads zero");

    clock.advance(1);
    assert_eq!(clock.now(), 1, "one millisecond is one millisecond");

    clock.advance(99);
    assert_eq!(clock.now(), 100, "the moves add up");

    // Reading it does not move it: two readings with nothing in between are the same reading, which
    // is what makes a difference between two of them a duration and not a race.
    assert_eq!(clock.now(), clock.now());

    clock.advance(0);
    assert_eq!(clock.now(), 100, "a move of nothing moves nothing");

    clock.advance(9_900);
    assert_eq!(clock.now(), 10_000);
}

/// The clock is read through the trait the kernel takes, and reads the same figure there.
///
/// The kernel never holds a `ManualClock`: it holds something that answers `now`. A clock that
/// answered its own figure but a constant through the trait would drive every deadline in the
/// batteries at a standstill while looking correct beside it.
#[test]
fn the_kernels_own_door_onto_the_clock_reads_the_same_hand() {
    let clock = ManualClock::default();
    clock.advance(4_096);
    let seen: &dyn Clock = &clock;
    assert_eq!(seen.now(), 4_096);
    clock.advance(4);
    assert_eq!(seen.now(), 4_100, "the door reads the hand, not a copy of it");
}
