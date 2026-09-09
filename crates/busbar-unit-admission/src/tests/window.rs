// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WEEK WINDOW — the sixth window word, and the one the vocabulary was missing.
//!
//! Money model, budgets: a cap is "any declared class or money over ANY configured window", and
//! `week` is a window operators ask for and could not spell. Until now the vocabulary was five
//! words, and a config that said `per: week` was refused at parse; a store row that said it fell
//! through `budget_window`'s fall-safe arm onto the all-time window, where a weekly cap would never
//! reset. Either way there was no weekly enforcement to be had.
//!
//! # Monday, and why the alignment is a decision rather than an accident
//!
//! `day` aligns to UTC midnight and `month` to the UTC first, so `week` aligns to a UTC weekday
//! boundary — and the boundary is MONDAY 00:00 UTC, the ISO-8601 week start. The Unix epoch is a
//! Thursday, so a naive `now / (7 * SECS_PER_DAY)` would put every week boundary on a Thursday,
//! which is nobody's week. The offset of three days in [`super::super::window::budget_window`] is
//! that correction and nothing else.
//!
//! The cases below pin the boundary against a date whose weekday is checked rather than assumed:
//! 2023-11-15 is a Wednesday, so its week runs from Monday 2023-11-13 to Monday 2023-11-20.

use super::{
    assert_blocked, chain, door, group_cfg, limit, no_card, table, LimitMetric, MINUTE, WEEK,
};
use crate::decide::Metric;
use crate::window::{budget_window, is_known_window, window_end, ALL_WINDOWS, SECS_PER_DAY};

/// Wednesday 2023-11-15 00:00:00 UTC. Mid-week on purpose: a boundary bug that rounded to the
/// nearest day, or to the epoch's own Thursday, would still land on the right answer for a Monday.
const WED: u64 = 1_700_006_400;
/// Monday 2023-11-13 00:00:00 UTC — the start of the week containing [`WED`].
const MON: u64 = 1_699_833_600;
/// Monday 2023-11-20 00:00:00 UTC — the roll.
const NEXT_MON: u64 = 1_700_438_400;

/// THE WEEK WINDOW STARTS ON MONDAY, not on the epoch's Thursday and not on `now`'s own midnight.
#[test]
fn a_week_window_is_aligned_to_monday_midnight_utc() {
    assert_eq!(
        budget_window(WEEK, WED),
        MON,
        "a Wednesday's week began on the Monday before it"
    );
    assert_eq!(
        budget_window(WEEK, MON),
        MON,
        "the boundary instant is inside its own window, not the previous one"
    );
    assert_eq!(
        budget_window(WEEK, NEXT_MON - 1),
        MON,
        "the last second before the roll is still the old week"
    );
    assert_eq!(
        budget_window(WEEK, NEXT_MON),
        NEXT_MON,
        "and the roll instant opens the new one"
    );
}

/// EVERY DAY OF ONE WEEK AGREES ON ITS WINDOW, and the eighth day does not.
///
/// The alignment is stated once above; this is the same claim made the way a cap experiences it —
/// seven consecutive days that must share a counter, and one that must not.
#[test]
fn the_seven_days_of_a_week_share_one_window_and_the_eighth_does_not() {
    for day in 0..7 {
        assert_eq!(
            budget_window(WEEK, MON + day * SECS_PER_DAY),
            MON,
            "day {day} of the week belongs to the week that started on Monday"
        );
    }
    assert_eq!(
        budget_window(WEEK, MON + 7 * SECS_PER_DAY),
        NEXT_MON,
        "the eighth day is the next week"
    );
}

/// THE RETRY HINT POINTS AT THE ROLL. A weekly refusal has somewhere to point, unlike `total`.
#[test]
fn a_week_window_ends_at_the_next_monday() {
    assert_eq!(window_end(WEEK, WED), Some(NEXT_MON));
    assert_eq!(
        window_end(WEEK, MON),
        Some(NEXT_MON),
        "measured from the window, never from `now`"
    );
}

/// THE WORD IS IN THE VOCABULARY. `is_known_window` is the one place a caller can notice the
/// corrupt-row case `budget_window`'s fall-safe swallows, so a `week` row that was NOT recognised
/// would be silently enforced as all-time — a weekly cap that never resets.
#[test]
fn week_is_a_known_window_word() {
    assert!(is_known_window(WEEK), "week is spellable");
    assert_eq!(ALL_WINDOWS.len(), 6, "six window words, not five");
    assert!(ALL_WINDOWS.contains(&WEEK));
    assert!(
        !is_known_window("fortnight"),
        "and the vocabulary is still closed"
    );
}

/// THE DOOR ENFORCES A WEEKLY CAP AND ROLLS IT. The end the operator actually configures: N
/// admissions pass inside one week, N+1 is refused naming (group, requests, week) with a hint to
/// the Monday roll, and the next week admits again.
#[test]
fn requests_per_week_enforced_and_window_rolls() {
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 2, Some(WEEK))],
        ),
    )]);
    let c = chain(&t, "k", Some("team"));
    let d = door();
    let p = no_card(0);

    d.try_admit(&p, &c, "", WED).expect("first of the week");
    // A different DAY of the same week: the counter is the week's, not the day's.
    d.try_admit(&p, &c, "", WED + SECS_PER_DAY)
        .expect("second, later in the same week");
    let err = d
        .try_admit(&p, &c, "", WED + 2 * SECS_PER_DAY)
        .expect_err("the weekly cap is spent");
    assert_blocked(err, "team", Metric::Requests, Some(WEEK), true);

    d.try_admit(&p, &c, "", NEXT_MON)
        .expect("the next week is fresh");
}

/// A WEEK CAP AND A MINUTE CAP ENFORCE INDEPENDENTLY, which is what makes `week` a window rather
/// than a rename of one that already existed: the two buckets roll on their own clocks.
#[test]
fn week_and_minute_windows_enforce_independently() {
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 3, Some(WEEK)),
                limit(LimitMetric::Requests, 1, Some(MINUTE)),
            ],
        ),
    )]);
    let c = chain(&t, "k", Some("team"));
    let d = door();
    let p = no_card(0);

    d.try_admit(&p, &c, "", WED).expect("first");
    // The minute is spent; the week is not.
    let err = d.try_admit(&p, &c, "", WED).expect_err("minute cap bites");
    assert_blocked(err, "team", Metric::Requests, Some(MINUTE), true);

    // A fresh minute inside the SAME week: the week's counter remembers the first admission.
    d.try_admit(&p, &c, "", WED + 60).expect("fresh minute");
    d.try_admit(&p, &c, "", WED + 120).expect("fresh minute");
    let err = d
        .try_admit(&p, &c, "", WED + 180)
        .expect_err("now the week cap bites, on a fresh minute");
    assert_blocked(err, "team", Metric::Requests, Some(WEEK), true);
}

/// THE FIRST FOUR DAYS OF THE EPOCH DO NOT PANIC.
///
/// The Monday that opens the epoch's own week is 1969-12-29, which is BEFORE the epoch and has no
/// `u64` to be. The day count for 1970-01-01 is 0 and the Monday offset is 3, so the subtraction
/// that finds the week start underflows — a debug panic, on a `now` that a zeroed or corrupt store
/// row supplies for free. Every other window word answers such a row rather than crashing on it,
/// and this one must too.
///
/// The answer is the epoch itself: that first Thursday-to-Sunday stub is a truncated week, and
/// truncating it is the tighter reading, never the wider one — the module's own fall-safe rule.
#[test]
fn the_epochs_own_partial_week_is_truncated_rather_than_underflowed() {
    assert_eq!(budget_window(WEEK, 0), 0, "the epoch instant itself");
    for day in 0..4 {
        assert_eq!(
            budget_window(WEEK, day * SECS_PER_DAY),
            0,
            "day {day} is in the epoch's truncated first week (Thursday to Sunday)"
        );
    }
    // 1970-01-05 is the first full Monday, and it opens a week of its own.
    assert_eq!(
        budget_window(WEEK, 4 * SECS_PER_DAY),
        4 * SECS_PER_DAY,
        "the first whole week starts on the first Monday"
    );
    assert_eq!(
        window_end(WEEK, 0),
        Some(4 * SECS_PER_DAY),
        "and the stub rolls at that same Monday, so no instant belongs to two windows"
    );
}
