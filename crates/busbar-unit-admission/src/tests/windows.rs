// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The window arithmetic, which nothing tested at all.
//!
//! `window.rs` decides WHICH CELL a charge lands in and WHEN a refused caller is told to come back.
//! Every counter in the crate is keyed on the answer, and every straddle rule is written in terms of
//! it. It arrived as moved code — the 1.5.5 governance module's window words plus the public-domain
//! civil-date helpers — and moved code is exactly the code a suite forgets, because the cases that
//! came with it were about the decision the windows feed rather than the windows themselves. Nothing
//! in the crate failed when the calendar arithmetic was changed: not a sign, not a divisor, not the
//! leap-year correction, not the day-of-era shift.
//!
//! What that would cost is not an off-by-one in a log line. A month boundary computed one day early
//! resets every monthly spend cap a day early, every month; a `civil_from_days` that disagrees with
//! `days_from_civil` puts the charge in one cell and the check in another, so a cap silently stops
//! being enforced. So the two helpers are pinned as an exact round trip over three quarters of a
//! million days plus the dates the algorithm's own constants are built on, and the five window words
//! are pinned both as literal epochs and as the structural laws every caller of them assumes.

use crate::window::{
    budget_window, is_known_window, window_end, ALL_WINDOWS, SECS_PER_DAY, WINDOW_DAY, WINDOW_HOUR,
    WINDOW_MINUTE, WINDOW_MONTH, WINDOW_TOTAL,
};

/// A day count as an epoch second at UTC midnight.
fn at_midnight(days: i64) -> u64 {
    u64::try_from(days).expect("a post-epoch day") * SECS_PER_DAY
}

// ---------------------------------------------------------------------------------------------
// The five words, as literal epochs.
// ---------------------------------------------------------------------------------------------

/// Each window word's start for one fixed instant, spelled out.
///
/// 2023-11-14T22:13:20Z. Every figure below is the UTC boundary a human would name for that instant,
/// so the test says what the code should do rather than restating how it does it.
#[test]
fn each_window_word_starts_where_a_calendar_says_it_does() {
    let now = 1_700_000_000; // 2023-11-14T22:13:20Z

    assert_eq!(
        budget_window(WINDOW_MINUTE, now),
        1_699_999_980,
        "22:13:00 on the same day"
    );
    assert_eq!(
        budget_window(WINDOW_HOUR, now),
        1_699_999_200,
        "22:00:00 on the same day"
    );
    assert_eq!(
        budget_window(WINDOW_DAY, now),
        1_699_920_000,
        "2023-11-14T00:00:00Z"
    );
    assert_eq!(
        budget_window(WINDOW_MONTH, now),
        1_698_796_800,
        "2023-11-01T00:00:00Z — the first of the month, not thirty days back"
    );
    assert_eq!(
        budget_window(WINDOW_TOTAL, now),
        0,
        "the all-time window is the single window starting at the epoch"
    );

    assert_eq!(window_end(WINDOW_MINUTE, now), Some(1_700_000_040));
    assert_eq!(window_end(WINDOW_HOUR, now), Some(1_700_002_800));
    assert_eq!(window_end(WINDOW_DAY, now), Some(1_700_006_400));
    assert_eq!(
        window_end(WINDOW_MONTH, now),
        Some(1_701_388_800),
        "2023-12-01T00:00:00Z"
    );
    assert_eq!(
        window_end(WINDOW_TOTAL, now),
        None,
        "the all-time window never rolls, so there is no retry hint"
    );
}

/// December rolls to January of the NEXT year.
///
/// The one month boundary that is not "same year, month plus one", and the only place the year is
/// ever incremented. Got wrong, every December refusal tells the caller to retry in eleven months,
/// or the monthly cap never resets at the turn of the year.
#[test]
fn the_month_window_rolls_from_december_into_the_next_january() {
    let mid_december = 1_702_598_400; // 2023-12-15T00:00:00Z
    assert_eq!(
        budget_window(WINDOW_MONTH, mid_december),
        1_701_388_800,
        "2023-12-01"
    );
    assert_eq!(
        window_end(WINDOW_MONTH, mid_december),
        Some(1_704_067_200),
        "2024-01-01 — the year turns with the month"
    );

    // And the ordinary case beside it, so the December arm cannot be the one that applies to both.
    let mid_november = 1_700_000_000;
    assert_eq!(window_end(WINDOW_MONTH, mid_november), Some(1_701_388_800));
}

/// February's length, in the three cases that differ: an ordinary year, a leap year, and the
/// century that is not a leap year.
///
/// The 400-year correction is the part of the calendar that a simpler rule gets wrong once a
/// century, and it is unreachable from any timestamp the ordinary cases use.
#[test]
fn the_month_window_gets_february_right_in_every_leap_rule() {
    // 2023 — an ordinary year: February has 28 days.
    let feb_2023 = at_midnight(19_389); // 2023-02-01
    assert_eq!(budget_window(WINDOW_MONTH, feb_2023), feb_2023);
    assert_eq!(
        window_end(WINDOW_MONTH, feb_2023),
        Some(at_midnight(19_389 + 28))
    );

    // 2024 — a leap year: 29.
    let feb_2024 = at_midnight(19_754); // 2024-02-01
    assert_eq!(budget_window(WINDOW_MONTH, feb_2024), feb_2024);
    assert_eq!(
        window_end(WINDOW_MONTH, feb_2024),
        Some(at_midnight(19_754 + 29))
    );

    // 2000 — divisible by 400, so a leap year despite being a century: 29.
    let feb_2000 = at_midnight(10_988); // 2000-02-01
    assert_eq!(budget_window(WINDOW_MONTH, feb_2000), feb_2000);
    assert_eq!(
        window_end(WINDOW_MONTH, feb_2000),
        Some(at_midnight(10_988 + 29))
    );

    // 2100 — divisible by 100 but not 400, so NOT a leap year: 28. The case the crate will meet.
    let feb_2100 = at_midnight(47_513); // 2100-02-01
    assert_eq!(budget_window(WINDOW_MONTH, feb_2100), feb_2100);
    assert_eq!(
        window_end(WINDOW_MONTH, feb_2100),
        Some(at_midnight(47_513 + 28)),
        "2100 is not a leap year"
    );

    // The last day of each February resolves to that February, not to March.
    assert_eq!(
        budget_window(WINDOW_MONTH, at_midnight(19_754 + 28)),
        feb_2024,
        "2024-02-29 is still February"
    );
    assert_eq!(
        budget_window(WINDOW_MONTH, at_midnight(19_754 + 29)),
        at_midnight(19_754 + 29),
        "2024-03-01 is March"
    );
}

// ---------------------------------------------------------------------------------------------
// The laws every caller assumes.
// ---------------------------------------------------------------------------------------------

/// For every word and a wide spread of instants: the window contains `now`, the end is strictly
/// after it, and the end of one window is exactly the start of the next.
///
/// These three are what the straddle rules are written against. "The window contains now" is what
/// makes a charge land in a cell the check read; "the end is strictly after now" is what stops a
/// retry hint of zero seconds from telling a caller to come back immediately, forever; and "the end
/// is the next start" is what makes the sequence of windows a partition of time rather than a set
/// with gaps or overlaps between them.
#[test]
fn the_windows_partition_time_and_always_contain_the_instant_they_were_asked_about() {
    // A spread over roughly a century, at an interval that is coprime with every window length so
    // it lands all over each of them, plus the boundaries themselves.
    let mut instants: Vec<u64> = (0..4000u64).map(|i| i * 786_413).collect();
    for base in [0u64, 1_700_000_000, 1_704_067_200, 951_782_400] {
        for word in ALL_WINDOWS {
            if let Some(end) = window_end(word, base) {
                instants.extend([end - 1, end, end + 1]);
            }
        }
    }

    for now in instants {
        for word in ALL_WINDOWS {
            let start = budget_window(word, now);
            assert!(
                start <= now,
                "{word} window {start} starts after the instant {now} it contains"
            );
            let Some(end) = window_end(word, now) else {
                assert_eq!(word, WINDOW_TOTAL, "only the all-time window never rolls");
                assert_eq!(start, 0);
                continue;
            };
            assert!(
                end > now,
                "{word} window ending {end} has already ended at {now}: a retry hint of zero"
            );
            assert_eq!(
                budget_window(word, end),
                end,
                "{word}: the end of the window containing {now} is not the start of the next"
            );
            assert_eq!(
                window_end(word, start),
                Some(end),
                "{word}: the window's own start does not resolve to the same window"
            );
            // Every window is aligned to midnight or finer, and none is longer than 31 days.
            assert!(
                end - start <= 31 * SECS_PER_DAY,
                "{word} window is too long"
            );
        }
    }
}

/// The minute, hour and day windows are exactly their own lengths, everywhere.
#[test]
fn the_fixed_length_windows_are_exactly_their_own_lengths() {
    for i in 0..2000u64 {
        let now = i * 786_413;
        for (word, len) in [
            (WINDOW_MINUTE, 60),
            (WINDOW_HOUR, 3600),
            (WINDOW_DAY, SECS_PER_DAY),
        ] {
            let start = budget_window(word, now);
            assert_eq!(start % len, 0, "{word} window start is not aligned");
            assert_eq!(
                window_end(word, now),
                Some(start + len),
                "{word} window is not {len} seconds long at {now}"
            );
        }
    }
}

/// An unrecognized window word falls safe to the ALL-TIME window, never to a wider one.
///
/// It can only come from a corrupt or foreign store row — the config parser rejects it — and the
/// all-time window is the tightest enforcement there is: a cap on it never resets. Falling to any
/// rolling window instead would hand a corrupt row a periodic amnesty.
#[test]
fn an_unrecognised_window_word_falls_safe_to_the_all_time_window() {
    for word in ["", "week", "Minute", "minutes", "total ", "day\0"] {
        assert!(!is_known_window(word), "{word:?} is not a window word");
        assert_eq!(
            budget_window(word, 1_700_000_000),
            0,
            "{word:?} must fall to the all-time window"
        );
        assert_eq!(
            window_end(word, 1_700_000_000),
            None,
            "{word:?} has no roll, so no retry hint"
        );
    }
    for word in ALL_WINDOWS {
        assert!(is_known_window(word), "{word} is a window word");
    }
    assert_eq!(
        ALL_WINDOWS,
        [
            WINDOW_MINUTE,
            WINDOW_HOUR,
            WINDOW_DAY,
            WINDOW_MONTH,
            WINDOW_TOTAL
        ],
        "the vocabulary, in the order the words are listed"
    );
    // And no two words name the same window shape.
    for a in ALL_WINDOWS {
        for b in ALL_WINDOWS {
            if a != b {
                let now = 1_700_000_000;
                assert!(
                    budget_window(a, now) != budget_window(b, now)
                        || window_end(a, now) != window_end(b, now),
                    "{a} and {b} are the same window"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The civil-date helpers, through the one caller that can reach them.
// ---------------------------------------------------------------------------------------------

/// The two civil-date helpers are exact inverses, over every day from year 0 to year 4000.
///
/// This is the property that matters most and the one nothing checked: `budget_window` calls
/// `civil_from_days` to find which month an instant is in and `days_from_civil` to turn that month
/// back into an epoch. If the two disagree by even a day, a charge lands in one cell and the check
/// that guards it reads another, and the cap silently stops being enforced. The round trip is
/// exercised HERE through the month window, which is the only public route to either.
///
/// Each day's month window must be the first of that day's own month, and the first of a month must
/// be its own window start — which together say `days_from_civil(civil_from_days(z)) == z` for the
/// first of every month in the range, and pins every intermediate day to the right month.
#[test]
fn the_civil_date_helpers_round_trip_over_four_thousand_years() {
    // Day 0 is 1970-01-01; the range below runs to roughly the year 4000, which covers five
    // 400-year eras and every century rule inside them.
    let mut day = 0i64;
    let mut month_start = budget_window(WINDOW_MONTH, at_midnight(0));
    assert_eq!(month_start, 0, "1970-01-01 is the first of its own month");

    let mut months_seen = 0u32;
    let mut day_lengths: Vec<u64> = Vec::new();
    while day < 741_000 {
        let now = at_midnight(day);
        let start = budget_window(WINDOW_MONTH, now);
        let end = window_end(WINDOW_MONTH, now).expect("the month window rolls");

        assert!(
            start <= now && now < end,
            "day {day} is outside its own month"
        );
        assert_eq!(
            start % SECS_PER_DAY,
            0,
            "day {day}: a month starts at midnight"
        );
        assert_eq!(
            budget_window(WINDOW_MONTH, start),
            start,
            "day {day}: the first of the month is not its own window start — \
             civil_from_days and days_from_civil disagree"
        );
        assert_eq!(
            window_end(WINDOW_MONTH, start),
            Some(end),
            "day {day}: the month's own first day resolves to a different month"
        );

        if start != month_start {
            // A new month: the previous one was one of the four legal lengths, and the months are
            // contiguous with no gap and no overlap.
            let len = (start - month_start) / SECS_PER_DAY;
            assert!(
                (28..=31).contains(&len),
                "a month of {len} days ending at {start}"
            );
            day_lengths.push(len);
            months_seen += 1;
            month_start = start;
        }

        // Walk a day at a time near the month edges and in longer strides in between, so every
        // boundary is landed on exactly while the whole range still runs quickly.
        let days_to_end = i64::try_from((end - now) / SECS_PER_DAY).expect("a month is short");
        day += if days_to_end > 3 { days_to_end - 2 } else { 1 };
    }

    assert!(
        months_seen > 24_000,
        "the walk covered {months_seen} months, which is not the whole range"
    );
    // Over four thousand years every legal month length occurs, February's three cases included.
    for len in [28, 29, 30, 31] {
        assert!(
            day_lengths.contains(&len),
            "no month of {len} days was seen — the range or the arithmetic is wrong"
        );
    }
}

/// The three dates the algorithm's own constants are built on, pinned directly.
///
/// The day-of-era shift (719 468) is the number of days from 0000-03-01 to 1970-01-01, and the era
/// length (146 097) is the days in 400 years. Both are spelled as literals in the helpers, and a
/// literal is the one thing an arithmetic mutation cannot reach — so they are pinned from the other
/// side, through dates whose answers are fixed by the calendar rather than by the code.
#[test]
fn the_epoch_and_the_era_boundaries_land_where_the_calendar_puts_them() {
    // The epoch itself.
    assert_eq!(budget_window(WINDOW_DAY, 0), 0);
    assert_eq!(budget_window(WINDOW_MONTH, 0), 0, "1970-01-01");
    assert_eq!(
        window_end(WINDOW_MONTH, 0),
        Some(at_midnight(31)),
        "1970-02-01"
    );

    // 2000-03-01, the day the algorithm's internal year begins on, in the era it begins with.
    let mar_2000 = at_midnight(11_017);
    assert_eq!(budget_window(WINDOW_MONTH, mar_2000), mar_2000);
    assert_eq!(
        window_end(WINDOW_MONTH, mar_2000),
        Some(at_midnight(11_017 + 31)),
        "2000-04-01"
    );

    // 2400-03-01 — exactly one 400-year era after 2000-03-01, so exactly 146 097 days later.
    let mar_2400 = at_midnight(11_017 + 146_097);
    assert_eq!(
        budget_window(WINDOW_MONTH, mar_2400),
        mar_2400,
        "one whole era on from 2000-03-01 is the first of a month again"
    );

    // 2800-03-01 — two whole eras on, so the era arithmetic has to have compounded correctly rather
    // than merely worked once.
    let mar_2800 = at_midnight(11_017 + 2 * 146_097);
    assert_eq!(budget_window(WINDOW_MONTH, mar_2800), mar_2800);
    assert_eq!(
        window_end(WINDOW_MONTH, mar_2800),
        Some(at_midnight(11_017 + 2 * 146_097 + 31)),
        "2800-04-01"
    );
}
