// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The window vocabulary, pinned.
//!
//! WHY THIS FILE EXISTS. `src/window.rs` says it was "moved from the 1.5.5 governance module
//! unchanged, civil-date helpers and all", and every other suite in this crate USES it — a dozen
//! call sites spell a bucket epoch with `budget_window` on the way to asserting something about the
//! door. None of them assert anything about `budget_window` itself. Measured on 2026-09-12: there
//! was no test in this crate that named a return value of `budget_window` or `window_end`, none
//! that named `is_known_window` or `ALL_WINDOWS` at all, and none that reached the civil-date
//! algorithm the month arm is built on. The one suite in the workspace that did pin this
//! arithmetic was the retiring engine's, over the retiring engine's own second copy of it — so the
//! copy that ships was the untested one, and deleting the copy that was tested would have retired
//! the coverage with it. (Naming that crate here is exactly what a unit may not do, which is its
//! own argument for why the cases belong on this side of the seam.)
//!
//! These cases are that suite, ported to the owner of the arithmetic. They are the 1.5.5 cases:
//! the tables, the chosen epochs and the comments explaining each choice are the ones written
//! against the original, because the original is what this code is.

use crate::price::units_total;
use crate::window::{
    budget_window, civil_from_days, days_from_civil, is_known_window, window_end, ALL_WINDOWS,
    SECS_PER_DAY, WINDOW_DAY, WINDOW_HOUR, WINDOW_MINUTE, WINDOW_MONTH, WINDOW_TOTAL,
};

/// `civil_from_days`/`days_from_civil` (Howard Hinnant's public-domain civil-calendar algorithm,
/// the same shape `budget_window`'s `WINDOW_MONTH` arm relies on) — a table of known epoch-day <->
/// date pairs spanning the epoch itself, both sides of it (the `z >= 0` branch and its negative
/// counterpart), a non-leap month boundary, a leap-year Feb 29 (both a leap century, 2000, and an
/// ordinary leap year, 2024), and a NON-leap century (1900 — divisible by 100 but not 400, the
/// exact case the `- doe / 36_524` / `- doe / 146_096` correction terms exist for) plus the very
/// distant 2400 (also a leap century) to pin the `era` math far from the epoch on both axes.
#[test]
fn civil_from_days_and_days_from_civil_known_dates() {
    let cases: &[(i64, (i64, i64, i64))] = &[
        (0, (1970, 1, 1)),
        (-1, (1969, 12, 31)),
        (-365, (1969, 1, 1)),
        (11_016, (2000, 2, 29)), // leap century
        (11_017, (2000, 3, 1)),
        (-25_508, (1900, 3, 1)),  // non-leap century boundary
        (-25_509, (1900, 2, 28)), // 1900 has no Feb 29
        (19_691, (2023, 11, 30)), // ordinary month boundary
        (19_692, (2023, 12, 1)),
        (19_782, (2024, 2, 29)), // ordinary leap year
        (19_783, (2024, 3, 1)),
        (157_113, (2400, 2, 29)), // leap century, far future
        // Deep negative z (year -768): the ONLY case where `z + 719_468` (the internal offset)
        // itself goes negative, exercising the `era`/`doe` negative-branch correction terms —
        // every other case above stays positive after the offset and can't reach this branch.
        // Expected value taken from the real (unmutated) algorithm's own output, not a hand-ported
        // reference: Rust's `/` truncates toward zero for negative operands (unlike e.g. Python's
        // `//`, which floors), so an independently-authored reference for deep negative inputs is
        // easy to get subtly wrong here.
        (-1_000_000, (-768, 2, 4)),
    ];
    for &(z, ymd) in cases {
        assert_eq!(civil_from_days(z), ymd, "civil_from_days({z})");
        assert_eq!(
            days_from_civil(ymd.0, ymd.1, ymd.2),
            z,
            "days_from_civil{ymd:?}"
        );
    }
}

/// The window word -> epoch-start map, one case per arm, plus the corrupt-row fall-safe.
#[test]
fn budget_window_periods() {
    assert_eq!(budget_window(WINDOW_TOTAL, 1_700_000_000), 0);
    // The corrupt/foreign store row: not one of the five words, so the tightest window, never a
    // wider one. This crate has no logger, so it falls safe silently; `is_known_window` below is
    // how a caller with a logger notices the same condition.
    assert_eq!(budget_window("unknown", 1_700_000_000), 0);
    assert_eq!(budget_window(WINDOW_DAY, 1_700_000_000), 1_699_920_000);
    // 1700000000 = 2023-11-14 -> 2023-11-01 00:00Z = 1698796800.
    assert_eq!(budget_window(WINDOW_MONTH, 1_700_000_000), 1_698_796_800);
    // WINDOW_HOUR: floor to the containing hour, `now / 3600 * 3600` (integer-division floor, NOT
    // `now * 3600 * 3600` nor `now / 3600 + 3600` - a non-hour-aligned timestamp catches either).
    // 1_700_000_000 = 2023-11-14 22:13:20 UTC -> hour start 2023-11-14 22:00:00 UTC = 1_699_999_200.
    assert_eq!(budget_window(WINDOW_HOUR, 1_700_000_000), 1_699_999_200);
    assert_eq!(
        budget_window(WINDOW_MINUTE, 1_700_000_010),
        1_700_000_040 - 60
    );
}

/// The window word -> roll-at map: the retry hint a windowed refusal carries.
#[test]
fn window_end_rolls() {
    // A minute rolls at the next :00; total never rolls.
    assert_eq!(
        window_end(WINDOW_MINUTE, 1_700_000_010),
        Some(1_700_000_040)
    );
    // WINDOW_HOUR rolls to the NEXT hour boundary (`+ 3600`, not `* 3600`).
    assert_eq!(
        window_end(WINDOW_HOUR, 1_700_000_000),
        Some(1_699_999_200 + 3600)
    );
    assert_eq!(
        window_end(WINDOW_DAY, 1_700_000_000),
        Some(1_699_920_000 + SECS_PER_DAY)
    );
    // 2023-11 rolls to 2023-12-01 00:00Z = 1701388800.
    assert_eq!(window_end(WINDOW_MONTH, 1_700_000_000), Some(1_701_388_800));
    assert_eq!(window_end(WINDOW_TOTAL, 1_700_000_000), None);
    // An unrecognized word has no roll to report, for the same reason `total` has none: it IS
    // `total` after the fall-safe above.
    assert_eq!(window_end("unknown", 1_700_000_000), None);
}

/// December is the arm that has to carry the year, and it is the only one that does. A month-end
/// test that never crosses a December cannot tell `(y, m + 1)` from `(y + 1, 1)`.
#[test]
fn window_end_month_carries_the_year_in_december() {
    // 2023-12-15 12:00:00Z. The month window rolls to 2024-01-01 00:00Z = 1704067200.
    let mid_december = 1_702_641_600;
    assert_eq!(budget_window(WINDOW_MONTH, mid_december), 1_701_388_800);
    assert_eq!(window_end(WINDOW_MONTH, mid_december), Some(1_704_067_200));
}

/// `is_known_window` and `ALL_WINDOWS` are one statement of the vocabulary, not two: the predicate
/// is the membership test over the list, and a word the list names must be a word `budget_window`
/// has an arm for.
#[test]
fn known_windows_are_exactly_the_five_words() {
    assert_eq!(ALL_WINDOWS.len(), 5);
    for word in ALL_WINDOWS {
        assert!(is_known_window(word), "{word} is in ALL_WINDOWS");
    }
    for word in [
        WINDOW_MINUTE,
        WINDOW_HOUR,
        WINDOW_DAY,
        WINDOW_MONTH,
        WINDOW_TOTAL,
    ] {
        assert!(ALL_WINDOWS.contains(&word), "{word} is a window word");
    }
    assert!(!is_known_window("unknown"));
    assert!(!is_known_window(""));
    // Case- and whitespace-exact: the word is a config token, and a near-miss is a corrupt row,
    // not a window. Falling safe to `total` is the right answer; silently accepting `Day` would
    // be the wrong one.
    assert!(!is_known_window("Day"));
    assert!(!is_known_window("day "));
}

/// Every window start is inside its own window, and `budget_window` is idempotent on a start it
/// produced. Both properties are what lets a bucket id be rebuilt from a stored epoch.
#[test]
fn window_starts_are_stable_under_reapplication() {
    for word in ALL_WINDOWS {
        for now in [0u64, 1, 1_700_000_000, 1_702_641_600, 4_102_444_800] {
            let start = budget_window(word, now);
            assert!(start <= now, "{word}: start {start} is not after now {now}");
            assert_eq!(
                budget_window(word, start),
                start,
                "{word}: budget_window is not idempotent at {start}"
            );
            if let Some(end) = window_end(word, now) {
                assert!(end > now, "{word}: roll {end} is not after now {now}");
                assert!(end > start, "{word}: roll {end} is not after start {start}");
            }
        }
    }
}

/// The scalar total over a ledger cell's per-model counters SATURATES. A total that wrapped would
/// read as a cap that had not been reached, which is the one direction this must never fail in.
#[test]
fn units_total_sums_and_saturates() {
    let mut units = std::collections::BTreeMap::new();
    assert_eq!(units_total(&units), 0);
    units.insert("input".to_string(), 7u64);
    units.insert("output".to_string(), 11u64);
    // A key outside the reserved four still counts toward the scalar total.
    units.insert("reasoning".to_string(), 5u64);
    assert_eq!(units_total(&units), 23);

    let mut huge = std::collections::BTreeMap::new();
    huge.insert("a".to_string(), u64::MAX);
    huge.insert("b".to_string(), 1u64);
    assert_eq!(
        units_total(&huge),
        u64::MAX,
        "the total saturates; it must never wrap to a small number"
    );
}
