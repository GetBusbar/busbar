// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Window words, and the two functions that turn one into an epoch.
//!
//! A cap is always "N per something": per minute, per hour, per day, per week, per month, or over
//! all time.
//! The word names the shape of the window; these functions turn the word plus the current second
//! into the window's start (which bucket the counters live in) and the window's end (what the
//! client is told to wait for). Moved from the 1.5.5 governance module unchanged, civil-date
//! helpers and all.

/// Seconds in a day. Named rather than spelled out because it appears in three window
/// computations and the eviction bound.
pub const SECS_PER_DAY: u64 = 86_400;

/// Days in a week, and the offset that puts the week boundary on a MONDAY.
///
/// The Unix epoch is a THURSDAY, so `days % 7 == 0` is a Thursday and a week window computed
/// straight off the day count would roll mid-week — which is nobody's week and no calendar's. Day
/// 0 is three days after the Monday that preceded it, so adding [`EPOCH_DOW_OFFSET`] before the
/// modulus shifts the whole grid onto Monday 00:00 UTC, the ISO-8601 week start. That is the only
/// thing the offset does.
const DAYS_PER_WEEK: u64 = 7;
/// Thursday is three days after Monday; see [`DAYS_PER_WEEK`].
const EPOCH_DOW_OFFSET: u64 = 3;

/// The all-time window. It never rolls, so a cap on it never resets and a refusal against it
/// carries no retry hint.
pub const WINDOW_TOTAL: &str = "total";
/// The calendar-day window, aligned to UTC midnight.
pub const WINDOW_DAY: &str = "day";
/// The calendar-month window, aligned to the UTC first of the month.
pub const WINDOW_MONTH: &str = "month";
/// The wall-clock minute window.
pub const WINDOW_MINUTE: &str = "minute";
/// The wall-clock hour window.
pub const WINDOW_HOUR: &str = "hour";
/// The calendar-week window, aligned to MONDAY 00:00 UTC (the ISO-8601 week start).
pub const WINDOW_WEEK: &str = "week";

/// Every window word, in the order the vocabulary lists them.
pub const ALL_WINDOWS: [&str; 6] = [
    WINDOW_MINUTE,
    WINDOW_HOUR,
    WINDOW_DAY,
    WINDOW_WEEK,
    WINDOW_MONTH,
    WINDOW_TOTAL,
];

/// The epoch start of the window containing `now` for a given window word (nouns): `total` = a
/// single all-time window (0); `day` = UTC midnight; `week` = UTC Monday midnight; `month` = UTC
/// first-of-month.
///
/// An unrecognized window word can only arise from a corrupt or foreign store row (config parse
/// rejects it). It falls safe to the all-time window (0), the tightest enforcement, never wider.
/// The 1.5.5 original emitted a diagnostic here; this crate has no logger, so the caller may
/// detect the same condition with [`is_known_window`].
pub fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        WINDOW_MINUTE => now / 60 * 60,
        WINDOW_HOUR => now / 3600 * 3600,
        WINDOW_DAY => now / SECS_PER_DAY * SECS_PER_DAY,
        WINDOW_WEEK => week_bounds_days(now).0 * SECS_PER_DAY,
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * SECS_PER_DAY
        }
        WINDOW_TOTAL => 0, // explicit all-time window (the documented sentinel)
        _ => 0,
    }
}

/// Whether `period` is one of the six window words. The one place a caller can notice the
/// corrupt-row case the fall-safe above swallows.
pub fn is_known_window(period: &str) -> bool {
    ALL_WINDOWS.contains(&period)
}

/// The epoch at which `period`'s window containing `now` rolls to the next window — the source of
/// the retry hint on a windowed refusal. `None` for `total` (never rolls) and for an unrecognized
/// word (backstopped to `total` above).
pub fn window_end(period: &str, now: u64) -> Option<u64> {
    match period {
        WINDOW_MINUTE => Some(now / 60 * 60 + 60),
        WINDOW_HOUR => Some(now / 3600 * 3600 + 3600),
        WINDOW_DAY => Some(now / SECS_PER_DAY * SECS_PER_DAY + SECS_PER_DAY),
        WINDOW_WEEK => Some(week_bounds_days(now).1 * SECS_PER_DAY),
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            Some((days_from_civil(ny, nm, 1) as u64) * SECS_PER_DAY)
        }
        _ => None,
    }
}

/// The day numbers of the MONDAY that opens the week containing `now` and of the Monday it rolls
/// at, as one answer.
///
/// Both come from one computation so the start and the roll cannot disagree about where a week
/// begins — a roll that is not exactly the next window's start would leave an instant belonging to
/// two windows, or to none.
///
/// The roll is `days + (7 - back)` rather than `start + 7`, and the difference is the epoch's own
/// week: `start` SATURATES there, because the Monday that opens it is 1969-12-29 and there is no
/// `u64` for it, so the first four days share a TRUNCATED week that rolls after four days and not
/// after seven. Truncating is the tighter reading and never the wider one — the same fall-safe rule
/// `budget_window` applies to a word it does not recognise. Without the saturation a zeroed or
/// corrupt store row is a debug panic rather than an answer.
fn week_bounds_days(now: u64) -> (u64, u64) {
    let days = now / SECS_PER_DAY;
    let back = (days + EPOCH_DOW_OFFSET) % DAYS_PER_WEEK;
    (days.saturating_sub(back), days + (DAYS_PER_WEEK - back))
}

// Public-domain civil-date algorithms; self-contained, no date crate.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
