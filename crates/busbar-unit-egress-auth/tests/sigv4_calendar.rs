// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The calendar `format_amz_time` computes, checked against an independent one.
//!
//! `format_amz_time` is a closed-form civil-from-days algorithm: four nested division terms whose
//! job is to count leap days across years, centuries and four-century eras. It decides two things a
//! SigV4 request cannot be wrong about — the `x-amz-date` header, and the datestamp that goes into
//! both the credential scope and the first link of the signing-key HMAC chain. A calendar that is a
//! day out signs every request under the wrong key and the wrong scope, and AWS answers 403 for a
//! reason no log on this side will name.
//!
//! One known-good epoch, which is what the crate's own test asserts, exercises exactly one point of
//! that arithmetic and pins almost none of it: at 2015-08-30 the century and era terms are both
//! zero, and the year term happens to round to the same value whether it is added or subtracted.
//! So this file checks the whole reachable range instead, day by day, against a reference written
//! the other way round — accumulate days a year and a month at a time, with the leap rule spelled
//! out — because two implementations that share no arithmetic agreeing on every day for five
//! centuries is worth more than any number of hand-picked cases.

use busbar_unit_egress_auth::sigv4::format_amz_time;

const SECS_PER_DAY: u64 = 86_400;

/// The Gregorian leap rule, written out.
fn is_leap(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => unreachable!("month {m}"),
    }
}

/// (year, month, day) for a count of days since 1970-01-01, by counting forward. Shares no term
/// with the closed-form algorithm under test.
fn reference_civil(days: u64) -> (u64, u64, u64) {
    let mut remaining = days;
    let mut y = 1970;
    loop {
        let in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < in_year {
            break;
        }
        remaining -= in_year;
        y += 1;
    }
    let mut m = 1;
    loop {
        let in_month = days_in_month(y, m);
        if remaining < in_month {
            break;
        }
        remaining -= in_month;
        m += 1;
    }
    (y, m, remaining + 1)
}

fn reference_format(epoch_secs: u64) -> (String, String) {
    let (y, m, d) = reference_civil(epoch_secs / SECS_PER_DAY);
    let sod = epoch_secs % SECS_PER_DAY;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    (
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Every day from the epoch through 2499-12-31 formats the same as the reference calendar.
///
/// The range is chosen to cross every kind of boundary the four division terms exist to handle: an
/// ordinary leap year (1972), a century that is not a leap year (1900 is before the epoch, so
/// 2100, 2200 and 2300 stand in), a century that is (2000, 2400), and the four-century era
/// rollover the algorithm's `era`/`doe` terms are built around, which falls on 2400-02-29 —
/// the single day of the whole range on which the last division term is not zero.
#[test]
fn every_day_for_five_centuries_formats_the_same_as_a_reference_calendar() {
    // The first day of each year, by the reference's own counting.
    let mut first_day_of = std::collections::BTreeMap::new();
    let mut day = 0u64;
    for y in 1970..2501 {
        first_day_of.insert(y, day);
        day += if is_leap(y) { 366 } else { 365 };
    }

    let check = |day: u64| {
        let epoch = day * SECS_PER_DAY;
        assert_eq!(
            format_amz_time(epoch),
            reference_format(epoch),
            "day {day} (epoch {epoch})"
        );
    };

    // Every day of the first century and a half, unbroken.
    for day in 0..first_day_of[&2120] {
        check(day);
    }
    // Then a window either side of each century and era rollover — where the three higher division
    // terms change value, and the only place past 2120 the closed form can diverge without also
    // diverging inside the unbroken range above.
    for year in [2200, 2300, 2400, 2500] {
        let start = first_day_of[&(year - 1)];
        for day in start..first_day_of[&year] + 366 {
            check(day);
        }
    }
}

/// The days the closed form is most likely to be wrong about, named so a failure says which rule
/// broke rather than only which day number.
#[test]
fn the_boundary_days_each_leap_rule_exists_for() {
    for (epoch, want) in [
        (0u64, "19700101"),
        // An ordinary leap day, and the days either side of it.
        (68_083_200, "19720228"),
        (68_169_600, "19720229"),
        (68_256_000, "19720301"),
        // 2000 is a leap year: divisible by 400.
        (951_782_400, "20000229"),
        (951_868_800, "20000301"),
        // 2100 is NOT a leap year: divisible by 100, not by 400. The century term.
        (4_107_456_000, "21000228"),
        (4_107_542_400, "21000301"),
        // 2400 is a leap year again, and 2400-02-29 is the last day of a four-century era —
        // the one day of this whole range the era term is non-zero.
        (13_574_563_200, "24000229"),
        (13_574_649_600, "24000301"),
        // A year end and the year start after it.
        (1_735_603_200, "20241231"),
        (1_735_689_600, "20250101"),
    ] {
        let (amz, datestamp) = format_amz_time(epoch);
        assert_eq!(datestamp, want, "datestamp for epoch {epoch}");
        assert_eq!(
            amz[..8],
            *want,
            "the amzdate carries the same day as the datestamp for epoch {epoch}"
        );
        assert_eq!(reference_format(epoch).1, want, "the fixture itself");
    }
}

/// The time-of-day half: hours, minutes and seconds are each carried, zero-padded, and none of them
/// bleeds into another.
#[test]
fn the_time_of_day_is_carried_field_by_field() {
    for (sod, want) in [
        (0u64, "T000000Z"),
        (1, "T000001Z"),
        (59, "T000059Z"),
        (60, "T000100Z"),
        (3599, "T005959Z"),
        (3600, "T010000Z"),
        (45_296, "T123456Z"),
        (86_399, "T235959Z"),
    ] {
        let (amz, datestamp) = format_amz_time(sod);
        assert_eq!(datestamp, "19700101", "still the first day at {sod}s");
        assert_eq!(&amz[8..], want, "{sod}s past midnight");
    }
}
