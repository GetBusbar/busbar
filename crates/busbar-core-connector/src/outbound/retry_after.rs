// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Retry-After`, both forms (RFC 9110 section 10.2.3): a number of seconds, or a date.
//!
//! v1.5.5 honoured both. The native dial read only the number, so a provider that answers 429 or
//! 503 with a date was retried as if it had said nothing. The date is read in the three forms a
//! recipient must accept (RFC 9110 section 5.6.7): IMF-fixdate, the obsolete RFC 850 form and
//! `asctime`. Nothing here reads a clock: the caller passes its one wall reading.

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    // March is month 0 of the shifted year, so the leap day is its last.
    let shifted = (month + 9) % 12;
    let day_of_year = i64::from((153 * shifted + 2) / 5 + day - 1);
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn month_of(text: &str) -> Option<u32> {
    let lower = text.get(..3)?.to_ascii_lowercase();
    MONTHS
        .iter()
        .position(|month| *month == lower)
        .map(|at| at as u32 + 1)
}

/// An HTTP date as seconds since the epoch. `now` (seconds since the epoch) places a two-digit
/// year: a date that would be more than 50 years ahead is read as the most recent past year with
/// those two digits (RFC 9110 section 5.6.7).
pub(crate) fn http_date(text: &str, now: u64) -> Option<u64> {
    let mut parts = text
        .split([' ', ',', '-', ':'])
        .filter(|part| !part.is_empty());
    let _weekday = parts.next()?;
    let second = parts.next()?;
    let (day, month, year, clock_first): (u32, u32, Option<&str>, bool) = match month_of(second) {
        // asctime: `Sun Nov  6 08:49:37 1994`.
        Some(month) if second.len() == 3 => (parts.next()?.parse().ok()?, month, None, true),
        // IMF-fixdate `Sun, 06 Nov 1994 08:49:37 GMT`; RFC 850 `Sunday, 06-Nov-94 08:49:37 GMT`.
        _ => {
            let day = second.parse().ok()?;
            let month = month_of(parts.next()?)?;
            (day, month, Some(parts.next()?), false)
        }
    };
    let hour: u64 = parts.next()?.parse().ok()?;
    let minute: u64 = parts.next()?.parse().ok()?;
    let seconds: u64 = parts.next()?.parse().ok()?;
    let year_text = match year {
        Some(year) => year,
        None => parts.next()?,
    };
    if !clock_first && !parts.next()?.eq_ignore_ascii_case("GMT") {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }
    let mut year: i64 = year_text.parse().ok()?;
    if year_text.len() == 2 {
        let this_year = 1970 + i64::try_from(now / 31_556_952).ok()?;
        year += 2000;
        if year > this_year + 50 {
            year -= 100;
        }
    }
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || seconds > 60 || year < 1970 {
        return None;
    }
    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + seconds)
}

/// How long the far end asked to be left alone, in seconds, from a `Retry-After` value. A date
/// already past is zero. `now` = the caller's one wall reading, in seconds since the epoch.
pub(crate) fn seconds(value: &str, now: u64) -> Option<u64> {
    let value = value.trim();
    if let Ok(number) = value.parse::<u64>() {
        return Some(number);
    }
    http_date(value, now).map(|at| at.saturating_sub(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1994-11-06 08:49:37 UTC.
    const THEN: u64 = 784_111_777;

    #[test]
    fn a_number_of_seconds_is_itself() {
        assert_eq!(seconds("120", THEN), Some(120));
        assert_eq!(seconds(" 0 ", THEN), Some(0));
    }

    #[test]
    fn the_three_date_forms_read_the_same_instant() {
        for text in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(http_date(text, THEN), Some(THEN), "{text}");
        }
    }

    #[test]
    fn a_date_ahead_is_the_seconds_until_it_and_a_date_past_is_zero() {
        let text = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert_eq!(seconds(text, THEN - 90), Some(90));
        assert_eq!(seconds(text, THEN + 5), Some(0));
    }

    #[test]
    fn leap_days_and_the_epoch_are_placed_right() {
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT", 0), Some(0));
        assert_eq!(
            http_date("Thu, 29 Feb 2024 00:00:00 GMT", 0),
            Some(1_709_164_800)
        );
        assert_eq!(
            http_date("Wed, 18 Nov 2026 22:30:00 GMT", 0),
            Some(1_795_041_000)
        );
    }

    #[test]
    fn a_two_digit_year_far_ahead_is_read_as_the_past() {
        // In 2026, `94` is 1994, and `30` is 2030.
        let now = 1_795_041_000;
        assert_eq!(http_date("Sunday, 06-Nov-94 08:49:37 GMT", now), Some(THEN));
        assert!(http_date("Wednesday, 06-Nov-30 08:49:37 GMT", now).is_some_and(|at| at > now));
    }

    #[test]
    fn what_is_neither_a_number_nor_a_date_is_nothing() {
        for text in [
            "",
            "soon",
            "Sun, 06 Nov 1994 08:49:37 PST",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 25:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT trailing",
            "-5",
        ] {
            assert_eq!(seconds(text, THEN), None, "{text:?}");
        }
    }
}
