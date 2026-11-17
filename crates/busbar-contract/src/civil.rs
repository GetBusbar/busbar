// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Civil-date math for the plane crates that render an epoch timestamp, on the `time` crate
//! (DEPENDENCY-LADDER C10). Both directions saturate at the calendar `time` carries, years -9999
//! to 9999: RFC 3339 has no spelling for a five-digit year.

use time::Date;

/// The Julian day number of 1970-01-01, the Unix epoch.
const UNIX_EPOCH_JULIAN_DAY: i64 = 2_440_588;

/// Days since the Unix epoch → the proleptic-Gregorian calendar date, saturating at
/// [`Date::MIN`] and [`Date::MAX`].
#[must_use]
pub fn date_from_days(days: i64) -> Date {
    i32::try_from(days.saturating_add(UNIX_EPOCH_JULIAN_DAY))
        .ok()
        .and_then(|julian| Date::from_julian_day(julian).ok())
        .unwrap_or(if days < 0 { Date::MIN } else { Date::MAX })
}

/// Days since the Unix epoch → (year, month, day), saturating as [`date_from_days`] does.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let date = date_from_days(z);
    (
        i64::from(date.year()),
        u32::from(u8::from(date.month())),
        u32::from(date.day()),
    )
}

pub use busbar_artifact_metadata::civil::rfc3339_from_secs;

#[cfg(test)]
#[path = "tests/civil_tests.rs"]
mod tests;
