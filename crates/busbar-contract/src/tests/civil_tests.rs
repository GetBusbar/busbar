// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the proleptic-Gregorian civil-date split in `crates/busbar-contract/src/civil.rs`.

use super::*;

#[test]
fn civil_from_days_maps_known_epochs() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));

    assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    assert_eq!(civil_from_days(18_322), (2020, 3, 1));

    assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    assert_eq!(civil_from_days(364), (1970, 12, 31));
    assert_eq!(civil_from_days(365), (1971, 1, 1));

    assert_eq!(civil_from_days(47_540), (2100, 2, 28));
    assert_eq!(civil_from_days(47_541), (2100, 3, 1));
}

#[test]
fn rfc3339_from_secs_renders_a_bare_second_instant() {
    assert_eq!(rfc3339_from_secs(0), "1970-01-01T00:00:00Z");

    assert_eq!(
        rfc3339_from_secs(18_321 * 86_400 + 86_399),
        "2020-02-29T23:59:59Z"
    );
}

/// DEPENDENCY-LADDER C10 (time 0.3): the civil split saturates at the calendar `time` carries
/// (years -9999 to 9999) instead of running past it. Named change, red on the hand Hinnant code:
/// it rendered day 2,932,897 as year 10000 and overflowed on `i64::MIN`.
#[test]
fn civil_from_days_saturates_at_the_calendar_range() {
    assert_eq!(civil_from_days(2_932_896), (9999, 12, 31));
    assert_eq!(civil_from_days(2_932_897), (9999, 12, 31));
    assert_eq!(civil_from_days(i64::MAX), (9999, 12, 31));
    assert_eq!(civil_from_days(-719_528), (0, 1, 1));
    assert_eq!(civil_from_days(i64::MIN), (-9999, 1, 1));
}

/// DEPENDENCY-LADDER C10: an instant past 9999-12-31T23:59:59Z has no RFC 3339 spelling (the
/// year is four digits), so the rendering saturates there. Named change, red on the hand code,
/// which wrote a five-digit year.
#[test]
fn rfc3339_from_secs_saturates_at_the_last_four_digit_year() {
    assert_eq!(rfc3339_from_secs(253_402_300_799), "9999-12-31T23:59:59Z");
    assert_eq!(rfc3339_from_secs(253_402_300_800), "9999-12-31T23:59:59Z");
    assert_eq!(rfc3339_from_secs(u64::MAX), "9999-12-31T23:59:59Z");
    // Whole seconds only: no fraction is ever written, and the zone is always `Z`.
    assert_eq!(rfc3339_from_secs(1_700_000_000), "2023-11-14T22:13:20Z");
}
