// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/civil.rs`.

use super::*;

#[test]
fn civil_from_days_maps_known_epochs() {
    // The epoch itself.
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    // A leap-year boundary: 2020 is a leap year, so day 29 of February exists. 2020-02-29 is
    // 18_321 days after the epoch, and the day after it is 2020-03-01.
    assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    assert_eq!(civil_from_days(18_322), (2020, 3, 1));
    // A century that is NOT a leap year (divisible by 100 but not 400): 2100-02-28 is followed by
    // 2100-03-01, with no February 29th. 2100-02-28 is 47_540 days after the epoch.
    assert_eq!(civil_from_days(47_540), (2100, 2, 28));
    assert_eq!(civil_from_days(47_541), (2100, 3, 1));
}

#[test]
fn rfc3339_from_secs_renders_a_bare_second_instant() {
    assert_eq!(rfc3339_from_secs(0), "1970-01-01T00:00:00Z");
    // 2020-02-29T23:59:59Z is the last second of the leap day: 18_321 days + 86_399 seconds.
    assert_eq!(
        rfc3339_from_secs(18_321 * 86_400 + 86_399),
        "2020-02-29T23:59:59Z"
    );
}
