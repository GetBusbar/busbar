// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the proleptic-Gregorian civil-date split in `crates/busbar-contract/src/civil.rs`.

use super::*;

#[test]
fn civil_from_days_maps_known_epochs() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));

    assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    assert_eq!(civil_from_days(18_322), (2020, 3, 1));

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
