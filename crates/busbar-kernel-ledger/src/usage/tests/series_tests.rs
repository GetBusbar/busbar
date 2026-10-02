// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The metering series fold: raw consumption per cell, observability only, never enforcement.

use super::INPUT;
use crate::usage::MeterCounts;

/// A genuinely empty cell is empty and is skipped rather than written: an empty row is not a fact
/// about anything. A cell holding a request but no quantities is NOT empty — a flat-fee operation
/// is something that happened.
#[test]
fn a_genuinely_empty_cell_is_skipped_and_a_request_alone_is_not_empty() {
    let empty = MeterCounts::default();
    assert!(empty.is_empty());

    let zeroed = MeterCounts {
        requests: 0,
        quantities: [(INPUT.to_string(), 0u64)].into_iter().collect(),
    };
    assert!(zeroed.is_empty(), "all-zero quantities are still nothing");

    let mut flat_fee = MeterCounts::default();
    flat_fee.accrue_response(None);
    assert!(
        !flat_fee.is_empty(),
        "a request alone is a fact worth writing"
    );
}
