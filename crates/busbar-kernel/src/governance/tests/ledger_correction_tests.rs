// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn overflow_keeps_the_entire_raw_candidate_unapplied() {
    let mut row = UsageLedger::default();
    move_unit(&mut row, "model", "input", i128::MAX).unwrap();
    let before = row.clone();
    let mut delta = ExactUsageDelta {
        requests: 1,
        billable_requests: 1,
        ..Default::default()
    };
    delta.unit("model", "input", 1);
    assert!(apply_delta(&mut row, &delta).is_err());
    assert_eq!(row, before);
}

#[test]
fn refund_floor_keeps_the_entire_raw_candidate_unapplied() {
    let mut row = UsageLedger {
        requests: 1,
        ..Default::default()
    };
    let before = row.clone();
    let mut delta = ExactUsageDelta {
        requests: -1,
        ..Default::default()
    };
    delta.unit("model", "input", -1);
    assert!(apply_delta(&mut row, &delta).is_err());
    assert_eq!(row, before);
}
