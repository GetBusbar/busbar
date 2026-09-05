// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The metering series fold: raw consumption per cell, observability only, never enforcement.

use super::*;
use crate::MeterCounts;

/// The split is preserved and a response with NO usage at all — a flat-fee operation — still counts
/// its request. Two responses into one cell coalesce into one set of totals carrying the REAL
/// count: a fold that invented a single increment per write would lose the second request.
#[test]
fn responses_accumulate_their_split_and_a_flat_fee_response_still_counts_its_request() {
    let mut cell = MeterCounts::default();
    let reported = usage(&[(INPUT, 11), (OUTPUT, 22), ("cache_read", 5)]);
    cell.accrue_response(Some(&reported));
    cell.accrue_response(None); // a flat-fee operation

    assert_eq!(cell.requests, 2, "the count survives coalescing");
    assert_eq!(cell.quantity(INPUT), 11);
    assert_eq!(cell.quantity(OUTPUT), 22);
    assert_eq!(cell.quantity("cache_read"), 5);
    assert_eq!(
        cell.quantity("cache_write"),
        0,
        "a class nothing reported stays at nothing"
    );
}

/// Two responses against the same cell accumulate rather than replace, and the cache classes carry
/// separately from the others because they price differently.
#[test]
fn two_responses_on_one_cell_accumulate() {
    let mut cell = MeterCounts::default();
    cell.accrue_response(Some(&usage(&[(INPUT, 100), (OUTPUT, 20)])));
    cell.accrue_response(Some(&usage(&[(INPUT, 50), (OUTPUT, 10)])));
    assert_eq!(
        (cell.quantity(INPUT), cell.quantity(OUTPUT), cell.requests),
        (150, 30, 2)
    );
}

/// A merge is a saturating ADD, never an overwrite. That is what makes a failed write safe to
/// retry: the counts go back into whatever accumulated meanwhile, and the next attempt carries the
/// full amount exactly once.
#[test]
fn a_merge_adds_and_never_overwrites() {
    let mut retried = MeterCounts::default();
    retried.accrue_response(Some(&usage(&[(INPUT, 7)])));

    let mut meanwhile = MeterCounts::default();
    meanwhile.accrue_response(Some(&usage(&[(INPUT, 3)])));

    meanwhile.merge(&retried);
    assert_eq!(meanwhile.requests, 2);
    assert_eq!(meanwhile.quantity(INPUT), 10);
}

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

/// The accumulation saturates rather than wrapping, so an adversarial series pins high instead of
/// landing back near nothing.
#[test]
fn the_accumulation_saturates() {
    let mut cell = MeterCounts {
        requests: u64::MAX,
        quantities: [(INPUT.to_string(), u64::MAX)].into_iter().collect(),
    };
    cell.accrue_response(Some(&usage(&[(INPUT, 5)])));
    assert_eq!(cell.requests, u64::MAX);
    assert_eq!(cell.quantity(INPUT), u64::MAX);
}
