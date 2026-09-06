// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money fold, at the top of its range.
//!
//! The derivation above this one already saturates: the cross-model sum uses `saturating_add`, and
//! the cent projection saturates rather than casting. This file pins the arithmetic INSIDE one
//! model's fold, which is the last place a plain operator could still wrap or panic before the
//! saturating layers ever see the number.

use std::collections::BTreeMap;

use crate::price::{
    RateNanos, RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

/// A unit map holding the largest count each of the four reserved keys can carry.
fn maximal_units() -> BTreeMap<String, u64> {
    RESERVED_UNITS
        .iter()
        .map(|u| ((*u).to_string(), u64::MAX))
        .collect()
}

/// The four reserved keys at the largest count and the largest rate the types allow.
///
/// Each of the four products is very nearly the whole width of the accumulator, so their sum is
/// past the top of it. A plain add panics on overflow in a debug build and wraps in a release one,
/// and a wrapped total lands back near zero — an over-the-top ledger deriving as nearly FREE and
/// escaping every budget cap. Saturating instead pins at the maximum, which is an astronomical
/// spend that blocks, and which the cent projection above then pins at the signed maximum.
#[test]
fn a_maximal_ledger_saturates_the_money_fold_rather_than_wrapping() {
    let rate = RateNanos {
        input: u64::MAX,
        output: u64::MAX,
        cache_read: u64::MAX,
        cache_write: u64::MAX,
    };
    assert_eq!(rate.reserved_nanos(&maximal_units()), u128::MAX);
}

/// One key at the maximum is representable exactly: a u64 count times a u64 rate fits the wide
/// accumulator with room to spare, so the saturation above is the SUM saturating, not a single
/// product being clipped. Without this, a fold that returned the maximum for everything large
/// would pass the case above while quietly destroying ordinary arithmetic.
#[test]
fn one_key_at_the_maximum_is_exact_and_does_not_saturate() {
    let rate = RateNanos {
        input: u64::MAX,
        ..RateNanos::default()
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), u64::MAX);
    let expected = u128::from(u64::MAX) * u128::from(u64::MAX);
    assert_eq!(rate.reserved_nanos(&units), expected);
    assert!(expected < u128::MAX);
}

/// Ordinary figures are untouched by the change: the fold is still an exact sum of four
/// multiply-adds everywhere below the top of the range.
#[test]
fn ordinary_counts_still_sum_exactly() {
    let rate = RateNanos {
        input: 3,
        output: 5,
        cache_read: 7,
        cache_write: 11,
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), 100);
    units.insert(UNIT_OUTPUT.to_string(), 200);
    units.insert(UNIT_CACHE_READ.to_string(), 300);
    units.insert(UNIT_CACHE_WRITE.to_string(), 400);
    assert_eq!(
        rate.reserved_nanos(&units),
        100 * 3 + 200 * 5 + 300 * 7 + 400 * 11
    );
}
