// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The book of balances, and the one seam that lets an owner retire what a checkpoint already sealed.

use crate::totals::Book;

use super::fixtures::{key, pool_key};

fn filled() -> Book {
    let mut book = Book::new();
    for window in [10u64, 20, 30, 40] {
        book.entry(key("b"), window).settled = window as i128;
        book.entry(pool_key("b", "west"), window).settled = window as i128 * 2;
    }
    book
}

/// A book that only ever grows has no upper bound an integrator can reach for, whatever their
/// retention policy says. The checkpoint is the retirement boundary, so retiring below one is the
/// one thing the book has to offer.
#[test]
fn retiring_below_a_watermark_drops_exactly_the_windows_beneath_it() {
    let mut book = filled();
    assert_eq!(book.len(), 8);

    let dropped = book.retain_from(30);

    assert_eq!(dropped, 4, "two keys in each of the two retired windows");
    assert_eq!(book.len(), 4);
    assert_eq!(
        book.get(&key("b"), 10).settled,
        0,
        "a retired window reads as zeros, the same as a window never touched"
    );
    assert_eq!(book.get(&key("b"), 20).settled, 0);
    assert_eq!(
        book.get(&key("b"), 30).settled,
        30,
        "the watermark survives"
    );
    assert_eq!(book.get(&pool_key("b", "west"), 40).settled, 80);
}

/// Retiring must not disturb the order the survivors iterate in: that order IS the checkpoint body,
/// and a body that hashed differently after a retirement would be a signature nobody else verifies.
#[test]
fn the_survivors_keep_the_order_a_checkpoint_is_signed_over() {
    let full = filled();
    let mut retired = filled();
    retired.retain_from(30);

    let expected: Vec<_> = full
        .iter()
        .filter(|((_, window), _)| *window >= 30)
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    let actual: Vec<_> = retired.iter().map(|(k, v)| (k.clone(), *v)).collect();
    assert_eq!(actual, expected);

    let snapshot_order: Vec<_> = retired.snapshot().into_iter().collect();
    assert_eq!(snapshot_order, expected);
}

/// Retiring from below everything is a no-op, and retiring from above everything empties the book.
#[test]
fn a_watermark_outside_the_book_is_all_or_nothing() {
    let mut none = filled();
    assert_eq!(none.retain_from(0), 0);
    assert_eq!(none.len(), 8);

    let mut all = filled();
    assert_eq!(all.retain_from(u64::MAX), 8);
    assert!(all.is_empty());
}
