// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The book of balances, and the rule that lets it retire what a checkpoint already sealed.

use std::collections::BTreeSet;

use crate::totals::{past_retention, Book, ALL_TIME_WINDOW, WINDOW_RETENTION_SECS};

use super::fixtures::{key, pool_key};

/// One day, in the seconds a window opens at.
const DAY: u64 = 86_400;

fn filled() -> Book {
    let mut book = Book::new();
    for window in [10u64, 20, 30, 40] {
        book.entry(key("b"), window).settled = window as i128;
        book.entry(pool_key("b", "west"), window).settled = window as i128 * 2;
    }
    book
}

fn windows(of: &[u64]) -> BTreeSet<u64> {
    of.iter().copied().collect()
}

/// Retiring names whole windows and takes exactly the balances in them.
#[test]
fn retiring_a_window_drops_exactly_its_balances() {
    let mut book = filled();
    assert_eq!(book.len(), 8);

    let dropped = book.retire(&windows(&[10, 20]));

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
        "a kept window survives"
    );
    assert_eq!(book.get(&pool_key("b", "west"), 40).settled, 80);
}

/// Retiring must not disturb the order the survivors iterate in: that order IS the checkpoint body,
/// and a body that hashed differently after a retirement would be a signature nobody else verifies.
#[test]
fn the_survivors_keep_the_order_a_checkpoint_is_signed_over() {
    let full = filled();
    let mut retired = filled();
    retired.retire(&windows(&[10, 20]));

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

/// The horizon is 1.5.5's: a rolling window is kept while `window + 31 days > now` and retired at
/// equality, and the all-time window is never past it however long the node runs.
#[test]
fn the_horizon_is_thirty_one_days_from_the_window_opening_and_the_all_time_window_never_ages() {
    assert_eq!(WINDOW_RETENTION_SECS, 31 * DAY);
    let window = 100 * DAY;
    assert!(!past_retention(window, window));
    assert!(!past_retention(window, window + WINDOW_RETENTION_SECS - 1));
    assert!(past_retention(window, window + WINDOW_RETENTION_SECS));
    assert!(
        !past_retention(ALL_TIME_WINDOW, u64::MAX),
        "the all-time window never ages, however long the node runs"
    );
    // Near the top of the range the sum saturates at `u64::MAX` and the window is evicted at the
    // cap, exactly as 1.5.5's `window_start.saturating_add(MAX_RETENTION_SECS) > n` keep-test did.
    assert!(past_retention(u64::MAX - 1, u64::MAX));
}

/// What may go is a window past the horizon that a checkpoint holds at the book's own figures, with
/// no hold open — and only whole windows.
#[test]
fn only_a_sealed_unchanged_settled_window_past_the_horizon_is_retirable() {
    let old = DAY;
    let moved = 2 * DAY;
    let held = 3 * DAY;
    let recent = 40 * DAY;
    let now = recent + DAY;

    let mut book = Book::new();
    for window in [ALL_TIME_WINDOW, old, moved, held, recent] {
        book.entry(key("b"), window).settled = 5;
        book.entry(pool_key("b", "west"), window).settled = 7;
    }
    book.entry(key("b"), held).open_holds = 1;
    let sealed = book.snapshot();
    // A figure that moved after the seal: the checkpoint no longer holds what the book would drop.
    book.entry(pool_key("b", "west"), moved).settled += 1;

    assert_eq!(
        book.retirable(&sealed, now),
        windows(&[old]),
        "the all-time window, a window that moved since the seal, a window with a hold open and a \
         window inside the horizon all stay"
    );
    assert!(
        book.retirable(&std::collections::BTreeMap::new(), now)
            .is_empty(),
        "nothing a checkpoint did not seal is retirable"
    );
}

// ── THE BOOKS SATURATE (#10 `BUSBAR-1.6.0.md:331`) ───────────────────────────────────────────────
// `Totals::headroom` and `Totals::overdraft_carried` subtracted bare `i128`s until this block was
// written. A plain `-` panics on overflow in a debug build and WRAPS in a release one, and the wrap
// is the dangerous half because it is silent. These two figures are what the budget gate reads, so
// a wrap here is not a wrong report — it is a request admitted.

/// **AN EXHAUSTED BUDGET MUST NOT READ AS HEADROOM.**
///
/// Measured before the fix, with overflow checks OFF: `budget = 0`, `settled = i128::MAX`,
/// `open_holds = i128::MAX` is a book with `-340282366920938463463374607431768211454` of headroom,
/// and the bare subtraction returned **`2`**. Two nano-units of room on a book that is drawn twice
/// past the largest figure the type holds — and the gate compares `headroom > 0`, so it admits.
///
/// Saturated, the same book answers `i128::MIN`: the true reading narrowed to what the type can
/// say, and it fails CLOSED, which is the only direction a money figure may be wrong in.
#[test]
fn an_exhausted_budget_never_reads_as_positive_headroom() {
    let drawn_past_the_ceiling = crate::totals::Totals {
        budget: 0,
        settled: i128::MAX,
        open_holds: i128::MAX,
        ..crate::totals::Totals::zero()
    };
    assert_eq!(drawn_past_the_ceiling.headroom(), i128::MIN);
    assert!(
        drawn_past_the_ceiling.headroom() < 0,
        "the bare subtraction returned 2 here, and 2 is a request admitted"
    );

    // Every column at the ceiling at once, which is the same question asked four ways.
    let all_maximal = crate::totals::Totals {
        budget: i128::MIN,
        settled: i128::MAX,
        open_holds: i128::MAX,
        overdraft_carried_in: i128::MAX,
        ..crate::totals::Totals::zero()
    };
    assert_eq!(all_maximal.headroom(), i128::MIN);

    // And the other direction pins at the top rather than wrapping negative: a budget that cannot
    // be spent down must not read as exhausted.
    let unspendable = crate::totals::Totals {
        budget: i128::MAX,
        settled: i128::MIN,
        ..crate::totals::Totals::zero()
    };
    assert_eq!(unspendable.headroom(), i128::MAX);
}

/// The largest overdraft there is must not report as the largest CREDIT there is.
///
/// Measured before the fix, overflow checks OFF: `out = i128::MAX`, `in = -1` returned
/// `-170141183460469231731687303715884105728` — `i128::MIN`. The sign flipped, so a node carrying
/// the maximum overdraft reported the maximum credit. Saturated, it pins at `i128::MAX`.
#[test]
fn a_maximal_overdraft_does_not_flip_sign() {
    let carrying_the_maximum = crate::totals::Totals {
        overdraft_carried_out: i128::MAX,
        overdraft_carried_in: -1,
        ..crate::totals::Totals::zero()
    };
    assert_eq!(carrying_the_maximum.overdraft_carried(), i128::MAX);
    assert!(carrying_the_maximum.overdraft_carried() > 0);

    let handed_the_maximum = crate::totals::Totals {
        overdraft_carried_out: -1,
        overdraft_carried_in: i128::MAX,
        ..crate::totals::Totals::zero()
    };
    assert_eq!(handed_the_maximum.overdraft_carried(), i128::MIN);
}

/// **BYTE-NEUTRALITY FOR ORDINARY FIGURES.** Saturation changes no answer the bare operators were
/// able to give, so every balance a deployment actually holds is unmoved.
///
/// The sweep is over figures a real book reaches — budgets, settlements, holds and carried
/// overdrafts up to a hundred billion nano-units, in both signs — and the reference is the bare
/// arithmetic the fix replaced, computed here in `i128` where it cannot overflow. Zero differences
/// is the whole claim.
#[test]
fn saturating_the_books_moves_no_ordinary_figure() {
    let scales = [0i128, 1, 7, 999, 1_000_000, 10_000_000_000, 100_000_000_000];
    let mut checked = 0u32;
    for &budget in &scales {
        for &settled in &scales {
            for &open_holds in &scales {
                for &carried_in in &scales {
                    for sign in [1i128, -1] {
                        let t = crate::totals::Totals {
                            budget,
                            settled: settled * sign,
                            open_holds,
                            overdraft_carried_in: carried_in * sign,
                            overdraft_carried_out: budget * sign,
                            ..crate::totals::Totals::zero()
                        };
                        assert_eq!(
                            t.headroom(),
                            t.budget - t.settled - t.open_holds - t.overdraft_carried_in,
                            "headroom moved at {t:?}"
                        );
                        assert_eq!(
                            t.overdraft_carried(),
                            t.overdraft_carried_out - t.overdraft_carried_in,
                            "overdraft_carried moved at {t:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 4_802, "the sweep must actually have run");
}
