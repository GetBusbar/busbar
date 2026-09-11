// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE AMOUNT HALF, ARITHMETIC BY ARITHMETIC.**
//!
//! Every case here is about one decision the schedule makes — which way a fraction goes, what a
//! floor and a cap do to a total, and what the previous release's one figure means in this shape.

use super::{FeeSchedule, PerUnitFee, Rounding};

/// No quantity at all, for the cases that charge only counts.
fn nothing(_: &str) -> u64 {
    0
}

/// **BANKER'S ROUNDING SPLITS THE HALVES EVENLY, AND THAT IS THE WHOLE REASON IT IS THE DEFAULT.**
///
/// The cell is written as the sum over a run rather than as four isolated cases: what makes the
/// rule the teller's rule is not where any one half goes, it is that over many roundings the ups
/// and the downs cancel. Rounding up and rounding down are shown against the same run so the bias
/// each of them carries is a number in this file.
#[test]
fn the_halves_split_evenly_under_bankers_and_do_not_under_the_other_two() {
    // halves only: 0.5, 1.5, 2.5 … 9.5, written as tenths over a `per` of 2.
    let halves: Vec<i128> = (0..10).map(|n| i128::from(n) * 2 + 1).collect();
    let sum = |r: Rounding| -> i128 { halves.iter().map(|n| r.divide(*n, 2)).sum() };
    let exact: i128 = 50; // 0.5 + 1.5 + … + 9.5
    assert_eq!(sum(Rounding::Bankers), exact, "no bias in either direction");
    assert_eq!(sum(Rounding::Up), exact + 5, "the house takes five");
    assert_eq!(sum(Rounding::Down), exact - 5, "the customer takes five");
}

/// A remainder that is not a half goes to the nearer side under banker's, which is ordinary
/// rounding; only the exact half is decided by the parity rule.
#[test]
fn a_remainder_that_is_not_a_half_goes_to_the_nearer_side() {
    assert_eq!(Rounding::Bankers.divide(1, 3), 0, "a third rounds down");
    assert_eq!(Rounding::Bankers.divide(2, 3), 1, "two thirds rounds up");
    assert_eq!(
        Rounding::Bankers.divide(3, 3),
        1,
        "an exact quotient is exact"
    );
    assert_eq!(Rounding::Up.divide(1, 3), 1);
    assert_eq!(Rounding::Down.divide(2, 3), 0);
}

/// A `per` of zero is refused by configuration validation; if one reaches the pricing site anyway
/// the answer is nothing, because a settlement may not be taken down by a configuration mistake.
#[test]
fn a_charge_per_zero_units_is_nothing_rather_than_a_panic() {
    assert_eq!(Rounding::Bankers.divide(999, 0), 0);
}

/// **THE PREVIOUS RELEASE'S SCHEDULE IS ONE FIGURE ON BOTH COUNTS**, and it charges nothing per
/// unit, has no floor and has no cap.
#[test]
fn the_previous_releases_schedule_charges_its_one_figure_per_count() {
    let s = FeeSchedule::flat(250);
    assert_eq!(s.charge_minor(0, 1, &nothing).total_minor, 250);
    assert_eq!(s.charge_minor(1, 1, &nothing).total_minor, 500);
    assert_eq!(s.charge_minor(0, 0, &nothing).total_minor, 0);
    assert!(s.per_units.is_empty());
    assert_eq!((s.minimum_minor, s.maximum_minor), (0, None));
    // a negative figure would credit the caller for having been charged; it is clamped at the one
    // place a schedule is made from a single number.
    assert_eq!(FeeSchedule::flat(-5), FeeSchedule::flat(0));
}

/// **A TOTAL IS DECOMPOSABLE**, because a total nobody can take apart is a bill nobody can dispute.
#[test]
fn every_line_that_made_the_total_is_reported_beside_it() {
    let s = FeeSchedule {
        entry_minor: 2,
        transaction_minor: 5,
        per_units: vec![PerUnitFee {
            class: "tokens_in".into(),
            per: 1000,
            minor: 3,
        }],
        ..FeeSchedule::default()
    };
    let charged = s.charge_minor(1, 1, &|c| if c == "tokens_in" { 1500 } else { 0 });
    let lines: Vec<(&str, u64, i128)> = charged
        .lines
        .iter()
        .map(|(c, n, m)| (c.as_str(), *n, *m))
        .collect();
    // 1500 tokens at 3 per 1000 is 4.5, and banker's sends an exact half to the even neighbour.
    assert_eq!(
        lines,
        vec![("entry", 1, 2), ("fee", 1, 5), ("tokens_in", 1500, 4)]
    );
    assert_eq!(charged.total_minor, 11);
    assert_eq!(charged.bound_adjustment_minor, 0);
}

/// **A FLOOR AND A CAP MOVE THE TOTAL AND SAY BY HOW MUCH.** Never a silent adjustment.
#[test]
fn a_floor_and_a_cap_report_what_they_moved() {
    let floored = FeeSchedule {
        transaction_minor: 1,
        minimum_minor: 10,
        ..FeeSchedule::default()
    }
    .charge_minor(0, 1, &nothing);
    assert_eq!(floored.total_minor, 10);
    assert_eq!(floored.bound_adjustment_minor, 9);

    let capped = FeeSchedule {
        transaction_minor: 100,
        maximum_minor: Some(25),
        ..FeeSchedule::default()
    }
    .charge_minor(0, 1, &nothing);
    assert_eq!(capped.total_minor, 25);
    assert_eq!(capped.bound_adjustment_minor, -75);

    // A cap of nothing is a cap, and it is a different statement from no cap at all.
    let free = FeeSchedule {
        transaction_minor: 100,
        maximum_minor: Some(0),
        ..FeeSchedule::default()
    }
    .charge_minor(0, 1, &nothing);
    assert_eq!(free.total_minor, 0);
}
