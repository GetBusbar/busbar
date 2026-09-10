// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one fold, under test: what it carries, in what order, and what it refuses to lose.

use std::collections::BTreeMap;

use busbar_caps::step::MeterClassId;
use busbar_caps::QuantitySource;

use crate::tests::token;
use crate::{report_from_units, CanonicalClass};

use super::{INPUT, OUTPUT};

const CACHE_READ: &str = "cache_read";
const SECONDS: &str = "seconds";

/// The report a delivered unit hands over.
fn units(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
    entries
        .iter()
        .map(|(class, quantity)| ((*class).to_string(), *quantity))
        .collect()
}

/// The declared table a caller states, in the order lines are written in.
fn declared(classes: &[&'static str]) -> Vec<CanonicalClass> {
    classes
        .iter()
        .map(|class| CanonicalClass::counted(MeterClassId::new(class)))
        .collect()
}

/// **THE LINE SEQUENCE IS THE DECLARED TABLE'S, NOT THE MAP'S.** A report is a `BTreeMap`, so its
/// own order is alphabetical and would put `cache_read` before `input`. The declared order is what
/// a card's fan-out and the map-shaped summation share, and a fold that returned the map's order
/// would make the line sequence a property of a collation nobody chose.
#[test]
fn lines_come_out_in_the_declared_order_and_not_the_maps() {
    let folded = report_from_units(
        &token(),
        &units(&[(CACHE_READ, 5), (INPUT, 11), (OUTPUT, 7)]),
        &declared(&[INPUT, OUTPUT, CACHE_READ]),
    )
    .expect("three lines fit any record");
    let classes: Vec<&str> = folded
        .usage
        .lines()
        .iter()
        .map(|line| line.class.as_str())
        .collect();
    assert_eq!(classes, vec![INPUT, OUTPUT, CACHE_READ]);
    assert!(folded.undeclared.is_empty(), "every class was declared");
}

/// A zero-quantity line is not a fact about anything. Both books on either side of the fold skip
/// zeros, and a line carrying nothing would be the one place they disagreed about whether a class
/// was reported at all.
#[test]
fn a_zero_quantity_is_not_a_line_and_is_not_undeclared_either() {
    let folded = report_from_units(
        &token(),
        &units(&[(INPUT, 11), (OUTPUT, 0), (SECONDS, 0)]),
        &declared(&[INPUT, OUTPUT]),
    )
    .expect("one line fits any record");
    assert_eq!(folded.usage.lines().len(), 1, "only the reported class");
    assert_eq!(folded.usage.lines()[0].quantity, 11);
    assert!(
        folded.undeclared.is_empty(),
        "a class reported at zero was not consumed, so nothing went unheld"
    );
}

/// **THE PROPERTY THE DUAL-BOOK COLLAPSE RESTS ON: NOTHING IS LOST QUIETLY.** The previous
/// release's budget cell accrues every class the report carries. This record cannot hold an
/// undeclared class — a line is keyed by a `MeterClassId`, which is a `&'static str`, and there is
/// no expression that mints one from a name read out of a map. So the fold hands it back, and the
/// two halves together are exactly what the report carried.
#[test]
fn an_undeclared_class_comes_back_by_name_rather_than_vanishing() {
    let reported = units(&[(INPUT, 11), (OUTPUT, 7), (SECONDS, 42)]);
    let folded = report_from_units(&token(), &reported, &declared(&[INPUT, OUTPUT]))
        .expect("two lines fit any record");

    assert!(
        !folded.undeclared.is_empty(),
        "one class could not be carried"
    );
    assert_eq!(folded.undeclared, units(&[(SECONDS, 42)]));

    // The identity: lines plus undeclared equals the report, class for class and figure for figure.
    let mut held: BTreeMap<String, u64> = folded
        .usage
        .lines()
        .iter()
        .map(|line| (line.class.as_str().to_string(), line.quantity))
        .collect();
    held.extend(folded.undeclared.iter().map(|(c, q)| (c.clone(), *q)));
    assert_eq!(held, reported, "the fold lost nothing");
}

/// The evidence is stated per class and travels onto the line, because it is per class in fact: a
/// figure a destination reported at a locator and a figure the node counted for itself are argued
/// from differently in a dispute, and the ledger seals which one it was into its digest.
#[test]
fn each_line_carries_the_evidence_its_class_declared() {
    let locator = QuantitySource::Locator {
        direction: crate::Direction::Input,
        ptr: crate::LocatorPtr::new(INPUT),
    };
    let table = vec![
        // The fields are public and the evidence is stated by naming them: a class whose figure is
        // the node's own floor read at a locator is not the ordinary case and has no constructor of
        // its own, because a constructor with no caller is surface a unit is charged for and nobody
        // reads.
        CanonicalClass {
            class: MeterClassId::new(INPUT),
            source: locator.clone(),
            estimated: true,
        },
        CanonicalClass::counted(MeterClassId::new(OUTPUT)),
    ];
    let folded = report_from_units(&token(), &units(&[(INPUT, 11), (OUTPUT, 7)]), &table)
        .expect("two lines fit any record");
    let lines = folded.usage.lines();
    assert_eq!(lines[0].source, locator);
    assert!(
        lines[0].estimated,
        "the declared mark travels onto the line"
    );
    assert_eq!(lines[1].source, QuantitySource::Count);
    assert!(!lines[1].estimated);
}

/// A report with nothing in it is not an error: it is what a unit that reported nothing consumed,
/// and it still prices whatever a flat fee costs.
#[test]
fn an_empty_report_folds_to_an_empty_record() {
    let folded = report_from_units(&token(), &BTreeMap::new(), &declared(&[INPUT, OUTPUT]))
        .expect("no lines fit any record");
    assert!(folded.usage.lines().is_empty());
    assert!(folded.undeclared.is_empty());
}
