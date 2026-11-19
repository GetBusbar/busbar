// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.4: cumulative USAGE per (class, source), the cancel table and the ledger mapping.

use super::*;

fn rec(amount: u64, scale: u32, source: u32) -> UsageRec {
    UsageRec {
        amount,
        scale,
        source,
    }
}

fn cancel(far_end_answered: bool, streamed: bool) -> Ending {
    Ending::Cancel {
        cause: ReasonCode::ClientGone,
        far_end_answered,
        streamed,
    }
}

fn amounts(bill: &Bill<'_>) -> Vec<(String, u64)> {
    match bill {
        Bill::Usage(kept) => kept
            .iter()
            .map(|r| (r.class.to_string(), r.amount))
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn one_class_keeps_one_value_per_source() {
    let mut usage = SessionUsage::new();
    usage.answer("tokens", rec(7, 0, SRC_ESTIMATED)).unwrap();
    usage.answer("tokens", rec(5, 0, SRC_REPORTED)).unwrap();
    usage.answer("tokens", rec(9, 0, SRC_ESTIMATED)).unwrap();
    let kept: Vec<_> = usage.last().iter().map(|r| (r.source, r.amount)).collect();
    assert_eq!(kept, vec![(SRC_ESTIMATED, 9), (SRC_REPORTED, 5)]);
}

#[test]
fn the_cancel_table() {
    let mut usage = SessionUsage::new();
    usage.answer("tokens", rec(40, 0, SRC_REPORTED)).unwrap();
    usage.answer("floor", rec(3, 0, SRC_FLOOR)).unwrap();
    usage.answer("guess", rec(99, 0, SRC_ESTIMATED)).unwrap();

    // Client gone after streaming: the billing sources only (rule 2).
    assert_eq!(
        amounts(&bill(cancel(true, true), &usage)),
        vec![("tokens".into(), 40), ("floor".into(), 3)]
    );
    // Before any upstream head: nothing and no estimate (rule 1).
    assert_eq!(bill(cancel(false, false), &usage), Bill::Nothing);
    assert_eq!(bill(cancel(false, true), &usage), Bill::Nothing);
    // After the head, before a byte reached the client: 0 (rule 3).
    assert_eq!(bill(cancel(true, false), &usage), Bill::Nothing);
    // A plane FAULT, quarantine or failed end posts nothing.
    assert_eq!(bill(Ending::Failed, &usage), Bill::Nothing);
    // A normal end posts every kept value, the estimated one included.
    assert_eq!(amounts(&bill(Ending::End, &usage)).len(), 3);
}

#[test]
fn only_an_end_with_no_usage_is_estimated() {
    let usage = SessionUsage::new();
    assert_eq!(bill(Ending::End, &usage), Bill::Estimate);
    assert_eq!(bill(cancel(true, true), &usage), Bill::Nothing);
    assert_eq!(bill(Ending::Failed, &usage), Bill::Nothing);
}

#[test]
fn a_cancel_bills_only_streamed_billing_sources() {
    assert!(cancel_bills_reported_units(true));
    assert!(!cancel_bills_reported_units(false));
    assert!(source_bills(SRC_REPORTED) && source_bills(SRC_FLOOR));
    assert!(!source_bills(SRC_ESTIMATED) && !source_bills(0));
}

#[test]
fn a_bad_usage_is_refused_and_not_kept() {
    let mut usage = SessionUsage::new();
    assert_eq!(
        usage.answer("", rec(1, 0, SRC_REPORTED)),
        Err(UsageInvalid::Class)
    );
    assert_eq!(
        usage.answer("Tokens", rec(1, 0, SRC_REPORTED)),
        Err(UsageInvalid::Class)
    );
    assert_eq!(
        usage.answer(&"a".repeat(MAX_CLASS + 1), rec(1, 0, SRC_REPORTED)),
        Err(UsageInvalid::Class)
    );
    assert_eq!(
        usage.answer("tokens", rec(1, MAX_SCALE + 1, SRC_REPORTED)),
        Err(UsageInvalid::Scale)
    );
    assert_eq!(
        usage.answer("tokens", rec(1, 0, 4)),
        Err(UsageInvalid::Source)
    );
    assert!(usage.is_empty());
    usage
        .answer("cache_write_30m:a.b", rec(1, MAX_SCALE, SRC_REPORTED))
        .unwrap();
}

#[test]
fn scale_maps_to_micro_units_and_rounds_half_even() {
    assert_eq!(scaled(5, 0), Some((Count::from_micros(5_000_000), false)));
    assert_eq!(
        scaled(1_234_567, 6),
        Some((Count::from_micros(1_234_567), false))
    );
    assert_eq!(scaled(15, 7), Some((Count::from_micros(2), true)));
    assert_eq!(scaled(25, 7), Some((Count::from_micros(2), true)));
    assert_eq!(scaled(35, 7), Some((Count::from_micros(4), true)));
    assert_eq!(scaled(26, 7), Some((Count::from_micros(3), true)));
    assert_eq!(scaled(30, 7), Some((Count::from_micros(3), false)));
    assert_eq!(scaled(1_500, 9), Some((Count::from_micros(2), true)));
    assert_eq!(
        scaled(u64::MAX, 0),
        Some((Count::from_micros(i128::from(u64::MAX) * 1_000_000), false))
    );
    assert_eq!(scaled(1, 10), None);
}

const TOKENS: MeterClassId = MeterClassId::new("tokens");
const REQUEST: MeterClassId = MeterClassId::new("request");

fn declared() -> DeclaredClasses {
    DeclaredClasses::new(vec![
        DeclaredClass {
            class: TOKENS,
            unit: busbar_plugin_abi::plane::UNIT_TOKENS,
            expected_units: f64::NAN,
        },
        DeclaredClass {
            class: REQUEST,
            unit: busbar_plugin_abi::plane::UNIT_COUNT,
            expected_units: 1.0,
        },
    ])
}

#[test]
fn an_undeclared_class_is_dropped_and_named_for_the_audit() {
    let mut usage = SessionUsage::new();
    usage.answer("tokens", rec(40, 0, SRC_REPORTED)).unwrap();
    usage.answer("images", rec(2, 0, SRC_REPORTED)).unwrap();
    usage.answer("request", rec(1, 0, SRC_FLOOR)).unwrap();
    usage.answer("tokens", rec(15, 7, SRC_ESTIMATED)).unwrap();
    let Bill::Usage(kept) = bill(Ending::End, &usage) else {
        panic!("end bills the kept values");
    };
    let mapped = declared().map(kept);
    assert_eq!(mapped.dropped, vec![Box::<str>::from("images")]);
    assert_eq!(mapped.rounded, vec![Box::<str>::from("tokens")]);
    assert_eq!(
        mapped.lines,
        vec![
            UsageLine {
                class: TOKENS,
                quantity: Count::from_micros(40_000_000),
                source: QuantitySource::Count,
                estimated: false,
            },
            UsageLine {
                class: REQUEST,
                quantity: Count::from_micros(1_000_000),
                source: QuantitySource::Count,
                estimated: true,
            },
            UsageLine {
                class: TOKENS,
                quantity: Count::from_micros(2),
                source: QuantitySource::Count,
                estimated: true,
            },
        ]
    );
}
