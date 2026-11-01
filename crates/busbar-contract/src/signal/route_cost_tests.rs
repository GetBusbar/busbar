// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn recipes_distinguish_legacy_empty_unknown_and_zero() {
    let mut bag = SignalBag::new();
    assert_eq!(decode(&bag), Ok(None));
    append(&mut bag, []);
    assert_eq!(decode(&bag), Ok(Some(Vec::new())));
    let terms = [
        Term {
            class: "seconds",
            nanos_per_unit: None,
            expected_units: 0.0,
        },
        Term {
            class: "seconds",
            nanos_per_unit: Some(0),
            expected_units: 3.5,
        },
    ];
    let mut bag = SignalBag::new();
    append(&mut bag, terms);
    assert_eq!(decode(&bag), Ok(Some(terms.to_vec())));
}

#[test]
fn malformed_or_truncated_terms_never_become_legacy() {
    let s = Signal::CandidateRouteCost;
    for values in [
        vec![SignalValue::Bool(false)],
        vec![SignalValue::Bool(true), SignalValue::Str("seconds".into())],
        vec![SignalValue::Bool(true), SignalValue::Bool(true)],
    ] {
        let mut bag = SignalBag::new();
        for value in values {
            bag.push(s, value);
        }
        assert!(decode(&bag).is_err());
    }
    for weight in [-1.0, f64::NAN, f64::INFINITY] {
        let mut bag = SignalBag::new();
        append(
            &mut bag,
            [Term {
                class: "seconds",
                nanos_per_unit: Some(1),
                expected_units: weight,
            }],
        );
        assert!(decode(&bag).is_err());
    }
}
