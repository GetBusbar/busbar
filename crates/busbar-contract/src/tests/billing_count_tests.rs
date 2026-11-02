// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The billed-count read. The cases are plane-llm's (`codec/tests/usage_count_tests.rs`), moved

use super::read_count_u64;
use serde_json::json;

#[test]
fn a_float_spelled_integer_is_the_integer() {
    assert_eq!(read_count_u64(&json!(27.0)), Some(27));
    assert_eq!(
        json!(27.0).as_u64(),
        None,
        "the bare read this module replaces"
    );
}

#[test]
fn a_plain_integer_still_reads_directly() {
    assert_eq!(read_count_u64(&json!(27)), Some(27));
    assert_eq!(read_count_u64(&json!(0)), Some(0));
}

#[test]
fn a_fractional_count_is_refused_not_rounded() {
    assert_eq!(read_count_u64(&json!(27.5)), None);
    assert_eq!(read_count_u64(&json!(0.5)), None);
}

#[test]
fn negatives_and_non_numbers_are_refused() {
    assert_eq!(read_count_u64(&json!(-1)), None);
    assert_eq!(read_count_u64(&json!(-1.0)), None);
    assert_eq!(read_count_u64(&json!("27")), None);
    assert_eq!(read_count_u64(&json!(null)), None);
    assert_eq!(read_count_u64(&json!({})), None);
}

#[test]
fn beyond_2_53_is_refused_because_the_fractional_test_goes_blind() {
    assert_eq!(read_count_u64(&json!(9_007_199_254_740_992.0_f64)), None);
    assert_eq!(read_count_u64(&json!(1.0e30_f64)), None);

    assert_eq!(
        read_count_u64(&json!(9_007_199_254_740_993_u64)),
        Some(9_007_199_254_740_993)
    );
}

#[test]
fn infinities_and_nan_are_refused() {
    let inf = serde_json::Number::from_f64(f64::INFINITY);
    assert!(
        inf.is_none(),
        "serde_json refuses non-finite numbers at construction"
    );
    assert_eq!(read_count_u64(&json!(f64::MAX)), None);
}
