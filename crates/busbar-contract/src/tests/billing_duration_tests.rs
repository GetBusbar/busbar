// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BILLABLE DURATION IS AN EXACT DECIMAL (#81). Its wire rendering, and the sweep that proves
//! it byte-identical, are the llm plane's own.

use super::{Billing, Count};

/// THE MONEY DAMAGE A DOUBLE DOES, shown rather than described.
///
/// Nothing prices a duration today, so nothing has been mis-billed. This is what would happen the
/// moment something does — and it is the same argument that took the token counts off `f64`.
#[test]
fn a_double_cannot_hold_a_billable_duration_and_an_exact_decimal_can() {
    // `12.1` seconds is not representable in binary floating point. The exact decimal is.
    let exact = Count::parse("12.1").expect("12.1 is an exact decimal");
    assert_eq!(exact.micros(), 12_100_000);
    assert_eq!(exact.to_decimal_string(), "12.1");

    // THE ACCUMULATION. Ten thousand calls of a tenth of a second is a thousand seconds — exactly,
    // in every order. The `f64` fold below is what the old carrier would have produced.
    let tenth = Count::parse("0.1").expect("0.1 is an exact decimal");
    let mut total = Count::ZERO;
    for _ in 0..10_000 {
        total = total.checked_add(tenth).expect("in range");
    }
    assert_eq!(total, Count::parse("1000").expect("exact"));
    assert_eq!(total.to_decimal_string(), "1000");

    // THE SAME FOLD IN A DOUBLE, for the record. This is not an assertion about our code — the
    // carrier no longer has an `f64` to fold — it is the number the old one drifted to.
    let drifted = {
        let mut f = 0.0_f64;
        for _ in 0..10_000 {
            f += 0.1_f64;
        }
        f
    };
    assert_ne!(
        drifted, 1000.0_f64,
        "the whole point: a double does not sum tenths to a thousand"
    );
    assert_eq!(format!("{drifted}"), "1000.0000000001588");

    // THE MULTIPLY, and the lesson it teaches. `1942.955374 s x 4.695712 /s` is exactly
    // `9123.558865156288` — TWELVE decimal places, because the product of two scale-6 numbers is a
    // scale-12 number. Asking for it back at scale 6 is therefore a REFUSAL and not a rounded
    // guess, which is the ruling working as intended...
    let rate = Count::parse("4.695712").expect("exact");
    let duration = Count::parse("1942.955374").expect("exact");
    assert_eq!(
        duration.checked_mul(rate),
        Err(crate::CountError::Inexact),
        "a product needing a seventh place must refuse, never round"
    );
    // ...and `checked_mul_wide` is the form a pricing fold accumulates in: the EXACT scale-12
    // product, so whatever rounding a later division owes (#44) is applied ONCE to the total rather
    // than silently, per row, here.
    assert_eq!(
        duration.checked_mul_wide(rate),
        Ok(9_123_558_865_156_288_i128)
    );

    // The same product in a double is NOT the same number — it only looks like it until you ask
    // for enough digits. Rounded to twelve places it agrees; expanded fully it does not, and it is
    // the full value that a sum of such products accumulates.
    let f = 1942.955374_f64 * 4.695712_f64;
    let expansion = format!("{f:.20}");
    assert_ne!(
        expansion, "9123.55886515628800000000",
        "the double is not the exact product"
    );
    assert!(
        expansion.starts_with("9123.558865156288"),
        "and it is close enough to pass any eyeball test: {expansion}"
    );
}

/// THE CARRIER HOLDS THE EXACT QUANTITY, and two equal durations are equal.
#[test]
fn two_equal_durations_are_equal_which_a_double_could_not_guarantee() {
    let a = Billing::Duration {
        seconds: Count::parse("12.1").expect("exact"),
    };
    let b = Billing::Duration {
        seconds: Count::parse("12.100000").expect("exact"),
    };
    assert_eq!(a, b, "the same quantity spelled two ways is one quantity");
}
