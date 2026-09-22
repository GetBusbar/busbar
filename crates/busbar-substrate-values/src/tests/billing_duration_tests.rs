// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BILLABLE DURATION IS AN EXACT DECIMAL, AND ITS WIRE RENDERING IS BYTE-IDENTICAL (#81).
//!
//! Two claims, both proven by sweeping rather than by a handful of pretty numbers — a quantity that
//! round-trips for the values someone thought to write down is not a quantity that round-trips.

use super::{duration_seconds_to_wire, Billing, Count};

/// A 64-bit xorshift, so the sweep draws from integers and the proof of exactness does not itself
/// rest on a double.
struct Xorshift(u64);

impl Xorshift {
    fn step(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// The exact decimal spelling of a micro-second count, built by integer arithmetic.
fn decimal_text(micros: i128) -> String {
    Count::from_micros(micros).to_decimal_string()
}

/// THE BYTE-IDENTITY CLAIM, SWEPT.
///
/// `duration_seconds_to_wire` must produce THE SAME DOUBLE as parsing the original decimal text,
/// bit for bit — otherwise a response busbar echoes would carry different bytes than it carried
/// before the quantity became exact, and that is an oracle divergence dressed up as a refactor.
#[test]
fn the_wire_rendering_is_the_same_double_the_text_used_to_parse_to() {
    let mut checked = 0usize;
    let check = |micros: i128| {
        let text = decimal_text(micros);
        let rendered = duration_seconds_to_wire(Count::from_micros(micros));
        let parsed: f64 = text
            .parse()
            .expect("a decimal this crate wrote is parseable");
        assert_eq!(
            rendered.to_bits(),
            parsed.to_bits(),
            "`{text}` renders to a different double than it parses to"
        );
        // And the JSON both sides would emit is the same bytes, which is the claim that matters.
        assert_eq!(
            serde_json::to_string(&serde_json::json!({ "seconds": rendered }))
                .expect("a finite number serializes"),
            serde_json::to_string(&serde_json::json!({ "seconds": parsed }))
                .expect("a finite number serializes"),
        );
    };

    // Every micro-second in the first hundredth of a second: the fine structure.
    for micros in 0..10_000i128 {
        check(micros);
        checked += 1;
    }
    // Realistic audio durations, out to a thousand hours, drawn from the integer generator.
    let mut rng = Xorshift(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..100_000 {
        check(i128::from(rng.step() % 3_600_000_000));
        checked += 1;
    }
    // The boundaries a renderer trips on: whole seconds, and one micro either side of them.
    for whole in 0..1_000i128 {
        for delta in -1..=1i128 {
            let micros = whole * 1_000_000 + delta;
            if micros >= 0 {
                check(micros);
                checked += 1;
            }
        }
    }
    assert!(checked > 100_000, "only {checked} values swept");
}

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
        Err(busbar_contract::CountError::Inexact),
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
