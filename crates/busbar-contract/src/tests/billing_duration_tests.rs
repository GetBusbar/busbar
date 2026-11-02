// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BILLABLE DURATION IS AN EXACT DECIMAL, AND ITS WIRE RENDERING IS BYTE-IDENTICAL (#81).

use super::{duration_seconds_to_wire, Billing, Count};

/// A 64-bit xorshift, so the sweep draws from integers and the proof of exactness does not itself

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

        assert_eq!(
            serde_json::to_string(&serde_json::json!({ "seconds": rendered }))
                .expect("a finite number serializes"),
            serde_json::to_string(&serde_json::json!({ "seconds": parsed }))
                .expect("a finite number serializes"),
        );
    };

    for micros in 0..10_000i128 {
        check(micros);
        checked += 1;
    }

    let mut rng = Xorshift(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..100_000 {
        check(i128::from(rng.step() % 3_600_000_000));
        checked += 1;
    }

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

#[test]
fn a_double_cannot_hold_a_billable_duration_and_an_exact_decimal_can() {
    let exact = Count::parse("12.1").expect("12.1 is an exact decimal");
    assert_eq!(exact.micros(), 12_100_000);
    assert_eq!(exact.to_decimal_string(), "12.1");

    let tenth = Count::parse("0.1").expect("0.1 is an exact decimal");
    let mut total = Count::ZERO;
    for _ in 0..10_000 {
        total = total.checked_add(tenth).expect("in range");
    }
    assert_eq!(total, Count::parse("1000").expect("exact"));
    assert_eq!(total.to_decimal_string(), "1000");

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

    let rate = Count::parse("4.695712").expect("exact");
    let duration = Count::parse("1942.955374").expect("exact");
    assert_eq!(
        duration.checked_mul(rate),
        Err(crate::CountError::Inexact),
        "a product needing a seventh place must refuse, never round"
    );

    assert_eq!(
        duration.checked_mul_wide(rate),
        Ok(9_123_558_865_156_288_i128)
    );

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
