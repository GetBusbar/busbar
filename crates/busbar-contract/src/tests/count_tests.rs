// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the exact decimal quantity (DECISION #81).

use super::{
    read_count, stored_scale_default, Count, CountError, COUNT_SCALE, MAX,
    MAX_ACROSS_A_64_BIT_COLUMN, MIN, MIN_ACROSS_A_64_BIT_COLUMN, SCALE_MICRO_UNITS,
    SCALE_WHOLE_UNITS,
};

/// Parse text that is expected to be a count, or fail the test saying which text did not.
fn ok(text: &str) -> Count {
    match Count::parse(text) {
        Ok(c) => c,
        Err(e) => panic!("`{text}` should parse, got {e}"),
    }
}

/// The mantissa a piece of text parses to.
fn micros_of(text: &str) -> i128 {
    ok(text).micros()
}

#[test]
fn the_scale_is_six_and_one_unit_is_a_million_mantissa_steps() {
    assert_eq!(COUNT_SCALE, 6);
    assert_eq!(Count::ONE.micros(), 1_000_000);
    assert_eq!(Count::EPSILON.micros(), 1);
    assert_eq!(Count::ZERO.micros(), 0);
}

/// THE IN-MEMORY RANGE CLAIM, CHECKED RATHER THAN QUOTED.
#[test]
fn the_in_memory_range_is_the_one_the_ruling_claims() {
    assert_eq!(MAX.micros(), i128::MAX);
    assert_eq!(MIN.micros(), i128::MIN);
    assert_eq!(
        MAX.to_decimal_string(),
        "170141183460469231731687303715884.105727"
    );
    assert_eq!(
        MIN.to_decimal_string(),
        "-170141183460469231731687303715884.105728"
    );

    let whole = MAX.to_decimal_string();
    let whole = whole.split('.').next().expect("a whole part");
    assert_eq!(whole.len(), 33, "1.7e32 has 33 digits before the point");
    assert!(whole.starts_with("170141"));

    assert_eq!(MAX.checked_add(Count::EPSILON), Err(CountError::Overflow));
    assert_eq!(MIN.checked_sub(Count::EPSILON), Err(CountError::Overflow));

    assert_eq!(ok(&MAX.to_decimal_string()), MAX);
    assert_eq!(ok(&MIN.to_decimal_string()), MIN);
    assert_eq!(
        ok("-170141183460469231731687303715884.105728").micros(),
        i128::MIN
    );

    assert_eq!(
        Count::parse("170141183460469231731687303715884.105728"),
        Err(CountError::OutOfRange)
    );
}

/// THE RULING, ONE ASSERTION AT A TIME. `27` is 27, `27.0` is 27, `27.5` is 27.5, `0.001` is 0.001.
#[test]
fn the_owners_worked_values_read_exactly() {
    assert_eq!(micros_of("27"), 27_000_000);
    assert_eq!(micros_of("27.0"), 27_000_000);
    assert_eq!(micros_of("27.5"), 27_500_000);
    assert_eq!(micros_of("0.001"), 1_000);
    assert_eq!(micros_of("0"), 0);
    assert_eq!(micros_of("0.0"), 0);
}

/// THE ONE VALUE A DOUBLE CANNOT HOLD. `27.1` is `27.100000000000001421…` as binary floating point,
#[test]
fn the_value_binary_floating_point_cannot_hold_reads_exactly() {
    assert_eq!(micros_of("27.1"), 27_100_000);
    assert_eq!(ok("27.1").to_decimal_string(), "27.1");

    assert_eq!(micros_of("27.099999"), 27_099_999);
    assert_eq!(micros_of("27.100001"), 27_100_001);
}

#[test]
fn a_fraction_finer_than_the_scale_is_refused_not_rounded() {
    assert_eq!(Count::parse("0.0000001"), Err(CountError::TooFine));
    assert_eq!(Count::parse("27.1234567"), Err(CountError::TooFine));
    assert_eq!(Count::parse("1e-7"), Err(CountError::TooFine));

    assert_eq!(micros_of("0.0000010"), 1);
    assert_eq!(micros_of("27.1000000000"), 27_100_000);
}

#[test]
fn a_negative_is_a_quantity_but_not_a_measurement() {
    assert_eq!(micros_of("-1"), -1_000_000);
    assert_eq!(micros_of("-27.5"), -27_500_000);
    assert_eq!(ok("-27.5").to_decimal_string(), "-27.5");

    assert_eq!(read_count("-1"), Err(CountError::Negative));
    assert_eq!(read_count("-0.000001"), Err(CountError::Negative));

    assert_eq!(read_count("-0"), Ok(Count::ZERO));
}

#[test]
fn a_magnitude_past_the_scale_is_refused() {
    assert_eq!(
        Count::parse("170141183460469231731687303715884.105728"),
        Err(CountError::OutOfRange)
    );

    assert_eq!(
        micros_of("170141183460469231731687303715884.105727"),
        i128::MAX
    );

    assert_eq!(
        Count::parse("170141183460469231731687303715885"),
        Err(CountError::OutOfRange)
    );
}

#[test]
fn an_exponent_is_honoured_exactly_and_a_huge_one_is_refused() {
    assert_eq!(micros_of("2.75e1"), 27_500_000);
    assert_eq!(micros_of("2.75E1"), 27_500_000);
    assert_eq!(micros_of("275e-1"), 27_500_000);
    assert_eq!(micros_of("2.75e+1"), 27_500_000);
    assert_eq!(micros_of("1e6"), 1_000_000_000_000);

    assert_eq!(Count::parse("1e400"), Err(CountError::OutOfRange));
    assert_eq!(Count::parse("-1e400"), Err(CountError::OutOfRange));

    assert_eq!(
        Count::parse("1e999999999999999999999999"),
        Err(CountError::OutOfRange)
    );
    assert_eq!(
        Count::parse("1e-999999999999999999999999"),
        Err(CountError::TooFine)
    );

    assert_eq!(Count::parse("0e999999999999999999999999"), Ok(Count::ZERO));
    assert_eq!(Count::parse("0.000e-400"), Ok(Count::ZERO));
}

#[test]
fn text_that_is_not_a_number_is_refused() {
    for bad in [
        "NaN",
        "nan",
        "-NaN",
        "Infinity",
        "-Infinity",
        "inf",
        "-inf",
        "1e",
        "1e+",
        "e5",
        ".5",
        "1.",
        "-",
        "+1",
        "007",
        "-007",
        "00.1",
        "0x1f",
        "1_000",
        "27.5.5",
        "27,5",
        " 27",
        "27 ",
        "27abc",
        "null",
        "\"27\"",
    ] {
        assert_eq!(
            Count::parse(bad),
            Err(CountError::Malformed),
            "`{bad}` is not a decimal number"
        );
    }
    assert_eq!(Count::parse(""), Err(CountError::Empty));
}

/// A JSON NUMBER WITH A HUGE EXPONENT, THE WAY A HOSTILE BODY SPELLS ONE. Refused as a magnitude,
#[test]
fn a_hostile_exponent_is_a_refusal_and_not_a_hang() {
    let mut text = String::from("9.9e");
    for _ in 0..4096 {
        text.push('9');
    }
    assert_eq!(Count::parse(&text), Err(CountError::OutOfRange));
    let mut text = String::from("9.9e-");
    for _ in 0..4096 {
        text.push('9');
    }
    assert_eq!(Count::parse(&text), Err(CountError::TooFine));
}

#[test]
fn a_long_run_of_zeros_does_not_change_the_quantity() {
    assert_eq!(micros_of("27.500000"), 27_500_000);
    assert_eq!(
        micros_of("0.000000000000000000000000000000000000000000000000000"),
        0
    );
    let mut text = String::from("27.5");
    for _ in 0..1000 {
        text.push('0');
    }
    assert_eq!(micros_of(&text), 27_500_000);
}

#[test]
fn a_quantity_renders_as_the_decimal_it_is_and_reads_back_the_same() {
    for (text, rendered) in [
        ("27", "27"),
        ("27.0", "27"),
        ("27.5", "27.5"),
        ("27.1", "27.1"),
        ("0.001", "0.001"),
        ("0", "0"),
        ("-27.5", "-27.5"),
        ("2.75e1", "27.5"),
        ("0.000001", "0.000001"),
        ("1000000", "1000000"),
    ] {
        let c = ok(text);
        assert_eq!(c.to_decimal_string(), rendered, "rendering `{text}`");
        assert_eq!(format!("{c}"), rendered, "Display of `{text}`");
        assert_eq!(
            ok(&c.to_decimal_string()),
            c,
            "`{text}` does not survive a round trip"
        );
    }
}

#[test]
fn every_mantissa_in_a_swept_band_round_trips_through_its_spelling() {
    for base in [
        -2_000_050i128,
        -1_000_000,
        -50,
        0,
        50,
        999_950,
        1_000_000,
        27_499_950,
    ] {
        for step in 0..100i128 {
            let c = Count::from_micros(base + step);
            let text = c.to_decimal_string();
            assert_eq!(ok(&text), c, "`{text}` did not round trip");
        }
    }
}

/// THE BANK-AUDITOR PROOF: NO QUANTITY LOSES A DIGIT GOING OUT AND COMING BACK.
#[test]
fn no_quantity_in_a_wide_deterministic_sweep_loses_a_digit_going_out_and_coming_back() {
    let mut checked = 0usize;
    let check = |m: i128| {
        let c = Count::from_micros(m);
        let text = c.to_decimal_string();
        let back = match Count::parse(&text) {
            Ok(b) => b,
            Err(e) => panic!("mantissa {m} rendered `{text}`, which will not parse: {e}"),
        };
        assert_eq!(
            back, c,
            "mantissa {m} rendered `{text}` and read back as something else"
        );
        assert_eq!(
            back.micros(),
            m,
            "mantissa {m} rendered `{text}` and came back as a different integer"
        );
        assert_eq!(
            back.to_decimal_string(),
            text,
            "mantissa {m} does not render to one stable spelling"
        );
    };

    for m in -1_000i128..=1_000 {
        check(m);
        checked += 1;
    }

    let mut power: i128 = 1;
    for _ in 0..38 {
        for delta in -200i128..=200 {
            if let Some(m) = power.checked_add(delta) {
                check(m);
                check(-m);
                checked += 2;
            }
        }
        match power.checked_mul(10) {
            Some(next) => power = next,
            None => break,
        }
    }

    let mut rng = Xorshift(0x1234_5678_9ABC_DEF0);
    for _ in 0..250_000 {
        let hi = u128::from(rng.step());
        let lo = u128::from(rng.step());
        check(((hi << 64) | lo) as i128);
        checked += 1;
    }

    for c in [
        MAX,
        MIN,
        MAX_ACROSS_A_64_BIT_COLUMN,
        MIN_ACROSS_A_64_BIT_COLUMN,
    ] {
        check(c.micros());
        checked += 1;
    }

    assert!(
        checked > 260_000,
        "the sweep only checked {checked} quantities, which is not a sweep"
    );
}

#[test]
fn the_debug_spelling_is_the_decimal_not_the_mantissa() {
    assert_eq!(format!("{:?}", ok("27.5")), "Count(27.5)");
    assert_eq!(format!("{:?}", MIN.checked_add(Count::ZERO).unwrap()), {
        let mut s = String::from("Count(");
        s.push_str(&MIN.to_decimal_string());
        s.push(')');
        s
    });
}

#[test]
fn addition_is_exact_and_checked_never_wrapping() {
    assert_eq!(ok("27.5").checked_add(ok("0.1")), Ok(ok("27.6")));
    assert_eq!(ok("27.1").checked_add(ok("27.1")), Ok(ok("54.2")));
    assert_eq!(
        ok("0.000001").checked_add(ok("0.000001")),
        Ok(ok("0.000002"))
    );
    assert_eq!(ok("27.5").checked_sub(ok("27.5")), Ok(Count::ZERO));
    assert_eq!(ok("0").checked_sub(ok("0.5")), Ok(ok("-0.5")));

    assert_eq!(MAX.checked_add(Count::ONE), Err(CountError::Overflow));
    assert_eq!(MIN.checked_sub(Count::ONE), Err(CountError::Overflow));
}

#[test]
fn a_tenth_added_ten_times_is_exactly_one() {
    let mut total = Count::ZERO;
    for _ in 0..10 {
        total = total.checked_add(ok("0.1")).expect("in range");
    }
    assert_eq!(total, Count::ONE);
    assert_eq!(total.micros(), 1_000_000);
    assert_eq!(total.to_decimal_string(), "1");
}

#[test]
fn multiplying_a_count_by_a_rate_is_exact_or_a_refusal() {
    assert_eq!(ok("27.5").checked_mul(ok("1.87")), Ok(ok("51.425")));
    assert_eq!(ok("27.1").checked_mul(ok("2")), Ok(ok("54.2")));
    assert_eq!(ok("0").checked_mul(ok("1.87")), Ok(Count::ZERO));

    assert_eq!(
        ok("0.000001").checked_mul(ok("0.000001")),
        Err(CountError::Inexact)
    );
    assert_eq!(
        ok("1.5").checked_mul(ok("0.000001")),
        Err(CountError::Inexact)
    );

    assert_eq!(ok("0.000001").checked_mul_wide(ok("0.000001")), Ok(1));
    assert_eq!(
        ok("27.5").checked_mul_wide(ok("1.87")),
        Ok(51_425_000_000_000)
    );
    assert_eq!(MAX.checked_mul(ok("2")), Err(CountError::Overflow));
    assert_eq!(MAX.checked_mul_wide(ok("2")), Err(CountError::Overflow));
}

#[test]
fn whole_multiples_and_whole_constructors_are_checked() {
    assert_eq!(Count::from_integer(27), Ok(ok("27")));
    assert_eq!(Count::from_integer(0), Ok(Count::ZERO));
    assert_eq!(Count::from_integer(-27), Ok(ok("-27")));
    assert_eq!(Count::from_integer(i128::MAX), Err(CountError::OutOfRange));
    assert!(ok("0").is_zero());
    assert!(ok("-0.000001").is_negative());
}

#[test]
fn ordering_is_the_ordering_of_the_quantities() {
    assert!(ok("27.1") < ok("27.5"));
    assert!(ok("-27.5") < ok("0"));
    assert!(ok("0.000001") > ok("0"));
    assert_eq!(ok("27"), ok("27.0"));
    assert_eq!(ok("27"), ok("2.7e1"));
    let mut sorted = [ok("27.5"), ok("-1"), ok("0.001"), ok("27.1"), ok("0")];
    sorted.sort();
    assert_eq!(
        sorted.map(Count::to_decimal_string).join(" "),
        "-1 0 0.001 27.1 27.5"
    );
}

/// A ROW'S SILENCE MEANS WHOLE UNITS, AND NOTHING ON DISK IS TOUCHED.
#[test]
fn an_old_row_reads_as_whole_units_and_a_new_row_as_a_mantissa() {
    assert_eq!(stored_scale_default(), SCALE_WHOLE_UNITS);
    assert_eq!(SCALE_MICRO_UNITS, COUNT_SCALE);
    assert_ne!(SCALE_WHOLE_UNITS, SCALE_MICRO_UNITS);

    assert_eq!(Count::from_stored(27, stored_scale_default()), Ok(ok("27")));

    assert_eq!(
        Count::from_stored(27_500_000, SCALE_MICRO_UNITS),
        Ok(ok("27.5"))
    );

    for _ in 0..3 {
        assert_eq!(Count::from_stored(27, SCALE_WHOLE_UNITS), Ok(ok("27")));
        assert_eq!(
            Count::from_stored(27_000_000, SCALE_MICRO_UNITS),
            Ok(ok("27"))
        );
    }

    assert_ne!(
        Count::from_stored(27, SCALE_WHOLE_UNITS),
        Count::from_stored(27, SCALE_MICRO_UNITS)
    );
}

#[test]
fn a_row_from_a_scale_this_build_cannot_read_is_refused() {
    for unknown in [1u32, 2, 3, 5, 7, 9, 18, u32::MAX] {
        assert_eq!(
            Count::from_stored(27, unknown),
            Err(CountError::UnknownScale),
            "scale {unknown} has no reading here and must not be guessed at"
        );
    }

    assert_eq!(
        Count::from_stored(i128::MAX, SCALE_WHOLE_UNITS),
        Err(CountError::OutOfRange)
    );
}

/// THE RANGE THAT ACTUALLY BINDS IS THE 64-BIT COLUMN, NOT THE 128-BIT TYPE.
#[test]
fn the_store_column_binds_long_before_the_type_does() {
    assert_eq!(MAX_ACROSS_A_64_BIT_COLUMN.micros(), i128::from(i64::MAX));
    assert_eq!(MIN_ACROSS_A_64_BIT_COLUMN.micros(), i128::from(i64::MIN));

    let whole = MAX_ACROSS_A_64_BIT_COLUMN.to_decimal_string();
    let whole = whole.split('.').next().expect("a whole part");
    assert_eq!(whole, "9223372036854");
    assert_eq!(whole.len(), 13, "9.2e12 has 13 digits before the point");

    assert!(MAX_ACROSS_A_64_BIT_COLUMN.fits_a_64_bit_column());
    assert!(MIN_ACROSS_A_64_BIT_COLUMN.fits_a_64_bit_column());
    assert!(ok("27.5").fits_a_64_bit_column());
    assert!(Count::ZERO.fits_a_64_bit_column());

    assert!(!MAX_ACROSS_A_64_BIT_COLUMN
        .checked_add(Count::EPSILON)
        .expect("in range")
        .fits_a_64_bit_column());
    assert!(!MAX.fits_a_64_bit_column());
    assert!(!MIN.fits_a_64_bit_column());
}

/// How many rows the order-independence proof folds.
const ROWS: usize = 1_000_000;

/// How many different arrival orders the same rows are folded in.
const SHUFFLES: usize = 16;

/// THE TOTAL, PINNED. If the arithmetic ever changes, this literal is what says so — an assertion
const PINNED_TOTAL: &str = "2499999999.5";

/// A 64-bit xorshift, written out so the shuffle draws from integers and nothing else.
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

    /// A number below `bound`, by remainder. The slight bias a remainder has is irrelevant here:
    fn below(&mut self, bound: usize) -> usize {
        (self.step() % (bound as u64)) as usize
    }
}

/// A million rows, each a fractional count, built by integer arithmetic.
fn rows() -> Vec<Count> {
    let mut out = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        let i = i as i128;

        let whole = i % 5_000;
        let fraction = (i * 7_919) % 1_000_000;
        out.push(Count::from_micros(whole * 1_000_000 + fraction));
    }
    out
}

#[test]
fn a_million_rows_sum_to_one_total_whatever_order_they_arrive_in() {
    let mut rows = rows();
    let reference = Count::total(rows.iter().copied()).expect("in range");
    assert_eq!(
        reference.to_decimal_string(),
        PINNED_TOTAL,
        "the total of the fixed rows is a pinned number, not whatever today's arithmetic makes it"
    );

    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    for shuffle in 0..SHUFFLES {
        for i in (1..rows.len()).rev() {
            let j = rng.below(i + 1);
            rows.swap(i, j);
        }
        let total = Count::total(rows.iter().copied()).expect("in range");
        assert_eq!(
            total, reference,
            "shuffle {shuffle} produced a different total"
        );
        assert_eq!(
            total.to_decimal_string(),
            PINNED_TOTAL,
            "shuffle {shuffle} produced a different spelling"
        );
    }

    assert_eq!(ok(PINNED_TOTAL), reference);
}

#[test]
fn a_count_is_read_from_the_bodys_own_bytes() {
    let body = br#"{"usage":{"output_tokens":27.5,"input_tokens":42,"cache_read":0.001}}"#;
    assert_eq!(
        Count::read_at(body, "/usage/output_tokens"),
        Ok(Some(ok("27.5")))
    );
    assert_eq!(
        Count::read_at(body, "/usage/input_tokens"),
        Ok(Some(ok("42")))
    );
    assert_eq!(
        Count::read_at(body, "/usage/cache_read"),
        Ok(Some(ok("0.001")))
    );

    assert_eq!(Count::read_at(body, "/usage/cache_write"), Ok(None));
    assert_eq!(Count::read_at(body, "/nowhere"), Ok(None));
}

#[test]
fn a_body_that_spells_a_count_any_other_way_is_refused_at_the_read() {
    assert_eq!(
        Count::read_at(br#"{"n":"27.5"}"#, "/n"),
        Err(CountError::Malformed)
    );
    assert_eq!(
        Count::read_at(br#"{"n":null}"#, "/n"),
        Err(CountError::Malformed)
    );

    assert_eq!(
        Count::read_at(br#"{"n":0.0000001}"#, "/n"),
        Err(CountError::TooFine)
    );

    assert_eq!(
        Count::read_at(br#"{"n":-3}"#, "/n"),
        Err(CountError::Negative)
    );

    assert_eq!(
        Count::read_at(br#"{"usage":{"output_tokens":27."#, "/usage/output_tokens"),
        Err(CountError::Truncated)
    );
}

/// THE DEFECT THIS SEAM REPLACES, STATED AS AN ASSERTION.
#[test]
fn a_float_spelled_count_is_the_count_and_never_a_silent_zero() {
    let body = br#"{"billed_units":{"output_tokens":27.0,"input_tokens":27.5}}"#;
    assert_eq!(
        Count::read_at(body, "/billed_units/output_tokens"),
        Ok(Some(ok("27")))
    );
    assert_eq!(
        Count::read_at(body, "/billed_units/input_tokens"),
        Ok(Some(ok("27.5")))
    );

    for e in [
        CountError::Empty,
        CountError::Malformed,
        CountError::Truncated,
        CountError::TooFine,
        CountError::OutOfRange,
        CountError::Overflow,
        CountError::Inexact,
        CountError::Negative,
    ] {
        assert!(!e.to_string().is_empty(), "{e:?} must say what it refused");
    }
}
