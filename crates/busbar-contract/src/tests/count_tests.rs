// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the exact decimal quantity (DECISION #81).
//!
//! NO BINARY FLOATING POINT APPEARS HERE. Not in an assertion, not in a fixture, not in the
//! shuffle that proves order independence — the shuffle draws from an integer generator written
//! out in full below, precisely so that the proof of exactness is not itself resting on a double.

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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The representation
// ─────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_scale_is_six_and_one_unit_is_a_million_mantissa_steps() {
    assert_eq!(COUNT_SCALE, 6);
    assert_eq!(Count::ONE.micros(), 1_000_000);
    assert_eq!(Count::EPSILON.micros(), 1);
    assert_eq!(Count::ZERO.micros(), 0);
}

/// THE IN-MEMORY RANGE CLAIM, CHECKED RATHER THAN QUOTED.
///
/// #81 says the range at scale 6 is "~1.7e32 units". The exact positive end is
/// `i128::MAX / 10^6` with the remainder as the fraction, and both ends round-trip through the
/// decimal spelling — which is the part that matters, because a bound you cannot render is a bound
/// you cannot report.
///
/// THIS IS NOT THE USABLE RANGE. A persisted count column is 64 bits wide, so anything that has to
/// survive being written down stops four-and-a-bit orders of magnitude earlier — see
/// [`the_store_column_binds_long_before_the_type_does`], which is the bound a caller must respect.
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
    // "~1.7e32": the whole part has 33 digits and begins 170141…, i.e. 1.70141…e32.
    let whole = MAX.to_decimal_string();
    let whole = whole.split('.').next().expect("a whole part");
    assert_eq!(whole.len(), 33, "1.7e32 has 33 digits before the point");
    assert!(whole.starts_with("170141"));
    // And the ends are exactly the ends: one more micro-unit either way does not exist.
    assert_eq!(MAX.checked_add(Count::EPSILON), Err(CountError::Overflow));
    assert_eq!(MIN.checked_sub(Count::EPSILON), Err(CountError::Overflow));

    // REGRESSION, AND IT WAS A REAL ONE. Both ends must READ BACK, not merely render. Building the
    // magnitude positive-first and negating at the end overflows one step before `MIN`, because
    // two's complement reaches one further downward than upward — so `MIN` rendered correctly and
    // then refused its own spelling as out of range. A quantity the type can hold but cannot read
    // back is a wrong ledger. The wide sweep below caught it; this names it.
    assert_eq!(ok(&MAX.to_decimal_string()), MAX);
    assert_eq!(ok(&MIN.to_decimal_string()), MIN);
    assert_eq!(
        ok("-170141183460469231731687303715884.105728").micros(),
        i128::MIN
    );
    // Its positive twin is genuinely out of range, and still is.
    assert_eq!(
        Count::parse("170141183460469231731687303715884.105728"),
        Err(CountError::OutOfRange)
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The parser — the load-bearing part
// ─────────────────────────────────────────────────────────────────────────────────────────────────

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
/// and it is exactly `27_100_000` here. This assertion is the whole reason the parser reads text.
#[test]
fn the_value_binary_floating_point_cannot_hold_reads_exactly() {
    assert_eq!(micros_of("27.1"), 27_100_000);
    assert_eq!(ok("27.1").to_decimal_string(), "27.1");
    // And the neighbours either side of it, so the answer is the value and not a lucky landing.
    assert_eq!(micros_of("27.099999"), 27_099_999);
    assert_eq!(micros_of("27.100001"), 27_100_001);
}

#[test]
fn a_fraction_finer_than_the_scale_is_refused_not_rounded() {
    // Seven places where the scale has six. Rounding it to `0` or to `0.000001` would both be
    // inventing the measurement.
    assert_eq!(Count::parse("0.0000001"), Err(CountError::TooFine));
    assert_eq!(Count::parse("27.1234567"), Err(CountError::TooFine));
    assert_eq!(Count::parse("1e-7"), Err(CountError::TooFine));
    // But a seventh place that is a ZERO takes nothing away, so it is the same quantity.
    assert_eq!(micros_of("0.0000010"), 1);
    assert_eq!(micros_of("27.1000000000"), 27_100_000);
}

#[test]
fn a_negative_is_a_quantity_but_not_a_measurement() {
    // The mantissa is signed, so the type holds it.
    assert_eq!(micros_of("-1"), -1_000_000);
    assert_eq!(micros_of("-27.5"), -27_500_000);
    assert_eq!(ok("-27.5").to_decimal_string(), "-27.5");
    // The reading seam refuses it: a provider reporting minus three tokens has not reported a count.
    assert_eq!(read_count("-1"), Err(CountError::Negative));
    assert_eq!(read_count("-0.000001"), Err(CountError::Negative));
    // Minus zero is zero, and zero is not below zero.
    assert_eq!(read_count("-0"), Ok(Count::ZERO));
}

#[test]
fn a_magnitude_past_the_scale_is_refused() {
    // One micro-unit past the top.
    assert_eq!(
        Count::parse("170141183460469231731687303715884.105728"),
        Err(CountError::OutOfRange)
    );
    // And the top itself still reads.
    assert_eq!(
        micros_of("170141183460469231731687303715884.105727"),
        i128::MAX
    );
    // A whole number past the range.
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
    // `1e400` is past everything.
    assert_eq!(Count::parse("1e400"), Err(CountError::OutOfRange));
    assert_eq!(Count::parse("-1e400"), Err(CountError::OutOfRange));
    // An exponent literal longer than an i64 holds is still answered, not panicked at.
    assert_eq!(
        Count::parse("1e999999999999999999999999"),
        Err(CountError::OutOfRange)
    );
    assert_eq!(
        Count::parse("1e-999999999999999999999999"),
        Err(CountError::TooFine)
    );
    // A zero mantissa is exactly zero at ANY exponent — there is no magnitude to be out of range.
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
/// never entertained as a float, and never a panic.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────────────────────────

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
    // A band either side of zero and either side of a whole unit, swept one mantissa step at a
    // time: if any spelling were lossy, a neighbour would collide with it.
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
///
/// A count that cannot round-trip exactly is a wrong ledger, and a wrong ledger corrupts every
/// price derived from it silently — money is a VIEW over `ledger x ratecard`, so an inexact count
/// is not a display problem, it is a book that disagrees with itself. So the round trip is proven
/// over a wide, deterministic sweep rather than asserted over a handful of pretty numbers:
///
/// * every mantissa within a thousand steps of zero, where the fraction is all there is;
/// * every mantissa within two hundred steps of each power of ten up to `10^37`, which is where a
///   carry crosses the decimal point and where a naive renderer drops a leading zero;
/// * a quarter of a million pseudorandom mantissas drawn across the WHOLE `i128` range, from an
///   integer generator written out in full — no floats, not even to pick a test value;
/// * and the four exact endpoints: both ends of the type and both ends of the store column.
///
/// The assertion is the strong one in both directions: the text a quantity renders to parses back
/// to the SAME quantity, and re-rendering that quantity gives back the SAME text. A representation
/// that merely "looked right" would have to survive both.
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

    // The fine structure either side of zero.
    for m in -1_000i128..=1_000 {
        check(m);
        checked += 1;
    }

    // Every carry boundary: two hundred steps either side of each power of ten, both signs.
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

    // A quarter of a million draws across the whole range, from the integer generator above.
    let mut rng = Xorshift(0x1234_5678_9ABC_DEF0);
    for _ in 0..250_000 {
        let hi = u128::from(rng.step());
        let lo = u128::from(rng.step());
        check(((hi << 64) | lo) as i128);
        checked += 1;
    }

    // The four exact endpoints.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Arithmetic
// ─────────────────────────────────────────────────────────────────────────────────────────────────

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
    // The ceiling refuses; it does not saturate, and it certainly does not wrap.
    assert_eq!(MAX.checked_add(Count::ONE), Err(CountError::Overflow));
    assert_eq!(MIN.checked_sub(Count::ONE), Err(CountError::Overflow));
}

#[test]
fn a_tenth_added_ten_times_is_exactly_one() {
    // The canonical binary-floating-point embarrassment: ten tenths is 0.9999999999999999 as a
    // double. Here it is one, exactly, and the assertion is on the mantissa so there is nothing to
    // argue about.
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
    // 27.5 tokens at 1.87 a token is exactly 51.425.
    assert_eq!(ok("27.5").checked_mul(ok("1.87")), Ok(ok("51.425")));
    assert_eq!(ok("27.1").checked_mul(ok("2")), Ok(ok("54.2")));
    assert_eq!(ok("0").checked_mul(ok("1.87")), Ok(Count::ZERO));
    // A product needing a seventh place is refused rather than rounded.
    assert_eq!(
        ok("0.000001").checked_mul(ok("0.000001")),
        Err(CountError::Inexact)
    );
    assert_eq!(
        ok("1.5").checked_mul(ok("0.000001")),
        Err(CountError::Inexact)
    );
    // The wide form keeps the places instead, for a caller that sums before it rounds.
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
    assert_eq!(ok("27.5").checked_mul_integer(2), Ok(ok("55")));
    assert_eq!(MAX.checked_mul_integer(2), Err(CountError::Overflow));
    assert!(ok("27").is_whole());
    assert!(!ok("27.5").is_whole());
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// What is written down, and how an old row reads (#81a)
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A ROW'S SILENCE MEANS WHOLE UNITS, AND NOTHING ON DISK IS TOUCHED.
///
/// The whole of #81a in one test: the value written before the scale existed is read as the count it
/// always was, the value written since is read as the mantissa it is, and neither reading multiplies
/// anything stored.
#[test]
fn an_old_row_reads_as_whole_units_and_a_new_row_as_a_mantissa() {
    assert_eq!(stored_scale_default(), SCALE_WHOLE_UNITS);
    assert_eq!(SCALE_MICRO_UNITS, COUNT_SCALE);
    assert_ne!(SCALE_WHOLE_UNITS, SCALE_MICRO_UNITS);

    // The v1.5.5 shape: a bare `27` with no discriminator beside it is twenty-seven tokens.
    assert_eq!(Count::from_stored(27, stored_scale_default()), Ok(ok("27")));
    // The shape written from here on: the mantissa, with the row saying so.
    assert_eq!(
        Count::from_stored(27_500_000, SCALE_MICRO_UNITS),
        Ok(ok("27.5"))
    );
    // A count writes its mantissa, and the record writes the scale beside it.
    assert_eq!(ok("27.5").stored_value(), 27_500_000);
    assert_eq!(ok("27").stored_value(), 27_000_000);

    // READING IS IDEMPOTENT, which is the property a rescale does not have. Re-reading the same
    // stored bytes any number of times gives the same count; `x 10^6` run twice gives `x 10^12`.
    for _ in 0..3 {
        assert_eq!(Count::from_stored(27, SCALE_WHOLE_UNITS), Ok(ok("27")));
        assert_eq!(
            Count::from_stored(27_000_000, SCALE_MICRO_UNITS),
            Ok(ok("27"))
        );
    }
    // And the two readings of the SAME bytes are different quantities, which is exactly why the
    // discriminator has to be on the row rather than assumed by the reader.
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
    // A whole-unit value too big to lift to the scale is out of range, not silently wrapped.
    assert_eq!(
        Count::from_stored(i128::MAX, SCALE_WHOLE_UNITS),
        Err(CountError::OutOfRange)
    );
}

/// A FRACTION BOUND FOR A WHOLE-UNIT DESTINATION REFUSES (#81a(f)).
#[test]
fn a_fraction_refuses_rather_than_truncating_into_a_whole_unit_column() {
    assert_eq!(ok("27").whole_units(), Ok(27));
    assert_eq!(ok("-27").whole_units(), Ok(-27));
    assert_eq!(Count::ZERO.whole_units(), Ok(0));
    // Truncating 27.5 to 27 would bill for a measurement nobody took.
    assert_eq!(ok("27.5").whole_units(), Err(CountError::NotWhole));
    assert_eq!(ok("0.000001").whole_units(), Err(CountError::NotWhole));
    assert_eq!(ok("-0.5").whole_units(), Err(CountError::NotWhole));
}

/// THE RANGE THAT ACTUALLY BINDS IS THE 64-BIT COLUMN, NOT THE 128-BIT TYPE.
///
/// `1.7e32` is what the type holds. A persisted count column is signed 64-bit and holds the
/// mantissa, so the usable whole-unit range is about `9.2e12` — four twenty-odd orders of magnitude
/// smaller, and the one a caller has to respect.
#[test]
fn the_store_column_binds_long_before_the_type_does() {
    assert_eq!(MAX_ACROSS_A_64_BIT_COLUMN.micros(), i128::from(i64::MAX));
    assert_eq!(MIN_ACROSS_A_64_BIT_COLUMN.micros(), i128::from(i64::MIN));
    // About 9.2e12 whole units: thirteen digits before the point.
    let whole = MAX_ACROSS_A_64_BIT_COLUMN.to_decimal_string();
    let whole = whole.split('.').next().expect("a whole part");
    assert_eq!(whole, "9223372036854");
    assert_eq!(whole.len(), 13, "9.2e12 has 13 digits before the point");

    assert!(MAX_ACROSS_A_64_BIT_COLUMN.fits_a_64_bit_column());
    assert!(MIN_ACROSS_A_64_BIT_COLUMN.fits_a_64_bit_column());
    assert!(ok("27.5").fits_a_64_bit_column());
    assert!(Count::ZERO.fits_a_64_bit_column());
    // One micro-unit past the column does not fit, and MAX is nowhere near fitting.
    assert!(!MAX_ACROSS_A_64_BIT_COLUMN
        .checked_add(Count::EPSILON)
        .expect("in range")
        .fits_a_64_bit_column());
    assert!(!MAX.fits_a_64_bit_column());
    assert!(!MIN.fits_a_64_bit_column());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Order independence over a million rows
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// How many rows the order-independence proof folds.
const ROWS: usize = 1_000_000;

/// How many different arrival orders the same rows are folded in.
const SHUFFLES: usize = 16;

/// THE TOTAL, PINNED. If the arithmetic ever changes, this literal is what says so — an assertion
/// that the two runs agreed with each other would still pass if both had drifted together.
const PINNED_TOTAL: &str = "2499999999.5";

/// A 64-bit xorshift, written out so the shuffle draws from integers and nothing else.
///
/// Deterministic from its seed, so the "many times" in "sum it many times" is many DIFFERENT
/// orders and the same orders on every machine and every run.
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
    /// the claim under test is that ANY order gives the same total, so a shuffle need only be
    /// varied, not uniform.
    fn below(&mut self, bound: usize) -> usize {
        (self.step() % (bound as u64)) as usize
    }
}

/// A million rows, each a fractional count, built by integer arithmetic.
fn rows() -> Vec<Count> {
    let mut out = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        let i = i as i128;
        // A whole part that cycles, and a fraction that does not divide evenly into it — so the
        // sum genuinely carries across the decimal point, over and over.
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
        // Fisher-Yates, drawing from the integer generator above.
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

    // And the total re-reads as itself: the spelling is not merely stable, it is the quantity.
    assert_eq!(ok(PINNED_TOTAL), reference);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Reading a count out of a body, without a document model in between
// ─────────────────────────────────────────────────────────────────────────────────────────────────

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
    // Absent is absent, which is a different fact from a count of zero.
    assert_eq!(Count::read_at(body, "/usage/cache_write"), Ok(None));
    assert_eq!(Count::read_at(body, "/nowhere"), Ok(None));
}

#[test]
fn a_body_that_spells_a_count_any_other_way_is_refused_at_the_read() {
    // A string is not a number, however numeric it looks.
    assert_eq!(
        Count::read_at(br#"{"n":"27.5"}"#, "/n"),
        Err(CountError::Malformed)
    );
    assert_eq!(
        Count::read_at(br#"{"n":null}"#, "/n"),
        Err(CountError::Malformed)
    );
    // A seventh place is refused here exactly as it is at the text seam.
    assert_eq!(
        Count::read_at(br#"{"n":0.0000001}"#, "/n"),
        Err(CountError::TooFine)
    );
    // A negative measurement is refused at the read.
    assert_eq!(
        Count::read_at(br#"{"n":-3}"#, "/n"),
        Err(CountError::Negative)
    );
    // Bytes that stop mid-value are a "later chunk may carry it", not a malformed body.
    assert_eq!(
        Count::read_at(br#"{"usage":{"output_tokens":27."#, "/usage/output_tokens"),
        Err(CountError::Truncated)
    );
}

/// THE DEFECT THIS SEAM REPLACES, STATED AS AN ASSERTION.
///
/// The house idiom recorded a float-spelled count as ZERO, because the integer accessor answers
/// "not an integer" for `27.0` and the default then wrote nothing down. Here `27.0` is 27 and
/// `27.5` is 27.5 — and neither is ever a silent zero, because a refusal is an `Err` and an `Err`
/// has to be handled.
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
    // Every refusal this module can produce is a distinct, nameable Err — none of them is zero.
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

/// NO BINARY FLOATING POINT IN THE TYPE, ITS ARITHMETIC, OR ITS TESTS.
///
/// A source scan of this module and its tests, because the ban is about what the code names and no
/// unit test of behaviour can observe a type that is not there. The gate
/// `cargo xtask gate no-float-money` holds the same line across the whole money path; this is the
/// in-crate copy, so the rule travels with the file rather than living only in a tool.
#[test]
fn neither_the_count_type_nor_its_tests_names_a_binary_float() {
    // Built rather than written, so this test's own source does not carry the needle it hunts.
    let needles = [format!("f{}", "64"), format!("f{}", "32")];
    for (name, src) in [
        ("count.rs", include_str!("../count.rs")),
        ("tests/count_tests.rs", include_str!("count_tests.rs")),
    ] {
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            // Prose about the ban is the prose that explains it; code is what the ban is about.
            if trimmed.starts_with("//") {
                continue;
            }
            for needle in &needles {
                assert!(
                    !line.contains(needle.as_str()),
                    "{name}:{}: `{needle}` on the money path",
                    i + 1
                );
            }
        }
    }
}
