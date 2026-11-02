// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::RateEntryCfg;
use busbar_kernel::cost::RateNanos;
use busbar_kernel_ledger::cost::{nano_rate, LaneClass, Money, RateCard, NANOS_PER_CENT};

fn admission_nano_rate(micro_per_unit: f64) -> u64 {
    RateNanos::from_cfg(&RateEntryCfg {
        input_utok: micro_per_unit,
        ..RateEntryCfg::default()
    })
    .input
}

struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

#[test]
fn the_two_conversions_agree_on_ten_thousand_generated_rates() {
    let mut seq = Seq(0xC0FF_EE00_D15E_A5E5);
    for case in 0..10_000u32 {
        let micro = seq.below(10_000_000_000) as f64 / 1_000_000.0;
        let ours = nano_rate(micro);
        let theirs = admission_nano_rate(micro);
        assert_eq!(
            ours, theirs,
            "case {case}: the two conversions disagree at {micro} micro-units per unit"
        );
    }
}

#[test]
fn every_boundary_value_converts_to_its_named_integer_and_both_readers_agree() {
    let cases: [(f64, u64, &str); 25] = [
        (0.0, 0, "zero is not a rate"),
        (
            0.0004,
            0,
            "four tenths of a nano-unit: refused, never rounded",
        ),
        (
            0.0005,
            0,
            "half a nano-unit: refused, never rounded up to one",
        ),
        (
            0.0014,
            0,
            "one and four tenths: refused, never rounded to one",
        ),
        (0.0015, 0, "one and a half: refused, never rounded to two"),
        (0.001, 1, "exactly one nano-unit"),
        (1.0, 1_000, "one micro-unit is a thousand nano-units"),
        (
            0.5005,
            0,
            "500.5 nano-units: neither 1.5.5's float-rounded 500 nor a half-away 501 — refused",
        ),
        (0.3, 300, "a three-decimal rate is exactly its nano-units"),
        (
            10_000.0,
            10_000_000,
            "ten thousand micro-units, converted flat",
        ),
        (
            f64::MIN_POSITIVE,
            0,
            "the smallest positive f64 rounds to nothing",
        ),
        (-0.0, 0, "negative zero is still not a rate"),
        (-1.0, 0, "a negative rate is not a discount"),
        (f64::NAN, 0, "cannot be ordered, so cannot be priced"),
        (f64::INFINITY, 0, "not finite"),
        (f64::NEG_INFINITY, 0, "not finite and not positive"),
        (f64::MAX, 0, "finite, but times a thousand it is not"),
        (
            18_446_744_073_709_548.0,
            18_446_744_073_709_548_000,
            "the last rate under the ceiling converts EXACTLY (the float product was …547_520)",
        ),
        (
            18_446_744_073_709_556.0,
            0,
            "one past what a u64 of nano-units holds: nothing, never u64::MAX",
        ),
        (
            1e15,
            1_000_000_000_000_000_000,
            "x1000 is 1e18: comfortably inside",
        ),
        (
            1e16,
            10_000_000_000_000_000_000,
            "x1000 is 1e19: still inside, and close — the largest decade that converts",
        ),
        (1e17, 0, "x1000 is 1e20: finite and past the ceiling"),
        (1e18, 0, "the config-typo case the clamp was written for"),
        (
            -1e18,
            0,
            "and its negative twin, which is not a discount either",
        ),
        (
            1e12,
            1_000_000_000_000_000,
            "an ordinary large rate, unmoved",
        ),
    ];

    for (micro, expected, why) in cases {
        assert_eq!(
            nano_rate(micro),
            expected,
            "{micro:e} micro-units per unit must convert to {expected} nano-units — {why}"
        );

        assert_eq!(
            admission_nano_rate(micro),
            expected,
            "the kernel's projection converted {micro:e} to something other than {expected} — a second \
             copy of the conversion has come back"
        );
    }

    for micro in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
        assert_eq!(nano_rate(micro), 0, "{micro} prices at nothing here");
        assert_eq!(
            admission_nano_rate(micro),
            0,
            "{micro} prices at nothing in the kernel's projection too"
        );
    }
}

#[test]
fn the_conversion_is_the_integer_the_card_holds() {
    let mut seq = Seq(0x1234_5678_9ABC_DEF0);
    for case in 0..10_000u32 {
        let micro = seq.below(10_000_000_000) as f64 / 1_000_000.0;
        let expected = nano_rate(micro);

        let built = RateCard::from_micro_rates([(LaneClass::new("lane", "input"), micro)], 0);

        let rates = built.lane_rates("lane").expect("the lane is priced");
        assert_eq!(
            rates.nanos_per_unit("input"),
            expected,
            "case {case}: the rate moved at {micro} micro-units per unit"
        );

        assert_eq!(
            rates.class_priced("input"),
            micro == 0.0 || expected != 0,
            "case {case}: {micro} micro-units per unit"
        );

        assert_eq!(admission_nano_rate(micro), expected, "case {case}");
    }
}

#[test]
fn the_projection_divides_by_the_one_constant() {
    assert_eq!(NANOS_PER_CENT, 10_000_000);
    let nanos = 3_500_000_000u128;

    let minor = Money::of_nanos(nanos).and_then(Money::minor_i64);
    assert_eq!(minor, Ok(350));
    assert_eq!(
        minor,
        Ok(i64::try_from(nanos / NANOS_PER_CENT).expect("fits")),
        "the projection is the constant and nothing else"
    );
}
