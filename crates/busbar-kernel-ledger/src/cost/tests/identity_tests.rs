// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MIGRATION'S EXACTNESS**, and the identity that ties the two readers together.

use super::*;
use crate::cost::MoneyError;

/// A deterministic sequence. Same numbers everywhere, forever.
struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    /// A value in `[0, bound)`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// The exact total above which the micro projection can no longer be SERVED, and therefore the

const MICRO_PROJECTION_CEILING_NANOS: u128 = (i64::MAX as u128) * crate::cost::NANOS_PER_MICRO;

/// The two projections are consistent with each other by construction, up to the point where the

#[test]
fn the_two_projections_agree_at_every_generated_total_below_the_micro_ceiling() {
    let mut seq = Seq(0x0FF1_CE00_1234_5678);
    let mut largest = 0u128;
    for _ in 0..10_000 {
        let raw = u128::from(seq.next()) * u128::from(seq.below(1_000_000) + 1);
        let nanos = raw % (MICRO_PROJECTION_CEILING_NANOS + 1);
        largest = largest.max(nanos);
        assert_eq!(
            minor_nanos(nanos),
            micros_nanos(nanos).map(|m| m / crate::cost::MICROS_PER_CENT)
        );
    }
    assert!(
        largest <= MICRO_PROJECTION_CEILING_NANOS,
        "the generator is bounded by the micro ceiling, not by luck"
    );
}

/// PAST THE MICRO CEILING THE MICRO PROJECTION REFUSES, AND THE MINOR ONE DOES NOT (item 28).

#[test]
fn past_the_micro_ceiling_the_micro_projection_refuses_and_the_minor_one_does_not() {
    let nanos = 10_000_000_000_000_000_000_000u128;
    assert!(nanos > MICRO_PROJECTION_CEILING_NANOS);
    assert_eq!(
        micros_nanos(nanos),
        Err(MoneyError::Overflow),
        "the finer projection refuses, never pins"
    );
    assert_eq!(
        minor_nanos(nanos),
        Ok(1_000_000_000_000_000),
        "the minor projection still fits and is exact"
    );

    assert_eq!(
        micros_nanos(MICRO_PROJECTION_CEILING_NANOS),
        Ok(i64::MAX),
        "at the ceiling itself the figure is exact, not pinned"
    );
    assert_eq!(
        minor_nanos(MICRO_PROJECTION_CEILING_NANOS),
        micros_nanos(MICRO_PROJECTION_CEILING_NANOS).map(|m| m / crate::cost::MICROS_PER_CENT),
        "at the ceiling itself the two still agree"
    );
    assert_eq!(
        micros_nanos(MICRO_PROJECTION_CEILING_NANOS + crate::cost::NANOS_PER_MICRO),
        Err(MoneyError::Overflow),
        "one micro-unit past the ceiling refuses"
    );
}
