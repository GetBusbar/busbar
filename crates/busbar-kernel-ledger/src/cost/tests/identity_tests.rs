// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MIGRATION'S EXACTNESS**, and the identity that ties the two readers together.
//!
//! Every case in this file prices through a SINGLE-ENTRY HISTORY effective from instant zero — the
//! shape a migration seals — and compares the answer against the legacy read-time derivation at
//! that same card. The claim under test is the one the migration rests on: a single-entry history
//! IS the pinned card, arithmetically, so a deployment that never edits a price sees no figure move
//! at all.
//!
//! The two paths reach the same figure by different routes — one truncates the quantities to cents
//! and then adds the fee in cents, the other sums the fee in as a line and truncates once at the
//! end — and they agree because the fee line is an exact multiple of a minor unit.
//!
//! The generator is a plain congruential sequence written out here rather than a dependency: the
//! cases must be identical on every machine and every run, and a money property that only fails on
//! someone else's seed is not a property.

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
/// exact bound the generator below must respect.
///
/// The micro projection divides the nano-unit total by a thousand and narrows to the signed served
/// type, CHECKED: the largest total it can state is `i64::MAX` micro-units, which is `i64::MAX *
/// NANOS_PER_MICRO` = 9_223_372_036_854_775_807_000 nano-units. One micro-unit past that and it
/// REFUSES (item 28) — the deleted `micros_of` pinned it at `i64::MAX` instead — while the minor
/// projection, dividing by ten million first, keeps counting for another three orders of magnitude.
const MICRO_PROJECTION_CEILING_NANOS: u128 = (i64::MAX as u128) * crate::cost::NANOS_PER_MICRO;

/// The two projections are consistent with each other by construction, up to the point where the
/// finer of them can no longer be served: a nano-unit total in micro-units, divided by the ten
/// thousand micro-units in a minor unit, is the same total in minor units.
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
///
/// Ten to the twenty-second nano-units is above `i64::MAX * NANOS_PER_MICRO`. The deleted pinning
/// projection answered `i64::MAX` micro-units here — read back into minor units it UNDERSTATED the
/// total by more than seven per cent, a bill nobody posted. The checked projection refuses instead,
/// while the minor projection still fits and is exact.
#[test]
fn past_the_micro_ceiling_the_micro_projection_refuses_and_the_minor_one_does_not() {
    let nanos = 10_000_000_000_000_000_000_000u128; // ten to the twenty-second
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

    // The last total on the served side of the line, and the first micro-unit past it: the ceiling
    // is a boundary, not an approximate region.
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
