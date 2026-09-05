// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The usage unit under test: the fold, the lane cross-check, the settlement table and the
//! metering series.

use busbar_caps::step::MeterClassId;
use busbar_caps::{KernelSeal, Usage, UsageLine, UsageToken};

use crate::{
    Direction, KernelCounts, KernelLine, LocatedValue, LocatorPtr, QuantitySource,
    RetainedLocatorValues,
};

mod lane_tests;
mod meter_tests;
mod series_tests;
mod settlement_tests;

/// The classes the older release priced, under the names it used.
pub(crate) const INPUT: &str = "input";
pub(crate) const OUTPUT: &str = "output";

/// Mint a usage token for a test.
///
/// A report can only be built by the usage unit holding its own token, which is the property this
/// crate exists to preserve; a test therefore needs one. The seal is confined to the kernel in real
/// code, and these lines are the same test-only exception the capability crate's own tests take.
pub(crate) fn token() -> UsageToken {
    let seal = KernelSeal::acquire_for_kernel();
    UsageToken::mint(&seal)
}

/// A located value: the destination reported this figure at a declared place in its payload.
pub(crate) fn located(class: &'static str, quantity: u64, direction: Direction) -> LocatedValue {
    LocatedValue {
        class: MeterClassId::new(class),
        quantity,
        source: QuantitySource::Locator {
            direction,
            ptr: LocatorPtr::new("/usage"),
        },
    }
}

/// A cardinality a plane surfaced as a declared content fact.
pub(crate) fn plane_count(class: &'static str, quantity: u64, fact: &'static str) -> LocatedValue {
    LocatedValue {
        class: MeterClassId::new(class),
        quantity,
        source: QuantitySource::PlaneCount {
            content_fact_key: fact.to_string(),
        },
    }
}

/// One of the kernel's own counts, as a plain count.
pub(crate) fn kernel_count(class: &'static str, quantity: u64) -> KernelLine {
    KernelLine {
        class: MeterClassId::new(class),
        quantity,
        source: QuantitySource::Count,
    }
}

/// The retained values, with no lane evidence at all.
pub(crate) fn retained(values: Vec<LocatedValue>) -> RetainedLocatorValues {
    RetainedLocatorValues::new(values)
}

/// The kernel's counts.
pub(crate) fn counts(lines: Vec<KernelLine>) -> KernelCounts {
    KernelCounts::new(lines)
}

/// A report built directly, for the settlement cases that are handed one.
pub(crate) fn usage(lines: &[(&'static str, u64)]) -> Usage {
    Usage::report(&token(), plain(lines)).expect("within the line bound")
}

/// The same, marked as the kernel's own floor.
pub(crate) fn estimated_usage(lines: &[(&'static str, u64)]) -> Usage {
    Usage::estimate(&token(), plain(lines)).expect("within the line bound")
}

/// Plain report lines.
pub(crate) fn plain(lines: &[(&'static str, u64)]) -> Vec<UsageLine> {
    lines
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
        })
        .collect()
}

/// A report's lines as plain pairs, for comparing against an expectation.
pub(crate) fn pairs(lines: &[UsageLine]) -> Vec<(&str, u64)> {
    lines
        .iter()
        .map(|l| (l.class.as_str(), l.quantity))
        .collect()
}
