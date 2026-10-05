// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The usage unit under test: the metering series, over reports built directly.

use busbar_contract::caps::step::MeterClassId;
use busbar_contract::caps::{Consumption, Grant, KernelSeal, Usage, UsageLine};

use busbar_kernel_ledger::usage::QuantitySource;

/// The classes the older release priced, under the names it used.
pub(crate) const INPUT: &str = "input";
pub(crate) const OUTPUT: &str = "output";

/// Mint a usage token for a test.
///
/// A report can only be built by the usage unit holding its own token, which is the property this
/// crate exists to preserve; a test therefore needs one. The seal is confined to the kernel in real
/// code, and these lines are the same test-only exception the capability crate's own tests take.
pub(crate) fn token() -> Grant<Consumption> {
    let seal = KernelSeal::acquire_for_kernel();
    Grant::<Consumption>::mint(&seal)
}

/// A report built directly, for the settlement cases that are handed one.
pub(crate) fn usage(lines: &[(&'static str, u64)]) -> Usage {
    Usage::report(&token(), plain(lines)).expect("within the line bound")
}

/// Plain report lines.
pub(crate) fn plain(lines: &[(&'static str, u64)]) -> Vec<UsageLine> {
    lines
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect()
}

