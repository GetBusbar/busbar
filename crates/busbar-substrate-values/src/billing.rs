// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable SHAPES — [`Billing`], [`TokenUsage`], [`Usage`], [`ServiceTier`], [`RawTierRates`]
//! and [`duration_seconds_to_wire`] — moved to `busbar_contract::billing` (DECISIONS #83: contract =
//! shapes; SD-1 of the #83a split) and are re-exported here under their historical paths, so every
//! caller compiles unchanged. The rate-card representation, `UnitRate`, is pricing semantics rather
//! than a shape, and lives with the card (`busbar_kernel_ledger::cost::UnitRate`, #83a O1).

pub use busbar_contract::billing::{
    duration_seconds_to_wire, Billing, RawTierRates, ServiceTier, TokenUsage, Usage,
};

/// The exact decimal every measured quantity is carried in (DECISION #81).
///
/// Re-exported HERE, beside the carrier that holds one, so a codec crate reads and writes a billable
/// quantity through the crate it already depends on for [`Billing`] — no new dependency edge, and
/// one obvious place to look for the type a billable number has.
pub use busbar_contract::Count;

#[cfg(test)]
#[path = "tests/billing_duration_tests.rs"]
mod billing_duration_tests;
