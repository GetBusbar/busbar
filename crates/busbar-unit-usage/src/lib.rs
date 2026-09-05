// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The usage unit: what a unit actually used, and what that settles to.
//!
//! Everything here is a pure function over integers. Given the values a unit's locators retained
//! while it ran, and the counts the kernel derived for itself, this crate produces the one report
//! the ledger settles against — and it produces it by rules that are written down rather than
//! negotiated per plane.
//!
//! # The four rules
//!
//! **The sources are closed.** A quantity may come from a located value, from kernel bytes divided
//! by a declared divisor, from kernel frames times a declared factor, from a transport that
//! decodes its own payload, from monotonic elapsed time, from a count the kernel derived, or from a
//! cardinality a plane surfaced as a declared content fact. There is no eighth source, and a value
//! a peer supplied during a handshake is never on its own enough. See [`QuantitySource`].
//!
//! **Two sources that disagree post the lower.** Where a reported quantity has a kernel-derived
//! companion in the same class, the two are compared; disagreement beyond the tolerance posts the
//! lower figure and marks the posting disputed. See [`meter`].
//!
//! **The floor is evidence, never a charge.** For a located class the located figure is always what
//! bills. The kernel's floor is a tripwire either side of it: a located figure far below the floor,
//! or far above it, raises a dispute, and neither changes the amount. See
//! [`MeterPolicy::locator_floor_ratio`].
//!
//! **The end decides the amount.** How a unit ended, and which evidence survived, together pick a
//! row of one table. See [`settle`].

mod evidence;
mod lane;
mod meter;
mod series;
mod settlement;
mod source;

pub use evidence::{
    KernelCounts, KernelLine, LocatedValue, MeterPolicy, RetainedLocatorValues,
    DEFAULT_LOCATOR_FLOOR_RATIO, DEFAULT_VARIANCE_TOLERANCE_BP,
};
pub use lane::{cross_check_lane, LaneCheck, LaneLegs, LegDeclaration};
pub use meter::{meter, Dispute, DisputeReason, Metered, UsageMeter};
pub use series::MeterCounts;
pub use settlement::{
    fee_count, requests_settled, settle, Evidence, FeeInputs, Finish, SettleFlag, Settlement,
    StatusClass, UnitEndKind,
};
pub use source::{quantity_from_raw, Direction, LocatorPtr, QuantitySource};

/// Basis points in a whole: the scale every ratio in this crate is expressed on, so no comparison
/// needs a decimal.
pub const WHOLE_BP: u64 = 10_000;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
