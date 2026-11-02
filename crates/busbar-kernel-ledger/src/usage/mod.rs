// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The usage unit: what a unit actually used, and what that settles to.

mod dated;
mod source;

pub use dated::{by_lane, price_dated, price_dated_raw, DatedHistory, FeeEras};
pub use source::{Direction, LocatorPtr, QuantitySource};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
