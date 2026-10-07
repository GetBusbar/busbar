// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The usage unit: what a unit actually used, and what that settles to.
//!
//! Everything here is a pure function over integers.
//!
//! **The sources are closed.** A quantity may come from a located value, from kernel bytes divided
//! by a declared divisor, from kernel frames times a declared factor, from a transport that
//! decodes its own payload, from monotonic elapsed time, from a count the kernel derived, or from a
//! cardinality a plane surfaced as a declared content fact. There is no eighth source, and a value
//! a peer supplied during a handshake is never on its own enough. See [`QuantitySource`].
//!
//! **The plane reports; the kernel writes** (`BUSBAR-1.6.0.md` §7, lines 989-993; owner ruling
//! 2026-09-27, line 4253). The report a unit settles against is the plane's own, built in the
//! plane's Meter step through `Usage::report`. The kernel adds no floor, compares no companion and
//! re-decides no figure. This unit once carried a kernel-side fold that did all three — post the
//! lower of two sources, trip on a kernel floor, cross-check the lane three ways — and nothing in
//! production ever constructed it; it disagreed with the spec it would have been wired under, so it
//! is gone rather than wired.
//!
//! How a unit ENDED is not decided here. The settlement writer is one function, the kernel teller's
//! `settle_written`, and the request slot beside it is the teller's too. This unit once carried a
//! second table of its own that nothing in production called, and it disagreed with the live one
//! about a durability-lost unit (item 436): two tables for one amount is one table too many.

mod dated;
mod series;
mod source;

pub use dated::{by_lane, price_dated, DatedHistory, FeeEras};
pub use series::MeterCounts;
pub use source::{quantity_from_raw, Direction, LocatorPtr, QuantitySource};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
