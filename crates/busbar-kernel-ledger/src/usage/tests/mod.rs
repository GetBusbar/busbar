// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The usage unit under test: the fold, the lane cross-check and the metering series — and the
//! settlement table's absence from it.

mod dated_tests;
mod lane_tests;
mod meter_tests;
mod one_table_tests;
mod series_tests;

/// The classes the older release priced, under the names it used.
pub(crate) const INPUT: &str = "input";
