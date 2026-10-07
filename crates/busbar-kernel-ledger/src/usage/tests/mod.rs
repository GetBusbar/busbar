// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The usage unit under test: the closed sources, the dated pricing and the metering series — and
//! the settlement table's absence from it.

mod dated_tests;
mod one_table_tests;
mod series_tests;
mod source_tests;

/// The classes the older release priced, under the names it used.
pub(crate) const INPUT: &str = "input";
