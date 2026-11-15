// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1d, the store 1.5.5 implied (AGREED QM2, owner 2026-11-15T20:54Z). Red stub: nothing written.

use busbar_contract::yaml::{Pairs, Value};

/// The store module 1.5.5 ran a store-less config on.
pub(crate) const STORE_1_5_5_IMPLIED: &str = "memory"; // AGREED QM2: 1.5.5-shape fact

/// Write the store block 1.5.5 implied.
pub(crate) fn name_the_implied_store(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    let _ = (root, resolved, report, STORE_1_5_5_IMPLIED);
}

#[cfg(test)]
#[path = "tests/absent_store_tests.rs"]
mod tests;
