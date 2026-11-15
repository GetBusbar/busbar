// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The overlay's hooks (MIGRATE-ON-BOOT §A3 1c, r29): red, the pass lands with the next commit.

use busbar_contract::json;
use busbar_contract::yaml::Pairs;

use crate::Refusal;

/// The overlay's hook fields (top level).
pub(crate) const KEYS: [&str; 3] = ["hooks", "global_hooks", "deleted"];

/// Fold the overlay's hooks (red: nothing is folded yet).
pub(crate) fn fold(
    _pairs: &mut Pairs,
    _doc: &json::Map,
    _o: &str,
    _report: &mut Vec<String>,
) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(test)]
#[path = "tests/overlay_hooks_tests.rs"]
mod tests;
