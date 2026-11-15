// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1d, the 1.5.5 -> 1 step's own passes. Red stub: no pass converts anything yet.

use busbar_contract::yaml::{Pairs, Value};

use crate::{Facts, Refusal};

/// The passes.
pub(crate) fn run(
    root: &mut Pairs,
    resolved: &Value,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    let _ = (root, resolved, facts, report);
    Ok(())
}

#[cfg(test)]
#[path = "tests/migrate_1_6_tests.rs"]
mod tests;
