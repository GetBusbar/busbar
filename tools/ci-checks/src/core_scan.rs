// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The section 15.8 core scan (red-proof stub).

use std::collections::BTreeSet;
use std::path::Path;

use super::Outcome;

pub(crate) fn module_values(_text: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn identity_hits(
    _source: &str,
    _words: &BTreeSet<String>,
) -> Result<Vec<(usize, String)>, String> {
    todo!("W1-X1")
}
pub(crate) fn core_scan(_root: &Path, _args: &[String]) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn test_file(_file: &Path) -> bool {
    todo!("W1-X1")
}
