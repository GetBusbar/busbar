// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

pub(crate) type FailedStep = &'static str;

/// Rotates the log file at `path`, keeping `keep` archives (see `crate::cold::host::rotate`).
pub(crate) fn rotate(path: &Path, keep: u32) -> (bool, Vec<FailedStep>) {
    crate::cold::host::rotate(path, keep)
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
