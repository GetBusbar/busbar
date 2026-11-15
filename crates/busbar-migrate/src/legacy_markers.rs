// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1a, the pre-1.5.5 markers (MIGRATE-ON-BOOT §A3 1a). Red stub: nothing is detected yet.

use busbar_contract::yaml::Value;

use crate::Refusal;

/// 1a over the interpolated document.
pub(crate) fn refuse(doc: &Value) -> Result<(), Refusal> {
    let _ = detect(doc);
    Ok(())
}

/// v1.5.5 `detect_legacy_markers`.
pub(crate) fn detect(doc: &Value) -> Vec<String> {
    let _ = doc;
    Vec::new()
}

#[cfg(test)]
#[path = "tests/legacy_markers_tests.rs"]
mod tests;
