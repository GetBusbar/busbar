// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `no-known-red` (TST-8, busbar#280): no ratchet, baseline or allow-failure list of failing tests exists in
//! the tree. A failing test is fixed, or becomes an OWNER ACCEPT row inside the test itself (TST-6); it is never
//! tolerated by a list a job reads beside it. The retired list lived at `ci/known-red/` (the CDT-KNOWN-RED
//! ratchet, deleted by owner ruling: AGREED "The known-red ratchet is deleted"), so that directory, or any file
//! in it, is a finding.

use std::path::Path;

use crate::Outcome;

/// Where the retired known-red ratchet kept its lists.
pub(crate) const KNOWN_RED_DIR: &str = "ci/known-red";

/// The findings for a tree: one per entry under [`KNOWN_RED_DIR`], or one for the directory itself when it is
/// present but empty.
pub(crate) fn no_known_red(root: &Path) -> Outcome {
    let dir = root.join(KNOWN_RED_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|error| format!("{KNOWN_RED_DIR}: {error}"))? {
        let entry = entry.map_err(|error| format!("{KNOWN_RED_DIR}: {error}"))?;
        entries.push(entry.file_name().to_string_lossy().into_owned());
    }
    entries.sort();
    if entries.is_empty() {
        return Ok(vec![finding(KNOWN_RED_DIR)]);
    }
    Ok(entries
        .iter()
        .map(|name| finding(&format!("{KNOWN_RED_DIR}/{name}")))
        .collect())
}

fn finding(path: &str) -> String {
    format!(
        "{path}: a known-red list tolerates failing tests (TST-8, busbar#280); fix each test or make it an \
         OWNER ACCEPT row inside the test (TST-6), and delete the list"
    )
}
