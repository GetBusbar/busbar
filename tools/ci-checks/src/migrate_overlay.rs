// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 overlay's checks (MIGRATE-ON-BOOT r42 §7 "Separation", §9 C1 reds (f2), (n4)(4),
//! (o7)): red, the scans land with the next commit.

use std::path::Path;

/// The 1.5.5 overlay's name, path and variable.
pub(crate) const WORDS: [&str; 3] = [
    "BUSBAR_CONFIG_OVERLAY",
    "busbar-overlay.json",
    "DEFAULT_OVERLAY_FILENAME",
];
/// The overlay key only the overlay-shape pass may name.
pub(crate) const HOOK_KEY: &str = "global_hooks";
/// (f2) the sentence the upgrade page carries.
pub(crate) const ONE_BOOT: &str = "1.6.0 checks the overlay only on this one upgrade boot";
/// (o7) the rollback's order: F first, else B.
pub(crate) const ROLLBACK: &str =
    "move `<o>.busbar-folding` back to `<o>` if it exists, else move `<o>.1.5.5` back";

pub(crate) fn separation(_root: &Path) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

pub(crate) fn hook_keys(_root: &Path) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

pub(crate) fn docs(root: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(root.join("docs/migration-1.6.md"))
        .map_err(|error| format!("docs/migration-1.6.md: {error}"))?;
    Ok(docs_findings(&text))
}

pub(crate) fn docs_findings(_text: &str) -> Vec<String> {
    Vec::new()
}

pub(crate) fn word_sites(_text: &str, _words: &[&str], _idents: bool) -> Vec<(usize, String)> {
    Vec::new()
}

#[cfg(test)]
#[path = "migrate_overlay_tests.rs"]
mod tests;
