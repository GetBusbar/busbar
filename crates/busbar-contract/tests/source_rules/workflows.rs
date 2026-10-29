// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO WORKFLOW SIGNS OR PACKS A PLUGIN (security P0, 2026-10-28). The 1.5 plugin-signing seed was the
//! `BUSBAR_SIGN_KEY` GitHub organisation secret, readable by every repository, and the workflow
//! that used it packed an UNSIGNED tarball whenever the secret was absent. A first-party plugin is
//! released by the release pipeline (#1713), never by a GitHub workflow: no workflow under
//! `.github/workflows/` reads that secret, declares it, builds the packer or packs a plugin.

use std::path::PathBuf;

use crate::walk;

/// A line that hands a workflow the signing seed or packs a plugin, and why it is refused.
const REFUSED: &[(&str, &str)] = &[
    ("secrets.BUSBAR_SIGN_KEY", "reads the plugin-signing secret"),
    ("--bin busbar-plugin-pack", "builds the plugin packer"),
    ("pack --lib", "packs a plugin tarball"),
    // W27 (security.astro:8-9): no GitHub workflow publishes or provenance-signs a release either.
    ("gh release create", "publishes a GitHub release"),
    ("gh release upload", "uploads release assets to GitHub"),
    (
        "slsa-framework/slsa-github-generator",
        "signs release provenance on GitHub",
    ),
];

/// Every workflow file, by its repo-relative path.
fn workflows() -> Vec<(String, String)> {
    let dir: PathBuf = walk::repo().join(".github/workflows");
    let mut files: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{} is readable: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            let rel = format!(
                ".github/workflows/{}",
                p.file_name().unwrap().to_string_lossy()
            );
            let text =
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{rel} is readable: {e}"));
            (rel, text)
        })
        .collect();
    files.sort();
    files
}

#[test]
fn no_workflow_signs_or_packs_unsigned_plugins() {
    let files = workflows();
    assert!(!files.is_empty(), "the workflow scan found no workflow");
    let mut found = Vec::new();
    for (rel, text) in &files {
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with('#') {
                continue;
            }
            // `BUSBAR_SIGN_KEY:` as a YAML key: a declared workflow secret, or an env binding.
            if code.starts_with("BUSBAR_SIGN_KEY:") {
                found.push(format!(
                    "{rel}:{}: declares the plugin-signing secret",
                    n + 1
                ));
            }
            for (needle, why) in REFUSED {
                if code.contains(needle) {
                    found.push(format!("{rel}:{}: {why} (`{needle}`)", n + 1));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a workflow signs or packs plugins; first-party plugins are released by the release \
         pipeline, never with a CI-held key:\n{}",
        found.join("\n")
    );
}
