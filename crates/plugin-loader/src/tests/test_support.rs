// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST ONLY: the artifact table this crate's tests locate fixtures by. Compiled under `cfg(test)`
//! and under the `test-support` feature; never in a shipped build.

/// The golden artifact names this crate's tests locate on disk, read from
/// `tests/fixtures/plugin_artifacts.txt` (data, not code: the loader names no plugin instance).
const PLUGIN_ARTIFACTS: &str = include_str!("../../tests/fixtures/plugin_artifacts.txt");

/// One artifact name from [`PLUGIN_ARTIFACTS`], by key. Panics on a missing key: a fixture that
/// lost a row must fail the test that needed it, never hand it an empty name.
pub fn artifact(key: &str) -> &'static str {
    PLUGIN_ARTIFACTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/plugin_artifacts.txt has no `{key}` row"))
}
