// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALIAS (ABI-MIN3-INTERFACE §14): `former_names` words, `NameConflict`, the plugins.yaml manifest job and
//! `module:` resolution (rounds 9, 11, 12).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): no test constructor for Registry<N> (Needs impl, ConfigBinder, Ceilings, a static Host) and no second-identity MIN-3 fixture image exist in busbar-plugin-test on dev"]
fn former_names_match_and_name_conflict_at_add() {
    todo!("owner: W1-L2 (C-ALIAS)")
}

#[test]
#[ignore = "owner: W1-X1; blocked (re-checked on dev 2026-11-16): a busbar-ci-checks job and fixture, not a plugin-test arm; no job on dev"]
fn the_plugins_yaml_manifest_job() {
    todo!("owner: W1-X1 (C-ALIAS)")
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn every_word_resolves_module_in_old_and_current_configs() {
    todo!("owner: W1-K9 (C-ALIAS)")
}
