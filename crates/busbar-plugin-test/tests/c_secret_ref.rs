// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SECRET-REF (ABI-MIN3-INTERFACE §14): Each secret plugin's 1.5.x `check` corpus gives the same verdict through
//! `--validate` with D_REF_SCHEMA.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7; re-checked 2026-11-16: the K7 binder is on dev (busbar-kernel plugin_config/binder.rs, unit-tested in plugin_config/tests.rs), but this crate's Harness binds through MemBinder, which stubs set_sugars/set_ref_schemas and ignores ref_paths (src/suites/harness.rs:246-267, registry lane MR !2680), and the arm runs through the --validate and boot path (min3_boot.rs ref_schemas()/sugars_of(), HOST-LAYERING: boot wiring through the MIN-3 Registry); it also needs the secret-env and secret-file 1.5.x check corpus (plugin repos); the ref-schema refusal itself is covered at kernel level by a_reference_failing_its_secret_instances_ref_schema_is_bad_reference"]
fn the_check_corpus_through_validate() {
    todo!("owner: W1-K7 (C-SECRET-REF)")
}
