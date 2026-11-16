// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SUGAR (ABI-MIN3-INTERFACE §14): Declared FILL/PATH words bind to the declaring instance; undeclared, core,
//! twice-declared and ambiguous words are refused; no shorthand word in core.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7; re-checked 2026-11-16: the K7 binder is on dev (busbar-kernel plugin_config/binder.rs, unit-tested in plugin_config/tests.rs), but this crate's Harness binds through MemBinder, which stubs set_sugars/set_ref_schemas and ignores ref_paths (src/suites/harness.rs:246-267, registry lane MR !2680), and the arm runs through the --validate and boot path (min3_boot.rs ref_schemas()/sugars_of(), HOST-LAYERING: boot wiring through the MIN-3 Registry); the declared-word, undeclared-word, twice-declared and ambiguous-instance clauses need fixtures declaring FILL and PATH words through a booted registry (sugars_of reads Registry::sugars() only in min3_boot.rs:585)"]
fn declared_words_bind_and_the_rest_are_refused() {
    todo!("owner: W1-K7 (C-SUGAR)")
}
