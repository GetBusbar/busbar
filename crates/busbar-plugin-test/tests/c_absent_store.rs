// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ABSENT-STORE (ABI-MIN3-INTERFACE §14): A 1.5.5 config with no `store:` block boots on the FB_EPHEMERAL store.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; re-checked 2026-11-16, HOST-LAYERING: the boot is crates/busbar/src/root/min3_boot.rs, which this crate cannot depend on, and its configured() still refuses a config with no store block (min3_boot.rs:538-541, store_required); the default store block is written by migrate-on-boot (open MR !2404), and the FB_EPHEMERAL selection rule is covered in busbar-migrate (absent_store.rs, tests/absent_store_tests.rs) and Registry::ephemeral_stores (plugin-loader instance.rs:451); the booted store-memory clauses also need the real store-memory image (plugin repo)"]
fn no_store_block_boots_on_the_ephemeral_store() {
    todo!("owner: W1-K9 (C-ABSENT-STORE)")
}
