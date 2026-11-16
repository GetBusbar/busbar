// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MIGRATE-ADMIT (ABI-MIN3-INTERFACE §14): MIGRATE-ON-BOOT: a store fixture's `open` calling `migrate_admit(2)`
//! with no at-rest key is REFUSED and nothing is written.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: the real migrate_admit host slot is installed only by the busbar root (root/migrate.rs); host_vt.rs leaves it None and busbar-plugin-test cannot depend on busbar; owner W1-K9"]
fn migrate_admit_without_an_at_rest_key_is_refused() {
    todo!("owner: W1-K9 (C-MIGRATE-ADMIT)")
}
