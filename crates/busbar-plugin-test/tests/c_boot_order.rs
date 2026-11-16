// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-BOOT-ORDER (ABI-MIN3-INTERFACE §14): A store whose password references a secret that references a second
//! secret: open order second, first, store, rest; a cycle is CONFIG.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; re-checked 2026-11-16, HOST-LAYERING: Registry::boot_plan (plugin-loader instance.rs:779) and the walk (busbar-kernel appbuild/boot_walk.rs:135, unit-tested by tests/boot_walk_tests.rs secrets_open_before_their_store_and_the_rest_after_it) are on dev, but the booted order and the store's migrate SECRET Need run through min3_boot.rs, which this crate cannot reach; Harness's MemBinder (src/suites/harness.rs:246-314) answers no secret() and holds no sugars, so boot_plan finds no dependency edge through it"]
fn secrets_open_before_their_store() {
    todo!("owner: W1-K9 (C-BOOT-ORDER)")
}
