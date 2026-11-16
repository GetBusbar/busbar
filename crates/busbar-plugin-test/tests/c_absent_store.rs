// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ABSENT-STORE (ABI-MIN3-INTERFACE §14): A 1.5.5 config with no `store:` block boots on the FB_EPHEMERAL store.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn no_store_block_boots_on_the_ephemeral_store() {
    todo!("owner: W1-K9 (C-ABSENT-STORE)")
}
