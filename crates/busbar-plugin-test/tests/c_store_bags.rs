// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STORE-BAGS (ABI-MIN3-INTERFACE §14): 1.5.5 store bags convert in the store's own `open` where the default
//! echo would be refused.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9 (blocked: needs 1.5.5 store bags through busbar-migrate plus the stores' own migrate; busbar-migrate is not a dev-dependency here and the per-store P arms live in the plugin repos)"]
fn old_store_bags_convert_in_open() {
    todo!("owner: W1-K9 (C-STORE-BAGS)")
}
