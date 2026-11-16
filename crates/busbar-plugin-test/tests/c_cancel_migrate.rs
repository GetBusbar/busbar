// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-MIGRATE (ABI-MIN3-INTERFACE §14): Read as the open chain (WBS rule 12): the registry's boot future
//! dropped mid-open.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): no test constructor for Registry<N> (Needs impl, ConfigBinder, Ceilings, a static Host) and no second-identity MIN-3 fixture image exist in busbar-plugin-test on dev"]
fn dropping_the_boot_future_mid_open_cancels_once() {
    todo!("owner: W1-L2 (C-CANCEL-MIGRATE)")
}
