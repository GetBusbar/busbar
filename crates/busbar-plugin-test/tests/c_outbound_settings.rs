// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUTBOUND-SETTINGS (ABI-MIN3-INTERFACE §14): Forwarded provider keys into every binding's `settings` (§12.10
//! item 3).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: boot-time binding settings forwarding lives in the busbar bin crate (busbar/src/root/migrate.rs, tests/kernel_application/central2_provider_boot.rs), unreachable from busbar-plugin-test; owner W1-K9"]
fn forwarded_keys_reach_the_bindings() {
    todo!("owner: W1-K9 (C-OUTBOUND-SETTINGS)")
}
