// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUTBOUND-SETTINGS (ABI-MIN3-INTERFACE §14): Forwarded provider keys into every binding's `settings` (§12.10
//! item 3).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boots the shipped Azure template, a jwt-bearer provider and an auth-sigv4 binding through MIN-3 auth bindings: plugin-loader adapters/auth.rs chain_req is still todo!() (OUTSTANDING row 1), W2-SW-AUTH is blocked (!2481) and auth-oauth/auth-sigv4 are plugin-repo images; the boot arm then moves into crates/busbar (crates/busbar is a bin crate, so nothing can depend on it) beside tests/kernel_application/central2_provider_boot.rs"]
fn forwarded_keys_reach_the_bindings() {
    todo!("owner: W1-K9 (C-OUTBOUND-SETTINGS)")
}
