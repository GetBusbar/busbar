// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOW-DEST (ABI-MIN3-INTERFACE §14): A K9 core-config fixture: core's resolved private providers are allowed
//! (round 18).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; re-checked 2026-11-16, HOST-LAYERING: the rule is on dev (busbar-migrate allow_dest.rs with tests/allow_dest_tests.rs; the guard in busbar-kernel config/tests/advanced_destinations_tests.rs), but the arm's boot ('after boot an upstream exchange under EGRESS_PROVIDER is admitted by the guard' and a plane fixture's migrate envelope) runs through min3_boot.rs, which busbar-plugin-test cannot reach (boot wiring through the MIN-3 Registry, crate layering); migrate-on-boot is open MR !2404"]
fn core_resolved_private_providers_are_allowed() {
    todo!("owner: W1-K9 (C-ALLOW-DEST)")
}
