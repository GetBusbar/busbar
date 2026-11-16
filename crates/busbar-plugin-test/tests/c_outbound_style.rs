// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUTBOUND-STYLE (ABI-MIN3-INTERFACE §14): Deferred `{"$style": ..}` bindings resolve to the one declaring
//! fixture (one process since MIGRATE-ON-BOOT r42).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): $style resolution needs two auth fixtures booted through the MIN-3 auth port (plugin-loader adapters/auth.rs chain_req todo!(), OUTSTANDING row 1; W2-SW-AUTH blocked) and the boot's resolve_styles over them; busbar-migrate styles.rs and the crates/busbar kernel_application tests carry the config halves, and the boot arm then moves into crates/busbar (crates/busbar is a bin crate, so nothing can depend on it)"]
fn deferred_styles_resolve_to_one_declaring_fixture() {
    todo!("owner: W1-K9 (C-OUTBOUND-STYLE)")
}
