// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MIGRATE-ADMIT (ABI-MIN3-INTERFACE §14): MIGRATE-ON-BOOT: a store fixture's `open` calling `migrate_admit(2)`
//! with no at-rest key is REFUSED and nothing is written.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): the MIN-3 host vtable's migrate_admit slot is None (busbar-plugin-abi host_side/host_vt.rs:644, :689) and nothing installs busbar root::migrate::admit_for_host into it, so a MIN-3 store's migrate_admit(2) is refused whatever the key and a green arm would prove nothing; once wired the arm moves into crates/busbar (crates/busbar is a bin crate, so nothing can depend on it). The verdict runs as busbar::root::migrate::tests::the_recoverable_gate_answers_from_the_at_rest_key"]
fn migrate_admit_without_an_at_rest_key_is_refused() {
    todo!("owner: W1-K9 (C-MIGRATE-ADMIT)")
}
