// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PROVIDER-KEYS (ABI-MIN3-INTERFACE §14): The §8.6 provider-key rule, arms (a)-(c) (K7 with L8).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7 + W1-L8; blocked (re-checked on dev 2026-11-16): (a)-(c) need plane fixtures declaring EXT_PROVIDER_KEYS (two reaching one provider) booted as MIN-3 planes (min3_boot and plane serving, OUTSTANDING rows 3, 7-10) and plane-llm's 1.5.5 provider fixtures; the boot arm then moves into crates/busbar (crates/busbar is a bin crate, so nothing can depend on it). The key-form parse runs in busbar-contract provider_keys tests and busbar-kernel config/tests/resolved_provider_tests.rs"]
fn provider_key_rule() {
    todo!("owner: W1-K7 (C-PROVIDER-KEYS)")
}
