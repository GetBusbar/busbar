// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PROVIDER-KEYS (ABI-MIN3-INTERFACE §14): The §8.6 provider-key rule, arms (a)-(c) (K7 with L8).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: the section 8.6 provider-key rule is enforced at boot in the busbar bin crate (K7 with L8); unreachable from busbar-plugin-test"]
fn provider_key_rule() {
    todo!("owner: W1-K7 (C-PROVIDER-KEYS)")
}
