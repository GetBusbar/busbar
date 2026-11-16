// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LIMITS (ABI-MIN3-INTERFACE §14): Instance limits (§12.22). No `plaintext` arm (rule 14).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7"]
fn limits_config_arms() {
    todo!("owner: W1-K7 (C-LIMITS)")
}

#[test]
#[ignore = "owner: W1-K8D"]
fn timeout_ms_and_max_inflight_at_port_call_sites() {
    todo!("owner: W1-K8D (C-LIMITS)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn connect_timeout_ms_at_the_dial() {
    todo!("owner: W1-C1A (C-LIMITS)")
}
