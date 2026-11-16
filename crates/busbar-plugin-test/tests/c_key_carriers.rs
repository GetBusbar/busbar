// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-KEY-CARRIERS (ABI-MIN3-INTERFACE §14): KEY_CARRIERS (§12.8).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: end-to-end arm needs the gateway request path with auth-header outbound-only; core arm is covered by busbar-kernel issued/tests.rs a_key_is_read_from_the_first_carrier_in_order"]
fn key_carriers() {
    todo!("blocked: end-to-end arm needs the gateway request path with auth-header outbound-only; core arm is covered by busbar-kernel issued/tests.rs a_key_is_read_from_the_first_carrier_in_order (C-KEY-CARRIERS)")
}
