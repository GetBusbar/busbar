// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-KEY-CARRIERS (ABI-MIN3-INTERFACE §14): KEY_CARRIERS (§12.8).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K6; re-checked 2026-11-16, W2-SW-AUTH: the end-to-end arm needs the gateway request path with auth-header outbound-only, and the live request path is the old AuthMiddleware::run_chain_on_request_path (busbar-kernel auth/mod.rs:784); chain_run and route_chain have no production caller until the auth switch-over (draft MR !2481); the core arm is covered by busbar-kernel issued/tests.rs a_key_is_read_from_the_first_carrier_in_order"]
fn key_carriers() {
    todo!("blocked: end-to-end arm needs the gateway request path with auth-header outbound-only; core arm is covered by busbar-kernel issued/tests.rs a_key_is_read_from_the_first_carrier_in_order (C-KEY-CARRIERS)")
}
