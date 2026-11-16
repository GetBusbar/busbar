// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UPSTREAM-AUTH (ABI-MIN3-INTERFACE §14): Upstream bindings (K1 + K6 + K8). The core arms are (d)-(h) and
//! (j)-(l). The image arms (a)-(c) and (i) need plane-mcp, plane-a2a, auth-header and auth-oauth images: owner
//! W2-SW-PLANE, filed on GetBusbar/busbar #217 (WBS delta 4).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B; re-checked 2026-11-16, W2-SW-AUTH: the core arms (d)-(h) are covered by busbar-kernel auth_bindings/tests.rs, but bind_upstreams (auth_bindings/upstream.rs:139) has no production caller, so the kernel config path does not resolve upstream bindings until the auth switch-over (draft MR !2481); (a)-(c), (i) and (l) need the plane-mcp, plane-a2a, auth-header and auth-oauth images (W2-SW-PLANE, #217, draft MR !2480); (j) and (k) need a plane and an auth image to describe through"]
fn core_config_and_refusal_arms() {
    todo!("owner: W1-K8B (C-UPSTREAM-AUTH)")
}
