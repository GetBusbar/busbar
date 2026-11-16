// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UPSTREAM-AUTH (ABI-MIN3-INTERFACE §14): Upstream bindings (K1 + K6 + K8). The core arms are (d)-(h) and
//! (j)-(l). The image arms (a)-(c) and (i) need plane-mcp, plane-a2a, auth-header and auth-oauth images: owner
//! W2-SW-PLANE, filed on GetBusbar/busbar #217 (WBS delta 4).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B (blocked: the core arms need K6/K8B's upstream binding resolution through the kernel config path with a plane-mcp/a2a image; the images are W2-SW-PLANE, #217)"]
fn core_config_and_refusal_arms() {
    todo!("owner: W1-K8B (C-UPSTREAM-AUTH)")
}
