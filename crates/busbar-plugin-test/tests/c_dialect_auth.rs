// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DIALECT-AUTH (ABI-MIN3-INTERFACE §14): D_DIALECT_AUTH templates and per-dialect bindings (§12.18; rounds 14,
//! 15, 17). The plane arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K6; re-checked 2026-11-16, W2-SW-AUTH: the D_DIALECT_AUTH decode (plugin-loader encode/plane.rs:29, Registry::dialect_auth at instance.rs:492), core's styles (busbar-contract config/dialect_styles.rs) and bind_providers (busbar-kernel auth_bindings/mod.rs:215, unit-tested in auth_bindings/tests.rs) are on dev, but bind_providers has no production caller, so the booted arms wait on the auth switch-over (draft MR !2481) and the plane-llm image (draft MR !2480)"]
fn dialect_auth_core_arms() {
    todo!("owner: W1-K6 (C-DIALECT-AUTH)")
}
