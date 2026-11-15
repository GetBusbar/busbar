// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-VERDICT-CACHE (ABI-MIN3-INTERFACE §14): The verdict cache (§12.28; K2 + K8), arms (a)-(i). The auth-oidc arm
//! runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn verdict_cache_core_arms() {
    todo!("owner: W1-K8B (C-VERDICT-CACHE)")
}
