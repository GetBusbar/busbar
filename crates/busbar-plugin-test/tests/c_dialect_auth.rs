// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DIALECT-AUTH (ABI-MIN3-INTERFACE §14): D_DIALECT_AUTH templates and per-dialect bindings (§12.18; rounds 14,
//! 15, 17). The plane arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K6; blocked (re-checked on dev 2026-11-16): the K6 credential cache / dialect-auth core arms need kernel wiring that is not on dev"]
fn dialect_auth_core_arms() {
    todo!("owner: W1-K6 (C-DIALECT-AUTH)")
}
