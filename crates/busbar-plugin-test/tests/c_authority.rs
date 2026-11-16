// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUTHORITY (ABI-MIN3-INTERFACE §14): An h2 request with `:authority` and no `host` reaches
//! `verify`/`verify_io` with `authority` set.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B; blocked (re-checked on dev 2026-11-16): the K8B head-authority to verify path was not found on dev (not traced in depth)"]
fn an_h2_authority_reaches_verify() {
    todo!("owner: W1-K8B (C-AUTHORITY)")
}
