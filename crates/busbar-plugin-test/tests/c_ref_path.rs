// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REF-PATH (ABI-MIN3-INTERFACE §14): D_REF_PATH bindings and `resolve_refs` (§12.7).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7 (blocked: W1-K7 rest (the binder's resolution and the kernel validate path for this arm are not on dev; OUTSTANDING 'K7-rest' is dispatched separately))"]
fn ref_path_bindings() {
    todo!("owner: W1-K7 (C-REF-PATH)")
}
