// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REFUSAL-MAP (ABI-MIN3-INTERFACE §14): Auth kind codes, hook MESSAGE and auth Fail text never reach a plane
//! REFUSAL by default.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8D"]
fn plugin_texts_never_reach_a_plane_refusal() {
    todo!("owner: W1-K8D (C-REFUSAL-MAP)")
}
