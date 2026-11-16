// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STYLE-VOCAB (ABI-MIN3-INTERFACE §14): The outbound style vocabulary (§12.18). The auth arms run in their
//! repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K6"]
fn style_vocabulary_core_arm() {
    todo!("owner: W1-K6 (C-STYLE-VOCAB)")
}
