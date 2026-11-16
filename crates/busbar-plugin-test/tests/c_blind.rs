// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-BLIND (ABI-MIN3-INTERFACE §14): No other plugin's identity reaches a plugin, and a stamp name appears only
//! inside `plugin_diag` (round 34). The fixtures fail and log with declared ERROR numbers.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn no_stamp_name_reaches_a_config_view_or_need_result() {
    todo!("owner: W1-L2 (C-BLIND)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn no_stamp_name_reaches_a_deliver_batch_or_render_snapshot() {
    todo!("owner: W1-K8C (C-BLIND)")
}

#[test]
#[ignore = "owner: W1-K8D"]
fn a_stamp_name_appears_only_inside_plugin_diag() {
    todo!("owner: W1-K8D (C-BLIND)")
}
