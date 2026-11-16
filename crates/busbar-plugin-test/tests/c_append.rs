// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-APPEND (ABI-MIN3-INTERFACE §14): File-sink appends (§12.21).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C"]
fn file_sink_appends() {
    todo!("owner: W1-K8C (C-APPEND)")
}
