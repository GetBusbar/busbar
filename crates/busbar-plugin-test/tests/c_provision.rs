// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PROVISION (ABI-MIN3-INTERFACE §14): The provisioning mount and the kernel directory (§12.29), a wave-2 mount
//! (W2-K8P).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W2-K8P"]
fn provisioning_core_arms() {
    todo!("owner: W2-K8P (C-PROVISION)")
}
