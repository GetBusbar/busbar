// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-A2A-CARD-REDIRECT (ABI-MIN3-INTERFACE §14): Card fetch redirects (§12.14; K8 + C1, WBS rule 10). The
//! plane-a2a arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn card_redirect_core_arms() {
    todo!("owner: W1-K8B (C-A2A-CARD-REDIRECT)")
}
