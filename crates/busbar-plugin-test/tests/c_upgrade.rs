// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UPGRADE (ABI-MIN3-INTERFACE §14): Server-side WebSocket upgrade (§12.27; K8 + L9 + C1C). The
//! transport-http/-ws image arms belong to W2-SW-TRANSPORT and are filed on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn upgrade_fixture_arm() {
    todo!("owner: W1-K8A (C-UPGRADE)")
}
