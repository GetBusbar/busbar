// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-CHANNEL (ABI-MIN3-INTERFACE §14): DemuxRec, MSG_ASK and DX_* delivery on shared channels (round 18). The
//! plane-mcp arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: DemuxRec/MSG_ASK delivery needs the core plane driver and a plane-mcp image; no such harness in busbar-plugin-test; owner W1-K8A"]
fn demux_ask_and_broadcast_core_arms() {
    todo!("owner: W1-K8A (C-MCP-CHANNEL)")
}
