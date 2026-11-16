// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-ASK (ABI-MIN3-INTERFACE §14): Random-id STORE/LOOKUP/COMMIT request state (§12.11). The plane-mcp arm
//! runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: STORE/LOOKUP/COMMIT request state (IF 12.11) lives in the kernel/root, not a busbar-plugin-test dev dep; owner W1-K10"]
fn mcp_ask_core_arms() {
    todo!("owner: W1-K10 (C-MCP-ASK)")
}
