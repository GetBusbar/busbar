// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-ARGGUARD (ABI-MIN3-INTERFACE §14): JUDGE per extracted destination; refused calls never reach the server.
//! The plane-mcp corpus arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn judge_per_extracted_destination() {
    todo!("owner: W1-K8A (C-MCP-ARGGUARD)")
}
