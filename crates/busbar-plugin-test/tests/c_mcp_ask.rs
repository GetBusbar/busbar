// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-ASK (ABI-MIN3-INTERFACE §14): Random-id STORE/LOOKUP/COMMIT request state (§12.11). The plane-mcp arm
//! runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K10; blocked (re-checked on dev 2026-11-16): STORE/LOOKUP/COMMIT request state (IF §12.11) needs MIN-3 plane serving (K10 remainder and K8A tail, OUTSTANDING rows 3, 5) and a plane-mcp fixture"]
fn mcp_ask_core_arms() {
    todo!("owner: W1-K10 (C-MCP-ASK)")
}
