// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-CONNECT (ABI-MIN3-INTERFACE §14): Caller connections: CONNECT BEGIN/COMPLETE, refresh, revoke (§12.12;
//! K10 core arms). The auth-oauth and plane-mcp image arms are on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: CONNECT BEGIN/COMPLETE/refresh/revoke core arms need the root connection store (busbar crate), not a busbar-plugin-test dev dep; owner W1-K10"]
fn connect_core_arms() {
    todo!("owner: W1-K10 (C-MCP-CONNECT)")
}
