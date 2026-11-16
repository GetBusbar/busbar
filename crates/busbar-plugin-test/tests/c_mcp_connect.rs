// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-CONNECT (ABI-MIN3-INTERFACE §14): Caller connections: CONNECT BEGIN/COMPLETE, refresh, revoke (§12.12;
//! K10 core arms). The auth-oauth and plane-mcp image arms are on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K10; blocked (re-checked on dev 2026-11-16): busbar-kernel connections/mod.rs is still the 65-line W0 stub (OUTSTANDING row 3: no CallerConnections impl, no callback route), so CONNECT BEGIN/COMPLETE/refresh/revoke have nothing to drive; plus the auth-oauth and plane-mcp P arms"]
fn connect_core_arms() {
    todo!("owner: W1-K10 (C-MCP-CONNECT)")
}
