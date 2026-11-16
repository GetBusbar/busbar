// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-ADMIN (ABI-MIN3-INTERFACE §14): Plane admin verbs on `admin_listen` with scopes, 404 on the data
//! listener, openapi equal to 1.5.5's (§12.11).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C; blocked (re-checked on dev 2026-11-16): re-pinned by owner ruling A-1 (AGREED: plane admin verbs answer only at /api/v1/admin/kinds/<kind>/instances/<instance>/ops/..., the 1.5.5 absolute paths 404), so the arm asserts A-1 paths, not the §14 text's; serving them needs plane-mcp/plane-a2a admin verbs mounted from MIN-3 planes (K8C/K10, OUTSTANDING rows 3, 4) and a plane double"]
fn admin_verbs_on_admin_listen() {
    todo!("owner: W1-K8C (C-PLANE-ADMIN)")
}
