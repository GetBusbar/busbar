// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ISSUED-SHAPE (ABI-MIN3-INTERFACE §14): D_ISSUED_SHAPE describe rules, `IssuedShapes`, minting and
//! `NameConflict` (L5 + K6). The auth-sigv4 arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L5 + W1-K6; blocked (re-checked on dev 2026-11-16): needs the auth-sigv4 image (plugin repo) describing D_ISSUED_KIND through the MIN-3 auth port (plugin-loader adapters/auth.rs chain_req todo!(), OUTSTANDING row 1) and core-admin issue_aws_credential minting over it; busbar-kernel issued/tests.rs covers IssuedShapes::get and for_issuing"]
fn issued_shapes_and_minting() {
    todo!("blocked: arm needs the auth-sigv4 image and core-admin issue_aws_credential minting over a Registry (no sigv4 fixture here); kernel issued/tests.rs covers IssuedShapes::get and for_issuing (C-ISSUED-SHAPE)")
}
