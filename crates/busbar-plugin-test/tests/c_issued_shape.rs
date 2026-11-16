// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ISSUED-SHAPE (ABI-MIN3-INTERFACE §14): D_ISSUED_SHAPE describe rules, `IssuedShapes`, minting and
//! `NameConflict` (L5 + K6). The auth-sigv4 arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: arm needs the auth-sigv4 image and core-admin issue_aws_credential minting over a Registry (no sigv4 fixture here); kernel issued/tests.rs covers IssuedShapes::get and for_issuing"]
fn issued_shapes_and_minting() {
    todo!("blocked: arm needs the auth-sigv4 image and core-admin issue_aws_credential minting over a Registry (no sigv4 fixture here); kernel issued/tests.rs covers IssuedShapes::get and for_issuing (C-ISSUED-SHAPE)")
}
