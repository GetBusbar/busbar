// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OPENER-REFUSE (ABI-MIN3-INTERFACE §14): Plane `request`/`probe` and transport `begin` refusing: `(None,
//! answer)`, no cancel, no session counted.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: typed session proxies over busbar-ffi Session, W1-A4 kind!)"]
fn refusing_openers_return_no_session_and_no_cancel() {
    todo!("owner: W1-H1 (C-OPENER-REFUSE)")
}
