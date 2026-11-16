// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUT-REWRITE (ABI-MIN3-INTERFACE §14): A plugin rewrites `out.ptr`/`cap`: the host keeps its own OutBuf
//! authority.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn a_rewritten_out_ptr_or_cap_is_ignored() {
    todo!("owner: W1-H1 (C-OUT-REWRITE)")
}
