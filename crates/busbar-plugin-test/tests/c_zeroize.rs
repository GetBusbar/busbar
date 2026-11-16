// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE (ABI-MIN3-INTERFACE §14): After a chain that wrote a secret, a FETCH header and a WRITE, the pooled
//! buffers read back all zero.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn chain_buffers_read_back_zero() {
    todo!("owner: W1-H1 (C-ZEROIZE)")
}
