// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-FRESH (ABI-MIN3-INTERFACE §14): A fresh pool miss parses as all zero; no secret of an earlier chain
//! is parsed; no `with_capacity`/`set_len`/`MaybeUninit` in `pool.rs` (H1 + A13 + T1).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn a_fresh_miss_parses_as_zero() {
    todo!("owner: W1-H1 (C-ZEROIZE-FRESH)")
}
