// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOC-LOAD (ABI-MIN3-INTERFACE §14): 8 workers, 4,000 parked chains: pool misses flat, retained bytes within
//! the cap, a 16 MiB chain in class 3.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: the counting allocator, W1-U1, and the EC2 bench)"]
fn parked_chains_keep_pool_misses_flat() {
    todo!("owner: W1-H1 (C-ALLOC-LOAD)")
}
