// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-WARM (ABI-MIN3-INTERFACE §14): 1,000 sequential OPEN -> CLOSE(REUSABLE) on one dest: one DNS lookup, one
//! guard check, one cert resolve.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: needs the connector pool plus DNS/guard/cert-resolve counters in busbar-core-connector, not a dependency of this crate (W1-C1A)"]
fn reusable_opens_resolve_and_judge_once() {
    todo!("owner: W1-C1A (C-POOL-WARM)")
}
