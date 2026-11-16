// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-GRPC-DEADLINE (ABI-MIN3-INTERFACE §14): H_BUDGET_NS and H_BODY_LEN on the client E_HEAD (round 22). The
//! transport-grpc arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1C"]
fn budget_and_body_length_on_the_client_head() {
    todo!("owner: W1-C1C (C-GRPC-DEADLINE)")
}
