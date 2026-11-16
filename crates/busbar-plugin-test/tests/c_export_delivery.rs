// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-DELIVERY (ABI-MIN3-INTERFACE §14): The export chunk contract (round 33).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A9"]
fn custody_and_delivery_records() {
    todo!("owner: W1-A9 (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-A9"]
fn confirm_and_delivery_describe_rules() {
    todo!("owner: W1-A9 (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-L7"]
fn custody_answer_rules() {
    todo!("owner: W1-L7 (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn delivery_ids_resends_and_acks() {
    todo!("owner: W1-K8C (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-K3"]
fn backoff_waits_and_breaker() {
    todo!("owner: W1-K3 (C-EXPORT-DELIVERY)")
}
