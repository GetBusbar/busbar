// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SPAN-RECORDS (ABI-MIN3-INTERFACE §14): FB_SPAN_RECORDS (§8.5; A9 + L7 + K8). The export-otlp arm runs in its
//! repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C"]
fn span_records_core_arms() {
    todo!("owner: W1-K8C (C-SPAN-RECORDS)")
}
