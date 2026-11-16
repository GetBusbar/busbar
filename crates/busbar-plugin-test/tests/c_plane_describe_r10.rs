// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-DESCRIBE-R10 (ABI-MIN3-INTERFACE §14): ROUTE_LINE/ROUTE_RECOVERY describe rules (DescribeInvalid) and
//! EMIT/WORK placement (BadRecords).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L8"]
fn route_line_and_route_recovery_rules() {
    todo!("owner: W1-L8 (C-PLANE-DESCRIBE-R10)")
}
