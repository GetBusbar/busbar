// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-KIND (ABI-MIN3-INTERFACE §14): Login kind from describe facts; `browser_login.client_secret` rules;
//! both bits or a bit without `login` is DescribeInvalid.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn login_kind_from_facts() {
    todo!("owner: W1-K8B (C-LOGIN-KIND)")
}
