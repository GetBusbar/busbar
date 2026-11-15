// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-OUTAGE (ABI-MIN3-INTERFACE §14): Login outages render the hosted 503 page with Retry-After (L5 + K8).
//! The auth-github and auth-oidc arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn login_outage_pages() {
    todo!("owner: W1-K8B (C-LOGIN-OUTAGE)")
}
