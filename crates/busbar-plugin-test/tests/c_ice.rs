// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ICE (ABI-MIN3-INTERFACE §14): Two rendezvous on one media port routed by ufrag; bad MESSAGE-INTEGRITY never a
//! path; PATH_DENIED, unbound SEND_TO, PATH_REBIND.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1B"]
fn rendezvous_checks_route_by_ufrag() {
    todo!("owner: W1-C1B (C-ICE)")
}
