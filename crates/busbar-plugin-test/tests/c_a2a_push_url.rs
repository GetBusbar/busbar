// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-A2A-PUSH-URL (ABI-MIN3-INTERFACE §14): Push URLs refused at set time and at delivery (§12.9). The plane-a2a
//! arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A; blocked (re-checked on dev 2026-11-16): the K8A tail (plane audit actions, Events::resight, serve_lines/recover_work/cost wiring; OUTSTANDING row 5) and K10 plane serving (row 3) are not on dev"]
fn push_urls_are_judged_at_set_and_delivery() {
    todo!("owner: W1-K8A (C-A2A-PUSH-URL)")
}
