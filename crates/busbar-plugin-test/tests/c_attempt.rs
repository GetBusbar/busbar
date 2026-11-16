// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ATTEMPT (ABI-MIN3-INTERFACE §14): ATTEMPT(RETRY, FC_CONTEXT_LENGTH), ATT_HARD, ATT_RELAY, ATT_DECLINE and
//! walk exhaustion.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A; blocked (re-checked on dev 2026-11-16): the K8A tail (plane audit actions, Events::resight, serve_lines/recover_work/cost wiring; OUTSTANDING row 5) and K10 plane serving (row 3) are not on dev"]
fn attempt_answers_drive_the_walk() {
    todo!("owner: W1-K8A (C-ATTEMPT)")
}
