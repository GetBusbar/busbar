// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SESSION-DROP (ABI-MIN3-INTERFACE §14): Cancel and close drop every `Session`: drop counter == begin counter.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A4"]
fn cancel_and_close_drop_every_session() {
    todo!("owner: W1-A4 (C-SESSION-DROP)")
}
