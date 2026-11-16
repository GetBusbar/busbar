// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CLOSE-LOG (ABI-MIN3-INTERFACE §14): A secret logged in `close` is attributed to the closing instance and
//! scrubbed; its slot is not reused until the close returns.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn a_close_log_line_is_attributed_and_scrubbed_and_the_slot_waits() {
    todo!("owner: W1-L2 (C-CLOSE-LOG)")
}
