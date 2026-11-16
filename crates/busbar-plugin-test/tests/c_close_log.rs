// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CLOSE-LOG (ABI-MIN3-INTERFACE §14): A secret logged in `close` is attributed to the closing instance and
//! scrubbed; its slot is not reused until the close returns.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): the Registry (Harness) and a second-identity image now exist, but no fixture logs a secret from close (the probe keeps no Host in its Drop) and the slot-not-reused-until-close-returns half is not observable: SlotTable and SlotLease are registry internals with no public reuse probe"]
fn a_close_log_line_is_attributed_and_scrubbed_and_the_slot_waits() {
    todo!("owner: W1-L2 (C-CLOSE-LOG)")
}
