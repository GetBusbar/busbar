// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MSG-FLAGS (ABI-MIN3-INTERFACE §14): Transport STREAM_BODY / `emit(E_BODY)` carry MSG_TEXT/MSG_BINARY/MSG_FIN
//! through a fragmented message.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L9"]
fn message_flags_cross_a_fragmented_message() {
    todo!("owner: W1-L9 (C-MSG-FLAGS)")
}
