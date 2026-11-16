// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CRYPTO-AWAIT (ABI-MIN3-INTERFACE §14): SCRAM shape: `random` and `crypto` inside a poll.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn random_and_crypto_inside_a_poll() {
    todo!("owner: W1-H1 (C-CRYPTO-AWAIT)")
}
