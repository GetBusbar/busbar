// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STRATEGY-WORD (ABI-MIN3-INTERFACE §14): Strategy words boot unchanged, one implicit instance, and the §12.25
//! refusals.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C (blocked: the kernel still names strategy words: config/pools.rs STRATEGY_CHEAPEST/FASTEST/LEAST_BUSY and config/hooks.rs:258, so the D_WORD move is not landed and the boot and source-scan arms cannot pass)"]
fn strategy_words_and_refusals() {
    todo!("owner: W1-K8C (C-STRATEGY-WORD)")
}
