// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STRATEGY-WORD (ABI-MIN3-INTERFACE §14): Strategy words boot unchanged, one implicit instance, and the §12.25
//! refusals.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C; re-checked 2026-11-16: the kernel still names strategy words (config/pools.rs:64-73 and :203 STRATEGY_CHEAPEST/FASTEST/LEAST_BUSY, config/hooks.rs:7 and :253), so the D_WORD move is not landed and the boot and source-scan arms cannot pass; open MR !2672 (strategy words judged after the MIN-3 boot walk, stacked on !2641 W2-SW-HOOK) lands it"]
fn strategy_words_and_refusals() {
    todo!("owner: W1-K8C (C-STRATEGY-WORD)")
}
