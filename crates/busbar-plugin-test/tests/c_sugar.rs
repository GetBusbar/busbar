// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SUGAR (ABI-MIN3-INTERFACE §14): Declared FILL/PATH words bind to the declaring instance; undeclared, core,
//! twice-declared and ambiguous words are refused; no shorthand word in core.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7 (blocked: W1-K7 rest (the binder's resolution and the kernel validate path for this arm are not on dev; OUTSTANDING 'K7-rest' is dispatched separately))"]
fn declared_words_bind_and_the_rest_are_refused() {
    todo!("owner: W1-K7 (C-SUGAR)")
}
