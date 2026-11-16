// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TOKEN-SPACE (ABI-MIN3-INTERFACE §14): a session token passed to `resume`, and a chain token passed to a
//! session method or `cancel` with a live session at the same index, FAULT BadToken or no-op and never cross-drop.
//! The token layout arm is W1-A1's (merged); the slot arm is the shim's.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::types::{Token, TOKEN_SESSION};

#[test]
fn chain_and_session_tokens_of_one_slot_differ_in_bit_63_only() {
    let chain: Token = (2 << 32) | 5;
    let session = chain | TOKEN_SESSION;
    assert_eq!(TOKEN_SESSION, 1 << 63);
    assert_ne!(chain, session);
    assert_eq!(session & !TOKEN_SESSION, chain);
    assert_eq!((chain >> 32) & 0x7fff_ffff, 2, "generation");
    assert_eq!(chain & 0xffff_ffff, 5, "index");
}

#[test]
#[ignore = "owner: W1-A3"]
fn a_token_of_the_other_space_never_cross_drops() {
    todo!("owner: W1-A3 (C-TOKEN-SPACE)")
}
