// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TOKEN-SPACE (ABI-MIN3-INTERFACE §14): a session token passed to `resume`, and a chain token passed to a
//! session method or `cancel` with a live session at the same index, FAULT BadToken or no-op and never cross-drop.
//! The token layout arm is W1-A1's (merged) and runs here; the slot arm is the shim's.
//!
//! The shim arm runs in busbar-ffi. Its safe host API takes no raw token (a `Session` and a `Chain` carry their
//! own), so a token of the other space can only be forged inside busbar-ffi `src/host.rs`, over a session-kind
//! fixture image there (GetBusbar/busbar#266 part 2; WBS rule 10: the owner's crate):
//!
//! - TEST-VALUE `a_token_of_the_other_space_never_cross_drops`:
//!   `busbar_ffi::host::tests::a_token_of_the_other_space_never_cross_drops` (crates/busbar-ffi/src/host.rs). A
//!   live plane session and a live chain sit at the same index (tokens differing in bit 63 only). The session
//!   token passed to `resume` is FAULT and the chain is not polled; the chain token passed to `piece` and to
//!   `end` is FAULT; the chain token passed to `cancel` drops only its own chain and is a no-op once stale; a
//!   session-space token at a live chain's slot is a no-op. Drop counters show the session and the chain are
//!   never dropped by the other space's token.

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
