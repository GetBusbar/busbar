// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/auth/caller_credential.rs`.

use super::*;

/// THE CALLER'S CREDENTIAL IS ONE ZEROISING BUFFER (Q128 arch u26 #11; THE DESIGN §6, "zeroised at
/// exit"): a clone rides the request as an extension and into a unit, and each one shares the same
/// bytes, so dropping the last holder wipes the only plaintext there is.
///
/// RED before the fix: the credential was a plain `#[derive(Clone)]` `String`, so every clone was
/// its own heap copy of the plaintext, none of them wiped on drop.
#[test]
fn a_cloned_caller_credential_shares_one_zeroising_buffer() {
    let held = CallerCredential::for_test("sk-caller-credential");
    let clone = held.clone();
    assert_eq!(
        held.buffer_for_test(),
        clone.buffer_for_test(),
        "a clone shares the one buffer, never a second plaintext copy"
    );
    assert_eq!(clone.reveal_for_test(), "sk-caller-credential");
    assert_eq!(format!("{clone:?}"), "CallerCredential(<present>)");
}
