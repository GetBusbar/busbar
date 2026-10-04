// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verbs unit's own test-only `SecretOnce` mint (ARCHITECT ruling B, GATE-GREEN, 2026-10-02).
//!
//! `SecretOnce::mint(` is spelled only inside `crates/busbar-core-admin/src` (construction row
//! `token-sealed:secret-once-mint`): the verbs unit is the one place a minted secret's placeholder is
//! built. A dependent crate's tests (the composition root's replay-encoder proof) still need a real
//! placeholder, so this crate mints it here and hands it out; the caller names this function and
//! never the constructor. Compiled only under `cfg(test)` or this crate's `test-support` feature.

use busbar_contract::caps::{AdminVerb, Grant, SecretOnce, UnitKey};

/// `SecretOnce::mint`: the placeholder for one minted secret, with the constructor's own arguments.
pub fn secret_once(
    admin: &Grant<AdminVerb>,
    nonce: u128,
    unit: UnitKey,
    target: impl Into<String>,
) -> SecretOnce {
    SecretOnce::mint(admin, nonce, unit, target)
}
