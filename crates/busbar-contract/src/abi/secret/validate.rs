// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ANSWER VALIDATORS FOR THE SECRET KIND (ARCHITECT RULING, 2026-09-28, all kinds): "each kind's
//! Out-validation is a PURE fn in `abi/<kind>/` beside its shapes ... uses `u64` math, has no
//! statics, and ships RED tests, one per rule, each failing if its check is removed. M1's
//! dispatcher calls it; no host re-implements it." Nothing dispatches through this yet (M3-wire);
//! this is the validator M1 will call.
//!
//! SEH FIX-FORWARD RULING H4 (ARCHITECT, 2026-09-27): a lease (memory class iv) is required
//! exactly when a READY answer carries material, and forbidden when it does not; `error_kind` must
//! stay in the known `0..=5` range and must be `ERROR_KIND_UNSET` on a READY answer.

use super::{ResolveOut, ERROR_KIND_INTERNAL, ERROR_KIND_UNSET};
use crate::abi::mechanism::call::Outcome;

/// Why a validator refused an `out` — FAULT, never a safe default
/// ([`Outcome::Fault`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault(pub &'static str);

/// The hard per-answer byte cap this kind's validators enforce (the ruling's "every
/// `needed_<count>` <= that kind's hard max, else FAULT"). ASSUMPTION (M3-SHAPES): no specific
/// number is stated for secret; 16 MiB matches the inbound cap set for a comparable sans-IO
/// backend (SANSIO-LDAP, `m3-inputs.md`'s OWNER SIGN-OFF batch).
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Validates `resolve`'s `out`. Pure, `u64` math, no statics.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_resolve(out: &ResolveOut) -> Result<(), Fault> {
    // A count (`secret.len`) > 0 with a NULL pointer is FAULT.
    if out.secret.len > 0 && out.secret.ptr.is_null() {
        return Err(Fault("resolve: secret.len > 0 with a NULL secret.ptr"));
    }
    // needed_bytes (here, the secret's own length) <= the kind's hard max, else FAULT.
    if out.secret.len as u64 > HARD_MAX_BYTES {
        return Err(Fault("resolve: secret.len exceeds the hard max"));
    }
    // H4: error_kind must stay in the known 0..=5 range.
    if out.error_kind as u64 > ERROR_KIND_INTERNAL as u64 {
        return Err(Fault("resolve: error_kind exceeds the known 0..=5 range"));
    }
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    // H4: error_kind must be 0 (UNSET) on a READY answer.
    if ready && out.error_kind != ERROR_KIND_UNSET {
        return Err(Fault("resolve: a READY answer must not set error_kind"));
    }
    // Secret-bearing answers are ALWAYS secret on the host side (ruling): a FAILED answer must
    // never carry material — no plugin-set "sensitive" flag decides this.
    if failed && !out.secret.ptr.is_null() {
        return Err(Fault(
            "resolve: a FAILED answer must not carry a secret blob",
        ));
    }
    // A FAILED answer's error_kind must be set (UNSET is reserved for a Ready answer).
    if failed && out.error_kind == ERROR_KIND_UNSET {
        return Err(Fault("resolve: a FAILED answer must set error_kind"));
    }
    // H4: a lease (class iv) is required exactly when a READY answer carries material.
    let has_material = out.secret.len > 0;
    if ready && has_material && out.head.lease == 0 {
        return Err(Fault(
            "resolve: a READY answer with secret material must set a non-zero lease",
        ));
    }
    if ready && !has_material && out.head.lease != 0 {
        return Err(Fault(
            "resolve: a READY answer with no secret material must not set a lease",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/validate_tests.rs"]
mod tests;
