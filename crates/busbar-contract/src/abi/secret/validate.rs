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
mod tests {
    use super::*;
    use crate::abi::mechanism::call::{AbiStr, Blob, Envelope, OutHead, RawOutcome, BLOB_SECRET};

    fn base_out() -> ResolveOut {
        ResolveOut {
            head: OutHead {
                size: std::mem::size_of::<ResolveOut>() as u32,
                outcome: RawOutcome(Outcome::Ready as u8),
                _reserved: [0; 3],
                wake_at_ns: 0,
                lease: 0,
                error: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                envelope: Envelope {
                    metrics: std::ptr::null(),
                    metrics_len: 0,
                    diags: std::ptr::null(),
                    diags_len: 0,
                },
                extensions: Blob {
                    ptr: std::ptr::null(),
                    len: 0,
                    fmt: 0,
                    flags: 0,
                },
            },
            secret: Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: 0,
                flags: 0,
            },
            error_kind: ERROR_KIND_UNSET,
            _reserved: 0,
        }
    }

    /// A READY answer with a well-formed absent secret passes.
    #[test]
    fn ready_with_no_secret_passes() {
        assert!(check_resolve(&base_out()).is_ok());
    }

    /// RED: `secret.len > 0` with a NULL `secret.ptr` is FAULT.
    #[test]
    fn null_ptr_with_nonzero_len_faults() {
        let mut out = base_out();
        out.secret.len = 4;
        assert_eq!(
            check_resolve(&out),
            Err(Fault("resolve: secret.len > 0 with a NULL secret.ptr"))
        );
    }

    /// RED: a secret longer than the hard max is FAULT.
    #[test]
    fn oversized_secret_faults() {
        let byte = 0u8;
        let mut out = base_out();
        out.secret.ptr = &byte as *const u8;
        out.secret.len = (HARD_MAX_BYTES + 1) as usize;
        out.secret.flags = BLOB_SECRET;
        out.head.lease = 1;
        assert_eq!(
            check_resolve(&out),
            Err(Fault("resolve: secret.len exceeds the hard max"))
        );
    }

    /// RED: a FAILED answer carrying a secret blob is FAULT (secret-bearing answers are always
    /// secret; a FAILED one must carry no material at all).
    #[test]
    fn failed_with_secret_faults() {
        let byte = 0u8;
        let mut out = base_out();
        out.head.outcome = RawOutcome(Outcome::Failed as u8);
        out.error_kind = super::super::ERROR_KIND_UNAVAILABLE;
        out.secret.ptr = &byte as *const u8;
        out.secret.len = 1;
        assert_eq!(
            check_resolve(&out),
            Err(Fault(
                "resolve: a FAILED answer must not carry a secret blob"
            ))
        );
    }

    /// RED: a FAILED answer that leaves `error_kind` UNSET is FAULT.
    #[test]
    fn failed_with_unset_error_kind_faults() {
        let mut out = base_out();
        out.head.outcome = RawOutcome(Outcome::Failed as u8);
        assert_eq!(
            check_resolve(&out),
            Err(Fault("resolve: a FAILED answer must set error_kind"))
        );
    }

    /// H4 RED: `error_kind` past the known `0..=5` range is FAULT, even on a well-formed FAILED
    /// answer.
    #[test]
    fn error_kind_out_of_range_faults() {
        let mut out = base_out();
        out.head.outcome = RawOutcome(Outcome::Failed as u8);
        out.error_kind = ERROR_KIND_INTERNAL + 1;
        assert_eq!(
            check_resolve(&out),
            Err(Fault("resolve: error_kind exceeds the known 0..=5 range"))
        );
    }

    /// H4 RED: a READY answer must not set `error_kind`.
    #[test]
    fn ready_with_error_kind_faults() {
        let mut out = base_out();
        out.error_kind = super::super::ERROR_KIND_UNAVAILABLE;
        assert_eq!(
            check_resolve(&out),
            Err(Fault("resolve: a READY answer must not set error_kind"))
        );
    }

    /// H4 RED: a READY answer with secret material but no lease is FAULT.
    #[test]
    fn ready_with_material_without_lease_faults() {
        let byte = 0u8;
        let mut out = base_out();
        out.secret.ptr = &byte as *const u8;
        out.secret.len = 1;
        out.head.lease = 0;
        assert_eq!(
            check_resolve(&out),
            Err(Fault(
                "resolve: a READY answer with secret material must set a non-zero lease"
            ))
        );
    }

    /// H4 RED: a READY answer with no secret material must not set a lease.
    #[test]
    fn ready_with_no_material_with_lease_faults() {
        let mut out = base_out();
        out.head.lease = 7;
        assert_eq!(
            check_resolve(&out),
            Err(Fault(
                "resolve: a READY answer with no secret material must not set a lease"
            ))
        );
    }
}
