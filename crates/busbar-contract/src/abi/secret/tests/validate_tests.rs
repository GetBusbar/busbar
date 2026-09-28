// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
