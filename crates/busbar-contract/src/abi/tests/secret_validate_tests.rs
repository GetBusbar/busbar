// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret answer validator: one RED test per arm, each asserting its exact rule and field and
//! failing if its check is removed, and the GREEN answers per outcome.

use super::*;
use crate::abi::mechanism::call::{AbiStr, Blob, Envelope, OutHead, RawOutcome, BLOB_SECRET};
use crate::abi::mechanism::check::HARD_MAX_BYTES;
use crate::abi::secret::ERROR_KIND_UNAVAILABLE;

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

fn red(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(Fault { rule, field })
}

/// A READY answer with a well-formed absent secret passes.
#[test]
fn ready_with_no_secret_passes() {
    assert!(check_resolve(&base_out()).is_ok());
}

/// A zeroed `out` on PENDING and on REFUSED passes: those outcomes carry no answer.
#[test]
fn zeroed_pending_and_refused_pass() {
    for o in [Outcome::Pending, Outcome::Refused] {
        let mut out = base_out();
        out.head.outcome = RawOutcome(o as u8);
        assert_eq!(check_resolve(&out), Ok(()), "{o:?}");
    }
}

/// RED: `secret.len > 0` with a NULL `secret.ptr`.
#[test]
fn null_ptr_with_nonzero_len_faults() {
    let mut out = base_out();
    out.secret.len = 4;
    assert_eq!(
        check_resolve(&out),
        red(Rule::NullWithCount, "resolve.secret")
    );
}

/// RED: a secret longer than the hard max.
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
        red(Rule::OverMax, "resolve.secret.len")
    );
}

/// RED: a FAILED answer carrying a secret blob (a FAILED one carries no material at all).
#[test]
fn failed_with_secret_faults() {
    let byte = 0u8;
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.error_kind = ERROR_KIND_UNAVAILABLE;
    out.secret.ptr = &byte as *const u8;
    out.secret.len = 1;
    assert_eq!(
        check_resolve(&out),
        red(Rule::Contradiction, "resolve.secret_on_failed")
    );
}

/// RED: a FAILED answer that leaves `error_kind` UNSET.
#[test]
fn failed_with_unset_error_kind_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    assert_eq!(
        check_resolve(&out),
        red(Rule::Missing, "resolve.error_kind_on_failed")
    );
}

/// RED: `error_kind` past the known `0..=5` range, even on an otherwise well-formed FAILED
/// answer.
#[test]
fn error_kind_out_of_range_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.error_kind = ERROR_KIND_INTERNAL + 1;
    assert_eq!(
        check_resolve(&out),
        red(Rule::UnknownCode, "resolve.error_kind")
    );
}

/// RED: a READY answer that sets `error_kind`.
#[test]
fn ready_with_error_kind_faults() {
    let mut out = base_out();
    out.error_kind = ERROR_KIND_UNAVAILABLE;
    assert_eq!(
        check_resolve(&out),
        red(Rule::Contradiction, "resolve.error_kind_on_ready")
    );
}

/// RED: a READY answer with secret material but no lease.
#[test]
fn ready_with_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = base_out();
    out.secret.ptr = &byte as *const u8;
    out.secret.len = 1;
    out.head.lease = 0;
    assert_eq!(check_resolve(&out), red(Rule::Missing, "resolve.lease"));
}

/// RED: a READY answer with no secret material that sets a lease.
#[test]
fn ready_with_no_material_with_lease_faults() {
    let mut out = base_out();
    out.head.lease = 7;
    assert_eq!(
        check_resolve(&out),
        red(Rule::Contradiction, "resolve.lease_without_material")
    );
}
