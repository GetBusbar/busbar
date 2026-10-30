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
        needed: 0,
    }
}

/// The host buffer a call is checked against: its address and capacity.
const BUF_CAP: u64 = 16;

fn check(out: &ResolveOut, buf: &[u8; 16]) -> Result<(), Fault> {
    check_resolve(out, buf.as_ptr() as usize, BUF_CAP)
}

fn red(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(Fault { rule, field })
}

/// RED (S3): a READY answer that names no material: a secret resolved to nothing is no secret,
/// and the host would hand an empty credential on (fail-closed: refused, never resolved empty).
#[test]
fn ready_with_no_secret_faults() {
    assert_eq!(
        check(&base_out(), &[0; 16]),
        red(Rule::Missing, "resolve.secret_on_ready")
    );
}

/// RED (S12): READY material in the host's buffer that is not flagged secret.
#[test]
fn ready_with_material_not_flagged_secret_faults() {
    let buf = [0u8; 16];
    let mut out = base_out();
    out.secret.ptr = buf.as_ptr();
    out.secret.len = 4;
    assert_eq!(
        check(&out, &buf),
        red(Rule::Missing, "resolve.secret.flags")
    );
}

/// A zeroed `out` on PENDING and on REFUSED passes: those outcomes carry no answer.
#[test]
fn zeroed_pending_and_refused_pass() {
    for o in [Outcome::Pending, Outcome::Refused] {
        let mut out = base_out();
        out.head.outcome = RawOutcome(o as u8);
        assert_eq!(check(&out, &[0; 16]), Ok(()), "{o:?}");
    }
}

/// RED: `secret.len > 0` with a NULL `secret.ptr`.
#[test]
fn null_ptr_with_nonzero_len_faults() {
    let mut out = base_out();
    out.secret.len = 4;
    assert_eq!(
        check(&out, &[0; 16]),
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
        check(&out, &[0; 16]),
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
        check(&out, &[0; 16]),
        red(Rule::Contradiction, "resolve.secret_on_failed")
    );
}

/// RED: a FAILED answer that leaves `error_kind` UNSET.
#[test]
fn failed_with_unset_error_kind_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    assert_eq!(
        check(&out, &[0; 16]),
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
        check(&out, &[0; 16]),
        red(Rule::UnknownCode, "resolve.error_kind")
    );
}

/// RED: a READY answer that sets `error_kind`.
#[test]
fn ready_with_error_kind_faults() {
    let mut out = base_out();
    out.error_kind = ERROR_KIND_UNAVAILABLE;
    assert_eq!(
        check(&out, &[0; 16]),
        red(Rule::Contradiction, "resolve.error_kind_on_ready")
    );
}

/// RED: a READY answer naming material and a lease: the material is the host's, never leased.
#[test]
fn ready_with_material_under_a_lease_faults() {
    let buf = [0u8; 16];
    let mut out = base_out();
    out.secret.ptr = buf.as_ptr();
    out.secret.len = 1;
    out.head.lease = 3;
    assert_eq!(check(&out, &buf), red(Rule::Contradiction, "resolve.lease"));
}

/// RED: a READY answer with no secret material that sets a lease.
#[test]
fn ready_with_no_material_with_lease_faults() {
    let mut out = base_out();
    out.head.lease = 7;
    assert_eq!(
        check(&out, &[0; 16]),
        red(Rule::Contradiction, "resolve.lease")
    );
}

/// GREEN: READY material written at the start of the host's buffer, within its capacity.
#[test]
fn ready_with_material_in_the_host_buffer_passes() {
    let buf = [0u8; 16];
    let mut out = base_out();
    out.secret.ptr = buf.as_ptr();
    out.secret.len = 16;
    out.secret.flags = BLOB_SECRET;
    assert_eq!(check(&out, &buf), Ok(()));
}

/// RED: READY material at an address the host never lent (plugin memory the host would copy).
#[test]
fn ready_with_material_outside_the_host_buffer_faults() {
    let buf = [0u8; 16];
    let plugin = [0u8; 4];
    let mut out = base_out();
    out.secret.ptr = plugin.as_ptr();
    out.secret.len = 4;
    assert_eq!(
        check(&out, &buf),
        red(Rule::Foreign, "resolve.secret_outside_buffer")
    );
}

/// RED: READY material longer than the buffer the host lent.
#[test]
fn ready_with_material_over_the_capacity_faults() {
    let buf = [0u8; 16];
    let mut out = base_out();
    out.secret.ptr = buf.as_ptr();
    out.secret.len = 17;
    assert_eq!(check(&out, &buf), red(Rule::OverCap, "resolve.needed"));
}

/// GREEN: the short-buffer answer: FAILED, `needed` above the capacity, nothing written.
#[test]
fn short_answer_passes() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.needed = BUF_CAP + 1;
    assert_eq!(check(&out, &[0; 16]), Ok(()));
}

/// RED: a short answer that also names an `error_kind` (one answer, one meaning).
#[test]
fn short_answer_with_error_kind_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.needed = BUF_CAP + 1;
    out.error_kind = ERROR_KIND_UNAVAILABLE;
    assert_eq!(
        check(&out, &[0; 16]),
        red(Rule::Contradiction, "resolve.error_kind_on_short")
    );
}

/// RED: a short answer asking for no more than the host gave (a wasted re-call).
#[test]
fn short_answer_within_the_capacity_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.needed = BUF_CAP;
    assert_eq!(
        check(&out, &[0; 16]),
        red(Rule::WastedRecall, "resolve.needed")
    );
}

/// RED: `needed` on a READY answer.
#[test]
fn needed_on_ready_faults() {
    let mut out = base_out();
    out.needed = BUF_CAP + 1;
    assert_eq!(
        check(&out, &[0; 16]),
        red(Rule::NeededNotFailed, "resolve.needed")
    );
}

/// RED: `needed` past the hard max.
#[test]
fn needed_over_the_hard_max_faults() {
    let mut out = base_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.needed = HARD_MAX_BYTES + 1;
    assert_eq!(check(&out, &[0; 16]), red(Rule::OverMax, "resolve.needed"));
}
