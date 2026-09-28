// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::call::{AbiStr, Envelope, RawOutcome};

fn head(outcome: Outcome) -> OutHead {
    OutHead {
        size: 0,
        outcome: RawOutcome(outcome as u8),
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
    }
}

fn blob_absent() -> Blob {
    Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: 0,
        flags: 0,
    }
}

/// RED: `written` beyond the given capacity is FAULT.
#[test]
fn written_beyond_cap_faults() {
    assert_eq!(
        check_written_needed(4, 5, 0, false),
        Err(Fault("written exceeds the given capacity"))
    );
}

/// RED: a successful write also claiming `needed` is FAULT.
#[test]
fn written_and_needed_together_faults() {
    assert_eq!(
        check_written_needed(4, 2, 1, false),
        Err(Fault(
            "a successful write must not also claim more is needed"
        ))
    );
}

/// H3 RED: `needed != 0` with an outcome other than FAILED is FAULT.
#[test]
fn needed_without_failed_faults() {
    assert_eq!(
        check_written_needed(4, 0, 8, false),
        Err(Fault("needed is non-zero without a FAILED outcome"))
    );
}

/// RED: `needed <= cap` when nothing was written wastes the one re-call.
#[test]
fn needed_not_larger_than_cap_faults() {
    assert_eq!(
        check_written_needed(4, 0, 4, true),
        Err(Fault("needed <= the given capacity wastes the one re-call"))
    );
}

/// RED: `needed` past the hard max is FAULT.
#[test]
fn needed_past_hard_max_faults() {
    assert_eq!(
        check_written_needed(0, 0, (HARD_MAX_BYTES + 1) as usize, true),
        Err(Fault("needed exceeds the kind's hard max"))
    );
}

/// H6 RED: `needed` past `u32::MAX` is FAULT (checked before the kind's own, smaller, hard
/// max).
#[test]
fn needed_past_u32_max_faults() {
    assert_eq!(
        check_written_needed(0, 0, u32::MAX as usize + 1, true),
        Err(Fault("needed exceeds u32::MAX"))
    );
}

/// The legitimate re-call shape passes: nothing written, `needed` bigger than `cap`, and the
/// outcome is FAILED (the FAILED-only re-call rule: a short buffer writes nothing).
#[test]
fn legitimate_too_small_answer_passes() {
    assert!(check_written_needed(4, 0, 8, true).is_ok());
}

/// RED: `scrape`'s `out` is checked against `cap`.
#[test]
fn scrape_out_checked_against_cap() {
    let out = ScrapeOut {
        head: head(Outcome::Ready),
        written: 10,
        needed: 0,
    };
    assert_eq!(
        check_scrape(&out, 4),
        Err(Fault("written exceeds the given capacity"))
    );
}

/// RED: `status`'s blob with a non-null-required NULL pointer is FAULT.
#[test]
fn status_null_with_len_faults() {
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.len = 4;
    assert_eq!(
        check_status(&out),
        Err(Fault("status: status.len > 0 with a NULL status.ptr"))
    );
}

/// H4 RED: a READY `status` answer with no material but a lease is FAULT (the spurious-lease
/// arm).
#[test]
fn status_ready_no_material_with_lease_faults() {
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_status(&out),
        Err(Fault(
            "status: a READY answer with no status material must not set a lease"
        ))
    );
}

/// H6 RED: `status`'s blob past the hard max is FAULT (the check_blob oversize arm).
#[test]
fn status_oversize_faults() {
    let byte = 0u8;
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.ptr = &byte as *const u8;
    out.status.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_status(&out),
        Err(Fault("status: status.len exceeds the hard max"))
    );
}

/// H4 RED: a READY `status` answer with material but no lease is FAULT.
#[test]
fn status_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.ptr = &byte as *const u8;
    out.status.len = 1;
    assert_eq!(
        check_status(&out),
        Err(Fault(
            "status: a READY answer with status material must set a non-zero lease"
        ))
    );
}

/// H2 RED: `serve`'s `headers_out_len` above the 128-entry cap is FAULT.
#[test]
fn serve_headers_out_len_exceeds_cap_faults() {
    let one = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: &one as *const AbiStr,
        headers_out_len: (HARD_MAX_HEADERS_OUT_LEN + 1) as usize,
        body: blob_absent(),
    };
    assert_eq!(
        check_serve(&out),
        Err(Fault(
            "serve: headers_out_len exceeds the 128-entry (64-header) cap"
        ))
    );
}

/// RED: `serve`'s `headers_out_len > 0` with a NULL pointer is FAULT.
#[test]
fn serve_headers_null_with_len_faults() {
    let out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 1,
        body: blob_absent(),
    };
    assert_eq!(
        check_serve(&out),
        Err(Fault("serve: headers_out_len > 0 with a NULL headers_out"))
    );
}

/// A well-formed `check` answer passes.
#[test]
fn check_out_absent_findings_passes() {
    let out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    assert!(check_check(&out).is_ok());
}

/// H6 RED: `check`'s findings blob with a NULL pointer and a non-zero len is FAULT.
#[test]
fn check_findings_null_with_len_faults() {
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.len = 4;
    assert_eq!(
        check_check(&out),
        Err(Fault("check: findings.len > 0 with a NULL findings.ptr"))
    );
}

/// H6 RED: `check`'s findings blob past the hard max is FAULT (the check_blob oversize arm).
#[test]
fn check_findings_oversize_faults() {
    let byte = 0u8;
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.ptr = &byte as *const u8;
    out.findings.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_check(&out),
        Err(Fault("check: findings.len exceeds the hard max"))
    );
}

/// H6 RED: a READY `check` answer with findings but no lease is FAULT.
#[test]
fn check_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.ptr = &byte as *const u8;
    out.findings.len = 1;
    assert_eq!(
        check_check(&out),
        Err(Fault(
            "check: a READY answer with findings must set a non-zero lease"
        ))
    );
}

/// H6 RED: a READY `check` answer with no findings but a lease is FAULT (the spurious-lease
/// arm).
#[test]
fn check_ready_no_material_with_lease_faults() {
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_check(&out),
        Err(Fault(
            "check: a READY answer with no findings must not set a lease"
        ))
    );
}

/// H6 RED: `serve`'s body blob with a NULL pointer and a non-zero len is FAULT.
#[test]
fn serve_body_null_with_len_faults() {
    let mut out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 0,
        body: blob_absent(),
    };
    out.body.len = 4;
    assert_eq!(
        check_serve(&out),
        Err(Fault("serve: body.len > 0 with a NULL body.ptr"))
    );
}

/// H6 RED: `serve`'s body blob past the hard max is FAULT (the check_blob oversize arm).
#[test]
fn serve_body_oversize_faults() {
    let byte = 0u8;
    let mut out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 0,
        body: blob_absent(),
    };
    out.body.ptr = &byte as *const u8;
    out.body.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_serve(&out),
        Err(Fault("serve: body.len exceeds the hard max"))
    );
}

/// H6 RED: a READY `serve` answer with a body but no lease is FAULT (the missing-lease arm).
#[test]
fn serve_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 0,
        body: blob_absent(),
    };
    out.body.ptr = &byte as *const u8;
    out.body.len = 1;
    assert_eq!(
        check_serve(&out),
        Err(Fault(
            "serve: a READY answer with headers or a body must set a non-zero lease"
        ))
    );
}

/// H6 RED: a READY `serve` answer with no headers and no body but a lease is FAULT (the
/// spurious-lease arm).
#[test]
fn serve_ready_no_material_with_lease_faults() {
    let mut out = ServeOut {
        head: head(Outcome::Ready),
        status_code: 200,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 0,
        body: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_serve(&out),
        Err(Fault(
            "serve: a READY answer with no headers and no body must not set a lease"
        ))
    );
}

/// A well-formed `deliver` answer passes.
#[test]
fn deliver_out_passes() {
    assert!(check_deliver(&head(Outcome::Ready)).is_ok());
}

/// H6 RED: `deliver`'s NULL-error check fires on a FAILED answer with `error.len > 0` and a
/// NULL `error.ptr`.
#[test]
fn deliver_null_error_faults() {
    let mut out = head(Outcome::Failed);
    out.error.len = 4;
    assert_eq!(
        check_deliver(&out),
        Err(Fault("deliver: error.len > 0 with a NULL error.ptr"))
    );
}
