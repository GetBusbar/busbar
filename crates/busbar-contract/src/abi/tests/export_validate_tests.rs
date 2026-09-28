// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export answer validators: one RED test per arm, each asserting its exact rule and field and
//! failing if its check is removed, and the GREEN answers per outcome.

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

fn serve_out(outcome: Outcome) -> ServeOut {
    ServeOut {
        head: head(outcome),
        status_code: 0,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 0,
        body: blob_absent(),
    }
}

fn red(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(Fault { rule, field })
}

/// A zeroed `out` on PENDING and on REFUSED passes every op's check: those outcomes carry no
/// answer beyond the head.
#[test]
fn zeroed_pending_and_refused_pass_every_op() {
    for o in [Outcome::Pending, Outcome::Refused] {
        assert_eq!(check_deliver(&head(o)), Ok(()), "deliver {o:?}");
        let scrape = ScrapeOut {
            head: head(o),
            written: 0,
            needed: 0,
        };
        assert_eq!(check_scrape(&scrape, 0), Ok(()), "scrape {o:?}");
        let status = StatusOut {
            head: head(o),
            status: blob_absent(),
        };
        assert_eq!(check_status(&status), Ok(()), "status {o:?}");
        let check = CheckOut {
            head: head(o),
            findings: blob_absent(),
        };
        assert_eq!(check_check(&check), Ok(()), "check {o:?}");
        assert_eq!(check_serve(&serve_out(o)), Ok(()), "serve {o:?}");
    }
}

/// RED: `written` beyond the given capacity.
#[test]
fn written_beyond_cap_faults() {
    assert_eq!(
        check_written_needed(4, 5, 0, false),
        red(Rule::OverCap, "scrape.written")
    );
}

/// RED: a write that also claims `needed`.
#[test]
fn written_and_needed_together_faults() {
    assert_eq!(
        check_written_needed(4, 2, 1, false),
        red(Rule::WrittenOnShort, "scrape.written_on_short")
    );
}

/// RED: `needed != 0` on an outcome other than FAILED.
#[test]
fn needed_without_failed_faults() {
    assert_eq!(
        check_written_needed(4, 0, 8, false),
        red(Rule::NeededNotFailed, "scrape.needed")
    );
}

/// RED: `needed <= cap` with nothing written wastes the one re-call.
#[test]
fn needed_not_larger_than_cap_faults() {
    assert_eq!(
        check_written_needed(4, 0, 4, true),
        red(Rule::WastedRecall, "scrape.needed_within_cap")
    );
}

/// RED: `needed` past the hard max.
#[test]
fn needed_past_hard_max_faults() {
    assert_eq!(
        check_written_needed(0, 0, (HARD_MAX_BYTES + 1) as usize, true),
        red(Rule::OverMax, "scrape.needed_max")
    );
}

/// RED: `needed` past `u32::MAX` (checked before the kind's own, smaller, hard max).
#[test]
fn needed_past_u32_max_faults() {
    assert_eq!(
        check_written_needed(0, 0, u32::MAX as usize + 1, true),
        red(Rule::OverMax, "scrape.needed_u32")
    );
}

/// The legitimate re-call shape passes: nothing written, `needed` above `cap`, FAILED.
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
    assert_eq!(check_scrape(&out, 4), red(Rule::OverCap, "scrape.written"));
}

/// RED: `status`'s blob with a length behind a NULL pointer.
#[test]
fn status_null_with_len_faults() {
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.len = 4;
    assert_eq!(
        check_status(&out),
        red(Rule::NullWithCount, "status.status")
    );
}

/// RED: a READY `status` answer with no material that sets a lease.
#[test]
fn status_ready_no_material_with_lease_faults() {
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_status(&out),
        red(Rule::Contradiction, "status.lease_without_material")
    );
}

/// RED: `status`'s blob past the hard max.
#[test]
fn status_oversize_faults() {
    let byte = 0u8;
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.ptr = &byte as *const u8;
    out.status.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(check_status(&out), red(Rule::OverMax, "status.status.len"));
}

/// RED: a READY `status` answer with material but no lease.
#[test]
fn status_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.ptr = &byte as *const u8;
    out.status.len = 1;
    assert_eq!(check_status(&out), red(Rule::Missing, "status.lease"));
}

/// RED: `serve`'s `headers_out_len` above the 128-entry cap.
#[test]
fn serve_headers_out_len_exceeds_cap_faults() {
    let one = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let mut out = serve_out(Outcome::Ready);
    out.headers_out = &one as *const AbiStr;
    out.headers_out_len = (HARD_MAX_HEADERS_OUT_LEN + 1) as usize;
    assert_eq!(
        check_serve(&out),
        red(Rule::OverMax, "serve.headers_out_len")
    );
}

/// RED: `serve`'s `headers_out_len > 0` with a NULL pointer.
#[test]
fn serve_headers_null_with_len_faults() {
    let mut out = serve_out(Outcome::Ready);
    out.headers_out_len = 1;
    assert_eq!(
        check_serve(&out),
        red(Rule::NullWithCount, "serve.headers_out")
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

/// RED: `check`'s findings with a length behind a NULL pointer.
#[test]
fn check_findings_null_with_len_faults() {
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.len = 4;
    assert_eq!(
        check_check(&out),
        red(Rule::NullWithCount, "check.findings")
    );
}

/// RED: `check`'s findings past the hard max.
#[test]
fn check_findings_oversize_faults() {
    let byte = 0u8;
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.ptr = &byte as *const u8;
    out.findings.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(check_check(&out), red(Rule::OverMax, "check.findings.len"));
}

/// RED: a READY `check` answer with findings but no lease.
#[test]
fn check_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.findings.ptr = &byte as *const u8;
    out.findings.len = 1;
    assert_eq!(check_check(&out), red(Rule::Missing, "check.lease"));
}

/// RED: a READY `check` answer with no findings that sets a lease.
#[test]
fn check_ready_no_material_with_lease_faults() {
    let mut out = CheckOut {
        head: head(Outcome::Ready),
        findings: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_check(&out),
        red(Rule::Contradiction, "check.lease_without_material")
    );
}

/// RED: `serve`'s body with a length behind a NULL pointer.
#[test]
fn serve_body_null_with_len_faults() {
    let mut out = serve_out(Outcome::Ready);
    out.body.len = 4;
    assert_eq!(check_serve(&out), red(Rule::NullWithCount, "serve.body"));
}

/// RED: `serve`'s body past the hard max.
#[test]
fn serve_body_oversize_faults() {
    let byte = 0u8;
    let mut out = serve_out(Outcome::Ready);
    out.body.ptr = &byte as *const u8;
    out.body.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(check_serve(&out), red(Rule::OverMax, "serve.body.len"));
}

/// RED: a READY `serve` answer with a body but no lease.
#[test]
fn serve_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = serve_out(Outcome::Ready);
    out.body.ptr = &byte as *const u8;
    out.body.len = 1;
    assert_eq!(check_serve(&out), red(Rule::Missing, "serve.lease"));
}

/// RED: a READY `serve` answer with no headers and no body that sets a lease.
#[test]
fn serve_ready_no_material_with_lease_faults() {
    let mut out = serve_out(Outcome::Ready);
    out.head.lease = 7;
    assert_eq!(
        check_serve(&out),
        red(Rule::Contradiction, "serve.lease_without_material")
    );
}

/// A well-formed `deliver` answer passes.
#[test]
fn deliver_out_passes() {
    assert!(check_deliver(&head(Outcome::Ready)).is_ok());
}

/// RED: a FAILED `deliver` answer's error text with a length behind a NULL pointer.
#[test]
fn deliver_null_error_faults() {
    let mut out = head(Outcome::Failed);
    out.error.len = 4;
    assert_eq!(
        check_deliver(&out),
        red(Rule::NullWithCount, "deliver.error")
    );
}
