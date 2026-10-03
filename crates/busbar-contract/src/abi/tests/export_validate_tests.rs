// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export answer validators: one RED test per arm, each asserting its exact rule and field and
//! failing if its check is removed, and the GREEN answers per outcome.

use super::*;
use crate::abi::mechanism::call::{AbiStr, Blob, Envelope, RawOutcome};
use crate::abi::mechanism::check::HARD_MAX_BYTES;

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

/// `scrape`'s answer with `written`/`needed` against `cap`, READY or FAILED.
fn scrape(cap: usize, written: usize, needed: usize, failed: bool) -> Result<(), Fault> {
    let outcome = if failed {
        Outcome::Failed
    } else {
        Outcome::Ready
    };
    let out = ScrapeOut {
        head: head(outcome),
        written,
        needed,
    };
    check_scrape(&out, cap)
}

/// RED: `written` beyond the given capacity.
#[test]
fn written_beyond_cap_faults() {
    assert_eq!(scrape(4, 5, 0, false), red(Rule::OverCap, "scrape.bytes"));
}

/// RED: a short answer that also wrote something.
#[test]
fn written_and_needed_together_faults() {
    assert_eq!(
        scrape(4, 2, 8, true),
        red(Rule::WrittenOnShort, "scrape.bytes")
    );
}

/// RED: `needed != 0` on an outcome other than FAILED.
#[test]
fn needed_without_failed_faults() {
    assert_eq!(
        scrape(4, 0, 8, false),
        red(Rule::NeededNotFailed, "scrape.bytes")
    );
}

/// RED: `needed <= cap` with nothing written wastes the one re-call.
#[test]
fn needed_not_larger_than_cap_faults() {
    assert_eq!(
        scrape(4, 0, 4, true),
        red(Rule::WastedRecall, "scrape.bytes")
    );
}

/// RED: `needed` past the hard max.
#[test]
fn needed_past_hard_max_faults() {
    assert_eq!(
        scrape(0, 0, (HARD_MAX_BYTES + 1) as usize, true),
        red(Rule::OverMax, "scrape.bytes")
    );
}

/// The legitimate re-call shape passes: nothing written, `needed` above `cap`, FAILED.
#[test]
fn legitimate_too_small_answer_passes() {
    assert!(scrape(4, 0, 8, true).is_ok());
}

/// RED: `scrape`'s `out` is checked against `cap`.
#[test]
fn scrape_out_checked_against_cap() {
    let out = ScrapeOut {
        head: head(Outcome::Ready),
        written: 10,
        needed: 0,
    };
    assert_eq!(check_scrape(&out, 4), red(Rule::OverCap, "scrape.bytes"));
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

// ── the Statement tail ─────────────────────────────────────────────────────────────────────────

fn tail(streams: &[u8], routes: &[Route]) -> Tail {
    Tail {
        head: crate::abi::mechanism::door::KindTailHead {
            size: core::mem::size_of::<Tail>() as u32,
            _reserved: 0,
        },
        streams: streams.as_ptr(),
        streams_len: streams.len(),
        routes: routes.as_ptr(),
        routes_len: routes.len(),
    }
}

fn s(v: &'static str) -> AbiStr {
    AbiStr {
        ptr: v.as_ptr(),
        len: v.len(),
    }
}

fn route(path: &'static str, method: &'static str, auth: u32) -> Route {
    Route {
        path: s(path),
        method: s(method),
        auth,
        _reserved: 0,
    }
}

#[test]
fn a_well_formed_tail_passes() {
    let routes = [route("/metrics", "GET", super::super::ROUTE_AUTH_KEY)];
    let t = tail(&[0], &routes);
    assert_eq!(check_tail(&t), Ok(()));
    assert_eq!(check_tail_entries(&[0, 1], &routes), Ok(()));
}

#[test]
fn a_tail_list_counted_behind_null_faults() {
    let mut t = tail(&[], &[]);
    t.streams = std::ptr::null();
    t.streams_len = 1;
    assert_eq!(check_tail(&t), red(Rule::NullWithCount, "tail.streams"));
    let mut t = tail(&[], &[]);
    t.routes = std::ptr::null();
    t.routes_len = 1;
    assert_eq!(check_tail(&t), red(Rule::NullWithCount, "tail.routes"));
}

#[test]
fn a_tail_with_more_streams_than_exist_faults() {
    let many = [0u8; 10];
    assert_eq!(
        check_tail(&tail(&many, &[])),
        red(Rule::OverMax, "tail.streams_len")
    );
}

#[test]
fn a_tail_with_too_many_routes_faults() {
    let routes: Vec<Route> = (0..65).map(|_| route("/metrics", "GET", 0)).collect();
    assert_eq!(
        check_tail(&tail(&[], &routes)),
        red(Rule::OverMax, "tail.routes_len")
    );
}

#[test]
fn a_stream_byte_outside_the_frozen_list_faults() {
    assert_eq!(
        check_tail_entries(&[9], &[]),
        red(Rule::UnknownCode, "tail.streams.code")
    );
}

#[test]
fn a_repeated_stream_faults() {
    assert_eq!(
        check_tail_entries(&[1, 1], &[]),
        red(Rule::Contradiction, "tail.streams.repeat")
    );
}

#[test]
fn a_route_text_counted_behind_null_faults() {
    let mut r = route("/metrics", "GET", 0);
    r.path.ptr = std::ptr::null();
    assert_eq!(
        check_tail_entries(&[], &[r]),
        red(Rule::NullWithCount, "tail.routes.path")
    );
    let mut r = route("/metrics", "GET", 0);
    r.method.ptr = std::ptr::null();
    assert_eq!(
        check_tail_entries(&[], &[r]),
        red(Rule::NullWithCount, "tail.routes.method")
    );
}

#[test]
fn a_route_path_not_rooted_faults() {
    assert_eq!(
        check_tail_entries(&[], &[route("metrics", "GET", 0)]),
        red(Rule::Missing, "tail.routes.path.root")
    );
}

#[test]
fn a_route_without_a_method_faults() {
    assert_eq!(
        check_tail_entries(&[], &[route("/metrics", "", 0)]),
        red(Rule::Missing, "tail.routes.method.empty")
    );
}

#[test]
fn a_route_auth_outside_its_vocabulary_faults() {
    assert_eq!(
        check_tail_entries(&[], &[route("/metrics", "GET", 3)]),
        red(Rule::UnknownCode, "tail.routes.auth")
    );
}
