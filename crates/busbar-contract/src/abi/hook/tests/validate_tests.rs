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

/// A single valid verb (ABSTAIN), nothing else set: the baseline every non-verb-focused test
/// builds on.
fn decide_out() -> DecideOut {
    DecideOut {
        head: head(Outcome::Ready),
        verbs: VERB_ABSTAIN,
        reject_status: 0,
        _reserved: 0,
        reject_message_written: 0,
        reject_message_needed: 0,
        restrict_tags_written: 0,
        restrict_tags_needed: 0,
        order_written: 0,
        order_needed: 0,
    }
}

fn transform_out() -> TransformOut {
    TransformOut {
        head: head(Outcome::Ready),
        verbs: VERB_REWRITE,
        reject_status: 0,
        _reserved: 0,
        reject_message_written: 0,
        reject_message_needed: 0,
        rewrite_written: 0,
        rewrite_needed: 0,
    }
}

/// The baseline decide answer (single ABSTAIN verb, nothing written) passes.
#[test]
fn decide_out_baseline_passes() {
    assert!(check_decide(&decide_out(), 0, 0, 0).is_ok());
}

/// H1 RED: zero verb bits set on READY is FAULT (was `empty_decide_out_passes`; the
/// exactly-one-verb rule makes the all-zero READY answer illegal, not a pass case).
#[test]
fn decide_zero_verbs_faults() {
    let mut out = decide_out();
    out.verbs = 0;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "decide: verbs must set exactly one of PREFER|ABSTAIN|REJECT|RESTRICT"
        ))
    );
}

/// H1 RED: two verb bits set together on READY is FAULT.
#[test]
fn decide_two_verbs_faults() {
    let mut out = decide_out();
    out.verbs = VERB_PREFER | VERB_RESTRICT;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "decide: verbs must set exactly one of PREFER|ABSTAIN|REJECT|RESTRICT"
        ))
    );
}

/// H1 RED: a `verbs` bit outside the known set is FAULT even though exactly one dimension
/// verb is also set.
#[test]
fn decide_unknown_verb_bit_faults() {
    let mut out = decide_out();
    out.verbs = VERB_ABSTAIN | (1 << 30);
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "decide: verbs sets a bit outside PREFER|ABSTAIN|REJECT|RESTRICT|HAS_REJECT_STATUS"
        ))
    );
}

/// H1 PASS: a FAILED answer with `verbs == 0` is legal — `verbs` carries no meaning outside
/// READY.
#[test]
fn decide_failed_zero_verbs_passes() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.verbs = 0;
    assert!(check_decide(&out, 0, 0, 0).is_ok());
}

/// H1 RED: `transform`'s exactly-one-verb rule FAULTs on zero bits (READY).
#[test]
fn transform_zero_verbs_faults() {
    let mut out = transform_out();
    out.verbs = 0;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault(
            "transform: verbs must set exactly one of REWRITE|ABSTAIN|REJECT"
        ))
    );
}

/// H1 RED: `transform`'s exactly-one-verb rule FAULTs on 2+ bits (READY).
#[test]
fn transform_two_verbs_faults() {
    let mut out = transform_out();
    out.verbs = VERB_REWRITE | VERB_REJECT;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault(
            "transform: verbs must set exactly one of REWRITE|ABSTAIN|REJECT"
        ))
    );
}

/// H1 RED: a `transform` `verbs` bit outside the known set is FAULT.
#[test]
fn transform_unknown_verb_bit_faults() {
    let mut out = transform_out();
    out.verbs = VERB_REWRITE | (1 << 30);
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault(
            "transform: verbs sets a bit outside REWRITE|ABSTAIN|REJECT|HAS_REJECT_STATUS"
        ))
    );
}

/// H1 PASS: a FAILED `transform` answer with `verbs == 0` is legal.
#[test]
fn transform_failed_zero_verbs_passes() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.verbs = 0;
    assert!(check_transform(&out, 0, 0).is_ok());
}

/// RED: `reject_status` set without `VERB_HAS_REJECT_STATUS` is FAULT.
#[test]
fn reject_status_without_bit_faults() {
    let mut out = decide_out();
    out.reject_status = 400;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "reject_status is non-zero without VERB_HAS_REJECT_STATUS"
        ))
    );
}

/// RED: `VERB_HAS_REJECT_STATUS` set without `VERB_REJECT` is FAULT.
#[test]
fn has_reject_status_without_reject_verb_faults() {
    let mut out = decide_out();
    out.verbs = VERB_ABSTAIN | VERB_HAS_REJECT_STATUS;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault("VERB_HAS_REJECT_STATUS is set without VERB_REJECT"))
    );
}

/// RED: `order_written` beyond `order_cap` is FAULT.
#[test]
fn order_written_beyond_cap_faults() {
    let mut out = decide_out();
    out.order_written = 5;
    assert_eq!(
        check_decide(&out, 0, 0, 4),
        Err(Fault("order_written exceeds order_cap"))
    );
}

/// H6 RED: a successful `order` write also claiming `needed` is FAULT.
#[test]
fn order_written_and_needed_together_faults() {
    let mut out = decide_out();
    out.order_written = 2;
    out.order_needed = 1;
    assert_eq!(
        check_decide(&out, 0, 0, 4),
        Err(Fault(
            "a successful order write must not also claim more is needed"
        ))
    );
}

/// H3 RED: `order_needed != 0` with an outcome other than FAILED is FAULT.
#[test]
fn order_needed_without_failed_faults() {
    let mut out = decide_out();
    out.order_needed = 4;
    assert_eq!(
        check_decide(&out, 0, 0, 4),
        Err(Fault("order_needed is non-zero without a FAILED outcome"))
    );
}

/// RED (M-SB REFINEMENT joint rule): `order_needed <= order_cap`, and no other dimension's
/// `needed` exceeds its cap either, so nothing justifies the re-call.
#[test]
fn order_needed_not_larger_than_cap_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.order_needed = 4;
    assert_eq!(
        check_decide(&out, 0, 0, 4),
        Err(Fault(
            "decide: a FAILED short-buffer answer must have at least one needed_* exceed its cap"
        ))
    );
}

/// M-SB REFINEMENT PASS: `order_needed <= order_cap` (fits) is legal when `reject_message`'s
/// `needed` exceeds ITS cap — one dimension's overflow is enough to justify the whole re-call.
#[test]
fn order_needed_fits_while_reject_message_overflows_passes() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = 64;
    out.order_needed = 4;
    assert!(check_decide(&out, 32, 0, 4).is_ok());
}

/// H6 RED: `order_needed` past the hard max slot count is FAULT (the hook needed hard-max
/// arm).
#[test]
fn order_needed_past_hard_max_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.order_needed = (HARD_MAX_ORDER_SLOTS + 1) as usize;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault("order_needed exceeds the hard max slot count"))
    );
}

/// The legitimate too-small answer passes: nothing written, `needed` bigger than `cap`,
/// FAILED (H3 + the M-SB REFINEMENT's single-overflow rule).
#[test]
fn legitimate_reject_message_too_small_passes() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = 64;
    assert!(check_decide(&out, 32, 0, 0).is_ok());
}

/// H6 RED: a successful `reject_message` write also claiming `needed` is FAULT (the
/// check_bytes_written_needed written&needed arm).
#[test]
fn decide_reject_message_written_and_needed_together_faults() {
    let mut out = decide_out();
    out.reject_message_written = 2;
    out.reject_message_needed = 1;
    assert_eq!(
        check_decide(&out, 4, 0, 0),
        Err(Fault(
            "decide: a successful reject_message write must not also claim more is needed"
        ))
    );
}

/// H6 RED: `reject_message_needed != 0` on a non-FAILED outcome is FAULT (the
/// check_bytes_written_needed needed-without-FAILED arm).
#[test]
fn decide_reject_message_needed_without_failed_faults() {
    let mut out = decide_out();
    out.reject_message_needed = 4;
    assert_eq!(
        check_decide(&out, 4, 0, 0),
        Err(Fault(
            "decide: reject_message_needed is non-zero without a FAILED outcome"
        ))
    );
}

/// H6 RED: `decide`'s `reject_message_needed` past `u32::MAX` is FAULT (checked before the
/// kind's own, smaller, hard max).
#[test]
fn decide_reject_message_needed_past_u32_max_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = u32::MAX as usize + 1;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault("decide: reject_message_needed exceeds u32::MAX"))
    );
}

/// H6 RED: `decide`'s `reject_message_needed` past its byte hard max is FAULT (the hook needed
/// hard-max arm, bytes side).
#[test]
fn decide_reject_message_needed_past_hard_max_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "decide: reject_message_needed exceeds the kind's hard max"
        ))
    );
}

/// H6 RED: `decide`'s `restrict_tags_written` beyond `restrict_tags_cap` is FAULT (the first
/// of both restrict_tags arms).
#[test]
fn decide_restrict_tags_written_beyond_cap_faults() {
    let mut out = decide_out();
    out.restrict_tags_written = 5;
    assert_eq!(
        check_decide(&out, 0, 4, 0),
        Err(Fault(
            "decide: restrict_tags_written exceeds restrict_tags_cap"
        ))
    );
}

/// RED (M-SB REFINEMENT joint rule; the second of both restrict_tags arms): `restrict_tags`
/// fits its cap, and nothing else overflows either, so nothing justifies the re-call.
#[test]
fn decide_restrict_tags_needed_not_larger_than_cap_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.restrict_tags_needed = 4;
    assert_eq!(
        check_decide(&out, 0, 4, 0),
        Err(Fault(
            "decide: a FAILED short-buffer answer must have at least one needed_* exceed its cap"
        ))
    );
}

/// RED: `transform`'s rewrite `written` beyond `rewrite_cap` is FAULT.
#[test]
fn transform_rewrite_written_beyond_cap_faults() {
    let mut out = transform_out();
    out.rewrite_written = 10;
    assert_eq!(
        check_transform(&out, 0, 4),
        Err(Fault("transform: rewrite_written exceeds rewrite_cap"))
    );
}

/// H6 RED: `transform`'s reject-message written beyond its cap is FAULT (transform's
/// reject-message arm).
#[test]
fn transform_reject_message_written_beyond_cap_faults() {
    let mut out = transform_out();
    out.reject_message_written = 5;
    assert_eq!(
        check_transform(&out, 4, 0),
        Err(Fault(
            "transform: reject_message_written exceeds reject_message_cap"
        ))
    );
}

/// RED: `configure` answering READY without acking the pushed version is FAULT.
#[test]
fn configure_ready_must_ack_pushed_version() {
    let out = ConfigureOut {
        head: head(Outcome::Ready),
        acked_version: 1,
    };
    assert_eq!(
        check_configure(&out, 2),
        Err(Fault(
            "configure: a READY answer must ack the pushed version"
        ))
    );
}

/// A nack (FAILED) need not ack the pushed version.
#[test]
fn configure_failed_need_not_ack() {
    let out = ConfigureOut {
        head: head(Outcome::Failed),
        acked_version: 0,
    };
    assert!(check_configure(&out, 2).is_ok());
}

/// RED: `status`'s blob is null-checked.
#[test]
fn status_null_with_len_faults() {
    let mut out = StatusOut {
        head: head(Outcome::Ready),
        status: blob_absent(),
    };
    out.status.len = 1;
    assert_eq!(
        check_status(&out),
        Err(Fault("status: status.len > 0 with a NULL status.ptr"))
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

/// H6 RED: a READY `status` answer with no material but a lease is FAULT (the spurious-lease
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

/// RED: `describe`'s blob is null-checked.
#[test]
fn describe_null_with_len_faults() {
    let mut out = DescribeOut {
        head: head(Outcome::Ready),
        describe: blob_absent(),
    };
    out.describe.len = 1;
    assert_eq!(
        check_describe(&out),
        Err(Fault("describe: describe.len > 0 with a NULL describe.ptr"))
    );
}

/// H6 RED: a READY `describe` answer with material but no lease is FAULT (the missing-lease
/// arm).
#[test]
fn describe_ready_material_without_lease_faults() {
    let byte = 0u8;
    let mut out = DescribeOut {
        head: head(Outcome::Ready),
        describe: blob_absent(),
    };
    out.describe.ptr = &byte as *const u8;
    out.describe.len = 1;
    assert_eq!(
        check_describe(&out),
        Err(Fault(
            "describe: a READY answer with describe material must set a non-zero lease"
        ))
    );
}

/// H6 RED: a READY `describe` answer with no material but a lease is FAULT (the
/// spurious-lease arm).
#[test]
fn describe_ready_no_material_with_lease_faults() {
    let mut out = DescribeOut {
        head: head(Outcome::Ready),
        describe: blob_absent(),
    };
    out.head.lease = 7;
    assert_eq!(
        check_describe(&out),
        Err(Fault(
            "describe: a READY answer with no describe material must not set a lease"
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

/// RED: `serve`'s headers are null-checked.
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

/// A well-formed `notify` answer passes.
#[test]
fn notify_out_passes() {
    assert!(check_notify(&head(Outcome::Ready)).is_ok());
}

/// H6 RED: `notify`'s NULL-error check fires on a FAILED answer with `error.len > 0` and a
/// NULL `error.ptr`.
#[test]
fn notify_null_error_faults() {
    let mut out = head(Outcome::Failed);
    out.error.len = 4;
    assert_eq!(
        check_notify(&out),
        Err(Fault("notify: error.len > 0 with a NULL error.ptr"))
    );
}

// ---- SEH follow-up: transform joint short-buffer rule (item 1) ----

/// RED (M-SB REFINEMENT joint rule, `transform`): both `reject_message_needed` and
/// `rewrite_needed` fit their own caps, so nothing justifies the re-call.
#[test]
fn transform_joint_both_dims_fit_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = 4;
    out.rewrite_needed = 4;
    assert_eq!(
        check_transform(&out, 8, 8),
        Err(Fault(
            "transform: a FAILED short-buffer answer must have at least one needed_* exceed its cap"
        ))
    );
}

/// M-SB REFINEMENT PASS (`transform`): `rewrite_needed` fits its cap while
/// `reject_message_needed` overflows its own — one dimension's overflow justifies the whole
/// re-call.
#[test]
fn transform_joint_one_dim_overflows_other_fits_passes() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = 64;
    out.rewrite_needed = 4;
    assert!(check_transform(&out, 32, 8).is_ok());
}

// ---- SEH follow-up: every check_dim_local arm, transform's two dimensions (item 2) ----

/// H6 RED: `transform`'s `reject_message_needed != 0` on a non-FAILED outcome is FAULT.
#[test]
fn transform_reject_message_needed_without_failed_faults() {
    let mut out = transform_out();
    out.reject_message_needed = 4;
    assert_eq!(
        check_transform(&out, 4, 0),
        Err(Fault(
            "transform: reject_message_needed is non-zero without a FAILED outcome"
        ))
    );
}

/// H6 RED: `transform`'s `reject_message_needed` past `u32::MAX` is FAULT.
#[test]
fn transform_reject_message_needed_past_u32_max_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = u32::MAX as usize + 1;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault("transform: reject_message_needed exceeds u32::MAX"))
    );
}

/// H6 RED: `transform`'s `reject_message_needed` past its byte hard max is FAULT.
#[test]
fn transform_reject_message_needed_past_hard_max_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault(
            "transform: reject_message_needed exceeds the kind's hard max"
        ))
    );
}

/// H6 RED: a successful `transform` `reject_message` write also claiming `needed` is FAULT.
#[test]
fn transform_reject_message_written_and_needed_faults() {
    let mut out = transform_out();
    out.reject_message_written = 2;
    out.reject_message_needed = 1;
    assert_eq!(
        check_transform(&out, 4, 0),
        Err(Fault(
            "transform: a successful reject_message write must not also claim more is needed"
        ))
    );
}

/// H6 RED: `transform`'s `rewrite_needed != 0` on a non-FAILED outcome is FAULT.
#[test]
fn transform_rewrite_needed_without_failed_faults() {
    let mut out = transform_out();
    out.rewrite_needed = 4;
    assert_eq!(
        check_transform(&out, 0, 4),
        Err(Fault(
            "transform: rewrite_needed is non-zero without a FAILED outcome"
        ))
    );
}

/// H6 RED: `transform`'s `rewrite_needed` past `u32::MAX` is FAULT.
#[test]
fn transform_rewrite_needed_past_u32_max_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.rewrite_needed = u32::MAX as usize + 1;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault("transform: rewrite_needed exceeds u32::MAX"))
    );
}

/// H6 RED: `transform`'s `rewrite_needed` past its byte hard max is FAULT.
#[test]
fn transform_rewrite_needed_past_hard_max_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.rewrite_needed = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_transform(&out, 0, 0),
        Err(Fault(
            "transform: rewrite_needed exceeds the kind's hard max"
        ))
    );
}

/// H6 RED: a successful `transform` `rewrite` write also claiming `needed` is FAULT.
#[test]
fn transform_rewrite_written_and_needed_faults() {
    let mut out = transform_out();
    out.rewrite_written = 2;
    out.rewrite_needed = 1;
    assert_eq!(
        check_transform(&out, 0, 4),
        Err(Fault(
            "transform: a successful rewrite write must not also claim more is needed"
        ))
    );
}

// ---- SEH follow-up: decide's restrict_tags arms (item 3) ----

/// H6 RED: `decide`'s `restrict_tags_needed != 0` on a non-FAILED outcome is FAULT.
#[test]
fn decide_restrict_tags_needed_without_failed_faults() {
    let mut out = decide_out();
    out.restrict_tags_needed = 4;
    assert_eq!(
        check_decide(&out, 0, 4, 0),
        Err(Fault(
            "decide: restrict_tags_needed is non-zero without a FAILED outcome"
        ))
    );
}

/// H6 RED: `decide`'s `restrict_tags_needed` past `u32::MAX` is FAULT.
#[test]
fn decide_restrict_tags_needed_past_u32_max_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.restrict_tags_needed = u32::MAX as usize + 1;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault("decide: restrict_tags_needed exceeds u32::MAX"))
    );
}

/// H6 RED: `decide`'s `restrict_tags_needed` past its byte hard max is FAULT.
#[test]
fn decide_restrict_tags_needed_past_hard_max_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.restrict_tags_needed = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_decide(&out, 0, 0, 0),
        Err(Fault(
            "decide: restrict_tags_needed exceeds the kind's hard max"
        ))
    );
}

/// H6 RED: a successful `decide` `restrict_tags` write also claiming `needed` is FAULT.
#[test]
fn decide_restrict_tags_written_and_needed_faults() {
    let mut out = decide_out();
    out.restrict_tags_written = 2;
    out.restrict_tags_needed = 1;
    assert_eq!(
        check_decide(&out, 0, 4, 0),
        Err(Fault(
            "decide: a successful restrict_tags write must not also claim more is needed"
        ))
    );
}

// ---- SEH follow-up: item 4 ----

/// H6 RED: `decide`'s `reject_message_written` beyond `reject_message_cap` is FAULT.
#[test]
fn decide_reject_message_written_beyond_cap_faults() {
    let mut out = decide_out();
    out.reject_message_written = 5;
    assert_eq!(
        check_decide(&out, 4, 0, 0),
        Err(Fault(
            "decide: reject_message_written exceeds reject_message_cap"
        ))
    );
}

// ---- SEH follow-up: item 5 ----

/// H6 RED: `describe`'s blob past the hard max is FAULT (the check_blob oversize arm).
#[test]
fn describe_oversize_faults() {
    let byte = 0u8;
    let mut out = DescribeOut {
        head: head(Outcome::Ready),
        describe: blob_absent(),
    };
    out.describe.ptr = &byte as *const u8;
    out.describe.len = (HARD_MAX_BYTES + 1) as usize;
    assert_eq!(
        check_describe(&out),
        Err(Fault("describe: describe.len exceeds the hard max"))
    );
}

// ---- M-SB addendum (item B): a short FAILED answer writes nothing ----

/// RED (M-SB addendum, m3-inputs.md): `decide`'s `reject_message` dimension is short
/// (`needed > cap`), so the WHOLE answer must write nothing — even `restrict_tags`, which
/// itself fits (`needed == 0`) and would otherwise be free to report a partial write.
#[test]
fn decide_short_answer_writes_something_faults() {
    let mut out = decide_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.reject_message_needed = 64;
    out.restrict_tags_written = 2;
    assert_eq!(
        check_decide(&out, 32, 4, 0),
        Err(Fault(
            "decide: a FAILED short-buffer answer must write nothing"
        ))
    );
}

/// RED (M-SB addendum, m3-inputs.md): same rule for `transform` — `rewrite` is short, so
/// `reject_message` (itself fitting) must not have written anything either.
#[test]
fn transform_short_answer_writes_something_faults() {
    let mut out = transform_out();
    out.head.outcome = RawOutcome(Outcome::Failed as u8);
    out.rewrite_needed = 64;
    out.reject_message_written = 2;
    assert_eq!(
        check_transform(&out, 4, 32),
        Err(Fault(
            "transform: a FAILED short-buffer answer must write nothing"
        ))
    );
}
