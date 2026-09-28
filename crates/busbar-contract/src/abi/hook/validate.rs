// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ANSWER VALIDATORS FOR THE HOOK KIND (ARCHITECT RULING, 2026-09-28, all kinds): "each kind's
//! Out-validation is a PURE fn in `abi/<kind>/` beside its shapes ... uses `u64` math, has no
//! statics, and ships RED tests, one per rule, each failing if its check is removed. M1's
//! dispatcher calls it; no host re-implements it." Nothing dispatches through this yet (M3-wire);
//! this is the validator M1 will call.
//!
//! SEH FIX-FORWARD RULINGS (ARCHITECT, 2026-09-27) applied here: H1 (`decide`/`transform` must set
//! EXACTLY one verb bit ON READY — [`Outcome::Failed`]/`Pending`/`Refused` carry no verb, per
//! [`super::TransformOut`]'s doc, so the check only fires on READY; an unknown verb bit is FAULT
//! too), H2 (a `serve` `headers_out_len` above 128 is FAULT), H3 (the short-buffer answer, per
//! RULING M-SB — [`Outcome::Failed`]'s doc, this kind's own instance of the one mechanism-wide
//! rule, every written/needed helper), H4 (a lease is required exactly when a READY off-path
//! answer carries material). The M-SB REFINEMENT (m3-inputs.md) governs `decide`'s and
//! `transform`'s `out`s, each a multi-dimension answer (three and two host-buffer dimensions
//! respectively): a joint short-buffer FAILED answer is legal as long as at least one dimension's
//! `needed_*` exceeds its own cap, even where another dimension's `needed_*` fits.

use super::{
    ConfigureOut, DecideOut, DescribeOut, ServeOut, StatusOut, TransformOut, VERB_ABSTAIN,
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use crate::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome};

/// Why a validator refused an `out` — FAULT, never a safe default
/// ([`Outcome::Fault`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault(pub &'static str);

/// The hard per-answer byte cap this kind's validators enforce. ASSUMPTION (M3-SHAPES): no
/// specific number is stated for hook; 16 MiB matches the inbound cap set for a comparable
/// sans-IO backend (SANSIO-LDAP, `m3-inputs.md`'s OWNER SIGN-OFF batch). `order_buf` is counted in
/// `u32` SLOTS, not bytes, so it is checked against a slot cap instead.
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// The hard cap on `order_buf`'s slot count (`u32` entries, not bytes).
pub const HARD_MAX_ORDER_SLOTS: u64 = 65536;
/// H2: the hard cap on `serve`'s `headers_out_len` — twice the 64-header cap (name, value pairs).
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// H1: `decide`'s exactly-one-verb bits (excludes [`VERB_HAS_REJECT_STATUS`], which is an
/// independent presence bit, not one of the verbs).
const DECIDE_VERB_MASK: u32 = VERB_PREFER | VERB_ABSTAIN | VERB_REJECT | VERB_RESTRICT;
/// H1: `transform`'s exactly-one-verb bits.
const TRANSFORM_VERB_MASK: u32 = VERB_REWRITE | VERB_ABSTAIN | VERB_REJECT;

fn check_blob(null_msg: &'static str, oversize_msg: &'static str, b: &Blob) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(Fault(null_msg));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(Fault(oversize_msg));
    }
    Ok(())
}

/// H4: a lease (memory class iv) is required exactly when a READY answer carries material, and
/// forbidden when it does not. Non-READY outcomes are unconstrained here.
fn check_lease(
    missing_msg: &'static str,
    spurious_msg: &'static str,
    outcome: RawOutcome,
    lease: u64,
    has_material: bool,
) -> Result<(), Fault> {
    if outcome.0 != (Outcome::Ready as u8) {
        return Ok(());
    }
    if has_material && lease == 0 {
        return Err(Fault(missing_msg));
    }
    if !has_material && lease != 0 {
        return Err(Fault(spurious_msg));
    }
    Ok(())
}

/// H1: `verbs & mask` must set exactly one bit, else FAULT. Callers gate this to READY: `verbs`
/// carries no meaning on `Failed`/`Pending`/`Refused` (`out.verbs`'s doc; OLD `Failed` maps to the
/// mechanism's own [`Outcome::Failed`] rather than a verb bit).
fn check_exactly_one_verb(verbs: u32, mask: u32, msg: &'static str) -> Result<(), Fault> {
    if (verbs & mask).count_ones() != 1 {
        return Err(Fault(msg));
    }
    Ok(())
}

/// H1: a `verbs` bit outside `mask | VERB_HAS_REJECT_STATUS` is FAULT. Callers gate this to
/// READY, same as [`check_exactly_one_verb`].
fn check_unknown_verb_bits(verbs: u32, mask: u32, msg: &'static str) -> Result<(), Fault> {
    if verbs & !(mask | VERB_HAS_REJECT_STATUS) != 0 {
        return Err(Fault(msg));
    }
    Ok(())
}

/// Validates one host-buffer dimension's `written`/`needed` LOCAL rules (capacity, the
/// write-then-need contradiction, H3's FAILED-only rule, and the hard max) — everything except
/// "does `needed` justify a re-call", which for a multi-dimension `out` is a JOINT rule across
/// every dimension (the M-SB REFINEMENT; see [`check_joint_short_answer`]).
#[allow(clippy::too_many_arguments)]
fn check_dim_local(
    cap: usize,
    written: usize,
    needed: usize,
    hard_max: u64,
    failed: bool,
    written_exceeds_cap: &'static str,
    written_and_needed: &'static str,
    needed_without_failed: &'static str,
    needed_exceeds_u32_max: &'static str,
    needed_exceeds_hard_max: &'static str,
) -> Result<(), Fault> {
    if written > cap {
        return Err(Fault(written_exceeds_cap));
    }
    if written > 0 && needed != 0 {
        return Err(Fault(written_and_needed));
    }
    if needed != 0 {
        if !failed {
            return Err(Fault(needed_without_failed));
        }
        if needed as u64 > u32::MAX as u64 {
            return Err(Fault(needed_exceeds_u32_max));
        }
        if needed as u64 > hard_max {
            return Err(Fault(needed_exceeds_hard_max));
        }
    }
    Ok(())
}

/// [`check_dim_local`] for `order` (slot-counted; no `u32::MAX` arm — 1.5.5 never named one for
/// this dimension, only the (smaller) slot hard max).
fn check_order_dim_local(
    cap: usize,
    written: usize,
    needed: usize,
    failed: bool,
) -> Result<(), Fault> {
    if written > cap {
        return Err(Fault("order_written exceeds order_cap"));
    }
    if written > 0 && needed != 0 {
        return Err(Fault(
            "a successful order write must not also claim more is needed",
        ));
    }
    if needed != 0 {
        if !failed {
            return Err(Fault("order_needed is non-zero without a FAILED outcome"));
        }
        if needed as u64 > HARD_MAX_ORDER_SLOTS {
            return Err(Fault("order_needed exceeds the hard max slot count"));
        }
    }
    Ok(())
}

/// M-SB REFINEMENT (m3-inputs.md, ARCHITECT 2026-09-27): a multi-dimension `out`'s joint
/// short-buffer rule. Only meaningful once every dimension's LOCAL rules already hold (called
/// after [`check_dim_local`]/[`check_order_dim_local`] on every dimension). Skipped outright when
/// the outcome isn't FAILED, or when no dimension claims `needed`. Otherwise: FAULT unless AT
/// LEAST ONE dimension's `needed` exceeds its own `cap` — a dimension that fits may still report
/// its (non-zero) full size without wasting the call, as long as some other dimension is why the
/// call is short.
fn check_joint_short_answer(
    failed: bool,
    dims: &[(usize, usize)],
    msg: &'static str,
) -> Result<(), Fault> {
    if !failed {
        return Ok(());
    }
    if !dims.iter().any(|&(needed, _cap)| needed != 0) {
        return Ok(());
    }
    if !dims.iter().any(|&(needed, cap)| needed > cap) {
        return Err(Fault(msg));
    }
    Ok(())
}

/// [`VERB_HAS_REJECT_STATUS`](super::VERB_HAS_REJECT_STATUS) must be the only reject-status
/// source, and must itself only accompany a REJECT verb: `reject_status` is meaningless without
/// the bit, so a non-zero `reject_status` with the bit unset is FAULT (a plugin cannot smuggle a
/// status the kernel would apply by accident); the bit set without [`VERB_REJECT`] is FAULT too
/// (there is no reject to carry a status).
fn check_reject_status(verbs: u32, reject_status: u16) -> Result<(), Fault> {
    if reject_status != 0 && (verbs & VERB_HAS_REJECT_STATUS) == 0 {
        return Err(Fault(
            "reject_status is non-zero without VERB_HAS_REJECT_STATUS",
        ));
    }
    if (verbs & VERB_HAS_REJECT_STATUS) != 0 && (verbs & VERB_REJECT) == 0 {
        return Err(Fault("VERB_HAS_REJECT_STATUS is set without VERB_REJECT"));
    }
    Ok(())
}

/// Validates `decide`'s `out` against the capacities [`super::DecideIn`] gave the plugin.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_decide(
    out: &DecideOut,
    reject_message_cap: usize,
    restrict_tags_cap: usize,
    order_cap: usize,
) -> Result<(), Fault> {
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    if ready {
        // H1: exactly one of PREFER|ABSTAIN|REJECT|RESTRICT, and no bit outside the known set.
        check_exactly_one_verb(
            out.verbs,
            DECIDE_VERB_MASK,
            "decide: verbs must set exactly one of PREFER|ABSTAIN|REJECT|RESTRICT",
        )?;
        check_unknown_verb_bits(
            out.verbs,
            DECIDE_VERB_MASK,
            "decide: verbs sets a bit outside PREFER|ABSTAIN|REJECT|RESTRICT|HAS_REJECT_STATUS",
        )?;
    }
    check_reject_status(out.verbs, out.reject_status)?;
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    check_dim_local(
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
        HARD_MAX_BYTES,
        failed,
        "decide: reject_message_written exceeds reject_message_cap",
        "decide: a successful reject_message write must not also claim more is needed",
        "decide: reject_message_needed is non-zero without a FAILED outcome",
        "decide: reject_message_needed exceeds u32::MAX",
        "decide: reject_message_needed exceeds the kind's hard max",
    )?;
    check_dim_local(
        restrict_tags_cap,
        out.restrict_tags_written,
        out.restrict_tags_needed,
        HARD_MAX_BYTES,
        failed,
        "decide: restrict_tags_written exceeds restrict_tags_cap",
        "decide: a successful restrict_tags write must not also claim more is needed",
        "decide: restrict_tags_needed is non-zero without a FAILED outcome",
        "decide: restrict_tags_needed exceeds u32::MAX",
        "decide: restrict_tags_needed exceeds the kind's hard max",
    )?;
    check_order_dim_local(order_cap, out.order_written, out.order_needed, failed)?;
    check_joint_short_answer(
        failed,
        &[
            (out.reject_message_needed, reject_message_cap),
            (out.restrict_tags_needed, restrict_tags_cap),
            (out.order_needed, order_cap),
        ],
        "decide: a FAILED short-buffer answer must have at least one needed_* exceed its cap",
    )
}

/// Validates `transform`'s `out` against the capacities [`super::DecideIn`] gave the plugin.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_transform(
    out: &TransformOut,
    reject_message_cap: usize,
    rewrite_cap: usize,
) -> Result<(), Fault> {
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    if ready {
        // H1: exactly one of REWRITE|ABSTAIN|REJECT, and no bit outside the known set.
        check_exactly_one_verb(
            out.verbs,
            TRANSFORM_VERB_MASK,
            "transform: verbs must set exactly one of REWRITE|ABSTAIN|REJECT",
        )?;
        check_unknown_verb_bits(
            out.verbs,
            TRANSFORM_VERB_MASK,
            "transform: verbs sets a bit outside REWRITE|ABSTAIN|REJECT|HAS_REJECT_STATUS",
        )?;
    }
    check_reject_status(out.verbs, out.reject_status)?;
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    check_dim_local(
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
        HARD_MAX_BYTES,
        failed,
        "transform: reject_message_written exceeds reject_message_cap",
        "transform: a successful reject_message write must not also claim more is needed",
        "transform: reject_message_needed is non-zero without a FAILED outcome",
        "transform: reject_message_needed exceeds u32::MAX",
        "transform: reject_message_needed exceeds the kind's hard max",
    )?;
    check_dim_local(
        rewrite_cap,
        out.rewrite_written,
        out.rewrite_needed,
        HARD_MAX_BYTES,
        failed,
        "transform: rewrite_written exceeds rewrite_cap",
        "transform: a successful rewrite write must not also claim more is needed",
        "transform: rewrite_needed is non-zero without a FAILED outcome",
        "transform: rewrite_needed exceeds u32::MAX",
        "transform: rewrite_needed exceeds the kind's hard max",
    )?;
    check_joint_short_answer(
        failed,
        &[
            (out.reject_message_needed, reject_message_cap),
            (out.rewrite_needed, rewrite_cap),
        ],
        "transform: a FAILED short-buffer answer must have at least one needed_* exceed its cap",
    )
}

/// Validates `notify`'s `out` (the shared [`OutHead`]; `notify` reads nothing back beyond it).
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_notify(out: &OutHead) -> Result<(), Fault> {
    if out.outcome.0 == (Outcome::Failed as u8) && out.error.len > 0 && out.error.ptr.is_null() {
        return Err(Fault("notify: error.len > 0 with a NULL error.ptr"));
    }
    Ok(())
}

/// Validates `configure`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_configure(out: &ConfigureOut, pushed_version: u64) -> Result<(), Fault> {
    if out.head.outcome.0 == (Outcome::Ready as u8) && out.acked_version != pushed_version {
        return Err(Fault(
            "configure: a READY answer must ack the pushed version",
        ));
    }
    Ok(())
}

/// Validates `status`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    check_blob(
        "status: status.len > 0 with a NULL status.ptr",
        "status: status.len exceeds the hard max",
        &out.status,
    )?;
    check_lease(
        "status: a READY answer with status material must set a non-zero lease",
        "status: a READY answer with no status material must not set a lease",
        out.head.outcome,
        out.head.lease,
        out.status.len > 0,
    )
}

/// Validates `describe`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_describe(out: &DescribeOut) -> Result<(), Fault> {
    check_blob(
        "describe: describe.len > 0 with a NULL describe.ptr",
        "describe: describe.len exceeds the hard max",
        &out.describe,
    )?;
    check_lease(
        "describe: a READY answer with describe material must set a non-zero lease",
        "describe: a READY answer with no describe material must not set a lease",
        out.head.outcome,
        out.head.lease,
        out.describe.len > 0,
    )
}

/// Validates `serve`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    if out.headers_out_len > 0 && out.headers_out.is_null() {
        return Err(Fault("serve: headers_out_len > 0 with a NULL headers_out"));
    }
    // H2: a serve headers_out_len above 2*64 = FAULT (the 64-header cap).
    if out.headers_out_len as u64 > HARD_MAX_HEADERS_OUT_LEN {
        return Err(Fault(
            "serve: headers_out_len exceeds the 128-entry (64-header) cap",
        ));
    }
    check_blob(
        "serve: body.len > 0 with a NULL body.ptr",
        "serve: body.len exceeds the hard max",
        &out.body,
    )?;
    check_lease(
        "serve: a READY answer with headers or a body must set a non-zero lease",
        "serve: a READY answer with no headers and no body must not set a lease",
        out.head.outcome,
        out.head.lease,
        out.headers_out_len > 0 || out.body.len > 0,
    )
}

#[cfg(test)]
mod tests {
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
}
