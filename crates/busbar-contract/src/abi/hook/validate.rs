// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ANSWER VALIDATORS FOR THE HOOK KIND (ARCHITECT RULING, 2026-09-28, all kinds): "each kind's
//! Out-validation is a PURE fn in `abi/<kind>/` beside its shapes ... uses `u64` math, has no
//! statics, and ships RED tests, one per rule, each failing if its check is removed. M1's
//! dispatcher calls it; no host re-implements it." Nothing dispatches through this yet (M3-wire);
//! this is the validator M1 will call.

use super::{ConfigureOut, DecideOut, DescribeOut, ServeOut, StatusOut, TransformOut};
use crate::abi::mechanism::call::{Blob, OutHead, Outcome};

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

fn check_blob(field: &'static str, b: &Blob) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(Fault(field));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(Fault(field));
    }
    Ok(())
}

/// Validates a `may_pend` op's byte `written`/`needed` pair against the capacity the plugin was
/// given: "FAILED with a non-zero `needed_*` that is <= the given capacity is FAULT, because it
/// wastes the one re-call", and `needed_bytes <= u32::MAX` (and this kind's hard max).
fn check_bytes_written_needed(
    field: &'static str,
    cap: usize,
    written: usize,
    needed: usize,
) -> Result<(), Fault> {
    if written > cap {
        return Err(Fault(field));
    }
    if written > 0 && needed != 0 {
        return Err(Fault(field));
    }
    if written == 0 && needed != 0 {
        if needed as u64 > u32::MAX as u64 {
            return Err(Fault(field));
        }
        if needed as u64 > HARD_MAX_BYTES {
            return Err(Fault(field));
        }
        if needed <= cap {
            return Err(Fault(field));
        }
    }
    Ok(())
}

/// Validates `order_written`/`order_needed` (slot-counted, not byte-counted).
fn check_order_written_needed(cap: usize, written: usize, needed: usize) -> Result<(), Fault> {
    if written > cap {
        return Err(Fault("order_written exceeds order_cap"));
    }
    if written > 0 && needed != 0 {
        return Err(Fault(
            "a successful order write must not also claim more is needed",
        ));
    }
    if written == 0 && needed != 0 {
        if needed as u64 > HARD_MAX_ORDER_SLOTS {
            return Err(Fault("order_needed exceeds the hard max slot count"));
        }
        if needed <= cap {
            return Err(Fault("order_needed <= order_cap wastes the one re-call"));
        }
    }
    Ok(())
}

/// [`VERB_HAS_REJECT_STATUS`](super::VERB_HAS_REJECT_STATUS) must be the only reject-status
/// source: `reject_status` is meaningless without it, so a non-zero `reject_status` with the bit
/// unset is FAULT (a plugin cannot smuggle a status the kernel would apply by accident).
fn check_reject_status(verbs: u32, reject_status: u16) -> Result<(), Fault> {
    if reject_status != 0 && (verbs & super::VERB_HAS_REJECT_STATUS) == 0 {
        return Err(Fault(
            "reject_status is non-zero without VERB_HAS_REJECT_STATUS",
        ));
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
    check_reject_status(out.verbs, out.reject_status)?;
    check_bytes_written_needed(
        "decide: reject_message written/needed",
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
    )?;
    check_bytes_written_needed(
        "decide: restrict_tags written/needed",
        restrict_tags_cap,
        out.restrict_tags_written,
        out.restrict_tags_needed,
    )?;
    check_order_written_needed(order_cap, out.order_written, out.order_needed)
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
    check_reject_status(out.verbs, out.reject_status)?;
    check_bytes_written_needed(
        "transform: reject_message written/needed",
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
    )?;
    check_bytes_written_needed(
        "transform: rewrite written/needed",
        rewrite_cap,
        out.rewrite_written,
        out.rewrite_needed,
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
        "status: status.len > 0 with a NULL status.ptr, or oversized",
        &out.status,
    )
}

/// Validates `describe`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_describe(out: &DescribeOut) -> Result<(), Fault> {
    check_blob(
        "describe: describe.len > 0 with a NULL describe.ptr, or oversized",
        &out.describe,
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
    check_blob(
        "serve: body.len > 0 with a NULL body.ptr, or oversized",
        &out.body,
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

    fn decide_out() -> DecideOut {
        DecideOut {
            head: head(Outcome::Ready),
            verbs: 0,
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

    /// The zeroed/default decide answer passes (abstain, nothing written).
    #[test]
    fn empty_decide_out_passes() {
        assert!(check_decide(&decide_out(), 0, 0, 0).is_ok());
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

    /// RED: `order_needed <= order_cap` when nothing was written wastes the one re-call.
    #[test]
    fn order_needed_not_larger_than_cap_faults() {
        let mut out = decide_out();
        out.order_needed = 4;
        assert_eq!(
            check_decide(&out, 0, 0, 4),
            Err(Fault("order_needed <= order_cap wastes the one re-call"))
        );
    }

    /// A legitimate too-small answer (nothing written, `needed` bigger than `cap`) passes.
    #[test]
    fn legitimate_reject_message_too_small_passes() {
        let mut out = decide_out();
        out.reject_message_needed = 64;
        assert!(check_decide(&out, 32, 0, 0).is_ok());
    }

    /// RED: `transform`'s rewrite `written` beyond `rewrite_cap` is FAULT.
    #[test]
    fn transform_rewrite_written_beyond_cap_faults() {
        let out = TransformOut {
            head: head(Outcome::Ready),
            verbs: super::super::VERB_REWRITE,
            reject_status: 0,
            _reserved: 0,
            reject_message_written: 0,
            reject_message_needed: 0,
            rewrite_written: 10,
            rewrite_needed: 0,
        };
        assert_eq!(
            check_transform(&out, 0, 4),
            Err(Fault("transform: rewrite written/needed"))
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
        assert!(check_status(&out).is_err());
    }

    /// RED: `describe`'s blob is null-checked.
    #[test]
    fn describe_null_with_len_faults() {
        let mut out = DescribeOut {
            head: head(Outcome::Ready),
            describe: blob_absent(),
        };
        out.describe.len = 1;
        assert!(check_describe(&out).is_err());
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

    /// A well-formed `notify` answer passes.
    #[test]
    fn notify_out_passes() {
        assert!(check_notify(&head(Outcome::Ready)).is_ok());
    }
}
