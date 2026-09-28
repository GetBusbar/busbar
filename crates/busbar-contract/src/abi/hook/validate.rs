// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S ANSWER VALIDATORS, beside the shapes they judge: one pure `check_<op>` per
//! answer, `u64` math, no statics, each answering the shared [`Fault`] (one [`Rule`] and one
//! distinct field per arm). The dispatcher turns an `Err` into FAULT; no host re-implements a
//! check.
//!
//! Per outcome:
//! * `decide`/`transform` set EXACTLY one verb bit, and no unknown bit, on READY only: FAILED,
//!   PENDING and REFUSED carry no verb ([`super::TransformOut`]'s doc).
//! * The reject-status pairing, every `written <= cap`, and every blob's or list's pointer/length
//!   pairing and size are judged on every outcome (a PENDING or REFUSED `out` the host zeroed
//!   passes them).
//! * A `needed_*` is non-zero only on FAILED, under the short-buffer rule
//!   ([`OutHead`](crate::abi::mechanism::call::OutHead)). `decide` (three host buffers) and
//!   `transform` (two) are each ONE short answer under the multi-buffer form: at least one
//!   dimension's `needed_*` above its own cap (a dimension that fits may report its full size),
//!   and nothing written in any dimension.
//! * A lease (memory class iv) is judged on READY only: required exactly when the answer carries
//!   material. `configure` acks the pushed version on READY only.

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{
    ConfigureOut, DecideOut, DescribeOut, ServeOut, StatusOut, TransformOut, VERB_ABSTAIN,
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use crate::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::check::fault;

/// The largest blob or byte `needed` one answer may state (16 MiB). `order_buf` is counted in
/// `u32` slots, not bytes, and has its own cap, [`HARD_MAX_ORDER_SLOTS`].
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// The most `order_buf` slots (`u32` entries, not bytes) one answer may state.
pub const HARD_MAX_ORDER_SLOTS: u64 = 65536;
/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// `decide`'s exactly-one-verb bits (not [`VERB_HAS_REJECT_STATUS`], an independent presence bit).
const DECIDE_VERB_MASK: u32 = VERB_PREFER | VERB_ABSTAIN | VERB_REJECT | VERB_RESTRICT;
/// `transform`'s exactly-one-verb bits.
const TRANSFORM_VERB_MASK: u32 = VERB_REWRITE | VERB_ABSTAIN | VERB_REJECT;

/// The fields one host-buffer dimension's arms name, as `op.field`.
struct DimFields {
    /// `written` above `cap` ([`Rule::OverCap`]).
    written: &'static str,
    /// `written` and `needed` both non-zero ([`Rule::WrittenOnShort`]).
    written_on_short: &'static str,
    /// `needed` on an outcome other than FAILED ([`Rule::NeededNotFailed`]).
    needed: &'static str,
    /// `needed` above `u32::MAX` ([`Rule::OverMax`]); `None` for a slot-counted dimension.
    needed_u32: Option<&'static str>,
    /// `needed` above the dimension's hard max ([`Rule::OverMax`]).
    needed_max: &'static str,
}

/// The [`DimFields`] of byte dimension `$dim` of op `$op`.
macro_rules! byte_dim {
    ($op:literal, $dim:literal) => {
        DimFields {
            written: concat!($op, ".", $dim, "_written"),
            written_on_short: concat!($op, ".", $dim, "_written_on_short"),
            needed: concat!($op, ".", $dim, "_needed"),
            needed_u32: Some(concat!($op, ".", $dim, "_needed_u32")),
            needed_max: concat!($op, ".", $dim, "_needed_max"),
        }
    };
}

/// A blob: a length above zero never comes with a NULL pointer, and never exceeds
/// [`HARD_MAX_BYTES`]. `null` and `over` name the two arms.
fn check_blob(null: &'static str, over: &'static str, b: &Blob) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, null));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, over));
    }
    Ok(())
}

/// On READY, a lease is required exactly when the answer carries material; `missing` and
/// `spurious` name the two arms. Other outcomes carry no lease rule.
fn check_lease(
    missing: &'static str,
    spurious: &'static str,
    outcome: RawOutcome,
    lease: u64,
    has_material: bool,
) -> Result<(), Fault> {
    if outcome.0 != (Outcome::Ready as u8) {
        return Ok(());
    }
    if has_material && lease == 0 {
        return Err(fault(Rule::Missing, missing));
    }
    if !has_material && lease != 0 {
        return Err(fault(Rule::Contradiction, spurious));
    }
    Ok(())
}

/// On READY, `verbs & mask` sets exactly one bit, and no bit outside `mask |
/// VERB_HAS_REJECT_STATUS` is set. `one` and `unknown` name the two arms.
fn check_verbs(
    ready: bool,
    verbs: u32,
    mask: u32,
    one: &'static str,
    unknown: &'static str,
) -> Result<(), Fault> {
    if !ready {
        return Ok(());
    }
    if (verbs & mask).count_ones() != 1 {
        return Err(fault(Rule::NotExactlyOne, one));
    }
    if verbs & !(mask | VERB_HAS_REJECT_STATUS) != 0 {
        return Err(fault(Rule::UnknownCode, unknown));
    }
    Ok(())
}

/// One host-buffer dimension's LOCAL rules: `written <= cap`, no `written` beside a `needed`,
/// `needed` only on FAILED, within `u32::MAX` (byte dimensions) and `hard_max`. Whether a
/// `needed` justifies the re-call is the joint rule ([`check_joint_short_answer`]).
fn check_dim_local(
    cap: usize,
    written: usize,
    needed: usize,
    hard_max: u64,
    failed: bool,
    f: &DimFields,
) -> Result<(), Fault> {
    if written > cap {
        return Err(fault(Rule::OverCap, f.written));
    }
    if written > 0 && needed != 0 {
        return Err(fault(Rule::WrittenOnShort, f.written_on_short));
    }
    if needed != 0 {
        if !failed {
            return Err(fault(Rule::NeededNotFailed, f.needed));
        }
        if let Some(u32_field) = f.needed_u32 {
            if needed as u64 > u32::MAX as u64 {
                return Err(fault(Rule::OverMax, u32_field));
            }
        }
        if needed as u64 > hard_max {
            return Err(fault(Rule::OverMax, f.needed_max));
        }
    }
    Ok(())
}

/// The multi-buffer short-answer rule, after every dimension's local rules hold: on FAILED with
/// any `needed` non-zero, AT LEAST ONE dimension's `needed` exceeds its own `cap` (else
/// [`Rule::WastedRecall`] on `needed`), and EVERY dimension's `written` is zero, even one that
/// fits (else [`Rule::WrittenOnShort`] on `written`). `dims` are `(written, needed, cap)`.
fn check_joint_short_answer(
    failed: bool,
    dims: &[(usize, usize, usize)],
    needed: &'static str,
    written: &'static str,
) -> Result<(), Fault> {
    if !failed {
        return Ok(());
    }
    if !dims.iter().any(|&(_w, n, _c)| n != 0) {
        return Ok(());
    }
    if !dims.iter().any(|&(_w, n, c)| n > c) {
        return Err(fault(Rule::WastedRecall, needed));
    }
    if dims.iter().any(|&(w, _n, _c)| w != 0) {
        return Err(fault(Rule::WrittenOnShort, written));
    }
    Ok(())
}

/// `reject_status` comes only with [`VERB_HAS_REJECT_STATUS`] (a plugin cannot smuggle a status
/// the kernel would apply by accident), and that bit only with [`VERB_REJECT`] (there is no reject
/// to carry a status). `status` and `bit` name the two arms.
fn check_reject_status(
    verbs: u32,
    reject_status: u16,
    status: &'static str,
    bit: &'static str,
) -> Result<(), Fault> {
    if reject_status != 0 && (verbs & VERB_HAS_REJECT_STATUS) == 0 {
        return Err(fault(Rule::Contradiction, status));
    }
    if (verbs & VERB_HAS_REJECT_STATUS) != 0 && (verbs & VERB_REJECT) == 0 {
        return Err(fault(Rule::Contradiction, bit));
    }
    Ok(())
}

/// Validates `decide`'s `out` against the capacities [`super::DecideIn`] gave the plugin.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_decide(
    out: &DecideOut,
    reject_message_cap: usize,
    restrict_tags_cap: usize,
    order_cap: usize,
) -> Result<(), Fault> {
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    check_verbs(
        ready,
        out.verbs,
        DECIDE_VERB_MASK,
        "decide.verbs",
        "decide.verbs_unknown",
    )?;
    check_reject_status(
        out.verbs,
        out.reject_status,
        "decide.reject_status",
        "decide.has_reject_status",
    )?;
    check_dim_local(
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
        HARD_MAX_BYTES,
        failed,
        &byte_dim!("decide", "reject_message"),
    )?;
    check_dim_local(
        restrict_tags_cap,
        out.restrict_tags_written,
        out.restrict_tags_needed,
        HARD_MAX_BYTES,
        failed,
        &byte_dim!("decide", "restrict_tags"),
    )?;
    check_dim_local(
        order_cap,
        out.order_written,
        out.order_needed,
        HARD_MAX_ORDER_SLOTS,
        failed,
        &DimFields {
            written: "decide.order_written",
            written_on_short: "decide.order_written_on_short",
            needed: "decide.order_needed",
            needed_u32: None,
            needed_max: "decide.order_needed_max",
        },
    )?;
    check_joint_short_answer(
        failed,
        &[
            (
                out.reject_message_written,
                out.reject_message_needed,
                reject_message_cap,
            ),
            (
                out.restrict_tags_written,
                out.restrict_tags_needed,
                restrict_tags_cap,
            ),
            (out.order_written, out.order_needed, order_cap),
        ],
        "decide.needed",
        "decide.written",
    )
}

/// Validates `transform`'s `out` against the capacities [`super::DecideIn`] gave the plugin.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_transform(
    out: &TransformOut,
    reject_message_cap: usize,
    rewrite_cap: usize,
) -> Result<(), Fault> {
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    check_verbs(
        ready,
        out.verbs,
        TRANSFORM_VERB_MASK,
        "transform.verbs",
        "transform.verbs_unknown",
    )?;
    check_reject_status(
        out.verbs,
        out.reject_status,
        "transform.reject_status",
        "transform.has_reject_status",
    )?;
    check_dim_local(
        reject_message_cap,
        out.reject_message_written,
        out.reject_message_needed,
        HARD_MAX_BYTES,
        failed,
        &byte_dim!("transform", "reject_message"),
    )?;
    check_dim_local(
        rewrite_cap,
        out.rewrite_written,
        out.rewrite_needed,
        HARD_MAX_BYTES,
        failed,
        &byte_dim!("transform", "rewrite"),
    )?;
    check_joint_short_answer(
        failed,
        &[
            (
                out.reject_message_written,
                out.reject_message_needed,
                reject_message_cap,
            ),
            (out.rewrite_written, out.rewrite_needed, rewrite_cap),
        ],
        "transform.needed",
        "transform.written",
    )
}

/// Validates `notify`'s `out` (the shared [`OutHead`]; `notify` reads nothing back beyond it).
/// A FAILED answer's error text is judged; other outcomes state nothing here.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_notify(out: &OutHead) -> Result<(), Fault> {
    if out.outcome.0 == (Outcome::Failed as u8) && out.error.len > 0 && out.error.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, "notify.error"));
    }
    Ok(())
}

/// Validates `configure`'s `out`: a READY answer acks the version the host pushed.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_configure(out: &ConfigureOut, pushed_version: u64) -> Result<(), Fault> {
    if out.head.outcome.0 == (Outcome::Ready as u8) && out.acked_version != pushed_version {
        return Err(fault(Rule::Contradiction, "configure.acked_version"));
    }
    Ok(())
}

/// Validates `status`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    check_blob("status.status", "status.status.len", &out.status)?;
    check_lease(
        "status.lease",
        "status.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.status.len > 0,
    )
}

/// Validates `describe`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_describe(out: &DescribeOut) -> Result<(), Fault> {
    check_blob("describe.describe", "describe.describe.len", &out.describe)?;
    check_lease(
        "describe.lease",
        "describe.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.describe.len > 0,
    )
}

/// Validates `serve`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    if out.headers_out_len > 0 && out.headers_out.is_null() {
        return Err(fault(Rule::NullWithCount, "serve.headers_out"));
    }
    if out.headers_out_len as u64 > HARD_MAX_HEADERS_OUT_LEN {
        return Err(fault(Rule::OverMax, "serve.headers_out_len"));
    }
    check_blob("serve.body", "serve.body.len", &out.body)?;
    check_lease(
        "serve.lease",
        "serve.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.headers_out_len > 0 || out.body.len > 0,
    )
}

#[cfg(test)]
#[path = "../tests/hook_validate_tests.rs"]
mod tests;
