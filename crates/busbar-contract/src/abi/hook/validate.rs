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
    ConfigureOut, DecideOut, DescribeOut, NotifyIn, PromptView, ServeOut, StatusOut, TransformOut,
    VERB_ABSTAIN, VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
    VIEW_HAS_PROMPT,
};
use crate::abi::mechanism::call::{OutHead, Outcome};
use crate::abi::mechanism::check::{blob, fault, lease, results, Dim, HARD_MAX_BYTES};

/// The most `order_buf` slots (`u32` entries, not bytes) one answer may state.
pub const HARD_MAX_ORDER_SLOTS: u64 = 65536;
/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// `decide`'s exactly-one-verb bits (not [`VERB_HAS_REJECT_STATUS`], an independent presence bit).
const DECIDE_VERB_MASK: u32 = VERB_PREFER | VERB_ABSTAIN | VERB_REJECT | VERB_RESTRICT;
/// `transform`'s exactly-one-verb bits.
const TRANSFORM_VERB_MASK: u32 = VERB_REWRITE | VERB_ABSTAIN | VERB_REJECT;

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

/// One host-buffer dimension of a short-buffer answer ([`results`]), from the `usize` counts the
/// hook shapes carry.
const fn dim(written: usize, needed: usize, cap: usize, max: u64, field: &'static str) -> Dim {
    Dim {
        written: written as u64,
        needed: needed as u64,
        cap: cap as u64,
        max,
        field,
    }
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
    let dims = [
        dim(
            out.reject_message_written,
            out.reject_message_needed,
            reject_message_cap,
            HARD_MAX_BYTES,
            "decide.reject_message",
        ),
        dim(
            out.restrict_tags_written,
            out.restrict_tags_needed,
            restrict_tags_cap,
            HARD_MAX_BYTES,
            "decide.restrict_tags",
        ),
        dim(
            out.order_written,
            out.order_needed,
            order_cap,
            HARD_MAX_ORDER_SLOTS,
            "decide.order",
        ),
    ];
    results(out.head.outcome.outcome(), "decide", &dims)?;
    Ok(())
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
    let dims = [
        dim(
            out.reject_message_written,
            out.reject_message_needed,
            reject_message_cap,
            HARD_MAX_BYTES,
            "transform.reject_message",
        ),
        dim(
            out.rewrite_written,
            out.rewrite_needed,
            rewrite_cap,
            HARD_MAX_BYTES,
            "transform.rewrite",
        ),
    ];
    results(out.head.outcome.outcome(), "transform", &dims)?;
    Ok(())
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
    blob(&out.status, "status.status", "status.status.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.status.len > 0,
        "status.lease",
        "status.lease_without_material",
    )
}

/// Validates `describe`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_describe(out: &DescribeOut) -> Result<(), Fault> {
    blob(&out.describe, "describe.describe", "describe.describe.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.describe.len > 0,
        "describe.lease",
        "describe.lease_without_material",
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
    blob(&out.body, "serve.body", "serve.body.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.headers_out_len > 0 || out.body.len > 0,
        "serve.lease",
        "serve.lease_without_material",
    )
}

/// The most messages one [`PromptView`] may carry (a FAULT ceiling far above any real request).
pub const HARD_MAX_MESSAGES: u64 = 65536;

/// Validates a HOST-BUILT [`PromptView`] (`decide`/`transform`'s `in.prompt`) before a plugin
/// reads it — the SDK's own reading of the view, since this half is the host's to get right:
/// `messages` is non-NULL whenever `messages_len > 0`, `messages_len` is within
/// [`HARD_MAX_MESSAGES`], `message_count` equals `messages_len` (the two state one length), and
/// the body blob obeys the blob rules. An absent view (`VIEW_HAS_PROMPT` unset) is not judged.
///
/// # Errors
/// The rule the view breaks.
pub fn check_prompt_view(view: &PromptView) -> Result<(), Fault> {
    if view.messages_len > 0 && view.messages.is_null() {
        return Err(fault(Rule::NullWithCount, "prompt.messages"));
    }
    if view.messages_len as u64 > HARD_MAX_MESSAGES {
        return Err(fault(Rule::OverMax, "prompt.messages_len"));
    }
    if view.message_count != view.messages_len as u64 {
        return Err(fault(Rule::Contradiction, "prompt.message_count"));
    }
    blob(&view.body, "prompt.body", "prompt.body.len")
}

/// The most signal entries one view may carry (a FAULT ceiling: the catalog holds ten signals).
pub const HARD_MAX_SIGNALS: u64 = 1024;

/// Validates a HOST-BUILT [`NotifyIn`] (WIRE-HOOK Q5): the signal list's pointer/length pairing
/// and bound, no presence bit beyond [`VIEW_HAS_PROMPT`], and — when that bit is set — the prompt
/// view by [`check_prompt_view`].
///
/// # Errors
/// The rule the `in` breaks.
pub fn check_notify_in(input: &NotifyIn) -> Result<(), Fault> {
    if input.signals_len > 0 && input.signals.is_null() {
        return Err(fault(Rule::NullWithCount, "notify.signals"));
    }
    if input.signals_len as u64 > HARD_MAX_SIGNALS {
        return Err(fault(Rule::OverMax, "notify.signals_len"));
    }
    if input.present & !VIEW_HAS_PROMPT != 0 {
        return Err(fault(Rule::UnknownCode, "notify.present"));
    }
    if input.present & VIEW_HAS_PROMPT != 0 {
        check_prompt_view(&input.prompt)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/hook_validate_tests.rs"]
mod tests;
