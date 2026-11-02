// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S ANSWER VALIDATORS, beside the shapes they judge: one pure `check_<op>` per

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{
    ConfigureOut, DecideOut, DescribeOut, NotifyIn, PromptView, ServeOut, StatusOut, TransformOut,
    VERB_ABSTAIN, VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
    VIEW_HAS_PROMPT,
};
use crate::abi::mechanism::call::{OutHead, Outcome};
use crate::abi::mechanism::check::{
    blob, failed_error, fault, leased_blob, results, served, Dim, HARD_MAX_BYTES,
};

/// The most `order_buf` slots (`u32` entries, not bytes) one answer may state.
pub const HARD_MAX_ORDER_SLOTS: u64 = 65536;
/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// `decide`'s exactly-one-verb bits (not [`VERB_HAS_REJECT_STATUS`], an independent presence bit).
const DECIDE_VERB_MASK: u32 = VERB_PREFER | VERB_ABSTAIN | VERB_REJECT | VERB_RESTRICT;
/// `transform`'s exactly-one-verb bits.
const TRANSFORM_VERB_MASK: u32 = VERB_REWRITE | VERB_ABSTAIN | VERB_REJECT;

/// On READY, `verbs & mask` sets exactly one bit, and no bit outside `mask |

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

pub fn check_notify(out: &OutHead) -> Result<(), Fault> {
    failed_error(out, "notify.error")
}

/// Validates `configure`'s `out`: a READY answer acks the version the host pushed.

pub fn check_configure(out: &ConfigureOut, pushed_version: u64) -> Result<(), Fault> {
    if out.head.outcome.0 == (Outcome::Ready as u8) && out.acked_version != pushed_version {
        return Err(fault(Rule::Contradiction, "configure.acked_version"));
    }
    Ok(())
}

/// Validates `status`'s `out`.

pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    leased_blob!(out, "status", status)
}

/// Validates `describe`'s `out`.

pub fn check_describe(out: &DescribeOut) -> Result<(), Fault> {
    leased_blob!(out, "describe", describe)
}

/// Validates `serve`'s `out`.

pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    let (h, n) = (out.headers_out, out.headers_out_len);
    served(&out.head, h, n, HARD_MAX_HEADERS_OUT_LEN, &out.body)
}

/// The most messages one [`PromptView`] may carry (a FAULT ceiling far above any real request).
pub const HARD_MAX_MESSAGES: u64 = 65536;

/// Validates a HOST-BUILT [`PromptView`] (`decide`/`transform`'s `in.prompt`) before a plugin

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
