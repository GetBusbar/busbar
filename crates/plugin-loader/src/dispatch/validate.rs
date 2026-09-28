// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VALIDATE EVERY ANSWER BEFORE READING IT. A plugin's `out` is untrusted input, and any violation
//! is FAULT, never a clamp and never a guess.
//!
//! Two layers, and only two. The MECHANISM's checks of every `out` head live here and run in every
//! crossing: `OutHead.size` within `size_of::<OutHead>()..=` the host's `out`, the error text and
//! the #85 arrays not NULL-with-length nor over-long, the outcome mirror, and PENDING on NONE (in
//! `plugin::judge`). A KIND's reply fields (spans, counts, `written`, `needed_*`) are checked only
//! by that kind's pure `check_<op>` in `abi/<kind>/`, reached through [`super::Kind::check`]
//! (ARCHITECT ruling "answer validators live with the shape"); the dispatcher adds the one re-call
//! rule on top ([`super::Kind::short`]): a second short answer on the same ticket is FAULT.

use std::mem::size_of;

use busbar_contract::abi::mechanism::call::{AbiStr, Envelope, OutHead, Outcome};

use super::plugin::MAX_ENVELOPE_ENTRIES;

/// The most bytes of error text a plugin may state; longer is a malformed answer.
pub const MAX_ERROR_LEN: usize = super::plugin::MAX_TEXT;

/// What was wrong with an answer. Every violation is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// The kind's own `check_<op>` refused the answer.
    Kind,
    /// A second SHORT answer on the one re-call.
    ShortTwice,
    /// A plugin-reported count passed the cap the host passed.
    Count {
        /// The reported count.
        count: u64,
        /// The host's cap.
        cap: u64,
    },
    /// A plugin-reported array is NULL with a non-zero count.
    NullArray(u64),
    /// `OutHead.size` is smaller than the head or larger than the host's `out`.
    OutSize {
        /// The size the plugin wrote back.
        stated: u32,
        /// The host's `out` size.
        host: u32,
    },
    /// The error text is NULL with a length, or longer than [`MAX_ERROR_LEN`].
    ErrorText(usize),
    /// An envelope array is NULL with a length, or longer than [`MAX_ENVELOPE_ENTRIES`].
    EnvelopeArray(usize),
}

impl Violation {
    /// Every violation answers FAULT.
    pub const fn outcome(self) -> Outcome {
        Outcome::Fault
    }
}

/// THE SLICE A PLUGIN REPORTED, for a kind validator that takes one (e.g. auth `check_identify`):
/// `count` is checked against the `cap` the host passed BEFORE any slice is built from plugin
/// memory, and a NULL pointer with a count is refused; only then is the slice made.
///
/// # Safety
/// `ptr` is the host buffer of capacity `cap` elements the host handed this op (or NULL).
pub unsafe fn reported_slice<'a, T>(
    ptr: *const T,
    count: u64,
    cap: u64,
) -> Result<&'a [T], Violation> {
    if count > cap {
        return Err(Violation::Count { count, cap });
    }
    if count == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Violation::NullArray(count));
    }
    let n = usize::try_from(count).map_err(|_| Violation::Count { count, cap })?;
    // SAFETY: the caller's contract; `n <= cap` elements of the host's own buffer.
    Ok(unsafe { std::slice::from_raw_parts(ptr, n) })
}

/// The mechanism's own checks of an `out` head, run on every crossing: its size, its error text
/// and its #85 arrays.
pub(crate) fn out_head(head: &OutHead, host_out_size: u32) -> Result<(), Violation> {
    let stated = head.size;
    if (stated as usize) < size_of::<OutHead>() || stated > host_out_size {
        return Err(Violation::OutSize {
            stated,
            host: host_out_size,
        });
    }
    text(head.error)?;
    envelope(&head.envelope)
}

fn text(s: AbiStr) -> Result<(), Violation> {
    if (s.ptr.is_null() && s.len != 0) || s.len > MAX_ERROR_LEN {
        return Err(Violation::ErrorText(s.len));
    }
    Ok(())
}

fn envelope(e: &Envelope) -> Result<(), Violation> {
    for (p, n) in [
        (e.metrics.is_null(), e.metrics_len),
        (e.diags.is_null(), e.diags_len),
    ] {
        if (p && n != 0) || n > MAX_ENVELOPE_ENTRIES {
            return Err(Violation::EnvelopeArray(n));
        }
    }
    Ok(())
}
