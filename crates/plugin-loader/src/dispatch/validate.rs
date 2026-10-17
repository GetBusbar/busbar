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
//! (answer validators live with the shape); the dispatcher adds the one re-call
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
