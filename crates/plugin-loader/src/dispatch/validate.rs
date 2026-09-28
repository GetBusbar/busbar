// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VALIDATE EVERY ANSWER BEFORE READING IT. A plugin's `out` is untrusted input: every length,
//! offset, count and size it wrote is checked against what the host handed it before the host
//! reads a byte through it, and any violation is FAULT, never a clamp and never a guess.
//!
//! The mechanism's checks run in every crossing (`OutHead.size`, the error text, the #85 arrays).
//! The helpers here are the ones every kind's decoder uses for its own reply fields (M3): a span
//! `(offset, len)` inside a host buffer of `cap` bytes, overflow-checked; a count within its cap;
//! `written` within the buffer; `needed` zero on READY (a READY that still needs more space is a
//! contradiction).

use std::mem::size_of;
use std::ops::Range;

use busbar_contract::abi::mechanism::call::{AbiStr, Envelope, OutHead, Outcome};

use super::plugin::MAX_ENVELOPE_ENTRIES;

/// The most bytes of error text a plugin may state; longer is a malformed answer.
pub const MAX_ERROR_LEN: usize = 64 * 1024;

/// What was wrong with an answer. Every violation is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// `offset + len` overflowed, or passed the buffer's capacity.
    Span {
        /// The stated offset.
        offset: u64,
        /// The stated length.
        len: u64,
        /// The host buffer's capacity.
        cap: u64,
    },
    /// A count passed its cap.
    Count {
        /// The stated count.
        count: u64,
        /// The cap.
        cap: u64,
    },
    /// `written` passed the buffer's capacity.
    Written {
        /// The stated bytes written.
        written: u64,
        /// The capacity.
        cap: u64,
    },
    /// READY with a non-zero `needed`.
    NeededOnReady(u64),
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

/// The span `[offset, offset + len)` inside a host buffer of `cap` bytes.
pub fn span(offset: u64, len: u64, cap: u64) -> Result<Range<usize>, Violation> {
    let bad = Violation::Span { offset, len, cap };
    let end = offset.checked_add(len).ok_or(bad)?;
    if end > cap {
        return Err(bad);
    }
    let start = usize::try_from(offset).map_err(|_| bad)?;
    let end = usize::try_from(end).map_err(|_| bad)?;
    Ok(start..end)
}

/// A count within its cap.
pub fn count(n: u64, cap: u64) -> Result<usize, Violation> {
    if n > cap {
        return Err(Violation::Count { count: n, cap });
    }
    usize::try_from(n).map_err(|_| Violation::Count { count: n, cap })
}

/// Bytes `written` into a host buffer of `cap` bytes.
pub fn written(w: u64, cap: u64) -> Result<usize, Violation> {
    if w > cap {
        return Err(Violation::Written { written: w, cap });
    }
    usize::try_from(w).map_err(|_| Violation::Written { written: w, cap })
}

/// `needed` (the space a reply still wants) must be zero on READY.
pub fn needed(outcome: Outcome, needed: u64) -> Result<(), Violation> {
    if outcome == Outcome::Ready && needed != 0 {
        return Err(Violation::NeededOnReady(needed));
    }
    Ok(())
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
