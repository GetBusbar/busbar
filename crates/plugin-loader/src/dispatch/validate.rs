// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VALIDATE EVERY ANSWER BEFORE READING IT. A plugin's `out` is untrusted input, and any violation
//! is FAULT, never a clamp and never a guess.
//!
//! Two layers, and only two. The MECHANISM's checks of every `out` head live here and run in every
//! crossing: `OutHead.size` within `size_of::<OutHead>()..=` the host's `out`, the error text and
//! the observability arrays not NULL-with-length nor over-long, the outcome mirror, and PENDING on NONE (in
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
/// and its observability arrays.
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

/// The most bytes any slice a plugin reports the length of may span: THE DESIGN's hard maximum,
/// "bytes ≤ `u32::MAX`" (§11, Hard maxima).
pub(crate) const MAX_LENT_BYTES: usize = busbar_contract::abi::mechanism::check::MAX_BYTES as usize;

/// THE ONE WAY A SLICE IS FORMED FROM A PLUGIN-REPORTED LENGTH (THE DESIGN §11.13 M1, "Every slice
/// built from a plugin-reported length is capped and validated before it is formed"): `len`
/// entries at `ptr`, or `None` (the caller's FAULT) when the range is non-empty behind NULL, spans
/// more than [`MAX_LENT_BYTES`], or is misaligned for `T`. Nothing is read or formed before the
/// checks pass; an empty range is empty whatever its pointer.
///
/// # Safety
///
/// A range that passes the checks names `len` live `T`s for as long as the slice is used.
pub(crate) unsafe fn lent<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }
    if !within(ptr, len) {
        return None;
    }
    // SAFETY: non-NULL, aligned, at most `MAX_LENT_BYTES` (so below `isize::MAX`); the caller's
    // contract for the rest.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// [`lent`] for a range the host writes into.
///
/// # Safety
///
/// As [`lent`], and the range is writable and unaliased for as long as the slice is used.
pub(crate) unsafe fn lent_mut<'a, T>(ptr: *mut T, len: usize) -> Option<&'a mut [T]> {
    if len == 0 {
        return Some(&mut []);
    }
    if !within(ptr.cast_const(), len) {
        return None;
    }
    // SAFETY: as in `lent`.
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// A plugin-reported string's bytes, by [`lent`].
///
/// # Safety
///
/// As [`lent`].
pub(crate) unsafe fn lent_str<'a>(s: AbiStr) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    unsafe { lent(s.ptr, s.len) }
}

/// A non-empty range's bounds: non-NULL, aligned for `T`, at most [`MAX_LENT_BYTES`].
fn within<T>(ptr: *const T, len: usize) -> bool {
    !ptr.is_null()
        && ptr.is_aligned()
        && len
            .checked_mul(size_of::<T>().max(1))
            .is_some_and(|bytes| bytes <= MAX_LENT_BYTES)
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
