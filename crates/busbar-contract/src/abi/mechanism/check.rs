// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED ANSWER-VALIDATOR HELPERS: the one [`Fault`], the per-op [`OpContract`] and its [`contract!`] builder, and the
//! pure checks every kind's `check_<op>` is built from. u64 arithmetic, no statics. The dispatcher
//! turns an `Err` into FAULT; no host re-implements a check.
//!
//! THE SHORT-BUFFER RULE, with its multi-buffer form, is stated once, on
//! [`OutHead`](super::call::OutHead); [`result`] and [`results`] enforce it, and [`within`] is the
//! check for an op with no short path.

use super::call::{AbiStr, Blob, DeadlineClass, Outcome, RawOutcome};

/// [`span`]: no bytes; the span's length is then `0`.
pub const SPAN_ABSENT: u32 = u32::MAX;

/// The largest byte count any answer may state (written or needed).
pub const MAX_BYTES: u64 = u32::MAX as u64;

/// The largest blob, or byte `needed`, one answer of the secret, hook or export kind may state
/// (16 MiB).
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Which rule an answer broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A needed size above the kind's maximum for it.
    OverMax,
    /// A written count above its capacity.
    OverCap,
    /// A needed size on an outcome other than FAILED.
    NeededNotFailed,
    /// FAILED with `0 < needed <= cap`: the re-call would be wasted.
    WastedRecall,
    /// A short answer that wrote something.
    WrittenOnShort,
    /// A count above zero with a NULL pointer.
    NullWithCount,
    /// An absent span with a non-zero length.
    SpanNotAbsent,
    /// A span outside the bytes written.
    SpanOutOfBounds,
    /// An index past the end of the list it names.
    IndexOutOfRange,
    /// An unknown code or bit.
    UnknownCode,
    /// An "exactly one of" with none or several.
    NotExactlyOne,
    /// A list the answer must carry is empty.
    Missing,
    /// A struct of a foreign size, or for another generation.
    Foreign,
    /// A number that is not finite, or negative where it may not be.
    NotFinite,
    /// Two fields that contradict each other.
    Contradiction,
}

/// Why an answer is FAULT: the rule, and the field that broke it (a distinct message per arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// The rule.
    pub rule: Rule,
    /// The field, as `op.field`.
    pub field: &'static str,
}

/// A [`Fault`].
#[must_use]
pub const fn fault(rule: Rule, field: &'static str) -> Fault {
    Fault { rule, field }
}

/// What a host-buffer result is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filled {
    /// Written; `written` bytes/elements are the answer.
    Written,
    /// Short: the host re-calls with at least `needed`.
    Short,
}

/// A host-buffer result under the short-buffer rule: `written`, `needed`, the `cap` the host gave and the kind's
/// `max` for `needed`.
///
/// # Errors
///
/// The rule the pair breaks.
pub const fn result(
    outcome: Outcome,
    written: u64,
    needed: u64,
    cap: u64,
    max: u64,
    field: &'static str,
) -> Result<Filled, Fault> {
    if needed > max {
        return Err(fault(Rule::OverMax, field));
    }
    if needed != 0 {
        if !matches!(outcome, Outcome::Failed) {
            return Err(fault(Rule::NeededNotFailed, field));
        }
        if needed <= cap {
            return Err(fault(Rule::WastedRecall, field));
        }
        if written != 0 {
            return Err(fault(Rule::WrittenOnShort, field));
        }
        return Ok(Filled::Short);
    }
    if written > cap {
        return Err(fault(Rule::OverCap, field));
    }
    Ok(Filled::Written)
}

/// One dimension of a multi-dimension host-buffer answer (bytes + items, bytes + fields, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dim {
    /// What was written.
    pub written: u64,
    /// On a short answer: this dimension's FULL size.
    pub needed: u64,
    /// The capacity the host gave.
    pub cap: u64,
    /// The kind's maximum for `needed`.
    pub max: u64,
    /// The field, as `op.field`.
    pub field: &'static str,
}

/// A multi-dimension host-buffer answer under the multi-buffer short-answer rule: the short answer is FAILED with
/// EVERY `needed` at its dimension's full size and AT LEAST ONE above its cap (a dimension that fits
/// reports its full size, which is legal), nothing written. FAULT when no `needed` exceeds its cap,
/// when any exceeds its max, or when any is non-zero on another outcome. Otherwise every `written`
/// fits its cap.
///
/// # Errors
///
/// The rule the answer breaks; `group` names the answer for the whole-answer rules.
pub fn results(outcome: Outcome, group: &'static str, dims: &[Dim]) -> Result<Filled, Fault> {
    for d in dims {
        if d.needed > d.max {
            return Err(fault(Rule::OverMax, d.field));
        }
    }
    if let Some(d) = dims.iter().find(|d| d.needed != 0) {
        if outcome != Outcome::Failed {
            return Err(fault(Rule::NeededNotFailed, d.field));
        }
        if !dims.iter().any(|d| d.needed > d.cap) {
            return Err(fault(Rule::WastedRecall, group));
        }
        if dims.iter().any(|d| d.written != 0) {
            return Err(fault(Rule::WrittenOnShort, group));
        }
        return Ok(Filled::Short);
    }
    for d in dims {
        within(d.written, d.cap, d.field)?;
    }
    Ok(Filled::Written)
}

/// A length with no short path: at most its capacity.
///
/// # Errors
///
/// [`Rule::OverCap`].
pub const fn within(len: u64, cap: u64, field: &'static str) -> Result<(), Fault> {
    if len > cap {
        return Err(fault(Rule::OverCap, field));
    }
    Ok(())
}

/// A list: a count above zero never comes with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn listed<T>(ptr: *const T, len: usize, field: &'static str) -> Result<(), Fault> {
    if len > 0 && ptr.is_null() {
        return Err(fault(Rule::NullWithCount, field));
    }
    Ok(())
}

/// THE SLICE A PLUGIN REPORTED over a HOST buffer: `count` is checked against the `cap` the host
/// passed, and a NULL pointer with a count refused, BEFORE any slice is built; only then is it
/// made. The one way a validator's slice argument is built from a plugin-reported count.
///
/// # Errors
///
/// [`Rule::OverCap`] when `count > cap`; [`Rule::NullWithCount`] for a NULL buffer with a count.
///
/// # Safety
///
/// A non-NULL `ptr` is the host's own buffer of at least `cap` live `T`s.
pub unsafe fn reported<'a, T>(
    ptr: *const T,
    count: u64,
    cap: u64,
    field: &'static str,
) -> Result<&'a [T], Fault> {
    if count > cap {
        return Err(fault(Rule::OverCap, field));
    }
    if count == 0 {
        return Ok(&[]);
    }
    listed(ptr, 1, field)?;
    let n = usize::try_from(count).map_err(|_| fault(Rule::OverCap, field))?;
    // SAFETY: the caller's contract; `n <= cap` elements of the host's own buffer.
    Ok(unsafe { core::slice::from_raw_parts(ptr, n) })
}

/// A string: a length above zero never comes with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn text(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    listed(s.ptr, s.len, field)
}

/// Every string of a list, by [`text`].
///
/// # Errors
///
/// [`Rule::NullWithCount`] for the first string counted with a NULL pointer.
pub fn texts(list: &[AbiStr], field: &'static str) -> Result<(), Fault> {
    for s in list {
        text(*s, field)?;
    }
    Ok(())
}

/// An index into a list of `len`.
///
/// # Errors
///
/// [`Rule::IndexOutOfRange`].
pub const fn index(i: u32, len: u64, field: &'static str) -> Result<(), Fault> {
    if i as u64 >= len {
        return Err(fault(Rule::IndexOutOfRange, field));
    }
    Ok(())
}

/// A code in `lo..=hi`.
///
/// # Errors
///
/// [`Rule::UnknownCode`].
pub const fn code(v: u64, lo: u64, hi: u64, field: &'static str) -> Result<(), Fault> {
    if v < lo || v > hi {
        return Err(fault(Rule::UnknownCode, field));
    }
    Ok(())
}

/// Bits within `known`.
///
/// # Errors
///
/// [`Rule::UnknownCode`].
pub const fn bits(v: u64, known: u64, field: &'static str) -> Result<(), Fault> {
    if v & !known != 0 {
        return Err(fault(Rule::UnknownCode, field));
    }
    Ok(())
}

/// A span `(offset, len)` inside the first `bound` bytes, or absent ([`SPAN_ABSENT`], `len == 0`);
/// checked arithmetic.
///
/// # Errors
///
/// [`Rule::SpanNotAbsent`], [`Rule::SpanOutOfBounds`].
pub const fn span(offset: u32, len: u32, bound: u64, field: &'static str) -> Result<(), Fault> {
    if offset == SPAN_ABSENT {
        if len != 0 {
            return Err(fault(Rule::SpanNotAbsent, field));
        }
        return Ok(());
    }
    match (offset as u64).checked_add(len as u64) {
        Some(end) if end <= bound => Ok(()),
        _ => Err(fault(Rule::SpanOutOfBounds, field)),
    }
}

/// A byte range `(offset, len)` inside the first `bound` bytes; checked arithmetic.
///
/// # Errors
///
/// [`Rule::SpanOutOfBounds`].
pub const fn range(offset: u64, len: u64, bound: u64, field: &'static str) -> Result<(), Fault> {
    match offset.checked_add(len) {
        Some(end) if end <= bound => Ok(()),
        _ => Err(fault(Rule::SpanOutOfBounds, field)),
    }
}

/// A weight: finite and not negative.
///
/// # Errors
///
/// [`Rule::NotFinite`].
pub fn weight(w: f64, field: &'static str) -> Result<(), Fault> {
    if !w.is_finite() || w < 0.0 {
        return Err(fault(Rule::NotFinite, field));
    }
    Ok(())
}

/// The first `n` elements of a host buffer.
///
/// # Errors
///
/// [`Rule::OverCap`] when the buffer holds fewer.
pub fn first<'a, T>(buf: &'a [T], n: u64, field: &'static str) -> Result<&'a [T], Fault> {
    usize::try_from(n)
        .ok()
        .and_then(|n| buf.get(..n))
        .ok_or(fault(Rule::OverCap, field))
}

/// A plugin-owned blob: a length above zero never comes with a NULL pointer, and never exceeds
/// [`HARD_MAX_BYTES`]. `null` and `over` name the two arms.
///
/// # Errors
///
/// [`Rule::NullWithCount`], [`Rule::OverMax`].
pub fn blob(b: &Blob, null: &'static str, over: &'static str) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, null));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, over));
    }
    Ok(())
}

/// The lease rule (memory class iv): on READY, a lease is required exactly when the answer
/// carries material; other outcomes carry no lease rule. `missing` and `spurious` name the arms.
///
/// # Errors
///
/// [`Rule::Missing`], [`Rule::Contradiction`].
pub fn lease(
    outcome: RawOutcome,
    lease: u64,
    has_material: bool,
    missing: &'static str,
    spurious: &'static str,
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

/// One op's contract: where it runs, whether it may pend, its largest `in`/`out`, its deadline
/// class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpContract {
    /// The slot index.
    pub slot: u32,
    /// `true` = on the request path; `false` = off-path.
    pub request_path: bool,
    /// `true` = the op may answer PENDING (on a real ticket).
    pub may_pend: bool,
    /// The largest `in` the host writes, in bytes.
    pub max_in: usize,
    /// The largest `out` the plugin writes, in bytes.
    pub max_out: usize,
    /// The deadline class the host stamps in `InHead::deadline_class`.
    pub deadline: DeadlineClass,
}

/// `contract!(SLOT, request_path, may_pend, In, Out, Class)`: one [`OpContract`] for the calling
/// kind's `slot::SLOT`, sized from its own `in`/`out` types.
macro_rules! contract {
    ($slot:ident, $rp:expr, $pend:expr, $in:ty, $out:ty, $class:ident) => {
        $crate::abi::mechanism::check::OpContract {
            slot: slot::$slot,
            request_path: $rp,
            may_pend: $pend,
            max_in: ::core::mem::size_of::<$in>(),
            max_out: ::core::mem::size_of::<$out>(),
            deadline: $crate::abi::mechanism::call::DeadlineClass::$class,
        }
    };
}
pub(crate) use contract;

#[cfg(test)]
#[path = "../tests/mechanism_check_tests.rs"]
mod tests;
