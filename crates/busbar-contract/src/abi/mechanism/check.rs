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
use super::door::{
    MarkWord, Rewrite, Section, Statement, MARKS_KNOWN, MARK_WORD_CARRIER, MARK_WORD_HOOK,
    REWRITE_ALIAS, REWRITE_KEY, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED,
};
use crate::abi::host::conn::connector::{
    Need, DIRECTION_INBOUND, DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED,
    KEEP_RESPONSE_HEADERS_MAX, NEVER_KEPT,
};

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

/// A string that must be present: non-empty, and never counted with a NULL pointer.
///
/// # Errors
///
/// [`Rule::Missing`], [`Rule::NullWithCount`].
pub fn named(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    if s.len == 0 {
        return Err(fault(Rule::Missing, field));
    }
    text(s, field)
}

/// A string that must be absent.
///
/// # Errors
///
/// [`Rule::Contradiction`].
pub const fn absent(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    if s.len != 0 {
        return Err(fault(Rule::Contradiction, field));
    }
    Ok(())
}

// ── THE STATEMENT'S LISTS (the design's One Statement: marks, rewrites, sections, needs) ──────

/// The marks: only known flag bits; every word mark of a known class, and named.
///
/// # Errors
///
/// The rule a mark breaks.
pub fn check_marks(marks: u64, words: &[MarkWord]) -> Result<(), Fault> {
    bits(marks, MARKS_KNOWN, "statement.marks")?;
    for w in words {
        code(
            u64::from(w.class),
            u64::from(MARK_WORD_HOOK),
            u64::from(MARK_WORD_CARRIER),
            "mark_word.class",
        )?;
        named(w.word, "mark_word.word")?;
    }
    Ok(())
}

/// The rewrites: a known class and a named `from`; `to` is named for a key move and absent
/// otherwise.
///
/// # Errors
///
/// The rule a rewrite breaks.
pub fn check_rewrites(rewrites: &[Rewrite]) -> Result<(), Fault> {
    for r in rewrites {
        code(
            u64::from(r.class),
            u64::from(REWRITE_ALIAS),
            u64::from(REWRITE_KEY),
            "rewrite.class",
        )?;
        named(r.from, "rewrite.from")?;
        if r.class == REWRITE_KEY {
            named(r.to, "rewrite.to")?;
        } else {
            absent(r.to, "rewrite.to")?;
        }
    }
    Ok(())
}

/// The sections: each named, known flags, and at most one declaring section (a plane has exactly
/// one: [`crate::abi::plane::check::check_sections`]).
///
/// # Errors
///
/// The rule the sections break.
pub fn check_statement_sections(sections: &[Section]) -> Result<(), Fault> {
    let known = SECTION_DECLARING | SECTION_REQUIRED | SECTION_CONSUMED;
    for s in sections {
        named(s.name, "section.name")?;
        bits(u64::from(s.flags), u64::from(known), "section.flags")?;
    }
    if sections
        .iter()
        .filter(|s| s.flags & SECTION_DECLARING != 0)
        .count()
        > 1
    {
        return Err(fault(Rule::NotExactlyOne, "section.flags"));
    }
    Ok(())
}

/// The needs: a known direction and a transport claim; strings and details never counted with a
/// NULL pointer.
///
/// # Errors
///
/// The rule a need breaks.
pub fn check_needs(needs: &[Need]) -> Result<(), Fault> {
    for n in needs {
        code(
            u64::from(n.direction),
            u64::from(DIRECTION_INBOUND),
            u64::from(DIRECTION_OUTBOUND),
            "need.direction",
        )?;
        code(
            u64::from(n.egress_class),
            u64::from(EGRESS_DEFAULT),
            u64::from(EGRESS_LOOPBACK_ALLOWED),
            "need.egress_class",
        )?;
        named(n.transport, "need.transport")?;
        text(n.auth, "need.auth")?;
        text(n.target_from, "need.target_from")?;
        text(n.trust_from, "need.trust_from")?;
        listed(n.details.ptr, n.details.len, "need.details")?;
        keep_response_headers(n)?;
    }
    Ok(())
}

/// A need's kept response head fields: a bounded list of lower-case tokens, none hop-by-hop or
/// credential-bearing ([`NEVER_KEPT`]: [`Rule::Foreign`], a field that is not the plugin's to read).
fn keep_response_headers(n: &Need) -> Result<(), Fault> {
    const FIELD: &str = "need.keep_response_headers";
    listed(n.keep_response_headers, n.keep_response_headers_len, FIELD)?;
    if n.keep_response_headers_len > KEEP_RESPONSE_HEADERS_MAX {
        return Err(fault(Rule::OverMax, FIELD));
    }
    if n.keep_response_headers_len == 0 {
        return Ok(());
    }
    // SAFETY: a non-NULL list of `keep_response_headers_len` strings the plugin's door states as
    // `'static` data (checked non-NULL above), bounded by `KEEP_RESPONSE_HEADERS_MAX`.
    let names = unsafe {
        core::slice::from_raw_parts(n.keep_response_headers, n.keep_response_headers_len)
    };
    for s in names {
        named(*s, FIELD)?;
        // SAFETY: `named` checked the string non-NULL with its length; the plugin's static bytes.
        let name = unsafe { core::slice::from_raw_parts(s.ptr, s.len) };
        let token = name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_');
        if !token {
            return Err(fault(Rule::UnknownCode, FIELD));
        }
        if NEVER_KEPT.iter().any(|k| k.as_bytes() == name) {
            return Err(fault(Rule::Foreign, FIELD));
        }
    }
    Ok(())
}

/// A `'static` Statement list as a slice, after [`listed`].
///
/// # Safety
///
/// A non-NULL `ptr` points at `len` live `'static` `T`s.
unsafe fn list<'a, T>(ptr: *const T, len: usize, field: &'static str) -> Result<&'a [T], Fault> {
    listed(ptr, len, field)?;
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: the caller's contract; `ptr` is non-NULL here.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// THE STATEMENT'S LISTS, at load: every list never counted with a NULL pointer, then
/// [`check_marks`], [`check_rewrites`], [`check_statement_sections`], [`check_needs`], the settings
/// paths and the declared answers. The same check runs for a compiled-in row and a dropped-in door.
///
/// # Errors
///
/// The rule the Statement breaks.
///
/// # Safety
///
/// `st` is a Statement a door answered: every non-NULL list points at its stated count of live
/// `'static` entries.
pub unsafe fn check_statement(st: &Statement) -> Result<(), Fault> {
    // SAFETY (each `list`): the caller's contract.
    let words = unsafe { list(st.mark_words, st.mark_words_len, "statement.mark_words") }?;
    check_marks(st.marks, words)?;
    check_rewrites(unsafe { list(st.rewrites, st.rewrites_len, "statement.rewrites") }?)?;
    check_statement_sections(unsafe { list(st.sections, st.sections_len, "statement.sections") }?)?;
    check_needs(unsafe { list(st.needs, st.needs_len, "statement.needs") }?)?;
    text(st.target_from, "statement.target_from")?;
    text(st.trust_from, "statement.trust_from")?;
    for a in unsafe { list(st.answers, st.answers_len, "statement.answers") }? {
        named(*a, "statement.answer")?;
    }
    for c in unsafe { list(st.claims, st.claims_len, "statement.claims") }? {
        named(*c, "statement.claim")?;
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
