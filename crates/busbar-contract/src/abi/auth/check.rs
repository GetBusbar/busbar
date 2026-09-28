// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ANSWER VALIDATORS (ARCHITECT ruling: answer validators live with the shape). Each is
//! a PURE function over the op's `out` and the capacities the host handed in. They use `u64`
//! math and hold no state. The dispatcher calls them after every READY or FAILED answer, and
//! any `Err` makes the answer FAULT. No host re-implements them.

use super::inbound::{BeginLoginOut, IdentifyOut, IdentityBuf, Span};
use super::outbound::{FieldSpan, FieldsOut};
use super::{
    BEGIN_AUTHORIZE, BEGIN_FORM, FIELD_SENSITIVE, IDENTITY_HAS_TTL, LOGIN_IDENTITY, LOGIN_OUTAGE,
    SPAN_ABSENT, VERDICT_IDENTITY, VERDICT_PASS,
};
use crate::abi::mechanism::call::{AbiStr, Outcome, BLOB_OCTETS};

/// The hard maximum of `needed_groups`: no identity asserts more groups than this.
pub const IDENTITY_GROUPS_HARD_MAX: u32 = 65_536;
/// The hard maximum of `needed_fields`: no style writes more auth fields than this.
pub const FIELDS_HARD_MAX: u32 = 64;

/// Why an answer is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A verdict or shape outside the op's vocabulary.
    Vocabulary,
    /// A bitfield that must have exactly one bit set has 0, or 2 or more.
    NotExactlyOne,
    /// READY with a non-zero `needed_*`.
    NeededOnReady,
    /// REFUSED or PENDING with a non-zero `needed_*`: only FAILED may ask for a larger buffer.
    NeededNotFailed,
    /// `needed_bytes > u32::MAX`, or a `needed_<count>` above its hard maximum.
    NeededTooLarge,
    /// FAILED with a non-zero `needed_*` that the given capacity already covers (it would waste the
    /// one re-call).
    NeededWithinCap,
    /// An absent span ([`SPAN_ABSENT`]) with a non-zero length.
    AbsentWithLen,
    /// A span past the buffer's capacity.
    SpanOutOfBounds,
    /// A count above its capacity.
    CountOverCap,
    /// A count that disagrees with the length of the slice the host built for it.
    CountMismatch,
    /// A count above zero with a NULL pointer.
    NullWithCount,
    /// A flag bit the ABI does not define.
    UnknownFlags,
    /// A part the answer requires is absent (an identity's subject, the URL or form a shape names).
    Missing,
}

/// `off + len <= cap` in `u64`, or [`SPAN_ABSENT`] with `len == 0` when `optional`.
fn span(s: Span, cap: u64, optional: bool) -> Result<(), Fault> {
    if s.off == SPAN_ABSENT {
        return match (s.len, optional) {
            (0, true) => Ok(()),
            (0, false) => Err(Fault::Missing),
            _ => Err(Fault::AbsentWithLen),
        };
    }
    if u64::from(s.off) + u64::from(s.len) > cap {
        return Err(Fault::SpanOutOfBounds);
    }
    Ok(())
}

/// A FAILED answer's `needed_*`: within the hard maxima, and `0` or above the capacity given.
fn short(
    needed_bytes: u64,
    bytes_cap: u64,
    needed_count: u32,
    count_cap: u32,
    hard: u32,
) -> Result<(), Fault> {
    if needed_bytes > u64::from(u32::MAX) || needed_count > hard {
        return Err(Fault::NeededTooLarge);
    }
    if (needed_bytes != 0 && needed_bytes <= bytes_cap)
        || (needed_count != 0 && needed_count <= count_cap)
    {
        return Err(Fault::NeededWithinCap);
    }
    Ok(())
}

/// REFUSED or PENDING answers ask for nothing: any non-zero `needed_*` is FAULT (ruling H3).
fn no_need(needed_bytes: u64, needed_count: u32) -> Result<(), Fault> {
    if needed_bytes != 0 || needed_count != 0 {
        return Err(Fault::NeededNotFailed);
    }
    Ok(())
}

/// `verify`'s answer. `buf` is the [`IdentityBuf`] the host handed in, and `groups` the first
/// `groups_len` spans of its group array.
///
/// HOST DUTY: the host checks `out.identity.groups_len <= buf.groups_cap` BEFORE it builds
/// `groups` from its array; a larger count is FAULT without reading a single span.
pub fn check_identify(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
) -> Result<(), Fault> {
    identify(
        outcome,
        out,
        buf,
        groups,
        (VERDICT_IDENTITY, VERDICT_PASS),
        VERDICT_IDENTITY,
    )
}

/// `complete_login`'s answer: the same rules as [`check_identify`] (and the same host duty), over
/// the login vocabulary [`LOGIN_IDENTITY`] ..= [`LOGIN_OUTAGE`].
pub fn check_complete_login(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
) -> Result<(), Fault> {
    identify(
        outcome,
        out,
        buf,
        groups,
        (LOGIN_IDENTITY, LOGIN_OUTAGE),
        LOGIN_IDENTITY,
    )
}

fn identify(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
    (lo, hi): (u32, u32),
    identified: u32,
) -> Result<(), Fault> {
    let cap = buf.buf_cap as u64;
    match outcome {
        Outcome::Failed => short(
            out.needed_bytes,
            cap,
            out.needed_groups,
            buf.groups_cap,
            IDENTITY_GROUPS_HARD_MAX,
        ),
        Outcome::Ready => {
            if out.needed_bytes != 0 || out.needed_groups != 0 {
                return Err(Fault::NeededOnReady);
            }
            if !(lo..=hi).contains(&out.verdict) {
                return Err(Fault::Vocabulary);
            }
            if out.verdict != identified {
                return Ok(());
            }
            let id = &out.identity;
            if id.flags & !IDENTITY_HAS_TTL != 0 {
                return Err(Fault::UnknownFlags);
            }
            if id.claims_fmt > BLOB_OCTETS {
                return Err(Fault::Vocabulary);
            }
            if id.groups_len > buf.groups_cap {
                return Err(Fault::CountOverCap);
            }
            if groups.len() as u64 != u64::from(id.groups_len) {
                return Err(Fault::CountMismatch);
            }
            span(id.subject, cap, false)?;
            for s in [
                id.key_id,
                id.key_name,
                id.user,
                id.provider,
                id.name,
                id.claims,
            ] {
                span(s, cap, true)?;
            }
            groups.iter().try_for_each(|g| span(*g, cap, false))
        }
        Outcome::Refused | Outcome::Pending => no_need(out.needed_bytes, out.needed_groups),
        Outcome::Fault => Ok(()),
    }
}

/// `fields`' answer. `field_buf_cap`/`fields_cap` are the capacities the host handed in, and
/// `fields` the first `fields_len` entries of its field array.
///
/// HOST DUTY: the host checks `out.fields_len <= fields_cap` BEFORE it builds `fields`.
pub fn check_fields(
    outcome: Outcome,
    out: &FieldsOut,
    field_buf_cap: usize,
    fields_cap: u32,
    fields: &[FieldSpan],
) -> Result<(), Fault> {
    let cap = field_buf_cap as u64;
    match outcome {
        Outcome::Failed => short(
            out.needed_bytes,
            cap,
            out.needed_fields,
            fields_cap,
            FIELDS_HARD_MAX,
        ),
        Outcome::Ready => {
            if out.needed_bytes != 0 || out.needed_fields != 0 {
                return Err(Fault::NeededOnReady);
            }
            if out.fields_len > fields_cap {
                return Err(Fault::CountOverCap);
            }
            if fields.len() as u64 != u64::from(out.fields_len) {
                return Err(Fault::CountMismatch);
            }
            fields.iter().try_for_each(|f| {
                if f.flags & !FIELD_SENSITIVE != 0 {
                    return Err(Fault::UnknownFlags);
                }
                span(f.name, cap, false)?;
                span(f.value, cap, false)
            })
        }
        Outcome::Refused | Outcome::Pending => no_need(out.needed_bytes, out.needed_fields),
        Outcome::Fault => Ok(()),
    }
}

/// A plugin-owned string: a non-zero length never rides a NULL pointer.
fn text(s: AbiStr) -> Result<(), Fault> {
    if s.len > 0 && s.ptr.is_null() {
        return Err(Fault::NullWithCount);
    }
    Ok(())
}

/// `begin_login`'s answer: exactly one of [`BEGIN_AUTHORIZE`] | [`BEGIN_FORM`], and the one it
/// names is present.
pub fn check_begin_login(outcome: Outcome, out: &BeginLoginOut) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    if out.shape & !(BEGIN_AUTHORIZE | BEGIN_FORM) != 0 {
        return Err(Fault::Vocabulary);
    }
    if out.shape.count_ones() != 1 {
        return Err(Fault::NotExactlyOne);
    }
    text(out.authorize_url)?;
    if out.form_len > 0 && out.form.is_null() {
        return Err(Fault::NullWithCount);
    }
    let named_absent = match out.shape {
        BEGIN_AUTHORIZE => out.authorize_url.ptr.is_null() || out.authorize_url.len == 0,
        _ => out.form_len == 0,
    };
    if named_absent {
        return Err(Fault::Missing);
    }
    Ok(())
}
