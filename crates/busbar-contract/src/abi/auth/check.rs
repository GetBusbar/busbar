// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ANSWER VALIDATORS (ARCHITECT ruling: answer validators live with the shape). Each is
//! a PURE function over the op's `out` and the capacities the host handed in. They use `u64`
//! math and hold no state. The dispatcher calls them after every READY or FAILED answer, and
//! any `Err` makes the answer FAULT. No host re-implements them.

use super::inbound::{BeginLoginOut, IdentifyOut, IdentityBuf};
use super::outbound::{FieldSpan, FieldsOut};
use super::{
    BEGIN_AUTHORIZE, BEGIN_FORM, FIELD_QUERY, FIELD_SENSITIVE, IDENTITY_HAS_TTL, LOGIN_IDENTITY,
    LOGIN_SECURITY_CHECK_FAILED, SPAN_ABSENT, STYLE_CALLER_CREDENTIAL, STYLE_NEEDS_BODY_HASH,
    STYLE_NEEDS_HEADERS, VERDICT_IDENTITY, VERDICT_PASS,
};
use crate::abi::mechanism::call::{AbiStr, Outcome, Span, BLOB_OCTETS};
use crate::abi::mechanism::check::{fault, results, Dim, Fault, Rule, MAX_BYTES};

/// The hard maximum of `needed_groups`: no identity asserts more groups than this.
pub const IDENTITY_GROUPS_HARD_MAX: u32 = 65_536;
/// The hard maximum of `needed_fields`: no style writes more auth fields than this.
pub const FIELDS_HARD_MAX: u32 = 64;

/// The fields one op's arms name, as `op.arm`: the shared [`Fault`] carries one of them.
struct Arms {
    /// The op, naming its whole short-buffer answer.
    op: &'static str,
    /// The byte dimension of its host buffer.
    bytes: &'static str,
    /// The counted dimension of its host buffer (groups, fields).
    count: &'static str,
    /// A verdict, shape or blob format outside the op's vocabulary ([`Rule::UnknownCode`]).
    vocabulary: &'static str,
    /// A flag bit the ABI does not define ([`Rule::UnknownCode`]).
    unknown_flags: &'static str,
    /// Not exactly one bit of a one-of bitfield ([`Rule::NotExactlyOne`]).
    not_exactly_one: &'static str,
    /// An absent span with a length ([`Rule::SpanNotAbsent`]).
    absent_with_len: &'static str,
    /// A span past the buffer's capacity ([`Rule::SpanOutOfBounds`]).
    span_out_of_bounds: &'static str,
    /// A count above its capacity ([`Rule::OverCap`]).
    count_over_cap: &'static str,
    /// A count that disagrees with the slice the host built for it ([`Rule::Contradiction`]).
    count_mismatch: &'static str,
    /// A count above zero with a NULL pointer ([`Rule::NullWithCount`]).
    null_with_count: &'static str,
    /// A part the answer requires is absent ([`Rule::Missing`]).
    missing: &'static str,
}

/// The [`Arms`] of op `$op`, its counted dimension `$count`.
macro_rules! arms {
    ($op:literal, $count:literal) => {
        Arms {
            op: $op,
            bytes: concat!($op, ".bytes"),
            count: concat!($op, ".", $count),
            vocabulary: concat!($op, ".vocabulary"),
            unknown_flags: concat!($op, ".unknown_flags"),
            not_exactly_one: concat!($op, ".not_exactly_one"),
            absent_with_len: concat!($op, ".absent_with_len"),
            span_out_of_bounds: concat!($op, ".span_out_of_bounds"),
            count_over_cap: concat!($op, ".count_over_cap"),
            count_mismatch: concat!($op, ".count_mismatch"),
            null_with_count: concat!($op, ".null_with_count"),
            missing: concat!($op, ".missing"),
        }
    };
}

const VERIFY: Arms = arms!("verify", "groups");
const COMPLETE_LOGIN: Arms = arms!("complete_login", "groups");
const FIELDS: Arms = arms!("fields", "fields");
const BEGIN_LOGIN: Arms = arms!("begin_login", "form");

/// `off + len <= cap` in `u64`, or [`SPAN_ABSENT`] with `len == 0` when `optional`.
fn span(s: Span, cap: u64, optional: bool, a: &Arms) -> Result<(), Fault> {
    if s.offset == SPAN_ABSENT {
        return match (s.len, optional) {
            (0, true) => Ok(()),
            (0, false) => Err(fault(Rule::Missing, a.missing)),
            _ => Err(fault(Rule::SpanNotAbsent, a.absent_with_len)),
        };
    }
    if u64::from(s.offset) + u64::from(s.len) > cap {
        return Err(fault(Rule::SpanOutOfBounds, a.span_out_of_bounds));
    }
    Ok(())
}

/// The host buffer's two dimensions under the multi-buffer short-buffer rule
/// ([`results`]): a `needed_*` only on FAILED, each within its hard maximum, at least one above
/// its capacity. The plugin states no `written` count, so each dimension's is `0`.
fn needed(
    outcome: Outcome,
    (needed_bytes, bytes_cap): (u64, u64),
    (needed_count, count_cap, hard): (u32, u32, u32),
    a: &Arms,
) -> Result<(), Fault> {
    let dims = [
        Dim {
            written: 0,
            needed: needed_bytes,
            cap: bytes_cap,
            max: MAX_BYTES,
            field: a.bytes,
        },
        Dim {
            written: 0,
            needed: u64::from(needed_count),
            cap: u64::from(count_cap),
            max: u64::from(hard),
            field: a.count,
        },
    ];
    results(outcome, a.op, &dims)?;
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
        &VERIFY,
    )
}

/// `complete_login`'s answer: the same rules as [`check_identify`] (and the same host duty), over
/// the login vocabulary [`LOGIN_IDENTITY`] ..= [`LOGIN_SECURITY_CHECK_FAILED`].
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
        (LOGIN_IDENTITY, LOGIN_SECURITY_CHECK_FAILED),
        LOGIN_IDENTITY,
        &COMPLETE_LOGIN,
    )
}

fn identify(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
    (lo, hi): (u32, u32),
    identified: u32,
    a: &Arms,
) -> Result<(), Fault> {
    if outcome == Outcome::Fault {
        return Ok(());
    }
    let cap = buf.buf_cap as u64;
    needed(
        outcome,
        (out.needed_bytes, cap),
        (out.needed_groups, buf.groups_cap, IDENTITY_GROUPS_HARD_MAX),
        a,
    )?;
    if outcome != Outcome::Ready {
        return Ok(());
    }
    if !(lo..=hi).contains(&out.verdict) {
        return Err(fault(Rule::UnknownCode, a.vocabulary));
    }
    if out.verdict != identified {
        return Ok(());
    }
    let id = &out.identity;
    if id.flags & !IDENTITY_HAS_TTL != 0 {
        return Err(fault(Rule::UnknownCode, a.unknown_flags));
    }
    if id.claims_fmt > BLOB_OCTETS {
        return Err(fault(Rule::UnknownCode, a.vocabulary));
    }
    // A replay TTL with no replay key is half an answer (its key is Missing): never half-read.
    if id.replay_ttl_secs != 0
        && (id.replay_key.offset == SPAN_ABSENT || id.replay_key.len == 0)
    {
        return Err(fault(Rule::Missing, a.missing));
    }
    if id.groups_len > buf.groups_cap {
        return Err(fault(Rule::OverCap, a.count_over_cap));
    }
    if groups.len() as u64 != u64::from(id.groups_len) {
        return Err(fault(Rule::Contradiction, a.count_mismatch));
    }
    span(id.subject, cap, false, a)?;
    for s in [
        id.key_id,
        id.key_name,
        id.user,
        id.provider,
        id.name,
        id.claims,
        id.replay_key,
    ] {
        span(s, cap, true, a)?;
    }
    groups.iter().try_for_each(|g| span(*g, cap, false, a))
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
    if outcome == Outcome::Fault {
        return Ok(());
    }
    let cap = field_buf_cap as u64;
    let a = &FIELDS;
    needed(
        outcome,
        (out.needed_bytes, cap),
        (out.needed_fields, fields_cap, FIELDS_HARD_MAX),
        a,
    )?;
    if outcome != Outcome::Ready {
        return Ok(());
    }
    if out.fields_len > fields_cap {
        return Err(fault(Rule::OverCap, a.count_over_cap));
    }
    if fields.len() as u64 != u64::from(out.fields_len) {
        return Err(fault(Rule::Contradiction, a.count_mismatch));
    }
    fields.iter().try_for_each(|f| {
        if f.flags & !(FIELD_SENSITIVE | FIELD_QUERY) != 0 {
            return Err(fault(Rule::UnknownCode, a.unknown_flags));
        }
        span(f.name, cap, false, a)?;
        span(f.value, cap, false, a)
    })
}

/// One [`super::StyleDecl::flags`]: only [`STYLE_NEEDS_BODY_HASH`] | [`STYLE_NEEDS_HEADERS`] |
/// [`STYLE_CALLER_CREDENTIAL`] bits, nothing else. Run by the loader when it reads a plugin's
/// declared styles, so a plugin build with a stray or future flag bit refuses the load rather than
/// have the kernel silently ignore it.
pub fn check_style_decl(flags: u32) -> Result<(), Fault> {
    if flags & !(STYLE_NEEDS_BODY_HASH | STYLE_NEEDS_HEADERS | STYLE_CALLER_CREDENTIAL) != 0 {
        return Err(fault(Rule::UnknownCode, "style.unknown_flags"));
    }
    Ok(())
}

/// A plugin-owned string: a non-zero length never rides a NULL pointer.
fn text(s: AbiStr, a: &Arms) -> Result<(), Fault> {
    if s.len > 0 && s.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, a.null_with_count));
    }
    Ok(())
}

/// `begin_login`'s answer: exactly one of [`BEGIN_AUTHORIZE`] | [`BEGIN_FORM`], and the one it
/// names is present.
pub fn check_begin_login(outcome: Outcome, out: &BeginLoginOut) -> Result<(), Fault> {
    let a = &BEGIN_LOGIN;
    if outcome != Outcome::Ready {
        return Ok(());
    }
    if out.shape & !(BEGIN_AUTHORIZE | BEGIN_FORM) != 0 {
        return Err(fault(Rule::UnknownCode, a.vocabulary));
    }
    if out.shape.count_ones() != 1 {
        return Err(fault(Rule::NotExactlyOne, a.not_exactly_one));
    }
    text(out.authorize_url, a)?;
    if out.form_len > 0 && out.form.is_null() {
        return Err(fault(Rule::NullWithCount, a.null_with_count));
    }
    let named_absent = match out.shape {
        BEGIN_AUTHORIZE => out.authorize_url.ptr.is_null() || out.authorize_url.len == 0,
        _ => out.form_len == 0,
    };
    if named_absent {
        return Err(fault(Rule::Missing, a.missing));
    }
    Ok(())
}
