// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ANSWER VALIDATORS (ARCHITECT ruling: answer validators live with the shape). Each is
//! a PURE function over the op's `out` and the capacities the host handed in. They use `u64`
//! math and hold no state. The dispatcher calls them after every READY or FAILED answer, and
//! any `Err` makes the answer FAULT. No host re-implements them.

use super::inbound::{BeginLoginOut, IdentifyOut, IdentityBuf, StripName};
use super::outbound::{FieldSpan, FieldsOut};
use super::points::{AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use super::{
    BEGIN_AUTHORIZE, BEGIN_FORM, CAP_INBOUND, DECISION_CONTINUE, DECISION_STOP, FIELD_QUERY,
    FIELD_SENSITIVE, IDENTITY_HAS_TTL, LOGIN_IDENTITY, LOGIN_SECURITY_CHECK_FAILED, SPAN_ABSENT,
    STRIP_FIELD, STRIP_QUERY, STYLE_CALLER_CREDENTIAL, STYLE_NEEDS_HEADERS, VERDICT_IDENTITY,
    VERDICT_PASS,
};
use crate::abi::mechanism::call::{AbiStr, Outcome, Span, BLOB_OCTETS};
use crate::abi::mechanism::check::{fault, results, Dim, Fault, Rule, MAX_BYTES};

/// The hard maximum of `needed_groups`: no identity asserts more groups than this.
pub const IDENTITY_GROUPS_HARD_MAX: u32 = 65_536;
/// The hard maximum of `needed_fields`: no style writes more auth fields than this. Also the
/// hard maximum of `verify`'s `needed_strip`: no auth names more lines to strip than this.
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
    /// A part the answer must not carry is present ([`Rule::Contradiction`]): a `credential`
    /// without an identity verdict, or a decision, strip names or a credential on a login.
    unexpected: &'static str,
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
            unexpected: concat!($op, ".unexpected"),
        }
    };
}

const VERIFY: Arms = arms!("verify", "groups");
const COMPLETE_LOGIN: Arms = arms!("complete_login", "groups");
const FIELDS: Arms = arms!("fields", "fields");
const BEGIN_LOGIN: Arms = arms!("begin_login", "form");

/// `verify`'s strip-array dimension, as `op.field`.
const VERIFY_STRIP: &str = "verify.strip";

/// A point set read off the ABI: only [`POINT_PEER`] | [`POINT_HEAD`] | [`POINT_HEAD_BODY`] bits
/// (an unknown bit is [`Rule::UnknownCode`]; [`POINT_FRAME`] is named, reserved and refused the
/// same way), never `HEAD` and `HEAD_BODY` together ([`Rule::Contradiction`]: `HeadBody` includes
/// the head), and, when `required`, not empty ([`Rule::Missing`]).
///
/// # Errors
/// The set breaks one of the rules above.
pub const fn check_points(bits: u32, required: bool) -> Result<AuthPoints, Fault> {
    if bits & !(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY | POINT_FRAME) != 0 {
        return Err(fault(Rule::UnknownCode, "points.unknown_flags"));
    }
    if bits & POINT_FRAME != 0 {
        return Err(fault(Rule::UnknownCode, "points.reserved_point"));
    }
    if bits & POINT_HEAD != 0 && bits & POINT_HEAD_BODY != 0 {
        return Err(fault(Rule::Contradiction, "points.points_overlap"));
    }
    if required && bits == 0 {
        return Err(fault(Rule::Missing, "points.missing"));
    }
    Ok(AuthPoints(bits))
}

/// An [`AuthTail`](super::AuthTail)'s `inbound_points` against its `caps`: with
/// [`CAP_INBOUND`] a valid, non-empty set ([`check_points`]); without it `0`
/// ([`Rule::Contradiction`] otherwise). Run by the loader when it reads the tail.
///
/// # Errors
/// The set is invalid, empty for an inbound plugin, or stated by a plugin that serves no
/// `verify`.
pub const fn check_inbound_points(caps: u32, points: u32) -> Result<AuthPoints, Fault> {
    if caps & CAP_INBOUND != 0 {
        return check_points(points, true);
    }
    if points != 0 {
        return Err(fault(Rule::Contradiction, "points.unexpected"));
    }
    Ok(AuthPoints::EMPTY)
}

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

/// One host-buffer dimension of an answer: what it needs, the capacity handed in and its hard
/// maximum. The plugin states no `written` count, so its `written` is `0`.
const fn dim(needed: u64, cap: u64, max: u64, field: &'static str) -> Dim {
    Dim {
        written: 0,
        needed,
        cap,
        max,
        field,
    }
}

/// The host buffer's two dimensions (bytes and the op's counted one) under the multi-buffer
/// short-buffer rule ([`results`]): a `needed_*` only on FAILED, each within its hard maximum,
/// at least one above its capacity.
fn needed(
    outcome: Outcome,
    (needed_bytes, bytes_cap): (u64, u64),
    (needed_count, count_cap, hard): (u32, u32, u32),
    a: &Arms,
) -> Result<(), Fault> {
    let dims = [
        dim(needed_bytes, bytes_cap, MAX_BYTES, a.bytes),
        dim(
            u64::from(needed_count),
            u64::from(count_cap),
            u64::from(hard),
            a.count,
        ),
    ];
    results(outcome, a.op, &dims)?;
    Ok(())
}

/// `verify`'s answer. `buf` is the [`IdentityBuf`] the host handed in, `groups` the first
/// `groups_len` spans of its group array, `strip_cap` the capacity of the strip array the host
/// handed in and `strips` its first `strip_len` entries.
///
/// HOST DUTY: the host checks `out.identity.groups_len <= buf.groups_cap` and
/// `out.strip_len <= strip_cap` BEFORE it builds `groups` and `strips` from its arrays; a larger
/// count is FAULT without reading a single entry.
///
/// # Errors
/// The answer breaks a rule [`IdentifyOut`] states.
pub fn check_identify(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
    strip_cap: u32,
    strips: &[StripName],
) -> Result<(), Fault> {
    if outcome == Outcome::Fault {
        return Ok(());
    }
    let a = &VERIFY;
    let cap = buf.buf_cap as u64;
    let dims = [
        dim(out.needed_bytes, cap, MAX_BYTES, a.bytes),
        dim(
            u64::from(out.needed_groups),
            u64::from(buf.groups_cap),
            u64::from(IDENTITY_GROUPS_HARD_MAX),
            a.count,
        ),
        dim(
            u64::from(out.needed_strip),
            u64::from(strip_cap),
            u64::from(FIELDS_HARD_MAX),
            VERIFY_STRIP,
        ),
    ];
    results(outcome, a.op, &dims)?;
    if outcome != Outcome::Ready {
        return Ok(());
    }
    identity(
        out,
        buf,
        groups,
        (VERDICT_IDENTITY, VERDICT_PASS),
        VERDICT_IDENTITY,
        a,
    )?;
    if !matches!(out.decision, DECISION_CONTINUE | DECISION_STOP) {
        return Err(fault(Rule::UnknownCode, a.vocabulary));
    }
    // The credential rides only an identity; `len == 0` is absent.
    if out.identity.credential.len != 0 {
        if out.verdict != VERDICT_IDENTITY {
            return Err(fault(Rule::Contradiction, a.unexpected));
        }
        span(out.identity.credential, cap, false, a)?;
    }
    if out.strip_len > strip_cap {
        return Err(fault(Rule::OverCap, a.count_over_cap));
    }
    if strips.len() as u64 != u64::from(out.strip_len) {
        return Err(fault(Rule::Contradiction, a.count_mismatch));
    }
    strips.iter().try_for_each(|s| {
        if !matches!(s.place, STRIP_FIELD | STRIP_QUERY) {
            return Err(fault(Rule::UnknownCode, a.vocabulary));
        }
        span(s.name, cap, false, a)
    })
}

/// `complete_login`'s answer: the same identity rules as [`check_identify`] (and the same host
/// duty for the groups), over the login vocabulary [`LOGIN_IDENTITY`] ..=
/// [`LOGIN_SECURITY_CHECK_FAILED`]. A login answers no decision, names no line to strip and
/// carries no credential: each is `0`/absent ([`Rule::Contradiction`] otherwise).
///
/// # Errors
/// The answer breaks a rule [`IdentifyOut`] states.
pub fn check_complete_login(
    outcome: Outcome,
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
) -> Result<(), Fault> {
    if outcome == Outcome::Fault {
        return Ok(());
    }
    let a = &COMPLETE_LOGIN;
    if out.decision != 0
        || out.strip_len != 0
        || out.needed_strip != 0
        || out.identity.credential.len != 0
    {
        return Err(fault(Rule::Contradiction, a.unexpected));
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
    identity(
        out,
        buf,
        groups,
        (LOGIN_IDENTITY, LOGIN_SECURITY_CHECK_FAILED),
        LOGIN_IDENTITY,
        a,
    )
}

/// A READY identity answer's shared rules: the verdict in `lo..=hi`, and, for the `identified`
/// verdict, a well-formed identity.
fn identity(
    out: &IdentifyOut,
    buf: &IdentityBuf,
    groups: &[Span],
    (lo, hi): (u32, u32),
    identified: u32,
    a: &Arms,
) -> Result<(), Fault> {
    let cap = buf.buf_cap as u64;
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
    if id.replay_ttl_secs != 0 && (id.replay_key.offset == SPAN_ABSENT || id.replay_key.len == 0) {
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

/// One [`super::StyleDecl`]'s `flags` and `points`: only [`STYLE_NEEDS_HEADERS`] |
/// [`STYLE_CALLER_CREDENTIAL`] flag bits, nothing else, and a valid, non-empty point set
/// ([`check_points`]). Run by the loader when it reads a plugin's declared styles, so a plugin
/// build with a stray or future bit, or a style that needs no point, refuses the load rather than
/// have the host silently ignore it.
///
/// # Errors
/// An unknown flag bit, or a point set [`check_points`] refuses.
pub const fn check_style_decl(flags: u32, points: u32) -> Result<AuthPoints, Fault> {
    if flags & !(STYLE_NEEDS_HEADERS | STYLE_CALLER_CREDENTIAL) != 0 {
        return Err(fault(Rule::UnknownCode, "style.unknown_flags"));
    }
    check_points(points, true)
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
