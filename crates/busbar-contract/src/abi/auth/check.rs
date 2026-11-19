// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH ANSWER VALIDATORS, defined beside their output shapes. Each is

use super::inbound::{IdentifyOut, IdentityBuf};
use super::outbound::TargetOut;
use super::points::{AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use super::{
    BEGIN_AUTHORIZE, BEGIN_FORM, CAP_INBOUND, DECISION_CONTINUE, FIELD_QUERY, FIELD_SENSITIVE,
    IDENTITY_HAS_TTL, LOGIN_IDENTITY, LOGIN_SECURITY_CHECK_FAILED, SPAN_ABSENT, STRIP_QUERY,
    STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL, STYLE_NEEDS_HEADERS, STYLE_RANK_MASK,
    VERDICT_IDENTITY,
};
use crate::abi::mechanism::call::{Outcome, Span, BLOB_OCTETS};
use crate::abi::mechanism::check::{fault, listed, results, text, Dim, Fault, Rule, MAX_BYTES};

/// The hard maximum of `needed_groups`: no identity asserts more groups than this.
pub const IDENTITY_GROUPS_HARD_MAX: u32 = 65_536;
/// The hard maximum of `needed_fields`: no style writes more auth fields than this. Also the
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

/// A point set read off the ABI: only [`POINT_PEER`] | [`POINT_HEAD`] | [`POINT_HEAD_BODY`] bits
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

/// A READY identity answer's shared rules: the verdict in `lo..=hi`, and, for the `identified`
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
    if id.subject.len == 0 {
        return Err(fault(Rule::Missing, a.missing));
    }
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

/// `target`'s answer. `buf_cap` is the capacity of the buffer the host handed in. On READY the
pub fn check_target(outcome: Outcome, out: &TargetOut, buf_cap: usize) -> Result<(), Fault> {
    let t = out.target;
    match outcome {
        Outcome::Fault | Outcome::Pending => Ok(()),
        Outcome::Ready if t.offset == SPAN_ABSENT => match t.len {
            0 => Ok(()),
            _ => Err(fault(Rule::SpanNotAbsent, "target.target.absent_with_len")),
        },
        Outcome::Ready if t.len == 0 => Err(fault(Rule::Missing, "target.target.empty")),
        Outcome::Ready if u64::from(t.offset) + u64::from(t.len) > buf_cap as u64 => {
            Err(fault(Rule::SpanOutOfBounds, "target.target.out_of_bounds"))
        }
        Outcome::Ready => Ok(()),
        _ if t.offset == SPAN_ABSENT && t.len == 0 => Ok(()),
        _ => Err(fault(Rule::Contradiction, "target.target.unexpected")),
    }
}
