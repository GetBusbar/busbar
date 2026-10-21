// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND FAMILY (the design's outbound auth): `open_outbound` binds a style to its
//! credential and answers a handle. `fields` is the call the binding's transport makes at the
//! style's auth points, the head final, before encode (THE DESIGN, "Auth points and guest
//! lists", step 5). `outbound_ready` is the
//! `ready` fact the health prober reads. The plugin caches inside itself: bearer and api-key build
//! at open, and minted tokens refresh ahead of expiry on `tick`.

use super::inbound::{NamedValue, RequestFacts};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Span};

/// `open_outbound`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenOutboundIn {
    /// The head.
    pub head: InHead,
    /// The style the provider entry resolved to (one the tail declares).
    pub style: AbiStr,
    /// The resolved credential (secret); absent for a passthrough-only binding.
    pub credential: Blob,
    /// The provider's auth settings (region, audience, token URL ...), a payload blob.
    pub settings: Blob,
}

/// `open_outbound`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenOutboundOut {
    /// The head.
    pub head: OutHead,
    /// The handle; opaque to the kernel, valid until `retire` of this generation.
    pub handle: u64,
}

/// `outbound_ready`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutboundReadyIn {
    /// The head.
    pub head: InHead,
    /// The handle.
    pub handle: u64,
}

/// `outbound_ready`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutboundReadyOut {
    /// The head.
    pub head: OutHead,
    /// `1` = `fields` would answer with a credential now; `0` = not yet (before the first mint,
    /// or expired with a failed refresh).
    pub ready: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// One field `fields` wrote: spans into [`FieldsIn::field_buf`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FieldSpan {
    /// The field name.
    pub name: Span,
    /// The field value.
    pub value: Span,
    /// [`super::FIELD_SENSITIVE`] | [`super::FIELD_QUERY`].
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

impl FieldSpan {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `FieldSpan { …, ..FieldSpan::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        name: Span::ZERO,
        value: Span::ZERO,
        flags: 0,
        _reserved: 0,
    };
}

/// `fields`' `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FieldsIn {
    /// The head.
    pub head: InHead,
    /// The handle `open_outbound` answered.
    pub handle: u64,
    /// [`super::MODE_OWN`] | [`super::MODE_PASSTHROUGH`].
    pub mode: u32,
    /// The [`AuthPoint`](super::AuthPoint) this call is made at: exactly one of the style's
    /// [`StyleDecl::points`](super::StyleDecl).
    pub point: u32,
    /// The request's fixed facts.
    pub request: RequestFacts,
    /// The caller's verified credential (secret), for [`super::MODE_PASSTHROUGH`]; else absent.
    pub caller_credential: Blob,
    /// The host buffer the field bytes go into. It holds credential material: the host treats it
    /// as a [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) (never logged, zeroised once
    /// the head is encoded).
    pub field_buf: *mut u8,
    /// Its capacity ([`super::FIELDS_BUF_BYTES`]).
    pub field_buf_cap: usize,
    /// The host array the fields go into, in order.
    pub fields: *mut FieldSpan,
    /// Its capacity ([`super::FIELDS_MAX`]).
    pub fields_cap: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The EXACT header envelope the framer will send, in order, filled only when the style
    /// declares [`super::STYLE_NEEDS_HEADERS`] (NULL otherwise, so bearer and api-key pay nothing).
    /// A signing style SETS its own fields over it (never appends) and signs the result, so its
    /// signed-header set is 1.5.5's byte for byte.
    pub headers: *const NamedValue,
    /// How many.
    pub headers_len: usize,
    /// The connection the binding sends on, so a style needing several points correlates them.
    pub conn: u64,
    /// The unit the request belongs to.
    pub unit: u64,
    /// The whole request body; present only at [`super::POINT_HEAD_BODY`], else absent. A style
    /// that signs the body hashes it itself.
    pub body: Blob,
}

/// `fields`' `out`. READY with `fields_len == 0` = no auth header.
///
/// THE ANSWER RULES, enforced by [`super::check_fields`] in `u64` math (any violation is FAULT).
/// On REFUSED or PENDING, every `needed_*` is `0`. On READY, `needed_fields == 0` and `needed_bytes == 0`, `fields_len <= fields_cap`, every
/// written [`FieldSpan`]'s name and value are present with `off + len <= field_buf_cap`, and its
/// `flags` hold only [`super::FIELD_SENSITIVE`] and [`super::FIELD_QUERY`]. On FAILED, `needed_bytes <= u32::MAX` and
/// `needed_fields <=` [`super::FIELDS_HARD_MAX`]; both `0` fails the attempt;
/// otherwise each reports its FULL size and at least one exceeds its capacity (a fitting
/// dimension's full size is legal; none exceeding is FAULT, a wasted re-call).
///
/// SHORT BUFFER: a plugin never writes past a capacity. When the fields do not fit it answers
/// `FAILED` with `needed_fields` or `needed_bytes` above the capacity it was given and writes
/// nothing else; the host re-issues the op once, as a fresh call on the SAME ticket, with buffers
/// at least that large, and a second short answer is FAULT. `FAILED` with both at `0` fails the
/// attempt. Nothing the plugin needs lives in this `out`: the host zeroes it before every call.
/// [`super::MODE_PASSTHROUGH`] on a handle whose style does not pass the caller's credential
/// answers `REFUSED`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FieldsOut {
    /// The head.
    pub head: OutHead,
    /// How many fields were written, in order.
    pub fields_len: u32,
    /// Short buffer: the fields needed.
    pub needed_fields: u32,
    /// Short buffer: the bytes needed.
    pub needed_bytes: u64,
}

/// `target`'s `in`: one style, its credential and its settings, and the host's buffer the answer
/// is written into.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TargetIn {
    /// The head.
    pub head: InHead,
    /// The style the provider entry resolved to (one the tail declares).
    pub style: AbiStr,
    /// The resolved credential (secret): read, never kept past the call.
    pub credential: Blob,
    /// The provider's auth settings, a payload blob, as `open_outbound` is handed them.
    pub settings: Blob,
    /// THE HOST'S BUFFER, lent for the call: READY writes the target URL into it and names it in
    /// [`TargetOut::target`]; FAILED writes why into it (UTF-8, cut on a char boundary) and names
    /// those bytes in `head.error`. Never secret material.
    pub buf: *mut u8,
    /// How many bytes `buf` holds.
    pub buf_cap: usize,
}

/// `target`'s `out`.
///
/// THE ANSWER RULES, enforced by [`super::check_target`]: on READY, `target` is
/// [`SPAN_ABSENT`](super::SPAN_ABSENT) with `len == 0` (no destination) or lies within
/// `buf_cap` and is not empty; on every other outcome it is absent.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TargetOut {
    /// The head.
    pub head: OutHead,
    /// The target URL, a span into [`TargetIn::buf`].
    pub target: Span,
}
