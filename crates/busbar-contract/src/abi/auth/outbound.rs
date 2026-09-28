// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND FAMILY (the design's outbound auth): `open_outbound` binds a style to its
//! credential and answers a handle. `fields` is the one per-attempt call the kernel makes before
//! encode. `outbound_ready` is the
//! `ready` fact the health prober reads. The plugin caches inside itself: bearer and api-key build
//! at open, and minted tokens refresh ahead of expiry on `tick`.

use super::inbound::{RequestFacts, Span};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead};

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
    /// [`super::FIELD_SENSITIVE`].
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
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
    /// Alignment padding.
    pub _reserved: u32,
    /// The request's fixed facts. `body_hash` is filled only when the style declares
    /// [`super::STYLE_NEEDS_BODY_HASH`].
    pub request: RequestFacts,
    /// The caller's verified credential (secret), for [`super::MODE_PASSTHROUGH`]; else absent.
    pub caller_credential: Blob,
    /// The host buffer the field bytes go into.
    pub field_buf: *mut u8,
    /// Its capacity ([`super::FIELDS_BUF_BYTES`]).
    pub field_buf_cap: usize,
    /// The host array the fields go into, in order.
    pub fields: *mut FieldSpan,
    /// Its capacity ([`super::FIELDS_MAX`]).
    pub fields_cap: u32,
    /// Alignment padding.
    pub _reserved2: u32,
}

/// `fields`' `out`. READY with `fields_len == 0` = no auth header. A plugin never writes past a
/// capacity: fields that would not fit answer `FAILED`, which fails the attempt.
/// [`super::MODE_PASSTHROUGH`] on a handle whose style does not pass the caller's credential
/// answers `REFUSED`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FieldsOut {
    /// The head.
    pub head: OutHead,
    /// How many fields were written, in order.
    pub fields_len: u32,
    /// Alignment padding.
    pub _reserved: u32,
}
