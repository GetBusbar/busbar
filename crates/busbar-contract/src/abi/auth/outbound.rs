// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND FAMILY (the design's outbound auth): `open_outbound` binds a style to its

use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Span};

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
