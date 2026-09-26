// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`WorkItem`] — THE extensibility keystone.
//!
//! `dispatch` generalizes from `(req_bytes, sink)` to a SIZED, `#[repr(C)]`, append-only-versioned
//! `WorkItem` carrying a `kind`-tagged INBOUND handle and a `kind`-tagged EMIT handle. From DAY ONE
//! the tags RESERVE every representation even though only some code paths ship:
//!
//! * inbound ∈ { [`Absent`](InboundKind::Absent), [`FiniteBuffer`](InboundKind::FiniteBuffer),
//!   [`Stream`](InboundKind::Stream) }
//! * emit ∈ { [`Absent`](EmitKind::Absent), [`Reply`](EmitKind::Reply),
//!   [`Stream`](EmitKind::Stream), [`Unsolicited`](EmitKind::Unsolicited) }
//!
//! This is what makes a future carrier an APPEND-ONLY add: a new carrier is a new `#[repr(u8)]` kind
//! variant plus a trailing vtable slot — never a breaking reshape of `dispatch`. Collapsing the
//! `WorkItem` to a bare `(ptr,len)+sink` would force that reshape on the first exotic carrier, so the
//! keystone declares ALL tags now. A CI witness (this module's tests) asserts the tags exist and that
//! `WorkItem` can represent an absent/duplex inbound+emit.

use super::host::{HostCtx, PlaneHostVtable};

/// The kind of a [`WorkItem`]'s inbound handle. Reserves all three representations from day one;
/// append-only (new kinds get a fresh trailing discriminant).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    /// No inbound payload (a host-initiated, reply-less carrier). RESERVED.
    Absent = 0,
    /// A single finite buffer (request/response, discrete message). WIRED.
    FiniteBuffer = 1,
    /// A streamed inbound (chunked request body / duplex read side). WIRED.
    Stream = 2,
}

/// The kind of a [`WorkItem`]'s emit handle. Reserves all four representations from day one;
/// append-only.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitKind {
    /// No emit channel (a fire-and-forget / pull carrier). RESERVED.
    Absent = 0,
    /// A single reply — which, for request/response, IS the ack. WIRED.
    Reply = 1,
    /// A streamed emit (response-stream). WIRED.
    Stream = 2,
    /// A host/peer-independent push not correlated to an inbound (duplex-session notification).
    /// WIRED for duplex-session; RESERVED generally.
    Unsolicited = 3,
}

/// A `#[repr(C)]` kind-tagged inbound handle. The `id`/`ptr`/`len` triple is interpreted PER `kind`:
/// for [`FiniteBuffer`](InboundKind::FiniteBuffer) the `(ptr,len)` borrow the request bytes; for
/// [`Stream`](InboundKind::Stream) `id` is a host-side stream handle and `(ptr,len)` are null/0; for
/// [`Absent`](InboundKind::Absent) all are zero. Append-only: new tail fields only.
///
/// # Safety / discipline
/// When `kind == FiniteBuffer` and `len > 0`, `ptr` MUST be a live, initialized range for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InboundHandle {
    /// The inbound representation this handle carries.
    pub kind: InboundKind,
    /// Preamble/alignment padding.
    pub _reserved: [u8; 7],
    /// A host-side handle (used by [`InboundKind::Stream`]; 0 otherwise).
    pub id: u64,
    /// Borrowed inbound bytes for [`InboundKind::FiniteBuffer`] (NOT owned; null otherwise).
    pub ptr: *const u8,
    /// Length of the borrowed inbound range.
    pub len: usize,
}

impl InboundHandle {
    /// An [`InboundKind::Absent`] handle — the reply-less / host-initiated shape.
    #[must_use]
    pub const fn absent() -> Self {
        InboundHandle {
            kind: InboundKind::Absent,
            _reserved: [0; 7],
            id: 0,
            ptr: core::ptr::null(),
            len: 0,
        }
    }

    /// A [`InboundKind::FiniteBuffer`] handle borrowing `bytes` for `'a`.
    #[must_use]
    pub fn finite_buffer(bytes: &[u8]) -> Self {
        InboundHandle {
            kind: InboundKind::FiniteBuffer,
            _reserved: [0; 7],
            id: 0,
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// A [`InboundKind::Stream`] handle over a host-side stream `id`.
    #[must_use]
    pub const fn stream(id: u64) -> Self {
        InboundHandle {
            kind: InboundKind::Stream,
            _reserved: [0; 7],
            id,
            ptr: core::ptr::null(),
            len: 0,
        }
    }
}

/// A `#[repr(C)]` kind-tagged emit handle. `id` is a host-side sink handle interpreted per `kind`
/// (a reply slot, a stream, an unsolicited-push channel). Append-only: new tail fields only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EmitHandle {
    /// The emit representation this handle carries.
    pub kind: EmitKind,
    /// Preamble/alignment padding.
    pub _reserved: [u8; 7],
    /// The host-side sink handle (0 for [`EmitKind::Absent`]).
    pub id: u64,
}

impl EmitHandle {
    /// An [`EmitKind::Absent`] handle — no emit channel.
    #[must_use]
    pub const fn absent() -> Self {
        EmitHandle {
            kind: EmitKind::Absent,
            _reserved: [0; 7],
            id: 0,
        }
    }

    /// An emit handle of `kind` over host-side sink `id`.
    #[must_use]
    pub const fn new(kind: EmitKind, id: u64) -> Self {
        EmitHandle {
            kind,
            _reserved: [0; 7],
            id,
        }
    }
}

/// THE dispatch keystone: a sized/versioned `#[repr(C)]` work item carrying a kind-tagged inbound
/// handle and a kind-tagged emit handle. `dispatch` takes `&WorkItem`; the combination of tags lets
/// ONE signature carry every carrier shape — request/response (finite-buffer + reply), response-
/// stream (finite-buffer/stream + stream), duplex-session (stream + unsolicited), and the reserved
/// pull/accept-loop shapes (absent inbound or absent emit) — with future carriers added append-only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkItem {
    /// `size_of::<WorkItem>()` at construction (the sized-struct guard).
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The kind-tagged inbound handle.
    pub inbound: InboundHandle,
    /// The kind-tagged emit handle.
    pub emit: EmitHandle,
    // ── THE DISPATCH'S OWN HOST AND REPLY (appended at minor 23). A host mints a fresh `HostCtx`
    //    per dispatch (its generation is live only for that call, on that thread), so a plane that
    //    serves a request calls back through THESE, not through the handle it stashed at `build`;
    //    a plane reads them only when `size` proves the host wrote them. ──
    /// The host vtable this dispatch calls back through; NULL = none (use the one handed at build).
    pub host: *const PlaneHostVtable,
    /// The host context minted for THIS dispatch, threaded into every host call it makes.
    pub host_ctx: HostCtx,
    /// A host-owned buffer the plane writes its reply bytes into (the [`EmitKind::Reply`] body);
    /// NULL = no reply channel.
    pub reply_ptr: *mut u8,
    /// Capacity of the reply buffer.
    pub reply_cap: usize,
    /// Where the plane records how many reply bytes it wrote (at most `reply_cap`); NULL with
    /// `reply_ptr`.
    pub reply_written: *mut usize,
}

impl WorkItem {
    /// Assemble a `WorkItem` from an inbound and an emit handle, stamping the sized/versioned
    /// preamble. Borrows carried by `inbound` must outlive the dispatch that receives `&WorkItem`.
    #[must_use]
    pub fn new(inbound: InboundHandle, emit: EmitHandle) -> Self {
        WorkItem {
            size: core::mem::size_of::<WorkItem>() as u32,
            version: super::pod::POD_VERSION,
            _reserved: 0,
            inbound,
            emit,
            host: core::ptr::null(),
            host_ctx: HostCtx::NULL,
            reply_ptr: core::ptr::null_mut(),
            reply_cap: 0,
            reply_written: core::ptr::null_mut(),
        }
    }

    /// This work item, dispatched over `host` with the `host_ctx` minted for it. Both must stay live
    /// for the dispatch call.
    #[must_use]
    pub fn with_host(mut self, host: *const PlaneHostVtable, host_ctx: HostCtx) -> Self {
        self.host = host;
        self.host_ctx = host_ctx;
        self
    }

    /// This work item, with a reply channel: the plane writes at most `reply.len()` bytes into
    /// `reply` and the count into `written`. Both borrows must outlive the dispatch call.
    #[must_use]
    pub fn with_reply(mut self, reply: &mut [u8], written: &mut usize) -> Self {
        self.reply_ptr = reply.as_mut_ptr();
        self.reply_cap = reply.len();
        self.reply_written = written;
        self
    }
}

#[cfg(test)]
#[path = "tests/workitem_tests.rs"]
mod tests;
