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
//!
//! THE CARRIER A PLANE IN ITS OWN REPOSITORY NEEDS (minor 30, DEC-SERVE G2) rides the same item,
//! appended: the request-head handle and its accessor slot (method, path, query, headers), the
//! answer's head slot (status `u16` + headers) and the response-stream handle and slot a body larger
//! than the reply buffer goes out through. The kind tags above are unchanged, and still reserve
//! absent/duplex.

use super::host::{HostCtx, PlaneHostVtable};
use super::pod::StatusClass;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

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
    // ── THE REQUEST HEAD AND THE ANSWER'S OWN HEAD AND BODY (appended at minor 30, DEC-SERVE G2).
    //    A plane that lives in its own repository reads what the caller sent — method, path, query,
    //    headers — and answers with the status, headers and body its provider answered, byte for
    //    byte. The head is a HANDLE the plane reads through `head_read`; the answer's status and
    //    headers go out through `emit_head`, and a body larger than `reply_cap` goes out in chunks
    //    through `emit_body` on the `stream` handle (the response-stream emit kind). All five are
    //    supplied by the door that built the work item, and a plane reads them only when `size`
    //    proves the host wrote them. ──
    /// The request-head handle: host-owned, live for the dispatch call, read ONLY through
    /// [`head_read`](Self::head_read). NULL = the host carries no head.
    pub head: *const c_void,
    /// The accessor slot over [`head`](Self::head); see [`HeadReadFn`].
    pub head_read: Option<HeadReadFn>,
    /// The slot that states the answer's status and headers, on [`emit`](Self::emit)'s id; see
    /// [`EmitHeadFn`].
    pub emit_head: Option<EmitHeadFn>,
    /// The response-stream emit handle ([`EmitKind::Stream`]) a body over `reply_cap` is written
    /// through; [`EmitKind::Absent`] = the host offers no stream.
    pub stream: EmitHandle,
    /// The slot that writes one body chunk on [`stream`](Self::stream)'s id; see [`EmitBodyFn`].
    pub emit_body: Option<EmitBodyFn>,
}

/// Which part of a request head [`HeadReadFn`] reads. Crosses the seam as its raw `u8` (a peer's
/// unknown value is refused, never transmuted); append-only.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadPart {
    /// The request method, as sent (`value` only).
    Method = 0,
    /// The request path, without the query (`value` only).
    Path = 1,
    /// The query string, without the `?` (`value` only; empty when the request carried none).
    Query = 2,
    /// The `index`-th header, in the order the host received them (`name` and `value`).
    Header = 3,
}

/// One borrowed head field: a `(name, value)` pair of byte ranges. For a method, path or query the
/// name is empty. Ranges handed OUT by [`HeadReadFn`] are live for the dispatch call; ranges handed
/// IN to [`EmitHeadFn`] are live for that call only (the host copies them).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HeadField {
    /// The field name's bytes (NULL with `name_len == 0` for none).
    pub name_ptr: *const u8,
    /// The field name's length.
    pub name_len: usize,
    /// The field value's bytes (NULL with `value_len == 0` for none).
    pub value_ptr: *const u8,
    /// The field value's length.
    pub value_len: usize,
}

impl HeadField {
    /// A field borrowing `name` and `value`.
    #[must_use]
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        HeadField {
            name_ptr: name.as_ptr(),
            name_len: name.len(),
            value_ptr: value.as_ptr(),
            value_len: value.len(),
        }
    }

    /// The name's bytes.
    ///
    /// # Safety
    /// The range must be live for `'a` (the discipline of whichever slot handed the field over).
    #[must_use]
    pub unsafe fn name<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's obligation.
        unsafe { borrowed(self.name_ptr, self.name_len) }
    }

    /// The value's bytes.
    ///
    /// # Safety
    /// As [`name`](Self::name).
    #[must_use]
    pub unsafe fn value<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's obligation.
        unsafe { borrowed(self.value_ptr, self.value_len) }
    }
}

/// A borrowed `(ptr, len)` range as a slice; empty for NULL or zero.
///
/// # Safety
/// A non-null `ptr` must address `len` live, initialized bytes for `'a`.
unsafe fn borrowed<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's obligation.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// READ ONE PART OF THE REQUEST HEAD: `part` is a [`HeadPart`] as its raw `u8`; `index` selects the
/// header (ignored for the other parts). Writes the field into `out` on [`StatusClass::Ok`] (init only
/// on Ok); [`StatusClass::Gone`] past the last header; [`StatusClass::Refused`] for a NULL head or
/// out, or a `part` this host does not know; [`StatusClass::Fault`] on a caught panic.
pub type HeadReadFn = extern "C-unwind" fn(
    head: *const c_void,
    part: u8,
    index: u32,
    out: *mut MaybeUninit<HeadField>,
) -> StatusClass;

/// STATE THE ANSWER'S HEAD on emit handle `emit`: the HTTP `status` the plane answers with (its
/// provider's, passed through) and `headers_len` headers, each a [`HeadField`]. Called at most once,
/// before any [`EmitBodyFn`] chunk; the host serves exactly this status and exactly these headers.
/// [`StatusClass::Ok`] when taken; [`StatusClass::Refused`] for a status outside `100..=999`, a
/// header the host cannot serve, a second call or a call after the body began;
/// [`StatusClass::Fault`] on a caught panic.
pub type EmitHeadFn = extern "C-unwind" fn(
    emit: u64,
    status: u16,
    headers_ptr: *const HeadField,
    headers_len: usize,
) -> StatusClass;

/// WRITE ONE CHUNK of a streamed body on emit handle `emit` (the work item's
/// [`stream`](WorkItem::stream) id). The first chunk commits the head (the one
/// [`EmitHeadFn`] stated, or the host's default) and the answer is then served as a stream: the
/// reply buffer is not read. [`StatusClass::Ok`] when taken; [`StatusClass::Gone`] when the caller
/// went away (the plane stops); [`StatusClass::Refused`] for a handle the host did not issue;
/// [`StatusClass::Fault`] on a caught panic.
pub type EmitBodyFn =
    extern "C-unwind" fn(emit: u64, chunk_ptr: *const u8, chunk_len: usize) -> StatusClass;

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
            head: core::ptr::null(),
            head_read: None,
            emit_head: None,
            stream: EmitHandle::absent(),
            emit_body: None,
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

    /// Read one part of the request head through the work item's own accessor slot: `Some` with the
    /// field when the host wrote a head and its slot answered `Ok`, `None` otherwise (an older host's
    /// work item, no head, a header `index` past the last).
    ///
    /// # Safety
    /// `work` must address a live work item for the dispatch call whose `size` states what its
    /// sender wrote (the dispatch discipline). The field's ranges are live for that call.
    #[must_use]
    pub unsafe fn read_head(
        work: *const WorkItem,
        part: HeadPart,
        index: u32,
    ) -> Option<HeadField> {
        // SAFETY: the caller's obligation; `size` leads every work item.
        let size = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*work).size)) };
        let head = crate::read_sized_field!(work, size, WorkItem, head)?;
        let read = crate::read_sized_field!(work, size, WorkItem, head_read)??;
        let mut out = MaybeUninit::<HeadField>::uninit();
        if read(head, part as u8, index, &mut out) != StatusClass::Ok {
            return None; // init-only-on-Ok: `out` stays unread
        }
        // SAFETY: init-only-on-Ok — the slot wrote `out` before answering `Ok`.
        Some(unsafe { out.assume_init() })
    }
}

#[cfg(test)]
#[path = "tests/workitem_tests.rs"]
mod tests;
