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
}

impl WorkItem {
    /// Assemble a `WorkItem` from an inbound and an emit handle, stamping the sized/versioned
    /// preamble. Borrows carried by `inbound` must outlive the dispatch that receives `&WorkItem`.
    #[must_use]
    pub fn new(inbound: InboundHandle, emit: EmitHandle) -> Self {
        WorkItem {
            size: core::mem::size_of::<WorkItem>() as u32,
            version: crate::pod::POD_VERSION,
            _reserved: 0,
            inbound,
            emit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workitem_can_represent_request_response() {
        let req = b"hello";
        let wi = WorkItem::new(
            InboundHandle::finite_buffer(req),
            EmitHandle::new(EmitKind::Reply, 42),
        );
        assert_eq!(wi.inbound.kind, InboundKind::FiniteBuffer);
        assert_eq!(wi.inbound.len, req.len());
        assert_eq!(wi.emit.kind, EmitKind::Reply);
    }

    #[test]
    fn workitem_can_represent_absent_inbound_and_emit() {
        // The reserved pull-class shape: host-initiated, reply-less. The keystone MUST express it
        // now so adding that carrier later is an append-only bump, not a reshape.
        let wi = WorkItem::new(InboundHandle::absent(), EmitHandle::absent());
        assert_eq!(wi.inbound.kind, InboundKind::Absent);
        assert_eq!(wi.emit.kind, EmitKind::Absent);
        assert!(wi.inbound.ptr.is_null());
    }

    #[test]
    fn workitem_can_represent_duplex_session() {
        // Independent in/out: a streamed inbound and an unsolicited push.
        let wi = WorkItem::new(
            InboundHandle::stream(7),
            EmitHandle::new(EmitKind::Unsolicited, 9),
        );
        assert_eq!(wi.inbound.kind, InboundKind::Stream);
        assert_eq!(wi.inbound.id, 7);
        assert_eq!(wi.emit.kind, EmitKind::Unsolicited);
        assert_eq!(wi.emit.id, 9);
    }

    #[test]
    fn all_reserved_kinds_are_declared() {
        // Witness: every reserved tag exists from day one (compile-time exhaustiveness).
        for k in [
            InboundKind::Absent,
            InboundKind::FiniteBuffer,
            InboundKind::Stream,
        ] {
            let _ = k as u8;
        }
        for k in [
            EmitKind::Absent,
            EmitKind::Reply,
            EmitKind::Stream,
            EmitKind::Unsolicited,
        ] {
            let _ = k as u8;
        }
    }
}
