// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Frames as a PLANE holds them, and the transport wire vocabulary it reads them against.
//!
//! Everything here belongs to the transport axis, and most of it now lives one crate down, in the
//! transport contract, where a plane author never has to read it. What is spelled here is the part
//! a plane genuinely touches — the frame, the bounded cursor it reads frames through, and the
//! envelope it hands back — because each of those borrows the arena and the bounded collections the
//! contract owns. The rest is named, so `busbar_contract::wire` still means what it meant.

pub use busbar_contract_transport::wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, FrameMeta, Framing, Handoff, HandshakeTrigger, Listener, ListenerHandle, RawIo,
    RawStream, StatusAt, StatusClass, TransportError, Unit0Trigger,
};

use crate::bounded::{ArenaBytes, BoundedVec, SlabBytes, MAX_KEYS};
use crate::ids::StreamId;

/// Transport bytes with a direction, a stream and meta. It has no meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Which way the bytes are moving.
    pub direction: Direction,
    /// Which stream of the connection they arrived on.
    pub stream: StreamId,
    /// The bytes, owned by the connection slab.
    pub bytes: SlabBytes,
    /// The transport's own reading of the frame.
    pub meta: FrameMeta,
}

/// A plane's bounded read cursor over the frames it has been handed.
///
/// A plane reads forward and never rewinds past what it has consumed. The cursor is what bounds a
/// plane's appetite: it never exposes more than the per-connection ceiling, so a plane cannot ask
/// the kernel to buffer an unbounded prefix on its behalf.
#[derive(Debug)]
pub struct FrameCursor<'u> {
    frames: &'u [Frame],
    position: usize,
    scanned: usize,
}

impl<'u> FrameCursor<'u> {
    /// A cursor over the frames a connection has produced so far.
    #[must_use]
    pub fn new(frames: &'u [Frame]) -> Self {
        Self {
            frames,
            position: 0,
            scanned: 0,
        }
    }

    /// The next unconsumed frame, without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&'u Frame> {
        self.frames.get(self.position)
    }

    /// Consume and return the next frame.
    pub fn next_frame(&mut self) -> Option<&'u Frame> {
        let frame = self.frames.get(self.position)?;
        self.position += 1;
        self.scanned = self.scanned.saturating_add(frame.bytes.len());
        Some(frame)
    }

    /// How many frames remain unconsumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.frames.len().saturating_sub(self.position)
    }

    /// How many bytes the plane has consumed through this cursor.
    #[must_use]
    pub fn scanned_bytes(&self) -> usize {
        self.scanned
    }
}

/// One field of an outbound request's transport envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeField<'u> {
    /// The field's name.
    pub name: &'u str,
    /// The field's bytes.
    pub value: ArenaBytes<'u>,
}

/// The transport-level shape of an outbound request.
///
/// The envelope must still equal the verified destination after the egress-auth step has decorated
/// it; the lane cross-check re-runs on the decorated bytes for exactly that reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportEnvelope<'u> {
    /// The envelope's fields.
    pub fields: BoundedVec<EnvelopeField<'u>, MAX_KEYS>,
}
