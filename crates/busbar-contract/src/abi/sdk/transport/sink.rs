// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER'S SINK FILL: what a framing owes the host ([`Owed`]: wire bytes, frame [`Piece`]s, a
//! deadline, its end) handed into the host's `FramerSink` as far as it holds ([`fill`]).
//!
//! Generic over the frame buffer `B` the framer's pieces carry (`::hyper::body::Bytes` under
//! [`hyper_io!`](crate::hyper_io), a `Vec<u8>` elsewhere), so the contract names no buffer crate:
//! the framer says how a split piece keeps its rest ([`Owed::rest`]).

use std::collections::VecDeque;

use crate::abi::sdk::{HostBuf, Lent, Out};
use crate::abi::transport::{
    FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, PIECE_CONTINUED, PIECE_END,
    PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN,
    PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED, PIECE_WRITABLE, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE, YIELD_STREAM_FULL,
};

/// A stream's head words, for its head slots (`HeadSlots`): what a head says that is never a
/// field. Empty = absent. An accepted stream states `method`, `target` and, where the caller named
/// one, `authority`; a dialled one the far end's `reason`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadWords<B> {
    /// The method.
    pub method: B,
    /// The target (path and query).
    pub target: B,
    /// The authority the caller named.
    pub authority: B,
    /// The far end's reason phrase, exactly as sent.
    pub reason: B,
}

impl<B: Default> HeadWords<B> {
    /// The far end's reason phrase alone.
    #[must_use]
    pub fn reason(reason: B) -> Self {
        Self {
            reason,
            ..Self::default()
        }
    }
}

impl<B: AsRef<[u8]>> HeadWords<B> {
    fn len(&self) -> usize {
        self.method.as_ref().len()
            + self.target.as_ref().len()
            + self.authority.as_ref().len()
            + self.reason.as_ref().len()
    }
}

/// A frame piece waiting for the host's sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece<B> {
    /// The stream.
    pub stream: u64,
    /// The frame bytes (empty: an empty frame, unless `end` says the stream is over).
    pub bytes: B,
    /// The status code the piece states, in the claim's own numbering.
    pub status: Option<u16>,
    /// The wait the far side asked for.
    pub retry_after_secs: Option<u64>,
    /// On a head's field block: the body length the head declared on the wire
    /// (`PIECE_HAS_DECLARED_LEN`), where it declared one.
    pub declared_len: Option<u64>,
    /// The stream failed; `bytes` are the reason, and this is its last piece.
    pub failed: bool,
    /// `bytes` are a field block (`PIECE_FIELDS`): a head, or the trailers.
    pub fields: bool,
    /// A full sink split this field block mid-line: `bytes` open by continuing a line.
    pub continued: bool,
    /// The stream's head words, handed with its head's first piece.
    pub head: Option<HeadWords<B>>,
    /// The stream's frames are over (`PIECE_END`): its last piece, with no bytes.
    pub end: bool,
    /// The framer's own fault reading of this piece, where it reads the answer from something
    /// other than `status` (a bare status line on a call that numbers its statuses otherwise, its
    /// status mapped to the call's numbering but its fault read by the status line's own band).
    /// `None`: [`fill`]'s `fault_of(status)`. Read only on a piece that states a status.
    pub fault: Option<u8>,
    /// The stream is writable again (`PIECE_WRITABLE`): an empty piece, nothing else set, after an
    /// `emit` answered the stream full ([`mark_stream_full`]).
    pub writable: bool,
}

impl<B> Piece<B> {
    /// Frame bytes on `stream`.
    #[must_use]
    pub fn data(stream: u64, bytes: B) -> Self {
        Self {
            stream,
            bytes,
            status: None,
            retry_after_secs: None,
            declared_len: None,
            failed: false,
            fields: false,
            continued: false,
            head: None,
            end: false,
            fault: None,
            writable: false,
        }
    }

    /// A field block on `stream`.
    #[must_use]
    pub fn fields(stream: u64, block: B) -> Self {
        Self {
            fields: true,
            ..Self::data(stream, block)
        }
    }
}

impl<B: Default> Piece<B> {
    /// `stream`'s frames are over: it ends whole (`PIECE_END`).
    #[must_use]
    pub fn end(stream: u64) -> Self {
        Self {
            end: true,
            ..Self::data(stream, B::default())
        }
    }

    /// `stream` is writable again: the host may emit on it.
    #[must_use]
    pub fn writable(stream: u64) -> Self {
        Self {
            writable: true,
            ..Self::data(stream, B::default())
        }
    }
}

impl<B: From<String>> Piece<B> {
    /// `stream` failed, for `why`.
    #[must_use]
    pub fn failure(stream: u64, why: &str) -> Self {
        Self {
            failed: true,
            ..Self::data(stream, B::from(why.to_owned()))
        }
    }
}

/// The `emit` just answered left its stream's queue at its high-water mark (`YIELD_STREAM_FULL`):
/// the host holds that stream's emits until a [`Piece::writable`] or the stream's last piece. Set
/// after [`fill`], on `emit` only.
pub fn mark_stream_full(o: &mut Out<'_, FramerOut>) {
    let mut y = o.get().yielded;
    y.flags |= YIELD_STREAM_FULL;
    o.set(|x| &x.yielded, y);
}

/// What a framing owes the host, as [`fill`] reads it; `B` is its pieces' frame buffer.
pub trait Owed<B> {
    /// Take up to `cap` wire bytes owed to the far side.
    fn take_wire(&mut self, cap: usize) -> Vec<u8>;
    /// Whether wire bytes are still owed after a take.
    fn wire_pending(&self) -> bool;
    /// The pieces waiting for the host.
    fn pieces(&mut self) -> &mut VecDeque<Piece<B>>;
    /// The earliest host time the framing must be called at.
    fn next_deadline(&self) -> Option<u64>;
    /// Whether the connection has ended.
    fn ended(&self) -> bool;
    /// Keep `bytes` from `at` on: the part of a piece the sink had no room for.
    fn rest(bytes: &mut B, at: usize);
}

/// Hand the host what `f` owes it, as far as the sink holds: wire bytes, then pieces (a piece that
/// does not fit whole is split, its end-of-frame on its last part; a field block only where a
/// continuation extends a value), each stream's head words in its head slots ahead of its head's
/// first piece, then the yield flags. `class_of` maps a piece's status code to its class (the
/// framer's status table); `fault_of` maps it to the breaker's fault reading (the framer's fault
/// table, `FAULT_NONE` off it).
pub fn fill<B: AsRef<[u8]>, F: Owed<B>>(
    f: &mut F,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    class_of: impl Fn(u16) -> u8,
    fault_of: impl Fn(u16) -> u8,
) {
    let mut wire_buf = sink.wire();
    let wire = f.take_wire(wire_buf.cap());
    wire_buf.extend(&wire);
    let mut y = o.get().yielded;
    y.wire_len = wire_buf.written() as u64;
    let (mut frame, mut pieces): (HostBuf<'_, u8>, HostBuf<'_, FramePiece>) =
        (sink.frame(), sink.pieces());
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    let mut head_slots: HostBuf<'_, HeadSlots> = sink.heads();
    let mut heads = 0_usize;
    while n < pieces.cap() {
        let Some(piece) = f.pieces().front_mut() else {
            break;
        };
        // A head's words ride its stream's head slots, in the answer that carries the head's first
        // piece, their bytes in the frame ahead of the piece's. A host that takes no slots (or a
        // frame too small ever to hold them) is not handed them.
        if let Some(words) = piece.head.take() {
            let need = words.len();
            if head_slots.cap() == 0 || need > frame.cap() {
                // Dropped.
            } else if heads == head_slots.cap() || need > frame.cap() - frame_len {
                piece.head = Some(words);
                break;
            } else {
                // The words fit the frame's room and `heads < heads_cap`.
                let mut span = |b: &B| {
                    let b = b.as_ref();
                    let at = frame_len;
                    frame.extend(b);
                    frame_len += b.len();
                    FrameSpan {
                        offset: if b.is_empty() { 0 } else { at as u64 },
                        len: b.len() as u64,
                    }
                };
                let slots = HeadSlots {
                    stream: piece.stream,
                    method: span(&words.method),
                    target: span(&words.target),
                    authority: span(&words.authority),
                    reason: span(&words.reason),
                };
                head_slots.push(slots);
                heads += 1;
            }
        }
        let bytes = piece.bytes.as_ref();
        let room = frame.cap() - frame_len;
        // A field block is cut only where the host takes a continuation: at a line's start or
        // inside a value. A name longer than the whole frame is cut anyway (the host refuses it by
        // name) rather than never moving.
        let take = if piece.fields {
            match field_cut(bytes, room, piece.continued) {
                0 if frame_len == 0 => bytes.len().min(room),
                cut => cut,
            }
        } else {
            bytes.len().min(room)
        };
        if take == 0 && !bytes.is_empty() {
            break;
        }
        let whole = take == bytes.len();
        let mut flags = if piece.writable {
            // A signal about the stream: it ends no frame.
            PIECE_WRITABLE
        } else if whole {
            PIECE_END_OF_FRAME
        } else {
            0
        };
        // A failure frame may span pieces like any other; its LAST piece says the stream failed.
        if piece.failed && whole {
            flags |= PIECE_STREAM_FAILED;
        }
        // The stream's end is said, never inferred from an empty piece.
        if piece.end {
            flags |= PIECE_END;
        }
        if piece.fields {
            flags |= PIECE_FIELDS;
            if piece.continued {
                flags |= PIECE_CONTINUED;
            }
        }
        let mut fp = FramePiece {
            stream: piece.stream,
            offset: frame_len as u64,
            len: take as u64,
            code: 0,
            status_class: 0,
            flags: 0,
            fault: 0,
            retry_after_secs: 0,
            declared_len: 0,
        };
        if let Some(code) = piece.status {
            flags |= PIECE_HAS_CODE;
            fp.code = u32::from(code);
            fp.status_class = class_of(code);
            fp.fault = piece.fault.unwrap_or_else(|| fault_of(code));
        }
        if let Some(secs) = piece.retry_after_secs {
            flags |= PIECE_HAS_RETRY_AFTER;
            fp.retry_after_secs = secs;
        }
        if let Some(declared) = piece.declared_len {
            flags |= PIECE_HAS_DECLARED_LEN;
            fp.declared_len = declared;
        }
        fp.flags = flags;
        // `take <= room` and `n < pieces_cap`: both fit.
        frame.extend(&bytes[..take]);
        pieces.push(fp);
        frame_len += take;
        n += 1;
        if whole {
            f.pieces().pop_front();
        } else {
            // The rest opens mid-line unless what was taken ended one.
            piece.continued = !bytes[..take].ends_with(b"\n");
            F::rest(&mut piece.bytes, take);
        }
    }
    y.frame_len = frame_len as u64;
    y.pieces_len = n as u32;
    y.heads_len = heads as u32;
    let more = f.wire_pending() || !f.pieces().is_empty();
    let mut flags = 0;
    if more {
        flags |= YIELD_MORE;
    }
    if let Some(at) = f.next_deadline() {
        flags |= YIELD_HAS_DEADLINE;
        y.next_deadline_ns = at;
    }
    if !more && f.ended() {
        flags |= YIELD_ENDED;
    }
    y.flags = flags;
    o.set(|x| &x.yielded, y);
}

/// How much of a field block's `bytes` a sink with `room` may take: all of it when it fits, else
/// the furthest cut at a line's start or inside a value, so a continued piece always extends a
/// value (the host refuses any other continuation). `in_value`: the bytes open inside a value.
/// `0`: no cut fits.
#[must_use]
pub fn field_cut(bytes: &[u8], room: usize, in_value: bool) -> usize {
    if bytes.len() <= room {
        return bytes.len();
    }
    // 0 = a line's start, 1 = a name, 2 = a value.
    let mut at = if in_value { 2 } else { 0 };
    let mut best = 0;
    for (i, &b) in bytes[..room].iter().enumerate() {
        at = match (at, b) {
            (0 | 1, b':') => 2,
            (0 | 1, _) => 1,
            (_, b'\n') => 0,
            _ => 2,
        };
        if at != 1 {
            best = i + 1;
        }
    }
    best
}

#[cfg(test)]
#[path = "../tests/transport_sink_tests.rs"]
mod tests;
