// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT 2.0 RECORDS THE OUTBOUND PARTS READ, in the layouts the interface revision fixes
//! (its section E.2: the one output model and the client role's statements).
//!
//! These are the contract's records, restated here so the parts are written before the contract
//! crate compiles. When the contract crate is the dependency, each type and number below is
//! replaced by a `pub(crate) use` of the contract's own name and this file keeps only [`Out`] and
//! its decoding: no part names a number directly, so nothing else changes.

/// `WIRE_PART`: write these bytes; they belong to `stream` and are of `class`.
pub(crate) const WIRE_PART: u16 = 0x0119;
/// `WIRE_END`: nothing more will name this stream.
pub(crate) const WIRE_END: u16 = 0x011A;
/// `WIRE_SEALED`: the engine writes bytes `offset..offset + len` of sealed value `slot` here.
pub(crate) const WIRE_SEALED: u16 = 0x011B;

/// A byte that carries a byte of a body piece the engine gave the transport, one for one.
pub(crate) const WIRE_PAYLOAD: u32 = 2;
/// Everything else: heads, trailers, framing, padding, end markers, resets, connection control.
pub(crate) const WIRE_CONTROL: u32 = 1;

/// `WIRE_END.how`: complete once flushed.
pub(crate) const END_FLUSH: u32 = 1;
/// `WIRE_END.how`: complete once the connection is shut down; nothing may follow in the session.
pub(crate) const END_SHUTDOWN: u32 = 2;
/// `WIRE_END.how`: the transport failed the stream's output.
pub(crate) const END_FAILED: u32 = 3;
/// `WIRE_END.arg`: a successful end whose protocol carries no body for this message.
pub(crate) const END_NO_BODY: u32 = 1;

/// `SESSION.flags`: the session carries several streams at once.
pub(crate) const S_MULTIPLEX: u32 = 1;
/// `STREAM_RESET.flags`: the far end guarantees it did not act on the stream.
pub(crate) const RESET_NOT_PROCESSED: u32 = 1;

/// The fixed part of `WIRE_PART`; its tail is the bytes, never empty.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WirePart {
    /// The stream the bytes belong to; 0 is the connection itself.
    pub(crate) stream: u64,
    /// [`WIRE_PAYLOAD`] or [`WIRE_CONTROL`].
    pub(crate) class: u32,
    /// Reserved, zero.
    pub(crate) _r: u32,
}

/// `WIRE_SEALED`, no tail. Always control.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireSealed {
    /// The request's own stream.
    pub(crate) stream: u64,
    /// The sealed value, by its order among the head's sealed records, from 0.
    pub(crate) slot: u32,
    /// Where in the value this run starts.
    pub(crate) offset: u32,
    /// How many bytes of the value go here.
    pub(crate) len: u32,
    /// Reserved, zero.
    pub(crate) _r: u32,
}

/// `WIRE_END`, no tail.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireEnd {
    /// The stream that ended.
    pub(crate) stream: u64,
    /// [`END_FLUSH`], [`END_SHUTDOWN`] or [`END_FAILED`].
    pub(crate) how: u32,
    /// [`END_NO_BODY`] on a successful end without body, else 0.
    pub(crate) arg: u32,
}

/// `SESSION`: what `begin` states about the session.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Session {
    /// [`S_MULTIPLEX`].
    pub(crate) flags: u32,
    /// The most inbound body bytes of one stream the far end may send before credit.
    pub(crate) stream_window: u32,
    /// The same bound over all the session's streams.
    pub(crate) conn_window: u32,
    /// Reserved, zero.
    pub(crate) _r: u32,
}

impl Session {
    /// The session carries several streams at once.
    pub(crate) const fn multiplexes(&self) -> bool {
        self.flags & S_MULTIPLEX != 0
    }
}

/// `STREAM_RESET`: the far end reset a stream.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamReset {
    /// The stream.
    pub(crate) stream: u64,
    /// The wire's own code, opaque to the engine.
    pub(crate) code: u32,
    /// [`RESET_NOT_PROCESSED`].
    pub(crate) flags: u32,
}

impl StreamReset {
    /// The far end states it did not act on the stream.
    pub(crate) const fn not_processed(&self) -> bool {
        self.flags & RESET_NOT_PROCESSED != 0
    }
}

/// One item of a transport's answer as the outbound parts read it, in the answer's own order. The
/// session adapter decodes an answer into these; the parts never see a record tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Out {
    /// `SESSION`, in the answer to `begin`.
    Session(Session),
    /// `STREAM_OPENED`: the stream the transport opened for the head just emitted.
    Opened(u64),
    /// `STREAM_BUSY`: the head was not taken; no stream opened, nothing written, nothing kept.
    Busy,
    /// `NO_NEW_STREAMS`: the far end is closing; open streams finish, none may open.
    NoNewStreams,
    /// `WIRE_PART` and the length of its tail.
    Part {
        /// The record's fixed part.
        part: WirePart,
        /// The length of the bytes that follow it.
        len: u32,
    },
    /// `WIRE_SEALED`.
    Sealed(WireSealed),
    /// `WIRE_END`.
    End(WireEnd),
    /// `STREAM_BODY`: inbound body bytes of a stream, by their count.
    Body {
        /// The stream.
        stream: u64,
        /// How many bytes.
        len: u32,
    },
    /// `STREAM_END`: the far end ended its side of the stream.
    Ended(u64),
    /// `STREAM_RESET`.
    Reset(StreamReset),
    /// `CLOSE`: the session is over once what precedes it is written.
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixed_parts_have_the_sizes_the_revision_states() {
        assert_eq!(std::mem::size_of::<WirePart>(), 16);
        assert_eq!(std::mem::size_of::<WireSealed>(), 24);
        assert_eq!(std::mem::size_of::<WireEnd>(), 16);
        assert_eq!(std::mem::size_of::<Session>(), 16);
        assert_eq!(std::mem::size_of::<StreamReset>(), 16);
    }

    #[test]
    fn the_three_output_records_keep_their_numbers() {
        assert_eq!(
            (WIRE_PART, WIRE_END, WIRE_SEALED),
            (0x0119, 0x011A, 0x011B)
        );
    }

    #[test]
    fn a_session_multiplexes_only_when_it_says_so() {
        assert!(!Session::default().multiplexes());
        assert!(Session {
            flags: S_MULTIPLEX,
            ..Session::default()
        }
        .multiplexes());
    }

    #[test]
    fn a_reset_is_unprocessed_only_by_the_far_ends_own_flag() {
        let reset = |flags| StreamReset {
            stream: 3,
            code: 7,
            flags,
        };
        assert!(!reset(0).not_processed());
        assert!(reset(RESET_NOT_PROCESSED).not_processed());
    }
}
