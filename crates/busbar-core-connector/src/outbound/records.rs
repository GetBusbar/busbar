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

/// `CLOSE`.
pub(crate) const CLOSE: u16 = 0x0101;
/// `STREAM_BODY`: `stream: u64, flags: u32, _r: u32`, then the bytes.
pub(crate) const STREAM_BODY: u16 = 0x0106;
/// `STREAM_END`: `stream: u64`.
pub(crate) const STREAM_END: u16 = 0x0107;
/// `STREAM_RESET`.
pub(crate) const STREAM_RESET: u16 = 0x0108;
/// `STREAM_OPENED`: `stream: u64`.
pub(crate) const STREAM_OPENED: u16 = 0x010A;
/// `SESSION`.
pub(crate) const SESSION: u16 = 0x011C;
/// `STREAM_BUSY`: no fixed part, no tail.
pub(crate) const STREAM_BUSY: u16 = 0x011D;
/// `NO_NEW_STREAMS`: no fixed part, no tail.
pub(crate) const NO_NEW_STREAMS: u16 = 0x011E;

/// One record of an answer, read for the outbound parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decoded<'a> {
    /// An item the driver reads, and its tail (the bytes of a part or of a body piece; else
    /// empty).
    Item(Out, &'a [u8]),
    /// A record that is not the driver's (a head, trailers, a timer, a flow record): the
    /// connection's own arms keep it.
    Other,
    /// One of the driver's records whose fixed part is short: FAULT BadRecords.
    Short,
}

fn u32_at(body: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(body: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(body.get(at..at + 8)?.try_into().ok()?))
}

/// Read one record of a transport's answer (`tag`, and `body` = its fixed part and tail as the
/// record walker hands them) into the item the driver reads. Fixed parts are read by prefix: a
/// longer one from a later second number is taken for the fields known here.
pub(crate) fn decode(tag: u16, body: &[u8]) -> Decoded<'_> {
    let item = || -> Option<(Out, &[u8])> {
        Some(match tag {
            SESSION => (
                Out::Session(Session {
                    flags: u32_at(body, 0)?,
                    stream_window: u32_at(body, 4)?,
                    conn_window: u32_at(body, 8)?,
                    _r: 0,
                }),
                &[][..],
            ),
            STREAM_OPENED => (Out::Opened(u64_at(body, 0)?), &[][..]),
            STREAM_BUSY => (Out::Busy, &[][..]),
            NO_NEW_STREAMS => (Out::NoNewStreams, &[][..]),
            WIRE_PART => {
                let part = WirePart {
                    stream: u64_at(body, 0)?,
                    class: u32_at(body, 8)?,
                    _r: 0,
                };
                let tail = body.get(16..)?;
                (
                    Out::Part {
                        part,
                        len: u32::try_from(tail.len()).ok()?,
                    },
                    tail,
                )
            }
            WIRE_SEALED => (
                Out::Sealed(WireSealed {
                    stream: u64_at(body, 0)?,
                    slot: u32_at(body, 8)?,
                    offset: u32_at(body, 12)?,
                    len: u32_at(body, 16)?,
                    _r: u32_at(body, 20)?,
                }),
                &[][..],
            ),
            WIRE_END => (
                Out::End(WireEnd {
                    stream: u64_at(body, 0)?,
                    how: u32_at(body, 8)?,
                    arg: u32_at(body, 12)?,
                }),
                &[][..],
            ),
            STREAM_BODY => {
                let stream = u64_at(body, 0)?;
                let tail = body.get(16..)?;
                (
                    Out::Body {
                        stream,
                        len: u32::try_from(tail.len()).ok()?,
                    },
                    tail,
                )
            }
            STREAM_END => (Out::Ended(u64_at(body, 0)?), &[][..]),
            STREAM_RESET => (
                Out::Reset(StreamReset {
                    stream: u64_at(body, 0)?,
                    code: u32_at(body, 8)?,
                    flags: u32_at(body, 12)?,
                }),
                &[][..],
            ),
            CLOSE => (Out::Close, &[][..]),
            _ => return None,
        })
    };
    let mine = matches!(
        tag,
        SESSION
            | STREAM_OPENED
            | STREAM_BUSY
            | NO_NEW_STREAMS
            | WIRE_PART
            | WIRE_SEALED
            | WIRE_END
            | STREAM_BODY
            | STREAM_END
            | STREAM_RESET
            | CLOSE
    );
    match item() {
        Some((out, tail)) => Decoded::Item(out, tail),
        None if mine => Decoded::Short,
        None => Decoded::Other,
    }
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
        assert_eq!((WIRE_PART, WIRE_END, WIRE_SEALED), (0x0119, 0x011A, 0x011B));
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

    fn bytes(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn each_record_of_the_driver_is_read_from_its_bytes() {
        let part = bytes(&[
            &7_u64.to_le_bytes(),
            &WIRE_PAYLOAD.to_le_bytes(),
            &[0; 4],
            b"{}",
        ]);
        assert_eq!(
            decode(WIRE_PART, &part),
            Decoded::Item(
                Out::Part {
                    part: WirePart {
                        stream: 7,
                        class: WIRE_PAYLOAD,
                        _r: 0
                    },
                    len: 2
                },
                b"{}"
            )
        );
        let sealed = bytes(&[
            &7_u64.to_le_bytes(),
            &1_u32.to_le_bytes(),
            &4_u32.to_le_bytes(),
            &20_u32.to_le_bytes(),
            &[0; 4],
        ]);
        assert_eq!(
            decode(WIRE_SEALED, &sealed),
            Decoded::Item(
                Out::Sealed(WireSealed {
                    stream: 7,
                    slot: 1,
                    offset: 4,
                    len: 20,
                    _r: 0
                }),
                &[]
            )
        );
        let end = bytes(&[
            &7_u64.to_le_bytes(),
            &END_FLUSH.to_le_bytes(),
            &END_NO_BODY.to_le_bytes(),
        ]);
        assert_eq!(
            decode(WIRE_END, &end),
            Decoded::Item(
                Out::End(WireEnd {
                    stream: 7,
                    how: END_FLUSH,
                    arg: END_NO_BODY
                }),
                &[]
            )
        );
        let session = bytes(&[
            &S_MULTIPLEX.to_le_bytes(),
            &(1_u32 << 20).to_le_bytes(),
            &(4_u32 << 20).to_le_bytes(),
            &[0; 4],
        ]);
        assert!(matches!(
            decode(SESSION, &session),
            Decoded::Item(Out::Session(session), _) if session.multiplexes()
        ));
        let reset = bytes(&[
            &7_u64.to_le_bytes(),
            &9_u32.to_le_bytes(),
            &RESET_NOT_PROCESSED.to_le_bytes(),
        ]);
        assert!(matches!(
            decode(STREAM_RESET, &reset),
            Decoded::Item(Out::Reset(reset), _) if reset.not_processed() && reset.code == 9
        ));
        assert_eq!(decode(STREAM_BUSY, &[]), Decoded::Item(Out::Busy, &[]));
        assert_eq!(
            decode(NO_NEW_STREAMS, &[]),
            Decoded::Item(Out::NoNewStreams, &[])
        );
        assert_eq!(
            decode(STREAM_OPENED, &3_u64.to_le_bytes()),
            Decoded::Item(Out::Opened(3), &[])
        );
    }

    #[test]
    fn a_short_fixed_part_is_a_fault_and_a_longer_one_is_read_by_prefix() {
        assert_eq!(decode(WIRE_SEALED, &[0; 23]), Decoded::Short);
        assert_eq!(decode(WIRE_PART, &[0; 15]), Decoded::Short);
        assert_eq!(decode(STREAM_OPENED, &[0; 7]), Decoded::Short);
        let longer = bytes(&[&5_u64.to_le_bytes(), &[0xAA; 8]]);
        assert_eq!(
            decode(STREAM_END, &longer),
            Decoded::Item(Out::Ended(5), &[])
        );
    }

    #[test]
    fn a_record_that_is_not_the_drivers_is_left_to_the_connection() {
        // STREAM_HEAD, STREAM_TRAILERS, WAKE_AT.
        for tag in [0x0105, 0x0109, 0x0102] {
            assert_eq!(decode(tag, &[0; 32]), Decoded::Other);
        }
    }
}
