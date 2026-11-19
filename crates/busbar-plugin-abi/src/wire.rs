// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one validator of the transport output model (transport 2.0; interface revision C.2 rule 2, F3).
//!
//! The engine's transport adapter and the conformance suite judge every answer of a transport session with
//! this one state machine, so they cannot disagree on the grammar. It checks rules L1 to L7 and L9 of
//! `transport::WirePart`, `WireSealed` and `WireEnd`; L8 (not ending early) cannot be checked without
//! knowing the protocol and is proven per transport by its suite.
//!
//! One `Wire` per session. The engine tells it what it asked for (`asked`), then feeds it each answer's
//! records in order (`record`). It holds one small entry per open stream and allocates only when a stream
//! opens; a part costs a lookup among the session's open streams and no heap call.

use zerocopy::FromBytes;

use crate::transport::{
    E_BODY, E_END, E_HEAD, E_REFUSE, END_FAILED, END_FLUSH, END_NO_BODY, END_SHUTDOWN, StreamHead,
    WIRE_CONTROL, WIRE_PAYLOAD, WireEnd, WirePart, WireSealed, tag,
};

/// Which rule an answer broke. Every breach is FAULT BadRecords for the whole answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rule {
    /// A wire record is malformed: a short or over-long fixed part, a non-zero `_r`, an empty WIRE_PART,
    /// an unknown class, `how` or `arg`, a zero-length WIRE_SEALED.
    Record,
    /// L2: the record names a stream that is neither 0 nor open.
    L2,
    /// L3: a PAYLOAD part (or a sealed part or an end) on stream 0.
    L3,
    /// L4: a second end for a stream within one answer, or a record naming a stream after its end.
    L4,
    /// L5: END_FLUSH or END_SHUTDOWN the engine did not ask for.
    L5,
    /// L6: the stream's PAYLOAD bytes are not the body bytes the engine gave (or END_NO_BODY with payload).
    L6,
    /// L7: a part after END_SHUTDOWN.
    L7,
    /// L9: a sealed slot out of order, overrun, or not covered before the first payload or the end.
    L9,
}

/// A breach: the rule and the stream the record named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Breach {
    pub rule: Rule,
    pub stream: u64,
}

/// What one accepted record means for the engine's writer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Part<'a> {
    /// Write these bytes; they belong to `stream`; `payload` says which class.
    Bytes {
        stream: u64,
        payload: bool,
        bytes: &'a [u8],
    },
    /// Write bytes `offset..offset + len` of the engine's sealed value `slot` of `stream` here.
    Sealed {
        stream: u64,
        slot: u32,
        offset: u32,
        len: u32,
    },
    /// The stream's output has ended. `how` and `arg` as the record states; `payload` = the PAYLOAD bytes
    /// the stream wrote in all (the delivery record's body count).
    End {
        stream: u64,
        how: u32,
        arg: u32,
        payload: u64,
    },
    /// Not a wire record (an event, a statement): the adapter's own decoder takes it.
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Asked {
    Nothing,
    End,
    Refuse,
}

struct Stream {
    id: u64,
    /// PAYLOAD bytes written so far.
    payload: u64,
    /// Body bytes the engine gave with E_BODY.
    given: u64,
    asked: Asked,
    /// The lengths of the sealed slots the engine declared for the stream, in slot order.
    sealed: Vec<u32>,
    /// The next sealed byte expected: (slot, offset).
    next: (usize, u32),
}

impl Stream {
    fn new(id: u64, sealed: Vec<u32>) -> Self {
        Stream {
            id,
            payload: 0,
            given: 0,
            asked: Asked::Nothing,
            sealed,
            next: (0, 0),
        }
    }
    /// Every declared slot is covered (zero-length slots need no part).
    fn covered(&mut self) -> bool {
        while self.sealed.get(self.next.0) == Some(&self.next.1) {
            self.next = (self.next.0 + 1, 0);
        }
        self.next.0 >= self.sealed.len()
    }
}

/// What a dial's set said, held until its stream is opened.
struct Pending {
    sealed: Vec<u32>,
    given: u64,
    asked: Asked,
}

/// The output state of one transport session.
#[derive(Default)]
pub struct Wire {
    open: Vec<Stream>,
    /// What an `emit` of E_HEAD on stream 0 (a dial) said, waiting for the STREAM_OPENED of its answer:
    /// the sealed lengths, the body bytes given, and whether the set ended or refused the message.
    pending: Option<Pending>,
    shutdown: bool,
}

impl Wire {
    pub fn new() -> Self {
        Wire::default()
    }

    /// How many streams are open.
    pub fn open_streams(&self) -> usize {
        self.open.len()
    }

    fn at(&mut self, stream: u64) -> Option<&mut Stream> {
        self.open.iter_mut().find(|s| s.id == stream)
    }

    /// The engine is about to `emit` on `stream`: `pieces` as it sends them, `body` = the bytes of its
    /// E_BODY entry (0 without one), `sealed` = the value length of each H_SEALED_* record of its E_HEAD
    /// entry, in order (empty without any). For E_HEAD on stream 0 (a dial) the slots attach to the stream
    /// the answer's STREAM_OPENED announces.
    pub fn asked(&mut self, stream: u64, pieces: u32, body: u64, sealed: &[u32]) {
        if stream == 0 {
            if pieces & E_HEAD != 0 {
                self.pending = Some(Pending {
                    sealed: sealed.to_vec(),
                    given: if pieces & E_BODY != 0 { body } else { 0 },
                    asked: if pieces & E_REFUSE != 0 {
                        Asked::Refuse
                    } else if pieces & E_END != 0 {
                        Asked::End
                    } else {
                        Asked::Nothing
                    },
                });
            }
            return;
        }
        let Some(s) = self.at(stream) else {
            return;
        };
        if pieces & E_HEAD != 0 && !sealed.is_empty() {
            s.sealed = sealed.to_vec();
            s.next = (0, 0);
        }
        if pieces & E_BODY != 0 {
            s.given = s.given.saturating_add(body);
        }
        if pieces & E_REFUSE != 0 {
            s.asked = Asked::Refuse;
        } else if pieces & E_END != 0 {
            s.asked = Asked::End;
        }
    }

    /// The dial's `emit(0, E_HEAD ..)` was answered STREAM_BUSY: nothing was opened, nothing is pending.
    pub fn busy(&mut self) {
        self.pending = None;
    }

    /// A session begun with CONN_UPGRADED serves the upgraded exchange as `stream` (1): it is open from
    /// `begin`, before any record. Called by the adapter before it judges the `begin` answer.
    pub fn adopt(&mut self, stream: u64) {
        if stream != 0 && self.at(stream).is_none() {
            self.open.push(Stream::new(stream, Vec::new()));
        }
    }

    /// The engine itself ended `stream` without the transport (a session cut, a reset it sent).
    pub fn forget(&mut self, stream: u64) {
        self.open.retain(|s| s.id != stream);
    }

    /// Judge the next record of an answer, in answer order.
    pub fn record<'a>(&mut self, tag_: u16, body: &'a [u8]) -> Result<Part<'a>, Breach> {
        match tag_ {
            tag::STREAM_HEAD => {
                // An accepted connection's new stream (L2): open from here on.
                if let Ok((head, _)) = StreamHead::read_from_prefix(body)
                    && self.at(head.stream).is_none()
                    && head.stream != 0
                {
                    self.open.push(Stream::new(head.stream, Vec::new()));
                }
                Ok(Part::Other)
            }
            tag::STREAM_OPENED => {
                // A dialled connection's new stream (L2): its id is the record's first eight bytes.
                let id = body
                    .get(..8)
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);
                if id != 0 && self.at(id).is_none() {
                    // What the dial's set said waits here and attaches to the stream it opened: the
                    // sealed lengths, the body bytes given, and whether the set ended or refused.
                    let pending = self.pending.take();
                    let mut stream = Stream::new(
                        id,
                        pending.as_ref().map_or_else(Vec::new, |p| p.sealed.clone()),
                    );
                    if let Some(p) = pending {
                        stream.given = p.given;
                        stream.asked = p.asked;
                    }
                    self.open.push(stream);
                }
                Ok(Part::Other)
            }
            tag::WIRE_PART => self.part(body),
            tag::WIRE_SEALED => self.sealed(body),
            tag::WIRE_END => self.end(body),
            _ => Ok(Part::Other),
        }
    }

    fn part<'a>(&mut self, body: &'a [u8]) -> Result<Part<'a>, Breach> {
        let Ok((rec, bytes)) = WirePart::read_from_prefix(body) else {
            return Err(Breach {
                rule: Rule::Record,
                stream: 0,
            });
        };
        let stream = rec.stream;
        let breach = |rule| Breach { rule, stream };
        if rec._r != 0 || bytes.is_empty() || !matches!(rec.class, WIRE_CONTROL | WIRE_PAYLOAD) {
            return Err(breach(Rule::Record));
        }
        if self.shutdown {
            return Err(breach(Rule::L7));
        }
        let payload = rec.class == WIRE_PAYLOAD;
        if stream == 0 {
            return if payload {
                Err(breach(Rule::L3))
            } else {
                Ok(Part::Bytes {
                    stream,
                    payload,
                    bytes,
                })
            };
        }
        let Some(s) = self.at(stream) else {
            return Err(breach(Rule::L2));
        };
        if payload {
            if !s.covered() {
                return Err(breach(Rule::L9));
            }
            s.payload = s.payload.saturating_add(bytes.len() as u64);
        }
        Ok(Part::Bytes {
            stream,
            payload,
            bytes,
        })
    }

    fn sealed<'a>(&mut self, body: &'a [u8]) -> Result<Part<'a>, Breach> {
        let Ok(rec) = WireSealed::read_from_bytes(body) else {
            return Err(Breach {
                rule: Rule::Record,
                stream: 0,
            });
        };
        let stream = rec.stream;
        let breach = |rule| Breach { rule, stream };
        if rec._r != 0 || rec.len == 0 {
            return Err(breach(Rule::Record));
        }
        if self.shutdown {
            return Err(breach(Rule::L7));
        }
        if stream == 0 {
            return Err(breach(Rule::L3));
        }
        let Some(s) = self.at(stream) else {
            return Err(breach(Rule::L2));
        };
        // Skip slots that need no bytes, then this part must be exactly the next bytes expected.
        let _ = s.covered();
        let (slot, offset) = s.next;
        let Some(&whole) = s.sealed.get(slot) else {
            return Err(breach(Rule::L9));
        };
        let end = rec.offset.checked_add(rec.len);
        if rec.slot as usize != slot || rec.offset != offset || !end.is_some_and(|e| e <= whole) {
            return Err(breach(Rule::L9));
        }
        s.next = (slot, offset + rec.len);
        Ok(Part::Sealed {
            stream,
            slot: rec.slot,
            offset: rec.offset,
            len: rec.len,
        })
    }

    fn end<'a>(&mut self, body: &'a [u8]) -> Result<Part<'a>, Breach> {
        let Ok(rec) = WireEnd::read_from_bytes(body) else {
            return Err(Breach {
                rule: Rule::Record,
                stream: 0,
            });
        };
        let stream = rec.stream;
        let breach = |rule| Breach { rule, stream };
        if stream == 0 {
            return Err(breach(Rule::L3));
        }
        let Some(at) = self.open.iter().position(|s| s.id == stream) else {
            // Not open: never opened (L2) or already ended (L4); the validator keeps no ended ids.
            return Err(breach(Rule::L4));
        };
        let Some(s) = self.open.get_mut(at) else {
            return Err(breach(Rule::L4));
        };
        match rec.how {
            END_FAILED => {}
            END_FLUSH | END_SHUTDOWN => {
                if !matches!(rec.arg, 0 | END_NO_BODY) {
                    return Err(breach(Rule::Record));
                }
                if !s.covered() {
                    return Err(breach(Rule::L9));
                }
                match s.asked {
                    Asked::Nothing => return Err(breach(Rule::L5)),
                    // A refusal is not counted (L6).
                    Asked::Refuse => {}
                    Asked::End => {
                        let whole = s.payload == s.given && rec.arg == 0;
                        let none = s.payload == 0 && rec.arg == END_NO_BODY;
                        if !(whole || none) {
                            return Err(breach(Rule::L6));
                        }
                    }
                }
            }
            _ => return Err(breach(Rule::Record)),
        }
        let payload = s.payload;
        self.open.swap_remove(at);
        if rec.how == END_SHUTDOWN {
            self.shutdown = true;
        }
        Ok(Part::End {
            stream,
            how: rec.how,
            arg: rec.arg,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;

    fn head(stream: u64) -> Vec<u8> {
        StreamHead {
            stream,
            flags: 0,
            _r: 0,
        }
        .as_bytes()
        .to_vec()
    }
    fn part(stream: u64, class: u32, bytes: &[u8]) -> Vec<u8> {
        let mut body = WirePart {
            stream,
            class,
            _r: 0,
        }
        .as_bytes()
        .to_vec();
        body.extend_from_slice(bytes);
        body
    }
    fn sealed(stream: u64, slot: u32, offset: u32, len: u32) -> Vec<u8> {
        WireSealed {
            stream,
            slot,
            offset,
            len,
            _r: 0,
        }
        .as_bytes()
        .to_vec()
    }
    fn end(stream: u64, how: u32, arg: u32) -> Vec<u8> {
        WireEnd { stream, how, arg }.as_bytes().to_vec()
    }
    fn rule(got: Result<Part<'_>, Breach>) -> Option<Rule> {
        got.err().map(|b| b.rule)
    }

    #[test]
    fn a_whole_answer_is_accepted_and_counted() {
        let mut w = Wire::new();
        assert_eq!(w.record(tag::STREAM_HEAD, &head(1)), Ok(Part::Other));
        w.asked(1, E_HEAD | E_BODY | E_END, 4, &[]);
        assert!(
            w.record(tag::WIRE_PART, &part(1, WIRE_CONTROL, b"HTTP/1.1 200"))
                .is_ok()
        );
        assert!(
            w.record(tag::WIRE_PART, &part(1, WIRE_PAYLOAD, b"body"))
                .is_ok()
        );
        assert_eq!(
            w.record(tag::WIRE_END, &end(1, END_FLUSH, 0)),
            Ok(Part::End {
                stream: 1,
                how: END_FLUSH,
                arg: 0,
                payload: 4
            })
        );
        assert_eq!(w.open_streams(), 0);
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(1, WIRE_CONTROL, b"x"))),
            Some(Rule::L2)
        );
    }

    #[test]
    fn each_rule_is_a_breach() {
        let mut w = Wire::new();
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(9, WIRE_CONTROL, b"x"))),
            Some(Rule::L2)
        );
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(0, WIRE_PAYLOAD, b"x"))),
            Some(Rule::L3)
        );
        assert!(
            w.record(tag::WIRE_PART, &part(0, WIRE_CONTROL, b"settings"))
                .is_ok()
        );
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(0, WIRE_CONTROL, b""))),
            Some(Rule::Record)
        );
        let _ = w.record(tag::STREAM_HEAD, &head(1));
        // L5: an end the engine did not ask for.
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(1, END_FLUSH, 0))),
            Some(Rule::L5)
        );
        // L6: the payload is not the body given.
        w.asked(1, E_BODY | E_END, 4, &[]);
        let _ = w.record(tag::WIRE_PART, &part(1, WIRE_PAYLOAD, b"bo"));
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(1, END_FLUSH, 0))),
            Some(Rule::L6)
        );
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(1, END_FLUSH, END_NO_BODY))),
            Some(Rule::L6)
        );
        // END_FAILED needs no asking and ends the stream; a second end is L4.
        assert!(w.record(tag::WIRE_END, &end(1, END_FAILED, 7)).is_ok());
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(1, END_FAILED, 7))),
            Some(Rule::L4)
        );
        // L7: nothing after END_SHUTDOWN.
        let _ = w.record(tag::STREAM_HEAD, &head(3));
        w.asked(3, E_HEAD | E_END, 0, &[]);
        assert!(
            w.record(tag::WIRE_END, &end(3, END_SHUTDOWN, END_NO_BODY))
                .is_ok()
        );
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(0, WIRE_CONTROL, b"x"))),
            Some(Rule::L7)
        );
    }

    #[test]
    fn sealed_slots_are_covered_in_order_before_payload_and_end() {
        let mut w = Wire::new();
        // A dial: the head on stream 0 declares two sealed values, of 5 and 3 bytes.
        w.asked(0, E_HEAD, 0, &[5, 3]);
        assert_eq!(
            w.record(tag::STREAM_OPENED, &7u64.to_le_bytes()),
            Ok(Part::Other)
        );
        assert!(
            w.record(tag::WIRE_PART, &part(7, WIRE_CONTROL, b"authorization: "))
                .is_ok()
        );
        assert_eq!(
            rule(w.record(tag::WIRE_SEALED, &sealed(7, 1, 0, 3))),
            Some(Rule::L9)
        );
        assert!(w.record(tag::WIRE_SEALED, &sealed(7, 0, 0, 2)).is_ok());
        assert_eq!(
            rule(w.record(tag::WIRE_PART, &part(7, WIRE_PAYLOAD, b"b"))),
            Some(Rule::L9)
        );
        assert_eq!(
            rule(w.record(tag::WIRE_SEALED, &sealed(7, 0, 2, 9))),
            Some(Rule::L9)
        );
        assert!(w.record(tag::WIRE_SEALED, &sealed(7, 0, 2, 3)).is_ok());
        w.asked(7, E_BODY | E_END, 1, &[]);
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(7, END_FLUSH, 0))),
            Some(Rule::L9)
        );
        assert!(w.record(tag::WIRE_SEALED, &sealed(7, 1, 0, 3)).is_ok());
        assert!(
            w.record(tag::WIRE_PART, &part(7, WIRE_PAYLOAD, b"b"))
                .is_ok()
        );
        assert!(w.record(tag::WIRE_END, &end(7, END_FLUSH, 0)).is_ok());
        assert_eq!(
            rule(w.record(tag::WIRE_SEALED, &sealed(0, 0, 0, 1))),
            Some(Rule::L3)
        );
    }

    // The two fits below are from designer `wire` (parts/solo-wire-fit.rs), carried on house/d-adapt.

    #[test]
    fn a_dialled_request_sent_as_one_set_ends_whole_in_the_answer_that_opened_it() {
        let mut w = Wire::new();
        w.asked(0, E_HEAD | E_BODY | E_END, 2, &[]);
        assert!(w.record(tag::STREAM_OPENED, &7u64.to_le_bytes()).is_ok());
        assert!(
            w.record(
                tag::WIRE_PART,
                &part(7, WIRE_CONTROL, b"POST / HTTP/1.1\r\n\r\n")
            )
            .is_ok()
        );
        assert!(
            w.record(tag::WIRE_PART, &part(7, WIRE_PAYLOAD, b"{}"))
                .is_ok()
        );
        assert!(w.record(tag::WIRE_END, &end(7, END_FLUSH, 0)).is_ok());
        assert_eq!(w.open_streams(), 0);
    }

    #[test]
    fn an_adopted_stream_is_open_from_begin() {
        let mut w = Wire::new();
        w.adopt(1);
        assert!(
            w.record(
                tag::WIRE_PART,
                &part(1, WIRE_CONTROL, b"HTTP/1.1 101 \r\n\r\n")
            )
            .is_ok()
        );
    }

    #[test]
    fn a_busy_dial_leaves_nothing_pending_for_the_next_stream() {
        let mut w = Wire::new();
        w.asked(0, E_HEAD | E_BODY | E_END, 2, &[4]);
        w.busy();
        // The next stream the session opens is not the refused dial: no end was asked of it.
        assert!(w.record(tag::STREAM_OPENED, &9u64.to_le_bytes()).is_ok());
        assert_eq!(
            rule(w.record(tag::WIRE_END, &end(9, END_FLUSH, 0))),
            Some(Rule::L5)
        );
    }
}
