// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE CONNECTION'S OUTPUT, DRIVEN: the delivery ledger, the sealed slots, the credit and the
//! lending state of one connection, applied to each of the transport's answers in the one order
//! that is right.
//!
//! The connection owns the socket, the TLS sessions and the socket queue; it hands every answer
//! here ([`Wire::answer`]) as its decoded items, and gets back what to do. For one answer:
//!
//! 1. Every item is checked, in order, against the output model (L1 to L7, L9), the sealed
//!    grammar and the windows. A breach returns a [`Fault`] before a byte of the answer is
//!    queued: nothing of that answer is written, the session ends, every message still open is
//!    recorded `transport_fault`.
//! 2. The answer's parts, with the engine's sealed bytes where the transport marked them, are
//!    queued for the socket as one run in one write.
//! 3. The ledger learns where the socket queue stands.
//!
//! A sealed value is read from its slot only in step 2, into the run; it is never copied
//! anywhere else and never handed to the transport.

use busbar_contract::secure::SecureVec;

use super::credit::{Credit, Overrun, StreamCredit};
use super::delivery::{Breach, Delivery, Ledger, Reason, Role, State};
use super::lend::InUse;
use super::records::{Out, StreamReset, WIRE_PAYLOAD};
use super::redial::Ended;
use super::seal::{Covered, SealBreach, Slots};
use super::tunnel::Dialling;

/// Why an answer was refused whole. Each is FAULT BadRecords, charged to the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A rule of the output model.
    Output(Breach),
    /// The sealed grammar.
    Sealed(SealBreach),
    /// A window the session stated.
    Window(Overrun),
    /// A record out of its place; the text says which.
    Order(&'static str),
    /// The socket queue or a TLS layer refused the run (not the transport's fault: the
    /// connection fails as for any write error).
    Queue,
}

impl Fault {
    /// The transport broke its answer grammar (every fault but [`Fault::Queue`]).
    pub(crate) const fn charged(&self) -> bool {
        !matches!(self, Self::Queue)
    }
}

/// One stream's slot in the connection.
struct Sent {
    id: u64,
    slots: Slots,
    credit: StreamCredit,
    /// The far end's reset of the stream, if it sent one.
    reset: Option<StreamReset>,
    /// The stream's sealed values were wiped (the head can no longer be sent again).
    released: bool,
    /// The far end ended its side.
    ended: bool,
}

/// What an answer asks of the connection, beyond the bytes it queued.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// `STREAM_OPENED`: the stream of the head just emitted.
    pub(crate) opened: Option<u64>,
    /// `STREAM_BUSY`: the head was not taken. Its sealed values, rewound, to offer on another
    /// connection. They never left the engine.
    pub(crate) busy: Option<Slots>,
    /// `CLOSE`: the session is over once the socket queue is written.
    pub(crate) closing: bool,
    /// The answer queued bytes for the socket.
    pub(crate) wrote: bool,
}

/// What pass one found a part to be.
#[derive(Clone, Copy)]
enum Run {
    /// The tail of the `WIRE_PART` at this index of the answer.
    Tail(usize),
    /// A covered run of a sealed value of the stream at this index.
    Sealed(usize, Covered),
}

/// THE DRIVER OF ONE CONNECTION'S OUTPUT.
pub(crate) struct Wire {
    role: Role,
    ledger: Ledger,
    credit: Option<Credit>,
    in_use: InUse,
    streams: Vec<Sent>,
    /// The sealed values of the head being emitted, until `STREAM_OPENED` binds them.
    offered: Option<Slots>,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wire")
            .field("role", &self.role)
            .field("streams", &self.streams.len())
            .finish_non_exhaustive()
    }
}

impl Wire {
    /// A connection before its session's `begin`.
    pub(crate) fn new(role: Role) -> Self {
        Self {
            role,
            ledger: Ledger::new(),
            credit: None,
            in_use: InUse::default(),
            streams: Vec::new(),
            offered: None,
        }
    }

    fn at(&self, stream: u64) -> Option<usize> {
        self.streams.iter().position(|one| one.id == stream)
    }

    /// The head about to be emitted (`emit(0, HEAD)`) seals these values. The caller has applied
    /// [`Slots::admit`]. They are bound to the stream the transport opens.
    pub(crate) fn offer(&mut self, slots: Slots) {
        self.offered = Some(slots);
    }

    /// An accepted connection's transport announced `stream` (`STREAM_HEAD`).
    ///
    /// # Errors
    /// L2 for stream 0 or a stream already open.
    pub(crate) fn announced(&mut self, stream: u64) -> Result<(), Fault> {
        self.ledger
            .open(stream, Role::Answer)
            .map_err(Fault::Output)?;
        self.in_use.opened();
        self.streams.push(Sent {
            id: stream,
            slots: Slots::default(),
            credit: StreamCredit::default(),
            reset: None,
            ended: false,
            released: false,
        });
        Ok(())
    }

    /// The engine is emitting `len` body bytes on `stream`.
    pub(crate) fn emitting_body(&mut self, stream: u64, len: u64) {
        self.ledger.emitted_body(stream, len);
    }

    /// The engine is emitting `E_END` on `stream`.
    pub(crate) fn emitting_end(&mut self, stream: u64) {
        self.ledger.asked_end(stream);
    }

    /// The engine is emitting `E_REFUSE` on `stream`.
    pub(crate) fn emitting_refuse(&mut self, stream: u64) {
        self.ledger.asked_refuse(stream);
    }

    /// The engine is stopping `stream` (`E_RESET`) for `reason`.
    pub(crate) fn stopping(&mut self, stream: u64, reason: Reason) {
        self.ledger.stopped(stream, reason);
    }

    /// ONE ANSWER of the transport, as its items in order. `tail(i)` = the bytes of the
    /// `WIRE_PART` at index `i`. `target_tls` and `dial` are the connection's layers, `out` its
    /// socket queue, `flushed` the bytes the socket has taken so far.
    ///
    /// # Errors
    /// The [`Fault`]: nothing of the answer was queued; the caller ends the session and calls
    /// [`Self::faulted`] (or [`Self::gone`] for [`Fault::Queue`]).
    pub(crate) fn answer<'a>(
        &mut self,
        items: &[Out],
        tail: impl Fn(usize) -> &'a [u8],
        target_tls: Option<&mut rustls::ClientConnection>,
        dial: &mut Dialling,
        out: &mut SecureVec,
        flushed: u64,
    ) -> Result<Outcome, Fault> {
        let mut outcome = Outcome::default();
        let mut run: smallvec::SmallVec<[Run; 16]> = smallvec::SmallVec::new();
        for (index, item) in items.iter().enumerate() {
            match *item {
                Out::Session(session) => {
                    if self.credit.is_some() {
                        return Err(Fault::Order("a second SESSION"));
                    }
                    // A multiplexing session states both windows; a session with one stream
                    // states none (the engine stops reading the socket instead).
                    let stated =
                        session.stream_window != 0 && session.conn_window >= session.stream_window;
                    if session.multiplexes() && !stated {
                        return Err(Fault::Order("a multiplexing SESSION states no window"));
                    }
                    self.credit = Some(Credit::new(session));
                    self.in_use = InUse::begun(&session);
                }
                Out::Opened(stream) => {
                    if self.credit.is_none() {
                        return Err(Fault::Order("STREAM_OPENED before SESSION"));
                    }
                    if outcome.opened.is_some() || outcome.busy.is_some() {
                        return Err(Fault::Order("a second answer to one head"));
                    }
                    self.ledger.open(stream, self.role).map_err(Fault::Output)?;
                    let mut slots = self.offered.take().unwrap_or_default();
                    slots.bind(stream);
                    self.in_use.opened();
                    self.streams.push(Sent {
                        id: stream,
                        slots,
                        credit: StreamCredit::default(),
                        reset: None,
                        ended: false,
                        released: false,
                    });
                    outcome.opened = Some(stream);
                }
                Out::Busy => {
                    if outcome.opened.is_some() || outcome.busy.is_some() || !run.is_empty() {
                        return Err(Fault::Order("STREAM_BUSY is answered alone"));
                    }
                    self.in_use.busy();
                    let mut slots = self.offered.take().unwrap_or_default();
                    slots.rewind();
                    outcome.busy = Some(slots);
                }
                Out::NoNewStreams => self.in_use.draining(),
                Out::Part { part, len } => {
                    if part.stream != 0 && part.class == WIRE_PAYLOAD {
                        let at = self.at(part.stream).ok_or(Fault::Output(Breach::L2))?;
                        self.streams[at]
                            .slots
                            .before_payload_or_end()
                            .map_err(Fault::Sealed)?;
                    }
                    self.ledger.part(part, len).map_err(Fault::Output)?;
                    run.push(Run::Tail(index));
                }
                Out::Sealed(sealed) => {
                    let at = self
                        .at(sealed.stream)
                        .ok_or(Fault::Sealed(SealBreach::WrongStream))?;
                    let covered = self.streams[at]
                        .slots
                        .cover(sealed)
                        .map_err(Fault::Sealed)?;
                    self.ledger
                        .sealed(sealed.stream, covered.len())
                        .map_err(Fault::Output)?;
                    run.push(Run::Sealed(at, covered));
                }
                Out::End(end) => {
                    let at = self.at(end.stream).ok_or(Fault::Output(Breach::L2))?;
                    if end.how != super::records::END_FAILED {
                        self.streams[at]
                            .slots
                            .before_payload_or_end()
                            .map_err(Fault::Sealed)?;
                    }
                    self.ledger.end(end).map_err(Fault::Output)?;
                }
                Out::Body { stream, len } => {
                    let at = self
                        .at(stream)
                        .ok_or(Fault::Order("STREAM_BODY for a stream that is not open"))?;
                    let credit = self
                        .credit
                        .as_mut()
                        .ok_or(Fault::Order("STREAM_BODY before SESSION"))?;
                    credit
                        .received(&mut self.streams[at].credit, len)
                        .map_err(Fault::Window)?;
                }
                Out::Ended(stream) => {
                    if let Some(at) = self.at(stream) {
                        self.streams[at].ended = true;
                    }
                }
                Out::Reset(reset) => {
                    if let Some(at) = self.at(reset.stream) {
                        self.streams[at].reset = Some(reset);
                    }
                }
                Out::Close => {
                    self.in_use.draining();
                    outcome.closing = true;
                }
            }
        }
        if !run.is_empty() {
            let streams = &self.streams;
            let pieces: smallvec::SmallVec<[&[u8]; 16]> = run
                .iter()
                .map(|piece| match *piece {
                    Run::Tail(index) => tail(index),
                    Run::Sealed(at, covered) => streams[at].slots.bytes(covered),
                })
                .collect();
            dial.run(target_tls, out, &pieces)
                .map_err(|_| Fault::Queue)?;
            outcome.wrote = true;
        }
        self.ledger.queued(flushed + out.len() as u64);
        Ok(outcome)
    }

    /// The socket has taken `flushed` bytes in all and the socket queue is empty of them.
    pub(crate) fn accepted(&mut self, flushed: u64) {
        self.ledger.accepted(flushed);
    }

    /// The shutdown an `END_SHUTDOWN` asked for succeeded.
    pub(crate) fn shut_down(&mut self) {
        self.ledger.shut_down();
    }

    /// The stream's reader took `len` inbound body bytes. `Some(n)` = `emit` `CONSUMED(stream, n)`.
    pub(crate) fn taken(&mut self, stream: u64, len: u64) -> Option<u64> {
        let at = self.at(stream)?;
        self.credit
            .as_mut()?
            .taken(&mut self.streams[at].credit, len)
    }

    /// Whether the engine reads the socket now.
    pub(crate) fn reads_socket(&self) -> bool {
        self.credit.as_ref().is_none_or(Credit::reads_socket)
    }

    /// How many body bytes the engine may emit on `stream` now, by the windows the session stated.
    /// `flushed` and `queue_len` are the socket queue's.
    pub(crate) fn write_room(&self, stream: u64, flushed: u64, queue_len: u64) -> u64 {
        let Some(credit) = self.credit.as_ref() else {
            return 0;
        };
        let stream_unsent = self
            .ledger
            .last_end(stream)
            .map_or(0, |end| end.saturating_sub(flushed).min(queue_len));
        credit.write_room(stream_unsent, queue_len)
    }

    /// The engine no longer needs to be able to send `stream`'s head again
    /// ([`super::redial::keeps_head`] turned false): its sealed values are wiped now.
    pub(crate) fn release_head(&mut self, stream: u64) {
        if let Some(at) = self.at(stream) {
            self.streams[at].slots.wipe();
            self.streams[at].released = true;
        }
    }

    /// How much of `stream`'s request the operating system accepted, as it stands.
    pub(crate) fn state_of(&self, stream: u64) -> State {
        self.ledger.state_of(stream)
    }

    /// How the attempt on `stream` ended, for [`super::redial::decide`], where the far end said so
    /// itself; `None` = the connection's own failure decides (`Connection`, `Deadline`, ...).
    pub(crate) fn ended_how(&self, stream: u64) -> Option<Ended> {
        let reset = self.streams[self.at(stream)?].reset?;
        Some(if reset.not_processed() {
            Ended::NotProcessed
        } else {
            Ended::Connection
        })
    }

    /// The stream is over for the engine (its reader finished, or left): its slot is released.
    /// Returns the sealed values, rewound, when the request is to be sent again (`resend`), and
    /// the credit to give the transport for what the stream still owed.
    pub(crate) fn over(&mut self, stream: u64, resend: bool) -> (Option<Slots>, Option<u64>) {
        let Some(at) = self.at(stream) else {
            return (None, None);
        };
        let mut sent = self.streams.swap_remove(at);
        self.in_use.stream_over();
        let credit = self
            .credit
            .as_mut()
            .and_then(|credit| credit.over(&mut sent.credit));
        // A head whose values were already wiped cannot be sent again: it would go without them.
        let slots = if resend && !sent.released {
            sent.slots.rewind();
            Some(sent.slots)
        } else {
            sent.slots.wipe();
            None
        };
        (slots, credit)
    }

    /// The verdict of `stream`'s message, read by its owner: the delivery entry is released.
    pub(crate) fn take_verdict(&mut self, stream: u64) -> Option<Delivery> {
        self.ledger.take(stream)
    }

    /// The connection failed: every open message's verdict is frozen as the socket's progress stands and
    /// the connection takes no more streams. The sealed values stay in their slots for the exchanges that
    /// may send their request again ([`Self::over`]); [`Self::gone`] wipes what is left when the connection
    /// is dropped.
    pub(crate) fn failed(&mut self, reason: Reason) {
        self.ledger.gone(reason);
        self.in_use.gone();
    }

    /// The connection is gone: every open message's verdict is frozen, every sealed value wiped.
    pub(crate) fn gone(&mut self, reason: Reason) {
        self.ledger.gone(reason);
        self.in_use.gone();
        for sent in &mut self.streams {
            sent.slots.wipe();
            sent.released = true;
        }
        self.offered = None;
    }

    /// The transport broke a rule: as [`Self::gone`], recorded `transport_fault`.
    pub(crate) fn faulted(&mut self) {
        self.ledger.faulted();
        self.in_use.gone();
        for sent in &mut self.streams {
            sent.slots.wipe();
            sent.released = true;
        }
        self.offered = None;
    }

    /// What the connection has said about taking streams ([`super::lend::choose`] reads it).
    pub(crate) const fn in_use(&self) -> InUse {
        self.in_use
    }

    /// The session's credit, once `begin` answered.
    pub(crate) const fn credit(&self) -> Option<&Credit> {
        self.credit.as_ref()
    }

    /// Hand-over on UPGRADE: `stream`'s delivery entry becomes stream 1 of the adopting session.
    pub(crate) fn adopt(&mut self, stream: u64) {
        self.ledger.adopt(stream);
        if let Some(at) = self.at(stream) {
            self.streams[at].id = 1;
        }
    }
}

/// THE REFERENCE TRANSPORT, CLIENT ROLE: a stand-in that answers as transport 2.0 says a correct
/// HTTP/1.1-shaped or multiplexing transport answers, so the driver is proven with no plugin. The
/// boundary tests of the real transport (`wire`'s reference fixture) replace these scripts with
/// the fixture's decoded answers and keep every assertion.
#[cfg(test)]
pub(crate) mod reference {
    use super::super::records::{
        Session, WireEnd, WirePart, WireSealed, END_FLUSH, S_MULTIPLEX, WIRE_CONTROL,
    };
    use super::*;

    /// A scripted answer: its items and the bytes of each part.
    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) items: Vec<Out>,
        pub(crate) tails: Vec<Vec<u8>>,
    }

    impl Script {
        pub(crate) fn item(mut self, item: Out) -> Self {
            self.items.push(item);
            self.tails.push(Vec::new());
            self
        }

        pub(crate) fn part(mut self, stream: u64, class: u32, bytes: &[u8]) -> Self {
            self.items.push(Out::Part {
                part: WirePart {
                    stream,
                    class,
                    _r: 0,
                },
                len: bytes.len() as u32,
            });
            self.tails.push(bytes.to_vec());
            self
        }

        pub(crate) fn sealed(self, stream: u64, slot: u32, offset: u32, len: u32) -> Self {
            self.item(Out::Sealed(WireSealed {
                stream,
                slot,
                offset,
                len,
                _r: 0,
            }))
        }

        pub(crate) fn end(self, stream: u64, how: u32, arg: u32) -> Self {
            self.item(Out::End(WireEnd { stream, how, arg }))
        }
    }

    /// `begin`'s answer.
    pub(crate) fn begin(multiplex: bool) -> Script {
        Script::default().item(Out::Session(Session {
            flags: if multiplex { S_MULTIPLEX } else { 0 },
            stream_window: if multiplex { 1 << 20 } else { 0 },
            conn_window: if multiplex { 4 << 20 } else { 0 },
            _r: 0,
        }))
    }

    /// The answer to `emit(0, HEAD)` of a GET whose head seals one header value of `sealed_len`
    /// bytes: the stream opens, the head is control with the mark where the value goes.
    pub(crate) fn head(stream: u64, sealed_len: u32) -> Script {
        let script = Script::default().item(Out::Opened(stream)).part(
            stream,
            WIRE_CONTROL,
            b"GET /v1/models HTTP/1.1\r\nhost: api.example\r\n",
        );
        if sealed_len == 0 {
            script.part(stream, WIRE_CONTROL, b"\r\n")
        } else {
            script
                .part(stream, WIRE_CONTROL, b"x-api-key: ")
                .sealed(stream, 0, 0, sealed_len)
                .part(stream, WIRE_CONTROL, b"\r\n\r\n")
        }
    }

    /// The answer to `emit(stream, END)` of a request with no body.
    pub(crate) fn end(stream: u64) -> Script {
        Script::default().end(stream, END_FLUSH, super::super::records::END_NO_BODY)
    }

    /// A connection in the clear, straight to the target, with its queue.
    pub(crate) struct Conn {
        pub(crate) wire: Wire,
        pub(crate) dial: Dialling,
        pub(crate) out: SecureVec,
        pub(crate) flushed: u64,
    }

    impl Conn {
        pub(crate) fn new() -> Self {
            Self {
                wire: Wire::new(Role::Attempt),
                dial: Dialling::direct(false),
                out: SecureVec::new(),
                flushed: 0,
            }
        }

        pub(crate) fn answer(&mut self, script: &Script) -> Result<Outcome, Fault> {
            self.wire.answer(
                &script.items,
                |index| script.tails[index].as_slice(),
                None,
                &mut self.dial,
                &mut self.out,
                self.flushed,
            )
        }

        /// The socket takes `n` of the queued bytes.
        pub(crate) fn socket_takes(&mut self, n: usize) -> Vec<u8> {
            let taken = self.out.as_slice()[..n].to_vec();
            self.out.consume(n);
            self.flushed += n as u64;
            self.wire.accepted(self.flushed);
            taken
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::records::{StreamReset, END_FLUSH, RESET_NOT_PROCESSED, WIRE_CONTROL};
    use super::super::redial;
    use super::reference::{begin, end, head, Conn, Script};
    use super::*;

    const KEY: &[u8] = b"sk-live-0123456789abcdef";

    fn sealed_head() -> Slots {
        let mut fields = vec![
            ("x-api-key".to_owned(), KEY.to_vec()),
            ("busbar-sealed-fields".to_owned(), b"x-api-key".to_vec()),
        ];
        Slots::take_from(&mut fields).unwrap()
    }

    fn count(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }

    #[test]
    fn the_credential_reaches_the_upstream_once_in_its_place_and_no_metadata_does() {
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(sealed_head());
        let script = head(1, KEY.len() as u32);
        assert!(
            script.tails.iter().all(|bytes| count(bytes, KEY) == 0),
            "no byte the transport made holds the credential"
        );
        let outcome = conn.answer(&script).unwrap();
        assert_eq!(outcome.opened, Some(1));
        let wire = conn.out.as_slice().to_vec();
        assert_eq!(count(&wire, KEY), 1);
        assert!(wire.ends_with(b"x-api-key: sk-live-0123456789abcdef\r\n\r\n"));
        assert_eq!(count(&wire, b"busbar-sealed"), 0);
    }

    #[test]
    fn a_provider_keyed_by_a_query_pair_gets_its_key_in_the_request_target() {
        let mut fields = vec![(
            "busbar-sealed-query".to_owned(),
            b"key=AIzaSyExample".to_vec(),
        )];
        let slots = Slots::take_from(&mut fields).unwrap();
        assert!(fields.is_empty());
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(slots);
        let script = Script::default()
            .item(Out::Opened(1))
            .part(1, WIRE_CONTROL, b"POST /v1beta/models/x:generate?key=")
            .sealed(1, 0, 0, 13)
            .part(1, WIRE_CONTROL, b" HTTP/1.1\r\nhost: g.example\r\n\r\n");
        conn.answer(&script).unwrap();
        assert!(conn
            .out
            .as_slice()
            .starts_with(b"POST /v1beta/models/x:generate?key=AIzaSyExample HTTP/1.1\r\n"));
    }

    #[test]
    fn a_breach_writes_nothing_of_that_answer() {
        for (name, script) in [
            ("wrong slot", head(1, 24).sealed(1, 1, 0, 1)),
            (
                "gap",
                Script::default()
                    .item(Out::Opened(1))
                    .part(1, WIRE_CONTROL, b"x-api-key: ")
                    .sealed(1, 0, 4, 20),
            ),
            (
                "short total then the end",
                Script::default()
                    .item(Out::Opened(1))
                    .part(1, WIRE_CONTROL, b"x-api-key: ")
                    .sealed(1, 0, 0, 23)
                    .end(1, END_FLUSH, 0),
            ),
            ("twice", head(1, 24).sealed(1, 0, 0, 24)),
            (
                "uncovered before payload",
                Script::default().item(Out::Opened(1)).part(
                    1,
                    super::super::records::WIRE_PAYLOAD,
                    b"{}",
                ),
            ),
        ] {
            let mut conn = Conn::new();
            conn.answer(&begin(false)).unwrap();
            conn.wire.offer(sealed_head());
            let fault = conn.answer(&script).unwrap_err();
            assert!(fault.charged(), "{name}: {fault:?}");
            assert!(conn.out.is_empty(), "{name}: nothing is written");
            conn.wire.faulted();
            assert_eq!(
                conn.wire.take_verdict(1).and_then(|d| d.reason),
                Some(Reason::TransportFault),
                "{name}"
            );
        }
    }

    #[test]
    fn a_head_spilled_into_the_next_answer_is_covered_there() {
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(sealed_head());
        let first = Script::default()
            .item(Out::Opened(1))
            .part(1, WIRE_CONTROL, b"\x00\x00\x10\x01\x04")
            .sealed(1, 0, 0, 10);
        conn.answer(&first).unwrap();
        // A CONTINUATION frame head between the two runs of the value.
        let second = Script::default()
            .part(1, WIRE_CONTROL, b"\x00\x00\x0e\x09\x04")
            .sealed(1, 0, 10, 14);
        conn.answer(&second).unwrap();
        assert_eq!(
            count(conn.out.as_slice(), KEY),
            0,
            "split by the frame head"
        );
        assert!(conn.out.as_slice().ends_with(&KEY[10..]));
        conn.wire.emitting_end(1);
        conn.answer(&end(1)).unwrap();
    }

    #[test]
    fn busy_gives_the_values_back_for_another_connection() {
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(sealed_head());
        let outcome = conn.answer(&Script::default().item(Out::Busy)).unwrap();
        assert!(conn.out.is_empty() && outcome.opened.is_none());
        assert!(!conn.wire.in_use().takes_a_stream());
        let mut other = Conn::new();
        other.answer(&begin(true)).unwrap();
        other.wire.offer(outcome.busy.unwrap());
        other.answer(&head(1, 24)).unwrap();
        assert_eq!(count(other.out.as_slice(), KEY), 1);
    }

    #[test]
    fn a_kept_connection_closed_before_any_byte_is_sent_again() {
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(sealed_head());
        conn.answer(&head(1, 24)).unwrap();
        // The far end had closed: the socket takes nothing.
        let sent = conn.wire.state_of(1);
        assert_eq!(sent, State::None);
        let decision = redial::decide(sent, redial::Ended::Connection, true, false);
        assert!(decision.resend && !decision.charge);
        let (slots, _) = conn.wire.over(1, decision.resend);
        conn.wire.gone(Reason::CallerGone);
        let mut fresh = Conn::new();
        fresh.answer(&begin(false)).unwrap();
        fresh.wire.offer(slots.unwrap());
        fresh.answer(&head(1, 24)).unwrap();
        assert_eq!(count(fresh.out.as_slice(), KEY), 1);
    }

    #[test]
    fn closed_after_the_head_was_accepted_is_not_sent_again() {
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        conn.socket_takes(10);
        let sent = conn.wire.state_of(1);
        assert_eq!(sent, State::Part);
        let decision = redial::decide(sent, redial::Ended::Connection, true, false);
        assert!(!decision.resend && decision.charge);
        assert_eq!(decision.record, redial::Recorded::Failed(State::Part));
    }

    #[test]
    fn two_requests_on_one_connection_only_the_unsent_one_is_sent_again() {
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        let first_len = conn.out.len();
        conn.wire.offer(Slots::default());
        conn.answer(&head(3, 0)).unwrap();
        conn.socket_takes(first_len);
        let (one, three) = (conn.wire.state_of(1), conn.wire.state_of(3));
        assert_eq!((one, three), (State::Part, State::None));
        assert!(!redial::decide(one, redial::Ended::Connection, true, false).resend);
        assert!(redial::decide(three, redial::Ended::Connection, true, false).resend);
    }

    #[test]
    fn a_stream_refused_unprocessed_is_sent_again_once_and_recorded() {
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        conn.wire.emitting_end(1);
        conn.answer(&end(1)).unwrap();
        let queued = conn.out.len();
        conn.socket_takes(queued);
        assert_eq!(conn.wire.state_of(1), State::Whole);
        let reset = Script::default().item(Out::Reset(StreamReset {
            stream: 1,
            code: 7,
            flags: RESET_NOT_PROCESSED,
        }));
        conn.answer(&reset).unwrap();
        let how = conn.wire.ended_how(1).unwrap();
        let decision = redial::decide(State::Whole, how, true, false);
        assert!(decision.resend && !decision.charge);
        assert_eq!(
            decision.record,
            redial::Recorded::RefusedUnprocessed(State::Whole)
        );
    }

    #[test]
    fn a_whole_request_has_a_whole_verdict_with_its_body_bytes() {
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        conn.wire.emitting_body(1, 2);
        conn.answer(&Script::default().part(1, super::super::records::WIRE_PAYLOAD, b"{}"))
            .unwrap();
        conn.wire.emitting_end(1);
        conn.answer(&Script::default().end(1, END_FLUSH, 0))
            .unwrap();
        assert_eq!(conn.wire.take_verdict(1), None);
        let queued = conn.out.len();
        conn.socket_takes(queued);
        assert_eq!(
            conn.wire.take_verdict(1),
            Some(Delivery {
                state: State::Whole,
                reason: None,
                body_bytes: 2
            })
        );
    }

    #[test]
    fn a_session_must_be_stated_before_any_stream() {
        let mut conn = Conn::new();
        conn.wire.offer(Slots::default());
        assert_eq!(
            conn.answer(&head(1, 0)).unwrap_err(),
            Fault::Order("STREAM_OPENED before SESSION")
        );
    }

    #[test]
    fn inbound_body_is_held_to_the_stated_window_and_credit_reopens_it() {
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        let body = |len| Script::default().item(Out::Body { stream: 1, len });
        conn.answer(&body(1 << 20)).unwrap();
        assert_eq!(
            conn.answer(&body(1)).unwrap_err(),
            Fault::Window(Overrun::Stream)
        );
        let mut conn = Conn::new();
        conn.answer(&begin(true)).unwrap();
        conn.wire.offer(Slots::default());
        conn.answer(&head(1, 0)).unwrap();
        conn.answer(&body(1 << 20)).unwrap();
        assert_eq!(conn.wire.taken(1, 1 << 20), Some(1 << 20));
        conn.answer(&body(1 << 20)).unwrap();
    }

    #[test]
    fn releasing_the_head_wipes_its_values() {
        let mut conn = Conn::new();
        conn.answer(&begin(false)).unwrap();
        conn.wire.offer(sealed_head());
        conn.answer(&head(1, 24)).unwrap();
        conn.wire.release_head(1);
        let (slots, _) = conn.wire.over(1, true);
        assert!(slots.unwrap().is_empty(), "nothing is left to send again");
    }
}
