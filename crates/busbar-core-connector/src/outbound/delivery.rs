// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DELIVERY RECORD AND ITS STATE MACHINE.
//!
//! "Delivered" means: every byte the transport made for the message, through its end mark, was
//! accepted by the operating system on the connection (under TLS as whole encrypted records), the
//! flush after it succeeded, and where the protocol ends a message by closing, the close succeeded.
//! The promise ends at the operating system's boundary. The engine counts and writes the bytes
//! itself, so the accounting is the engine's; the labels are the transport's, and the rules below
//! are what a faulty transport is held to.
//!
//! One [`Ledger`] per connection, one entry per stream in flight, both roles:
//!
//! * [`Role::Answer`]: an answer to a caller on an accepted connection. `part` = at least one body
//!   byte was accepted.
//! * [`Role::Attempt`]: a request to a provider on a dialled connection. `none` is proof the
//!   provider received nothing of it: not one byte of the stream, head included, was accepted. That
//!   is the only state another attempt may follow without a second spend.
//!
//! Offsets are positions in the connection's socket queue: the count of bytes ever queued for the
//! socket. The connection records the parts of a run ([`Ledger::part`], [`Ledger::sealed`],
//! [`Ledger::end`]), hands the run to the socket queue in one write (one vectored write under TLS,
//! so a sealed value never has a record of its own whose size would state its length), then states
//! where the queue stands ([`Ledger::queued`]) and, as the socket drains, what it has taken
//! ([`Ledger::accepted`]). Every part of a run starts at the run's start and ends at the run's end:
//! under TLS a run is whole records, so "the socket took everything up to a part's end" is exactly
//! "accepted as whole encrypted records", and "the socket took nothing past the run's start" is
//! exactly "no byte of it left".
//!
//! Held per connection: the entries. Held per message in flight: one entry (five counts and a few
//! flags). No heap call per part; the entry of the last part is remembered, so consecutive parts of
//! one stream cost no search.

use super::records::{
    WireEnd, WirePart, END_FAILED, END_FLUSH, END_NO_BODY, END_SHUTDOWN, WIRE_CONTROL, WIRE_PAYLOAD,
};

/// How much of a message the operating system accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// An answer: no body byte was accepted. An attempt: no byte at all was accepted.
    None,
    /// Something was accepted and the message did not reach [`State::Whole`].
    Part,
    /// Everything through the end mark was accepted and flushed (and shut down where the protocol
    /// ends by closing).
    Whole,
}

impl State {
    /// The word the record carries.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Part => "part",
            Self::Whole => "whole",
        }
    }
}

/// Why a message is not [`State::Whole`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The connection failed or was reset by the far end.
    CallerGone,
    /// The engine's deadline ended the message.
    Deadline,
    /// The message's owner cancelled it.
    Cancelled,
    /// The transport failed the message (`END_FAILED`).
    Protocol,
    /// The transport broke a rule of the output model; the session was ended for it.
    TransportFault,
    /// The engine was shutting down.
    Shutdown,
}

impl Reason {
    /// The word the record carries.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CallerGone => "caller_gone",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
            Self::TransportFault => "transport_fault",
            Self::Shutdown => "shutdown",
        }
    }
}

/// THE DELIVERY RECORD: the `delivery` field group of an answer's audit record, and the evidence of
/// one provider attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Delivery {
    /// `whole`, `part` or `none`.
    pub(crate) state: State,
    /// Only when not `whole`.
    pub(crate) reason: Option<Reason>,
    /// Bytes of class payload the transport made for the message. When `state` is `whole` all of
    /// them were accepted.
    pub(crate) body_bytes: u64,
}

impl Delivery {
    /// The record as the root's settlement and audit read it today
    /// ([`busbar_contract::response_delivery::DeliverySnapshot`]): `whole` is the complete terminal;
    /// `part` and `none` are a failed terminal, told apart by whether a body byte was accepted. The
    /// audit's finish is then Complete, Partial or Error as before; `reason` and `body_bytes` are
    /// what the record gains.
    pub(crate) fn snapshot(&self) -> busbar_contract::response_delivery::DeliverySnapshot {
        use busbar_contract::response_delivery::{
            DeliverySnapshot, DeliveryTerminal, ResponseStop,
        };
        let stop = match self.reason {
            Some(Reason::Deadline) => ResponseStop::Deadline,
            Some(Reason::Cancelled) => ResponseStop::Cancelled,
            Some(Reason::Protocol) => ResponseStop::Protocol,
            Some(Reason::TransportFault) => ResponseStop::Integrity,
            Some(Reason::CallerGone | Reason::Shutdown) | None => ResponseStop::CarrierRetired,
        };
        DeliverySnapshot {
            first_payload_written: match self.state {
                State::Whole => self.body_bytes > 0,
                State::Part => true,
                State::None => false,
            },
            terminal: Some(match self.state {
                State::Whole => DeliveryTerminal::Complete,
                State::Part | State::None => DeliveryTerminal::Failed(stop),
            }),
        }
    }
}

/// Which side of the engine the stream is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// An answer on an accepted connection (announced by `STREAM_HEAD`).
    Answer,
    /// A request on a dialled connection (announced by `STREAM_OPENED`).
    Attempt,
}

/// A rule of the output model the transport broke. Every one is FAULT BadRecords: nothing of the
/// answer that carried it is written, the session ends, the plugin is charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Breach {
    /// L1: a part with no bytes, or a class that is neither payload nor control.
    L1,
    /// L2: a part or an end mark names a stream that is not open.
    L2,
    /// L3: a payload part on stream 0.
    L3,
    /// L4: a record names a stream after its end mark.
    L4,
    /// L5: a successful end the engine did not ask for.
    L5,
    /// L6: at a successful end the payload bytes are not the body bytes the engine emitted.
    L6,
    /// L7: a part after `END_SHUTDOWN`.
    L7,
}

impl Breach {
    /// The rule's name, for the fault's audit line.
    pub(crate) const fn rule(self) -> &'static str {
        match self {
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L4 => "L4",
            Self::L5 => "L5",
            Self::L6 => "L6",
            Self::L7 => "L7",
        }
    }
}

/// No byte yet.
const NEVER: u64 = u64::MAX;

/// In the run being recorded: its end is not known until [`Ledger::queued`]. Larger than any
/// count the socket can report, so nothing in an open run reads as accepted.
const IN_RUN: u64 = u64::MAX - 1;

/// What the engine asked of a stream's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    /// Nothing that ends it.
    Open,
    /// `emit(E_END)`.
    End,
    /// `emit(E_REFUSE)`: a refusal's bytes are not counted against the body.
    Refuse,
}

/// One message in flight.
#[derive(Clone, Copy, Debug)]
struct Entry {
    stream: u64,
    role: Role,
    /// The queue position before the stream's first byte.
    first_start: u64,
    /// The queue position after the stream's first payload part.
    first_body_end: u64,
    /// The queue position after the stream's last byte so far; at an end mark, the mark's position.
    last_end: u64,
    /// Payload bytes the transport made.
    payload: u64,
    /// Body bytes the engine emitted.
    emitted: u64,
    asked: Asked,
    /// The end mark's `how`, once sent.
    ended: Option<u32>,
    /// The engine stopped the message (`emit(E_RESET)`) for this reason.
    stopped: Option<Reason>,
    /// The verdict, once nothing can change it.
    verdict: Option<Delivery>,
}

impl Entry {
    /// The state as the socket's progress stands, before any end is judged.
    fn progress(&self, accepted: u64) -> State {
        let reached = match self.role {
            Role::Answer => self.first_body_end != NEVER && accepted >= self.first_body_end,
            Role::Attempt => self.first_start != NEVER && accepted > self.first_start,
        };
        if reached {
            State::Part
        } else {
            State::None
        }
    }

    fn freeze(&mut self, state: State, reason: Option<Reason>) {
        if self.verdict.is_none() {
            self.verdict = Some(Delivery {
                state,
                reason: if state == State::Whole { None } else { reason },
                body_bytes: self.payload,
            });
        }
    }
}

/// THE CONNECTION'S DELIVERY LEDGER.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    entries: Vec<Entry>,
    /// The entry the last record named.
    last: usize,
    /// Bytes ever queued for the socket, as the connection last stated it.
    queued: u64,
    /// Bytes the socket has taken.
    accepted: u64,
    /// Control bytes on stream 0 (the connection's own, and answers the transport made by itself).
    connection_bytes: u64,
    /// `END_SHUTDOWN` was sent: no part may follow.
    shutting: bool,
    /// The shutdown the last `END_SHUTDOWN` asked for succeeded.
    shut: bool,
    /// Parts were recorded since the last [`Ledger::queued`].
    run_open: bool,
}

impl Ledger {
    /// An empty ledger: nothing is made before the first stream.
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            last: 0,
            queued: 0,
            accepted: 0,
            connection_bytes: 0,
            shutting: false,
            shut: false,
            run_open: false,
        }
    }

    /// A stream is announced (`STREAM_HEAD` on an accepted connection, `STREAM_OPENED` on a dialled
    /// one). Made then, not at admission: an end mark that arrives before the request is admitted
    /// is valid and is remembered.
    ///
    /// # Errors
    /// L2 when the stream is 0 or already open.
    pub(crate) fn open(&mut self, stream: u64, role: Role) -> Result<(), Breach> {
        if stream == 0 || self.find(stream).is_some() {
            return Err(Breach::L2);
        }
        self.entries.push(Entry {
            stream,
            role,
            first_start: NEVER,
            first_body_end: NEVER,
            last_end: self.queued,
            payload: 0,
            emitted: 0,
            asked: Asked::Open,
            ended: None,
            stopped: None,
            verdict: None,
        });
        self.last = self.entries.len() - 1;
        Ok(())
    }

    /// The engine emitted `len` body bytes on `stream` (`emit(E_BODY)`).
    pub(crate) fn emitted_body(&mut self, stream: u64, len: u64) {
        if let Some(at) = self.find(stream) {
            let entry = &mut self.entries[at];
            entry.emitted = entry.emitted.saturating_add(len);
        }
    }

    /// The engine emitted `E_END` on `stream`.
    pub(crate) fn asked_end(&mut self, stream: u64) {
        if let Some(at) = self.find(stream) {
            if self.entries[at].asked == Asked::Open {
                self.entries[at].asked = Asked::End;
            }
        }
    }

    /// The engine emitted `E_REFUSE` on `stream`.
    pub(crate) fn asked_refuse(&mut self, stream: u64) {
        if let Some(at) = self.find(stream) {
            self.entries[at].asked = Asked::Refuse;
        }
    }

    /// The engine stopped `stream` (`emit(E_RESET)`): the reason its record will carry.
    pub(crate) fn stopped(&mut self, stream: u64, reason: Reason) {
        if let Some(at) = self.find(stream) {
            let entry = &mut self.entries[at];
            if entry.stopped.is_none() {
                entry.stopped = Some(reason);
            }
        }
    }

    /// The run recorded so far is in the socket queue, which now stands at `queue_end` bytes ever
    /// queued. Called once per run, after the one write that queued it.
    pub(crate) fn queued(&mut self, queue_end: u64) {
        if self.run_open {
            for entry in &mut self.entries {
                if entry.first_body_end == IN_RUN {
                    entry.first_body_end = queue_end;
                }
                if entry.last_end == IN_RUN {
                    entry.last_end = queue_end;
                }
            }
            self.run_open = false;
        }
        self.queued = queue_end;
        self.settle();
    }

    /// One part queued alone: [`Self::part`] then [`Self::queued`].
    ///
    /// # Errors
    /// As [`Self::part`]; the queue position does not move for a part that breaks a rule.
    pub(crate) fn part_at(
        &mut self,
        part: WirePart,
        len: u32,
        queue_end: u64,
    ) -> Result<(), Breach> {
        self.part(part, len)?;
        self.queued(queue_end);
        Ok(())
    }

    /// A `WIRE_PART` of `len` bytes joins the run being recorded.
    ///
    /// # Errors
    /// The rule the part breaks. Nothing is recorded for a part that breaks one.
    pub(crate) fn part(&mut self, part: WirePart, len: u32) -> Result<(), Breach> {
        if len == 0 || !matches!(part.class, WIRE_PAYLOAD | WIRE_CONTROL) {
            return Err(Breach::L1);
        }
        if self.shutting {
            return Err(Breach::L7);
        }
        let start = self.queued;
        if part.stream == 0 {
            if part.class != WIRE_CONTROL {
                return Err(Breach::L3);
            }
            self.connection_bytes = self.connection_bytes.saturating_add(u64::from(len));
            self.run_open = true;
            return Ok(());
        }
        let at = self.find(part.stream).ok_or(Breach::L2)?;
        let entry = &mut self.entries[at];
        if entry.ended.is_some() {
            return Err(Breach::L4);
        }
        if entry.first_start == NEVER {
            entry.first_start = start;
        }
        if part.class == WIRE_PAYLOAD {
            entry.payload = entry.payload.saturating_add(u64::from(len));
            if entry.first_body_end == NEVER {
                entry.first_body_end = IN_RUN;
            }
        }
        entry.last_end = IN_RUN;
        self.run_open = true;
        Ok(())
    }

    /// The engine wrote `len` bytes of a sealed value for `stream` (a `WIRE_SEALED` it covered) into
    /// the run being recorded. A sealed part is always control.
    ///
    /// # Errors
    /// As [`Self::part`] for a control part on `stream`.
    pub(crate) fn sealed(&mut self, stream: u64, len: u32) -> Result<(), Breach> {
        if stream == 0 {
            return Err(Breach::L2);
        }
        self.part(
            WirePart {
                stream,
                class: WIRE_CONTROL,
                _r: 0,
            },
            len,
        )
    }

    /// A `WIRE_END`.
    ///
    /// # Errors
    /// L2 for a stream that is not open, L4 for a second end, L5 for a successful end the engine did
    /// not ask for, L6 when the payload is not the body the engine emitted.
    pub(crate) fn end(&mut self, end: WireEnd) -> Result<(), Breach> {
        if !matches!(end.how, END_FLUSH | END_SHUTDOWN | END_FAILED) {
            return Err(Breach::L1);
        }
        let at = self.find(end.stream).ok_or(Breach::L2)?;
        let entry = &mut self.entries[at];
        if entry.ended.is_some() {
            return Err(Breach::L4);
        }
        if end.how != END_FAILED {
            match entry.asked {
                Asked::Open => return Err(Breach::L5),
                Asked::Refuse => {}
                Asked::End => {
                    let exact = entry.payload == entry.emitted;
                    let bodiless = entry.payload == 0 && end.arg == END_NO_BODY;
                    if !(exact || bodiless) {
                        return Err(Breach::L6);
                    }
                }
            }
        }
        entry.ended = Some(end.how);
        // An end mark inside an open run stands at the run's end; alone, where the queue stands.
        if entry.last_end != IN_RUN {
            entry.last_end = self.queued;
        }
        if end.how == END_SHUTDOWN {
            self.shutting = true;
        }
        self.settle();
        Ok(())
    }

    /// The socket has taken `total` bytes since the connection opened, and nothing it took is still
    /// in a buffer of the engine's (the flush).
    pub(crate) fn accepted(&mut self, total: u64) {
        if total > self.accepted {
            self.accepted = total;
            self.settle();
        }
    }

    /// The shutdown an `END_SHUTDOWN` asked for succeeded.
    pub(crate) fn shut_down(&mut self) {
        self.shut = true;
        self.settle();
    }

    /// The connection is gone (failed, reset, closed by the engine): every message still open has
    /// its verdict frozen as the socket's progress stands. A message the engine had stopped keeps
    /// the reason it was stopped for.
    pub(crate) fn gone(&mut self, reason: Reason) {
        let accepted = self.accepted;
        for entry in &mut self.entries {
            let state = entry.progress(accepted);
            entry.freeze(state, Some(entry.stopped.unwrap_or(reason)));
        }
    }

    /// The transport broke a rule: the session ends, and every message still open is `part` or
    /// `none` with reason `transport_fault`.
    pub(crate) fn faulted(&mut self) {
        let accepted = self.accepted;
        for entry in &mut self.entries {
            let state = entry.progress(accepted);
            entry.freeze(state, Some(Reason::TransportFault));
        }
    }

    /// The verdict of `stream`, once nothing can change it.
    pub(crate) fn verdict(&self, stream: u64) -> Option<Delivery> {
        self.entries
            .iter()
            .find(|entry| entry.stream == stream)
            .and_then(|entry| entry.verdict)
    }

    /// The message's owner reads its verdict: the entry is released. `None` while it is not final.
    pub(crate) fn take(&mut self, stream: u64) -> Option<Delivery> {
        let at = self.find(stream)?;
        let verdict = self.entries[at].verdict?;
        self.entries.swap_remove(at);
        self.last = 0;
        Some(verdict)
    }

    /// The state of `stream` as it stands now, final or not: what a redial is decided from. A
    /// stream the ledger does not hold sent nothing.
    pub(crate) fn state_of(&self, stream: u64) -> State {
        self.entries
            .iter()
            .find(|entry| entry.stream == stream)
            .map_or(State::None, |entry| match entry.verdict {
                Some(verdict) => verdict.state,
                None => entry.progress(self.accepted),
            })
    }

    /// Hand-over on UPGRADE: the upgraded request's entry becomes stream 1 of the adopting session.
    /// The connection's counters are not reset.
    pub(crate) fn adopt(&mut self, stream: u64) {
        if let Some(at) = self.find(stream) {
            self.entries[at].stream = 1;
        }
    }

    /// Control bytes written on stream 0.
    pub(crate) const fn connection_bytes(&self) -> u64 {
        self.connection_bytes
    }

    /// Messages in flight.
    pub(crate) fn open_streams(&self) -> usize {
        self.entries.len()
    }

    /// The queue position after `stream`'s last byte (what the per-stream write bound reads).
    pub(crate) fn last_end(&self, stream: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.stream == stream)
            .map(|entry| entry.last_end)
    }

    /// Bytes the socket has taken.
    pub(crate) const fn taken(&self) -> u64 {
        self.accepted
    }

    fn find(&mut self, stream: u64) -> Option<usize> {
        if self
            .entries
            .get(self.last)
            .is_some_and(|entry| entry.stream == stream)
        {
            return Some(self.last);
        }
        let at = self
            .entries
            .iter()
            .position(|entry| entry.stream == stream)?;
        self.last = at;
        Some(at)
    }

    /// Freeze every ended message whose bytes are all out.
    fn settle(&mut self) {
        let (accepted, shut) = (self.accepted, self.shut);
        for entry in &mut self.entries {
            let Some(how) = entry.ended else {
                continue;
            };
            if entry.verdict.is_some() || accepted < entry.last_end {
                continue;
            }
            match how {
                END_FLUSH => entry.freeze(State::Whole, None),
                END_SHUTDOWN if shut => entry.freeze(State::Whole, None),
                END_SHUTDOWN => {}
                _ => {
                    let state = entry.progress(accepted);
                    entry.freeze(state, Some(entry.stopped.unwrap_or(Reason::Protocol)));
                }
            }
        }
    }
}

/// One piece of an answer the engine is about to give the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece {
    /// `E_HEAD`. `ends` = the engine set `SH_END_STREAM`; `stated_len` = the body length the head
    /// states exactly, if it states one.
    Head {
        /// No body follows.
        ends: bool,
        /// The exact body length the head states.
        stated_len: Option<u64>,
    },
    /// `E_BODY` of this many bytes.
    Body(u64),
    /// `E_TRAILERS`.
    Trailers,
    /// `E_END`.
    End,
}

/// THE HOLD ON AN ANSWER'S LAST PIECE. It is the engine's: when an answer must wait for its record
/// (`advanced.wait_for_commit`), the engine does not give the transport the piece that completes
/// the answer until the record is in. With the setting off nothing is withheld and nothing is
/// paid. The wait is on one stream only; nothing is parked in the connection's byte pipe.
///
/// | The answer ends with | Withheld |
/// |---|---|
/// | any body, then the end | `E_END` |
/// | trailers | `E_TRAILERS` and `E_END` |
/// | a body whose exact length the head stated | the body piece that reaches that length, and `E_END` |
/// | a head and nothing else | the head, and `E_END` |
#[derive(Clone, Copy, Debug)]
pub struct Hold {
    /// The record is not in yet.
    waiting: bool,
    /// A piece was withheld: every later piece waits behind it, in order.
    held: bool,
    stated_len: Option<u64>,
    sent: u64,
}

impl Hold {
    /// `wait` = the answer must wait for its record.
    #[must_use]
    pub const fn new(wait: bool) -> Self {
        Self {
            waiting: wait,
            held: false,
            stated_len: None,
            sent: 0,
        }
    }

    /// Whether the engine withholds `piece` now. A piece that is not withheld is counted as given.
    pub fn withholds(&mut self, piece: Piece) -> bool {
        if !self.waiting {
            return false;
        }
        if self.held {
            return true;
        }
        let completes = match piece {
            Piece::Head { ends, stated_len } => {
                self.stated_len = stated_len;
                ends || stated_len == Some(0)
            }
            Piece::Body(len) => self
                .stated_len
                .is_some_and(|stated| self.sent.saturating_add(len) >= stated),
            Piece::Trailers | Piece::End => true,
        };
        if completes {
            self.held = true;
            return true;
        }
        if let Piece::Body(len) = piece {
            self.sent = self.sent.saturating_add(len);
        }
        false
    }

    /// The record is in: every withheld piece goes now, in the order it was withheld.
    pub fn committed(&mut self) {
        self.waiting = false;
        self.held = false;
    }

    /// A piece is being withheld.
    #[must_use]
    pub const fn holding(&self) -> bool {
        self.waiting && self.held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(stream: u64) -> WirePart {
        WirePart {
            stream,
            class: WIRE_PAYLOAD,
            _r: 0,
        }
    }

    fn control(stream: u64) -> WirePart {
        WirePart {
            stream,
            class: WIRE_CONTROL,
            _r: 0,
        }
    }

    fn end(stream: u64, how: u32, arg: u32) -> WireEnd {
        WireEnd { stream, how, arg }
    }

    /// An answer of a 10-byte head and a 100-byte body, queued in the clear.
    fn answer() -> Ledger {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Answer).unwrap();
        ledger.part_at(control(1), 10, 10).unwrap();
        ledger.emitted_body(1, 100);
        ledger.part_at(payload(1), 100, 110).unwrap();
        ledger
    }

    #[test]
    fn whole_needs_the_end_mark_and_every_byte_accepted() {
        let mut ledger = answer();
        ledger.asked_end(1);
        ledger.part_at(control(1), 5, 115).unwrap();
        ledger.end(end(1, END_FLUSH, 0)).unwrap();
        ledger.accepted(114);
        assert_eq!(
            ledger.verdict(1),
            None,
            "one byte of the end marker is not out"
        );
        ledger.accepted(115);
        assert_eq!(
            ledger.take(1),
            Some(Delivery {
                state: State::Whole,
                reason: None,
                body_bytes: 100
            })
        );
        assert_eq!(ledger.open_streams(), 0);
    }

    #[test]
    fn a_stream_cut_mid_body_is_part() {
        let mut ledger = answer();
        ledger.accepted(110);
        ledger.gone(Reason::CallerGone);
        assert_eq!(
            ledger.take(1),
            Some(Delivery {
                state: State::Part,
                reason: Some(Reason::CallerGone),
                body_bytes: 100
            })
        );
    }

    #[test]
    fn an_answer_whose_head_alone_was_accepted_is_none() {
        let mut ledger = answer();
        ledger.accepted(10);
        ledger.gone(Reason::CallerGone);
        assert_eq!(ledger.take(1).map(|d| d.state), Some(State::None));
    }

    #[test]
    fn an_attempt_is_none_only_while_no_byte_of_it_was_accepted() {
        let mut ledger = Ledger::new();
        // Another request's 40 bytes precede this one on the shared connection.
        ledger.open(1, Role::Attempt).unwrap();
        ledger.part_at(control(1), 40, 40).unwrap();
        ledger.open(3, Role::Attempt).unwrap();
        ledger.part_at(control(3), 30, 70).unwrap();
        ledger.accepted(40);
        assert_eq!(ledger.state_of(1), State::Part);
        assert_eq!(
            ledger.state_of(3),
            State::None,
            "the socket took nothing of stream 3"
        );
        ledger.accepted(41);
        assert_eq!(
            ledger.state_of(3),
            State::Part,
            "one byte of the head is enough: the provider may have seen the request"
        );
    }

    #[test]
    fn two_requests_on_one_connection_have_their_own_states() {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Attempt).unwrap();
        ledger.open(3, Role::Attempt).unwrap();
        ledger.part_at(control(1), 20, 20).unwrap();
        ledger.part_at(control(3), 20, 40).unwrap();
        ledger.accepted(20);
        ledger.gone(Reason::CallerGone);
        assert_eq!(ledger.take(1).map(|d| d.state), Some(State::Part));
        assert_eq!(ledger.take(3).map(|d| d.state), Some(State::None));
    }

    #[test]
    fn a_stream_the_ledger_does_not_hold_sent_nothing() {
        assert_eq!(Ledger::new().state_of(9), State::None);
    }

    #[test]
    fn shutdown_end_is_whole_only_once_the_shutdown_succeeded() {
        let mut ledger = answer();
        ledger.asked_end(1);
        ledger.end(end(1, END_SHUTDOWN, 0)).unwrap();
        ledger.accepted(110);
        assert_eq!(ledger.verdict(1), None);
        ledger.shut_down();
        assert_eq!(ledger.take(1).map(|d| d.state), Some(State::Whole));
    }

    #[test]
    fn a_failed_end_is_frozen_when_its_bytes_are_out_with_the_engines_reason() {
        let mut ledger = answer();
        ledger.stopped(1, Reason::Deadline);
        ledger.part_at(control(1), 9, 119).unwrap();
        ledger.end(end(1, END_FAILED, 0)).unwrap();
        ledger.accepted(119);
        assert_eq!(
            ledger.take(1),
            Some(Delivery {
                state: State::Part,
                reason: Some(Reason::Deadline),
                body_bytes: 100
            })
        );
    }

    #[test]
    fn a_failed_end_the_engine_did_not_ask_for_is_the_protocols() {
        let mut ledger = answer();
        ledger.end(end(1, END_FAILED, 0)).unwrap();
        ledger.accepted(110);
        assert_eq!(
            ledger.take(1).and_then(|d| d.reason),
            Some(Reason::Protocol)
        );
    }

    #[test]
    fn l1_an_empty_part_or_an_unknown_class_is_a_breach() {
        let mut ledger = answer();
        assert_eq!(ledger.part_at(control(1), 0, 110), Err(Breach::L1));
        let odd = WirePart {
            stream: 1,
            class: 9,
            _r: 0,
        };
        assert_eq!(ledger.part_at(odd, 4, 114), Err(Breach::L1));
    }

    #[test]
    fn l2_a_part_for_a_stream_never_announced_is_a_breach() {
        let mut ledger = Ledger::new();
        assert_eq!(ledger.part_at(control(5), 4, 4), Err(Breach::L2));
        assert_eq!(ledger.end(end(5, END_FAILED, 0)), Err(Breach::L2));
        assert_eq!(ledger.open(0, Role::Answer), Err(Breach::L2));
    }

    #[test]
    fn l3_stream_zero_is_control_only_and_is_counted() {
        let mut ledger = Ledger::new();
        assert_eq!(ledger.part_at(payload(0), 4, 4), Err(Breach::L3));
        ledger.part_at(control(0), 24, 24).unwrap();
        assert_eq!(ledger.connection_bytes(), 24);
    }

    #[test]
    fn l4_nothing_names_a_stream_after_its_end() {
        let mut ledger = answer();
        ledger.asked_end(1);
        ledger.end(end(1, END_FLUSH, 0)).unwrap();
        assert_eq!(ledger.part_at(control(1), 4, 114), Err(Breach::L4));
        assert_eq!(ledger.end(end(1, END_FLUSH, 0)), Err(Breach::L4));
    }

    #[test]
    fn l5_a_transport_cannot_declare_an_end_the_engine_did_not_ask_for() {
        let mut ledger = answer();
        assert_eq!(ledger.end(end(1, END_FLUSH, 0)), Err(Breach::L5));
        assert_eq!(ledger.end(end(1, END_SHUTDOWN, 0)), Err(Breach::L5));
    }

    #[test]
    fn l6_the_payload_is_the_body_the_engine_emitted() {
        let mut ledger = answer();
        ledger.emitted_body(1, 1);
        ledger.asked_end(1);
        assert_eq!(
            ledger.end(end(1, END_FLUSH, 0)),
            Err(Breach::L6),
            "101 emitted, 100 made"
        );
    }

    #[test]
    fn l6_a_bodiless_protocol_answer_says_so() {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Answer).unwrap();
        ledger.part_at(control(1), 10, 10).unwrap();
        ledger.emitted_body(1, 50);
        ledger.asked_end(1);
        assert_eq!(ledger.end(end(1, END_FLUSH, 0)), Err(Breach::L6));
        ledger.end(end(1, END_FLUSH, END_NO_BODY)).unwrap();
    }

    #[test]
    fn l6_a_refusal_is_not_counted_against_the_body() {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Answer).unwrap();
        ledger.asked_refuse(1);
        ledger.part_at(control(1), 30, 30).unwrap();
        ledger.part_at(payload(1), 12, 42).unwrap();
        ledger.end(end(1, END_FLUSH, 0)).unwrap();
    }

    #[test]
    fn l7_no_part_follows_a_shutdown_end() {
        let mut ledger = answer();
        ledger.asked_end(1);
        ledger.end(end(1, END_SHUTDOWN, 0)).unwrap();
        assert_eq!(ledger.part_at(control(0), 4, 114), Err(Breach::L7));
    }

    #[test]
    fn a_fault_freezes_every_open_message_as_transport_fault() {
        let mut ledger = answer();
        ledger.open(3, Role::Answer).unwrap();
        ledger.accepted(110);
        ledger.faulted();
        assert_eq!(
            ledger.take(1),
            Some(Delivery {
                state: State::Part,
                reason: Some(Reason::TransportFault),
                body_bytes: 100
            })
        );
        assert_eq!(
            ledger.take(3),
            Some(Delivery {
                state: State::None,
                reason: Some(Reason::TransportFault),
                body_bytes: 0
            })
        );
    }

    #[test]
    fn an_end_before_admission_is_remembered() {
        let mut ledger = Ledger::new();
        ledger.open(7, Role::Answer).unwrap();
        ledger.end(end(7, END_FAILED, 0)).unwrap();
        assert_eq!(ledger.verdict(7).map(|d| d.state), Some(State::None));
    }

    #[test]
    fn an_upgraded_request_becomes_stream_one() {
        let mut ledger = Ledger::new();
        ledger.open(9, Role::Answer).unwrap();
        ledger.adopt(9);
        ledger.part_at(control(1), 129, 129).unwrap();
        assert_eq!(ledger.last_end(1), Some(129));
    }

    #[test]
    fn a_verdict_once_frozen_does_not_change() {
        let mut ledger = answer();
        ledger.accepted(10);
        ledger.gone(Reason::Cancelled);
        ledger.accepted(110);
        ledger.gone(Reason::Shutdown);
        assert_eq!(
            ledger.take(1),
            Some(Delivery {
                state: State::None,
                reason: Some(Reason::Cancelled),
                body_bytes: 100
            })
        );
    }

    #[test]
    fn with_the_setting_off_nothing_is_withheld() {
        let mut hold = Hold::new(false);
        for piece in [
            Piece::Head {
                ends: false,
                stated_len: None,
            },
            Piece::Body(10),
            Piece::Trailers,
            Piece::End,
        ] {
            assert!(!hold.withholds(piece));
        }
        assert!(!hold.holding());
    }

    #[test]
    fn a_streamed_answer_holds_only_its_end() {
        let mut hold = Hold::new(true);
        assert!(!hold.withholds(Piece::Head {
            ends: false,
            stated_len: None
        }));
        assert!(!hold.withholds(Piece::Body(4096)));
        assert!(hold.withholds(Piece::End));
        assert!(hold.holding());
        hold.committed();
        assert!(!hold.withholds(Piece::End));
    }

    #[test]
    fn trailers_are_held_with_the_end() {
        let mut hold = Hold::new(true);
        assert!(!hold.withholds(Piece::Head {
            ends: false,
            stated_len: None
        }));
        assert!(hold.withholds(Piece::Trailers));
        assert!(hold.withholds(Piece::End));
    }

    #[test]
    fn a_stated_length_holds_the_piece_that_reaches_it() {
        let mut hold = Hold::new(true);
        assert!(!hold.withholds(Piece::Head {
            ends: false,
            stated_len: Some(100)
        }));
        assert!(!hold.withholds(Piece::Body(60)));
        assert!(
            hold.withholds(Piece::Body(40)),
            "a caller knows such an answer is complete at its last byte"
        );
        assert!(hold.withholds(Piece::End));
    }

    #[test]
    fn a_head_that_is_the_whole_answer_is_held() {
        let mut hold = Hold::new(true);
        assert!(hold.withholds(Piece::Head {
            ends: true,
            stated_len: None
        }));
        let mut empty = Hold::new(true);
        assert!(empty.withholds(Piece::Head {
            ends: false,
            stated_len: Some(0)
        }));
    }

    #[test]
    fn a_run_shares_its_start_and_its_end() {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Attempt).unwrap();
        ledger.queued(1_000);
        ledger.accepted(1_000);
        // The head as three parts of one run: control, a sealed value, control.
        ledger.part(control(1), 20).unwrap();
        ledger.sealed(1, 32).unwrap();
        ledger.part(control(1), 4).unwrap();
        assert_eq!(
            ledger.state_of(1),
            State::None,
            "an open run is not in the socket queue yet"
        );
        ledger.queued(1_056);
        assert_eq!(ledger.last_end(1), Some(1_056));
        assert_eq!(ledger.state_of(1), State::None);
        ledger.accepted(1_001);
        assert_eq!(ledger.state_of(1), State::Part);
    }

    #[test]
    fn an_end_mark_inside_a_run_stands_at_the_runs_end() {
        let mut ledger = Ledger::new();
        ledger.open(1, Role::Answer).unwrap();
        ledger.asked_end(1);
        ledger.part(control(1), 10).unwrap();
        ledger.end(end(1, END_FLUSH, END_NO_BODY)).unwrap();
        ledger.accepted(5);
        assert_eq!(ledger.verdict(1), None);
        ledger.queued(10);
        assert_eq!(ledger.verdict(1), None);
        ledger.accepted(10);
        assert_eq!(ledger.take(1).map(|d| d.state), Some(State::Whole));
    }

    #[test]
    fn the_record_maps_onto_todays_snapshot_with_no_loss() {
        use busbar_contract::response_delivery::{DeliveryTerminal, ResponseStop};
        let record = |state, reason, body_bytes| Delivery {
            state,
            reason,
            body_bytes,
        };
        let whole = record(State::Whole, None, 100).snapshot();
        assert_eq!(whole.terminal, Some(DeliveryTerminal::Complete));
        assert!(whole.first_payload_written);
        assert!(
            !record(State::Whole, None, 0)
                .snapshot()
                .first_payload_written
        );
        let part = record(State::Part, Some(Reason::Deadline), 100).snapshot();
        assert_eq!(
            part.terminal,
            Some(DeliveryTerminal::Failed(ResponseStop::Deadline))
        );
        assert!(part.first_payload_written);
        let none = record(State::None, Some(Reason::TransportFault), 0).snapshot();
        assert_eq!(
            none.terminal,
            Some(DeliveryTerminal::Failed(ResponseStop::Integrity))
        );
        assert!(!none.first_payload_written);
    }

    #[test]
    fn the_words_of_the_record_are_fixed() {
        assert_eq!(
            [State::Whole, State::Part, State::None].map(State::as_str),
            ["whole", "part", "none"]
        );
        assert_eq!(
            [
                Reason::CallerGone,
                Reason::Deadline,
                Reason::Cancelled,
                Reason::Protocol,
                Reason::TransportFault,
                Reason::Shutdown
            ]
            .map(Reason::as_str),
            [
                "caller_gone",
                "deadline",
                "cancelled",
                "protocol",
                "transport_fault",
                "shutdown"
            ]
        );
    }
}
