// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANSWERS OF ONE ACCEPTED CONNECTION, AND WHO READS EACH VERDICT.
//!
//! An accepted connection is driven by the same driver as a dialled one
//! ([`crate::outbound::wire::Wire`], here with [`Role::Answer`]): every answer of the transport is
//! checked against the output model (L1 to L7, L9) and placed for the connection as one run, and the
//! delivery state machine ([`crate::outbound::delivery`]) says, per answer, how much of it the
//! operating system accepted. [`DeliveryLedger`] is that driver for one accepted connection, with the
//! one thing the dial does not have: each answer's OWNER, the request's side in the root, which reads
//! the verdict through the handles it was given at admission ([`ResponseHandles`]).
//!
//! "Delivered" is the owner's definition and nothing else: every byte the transport made for the
//! answer, through its end mark, was accepted by the operating system on the caller's connection (under
//! TLS as whole encrypted records), the flush after it succeeded, and where the protocol ends an answer
//! by closing, the close succeeded. The record is `whole`, `part` or `none`, the reason when it is not
//! whole, and the count of body bytes ([`DeliveryRecord`]).
//!
//! THE HOLD IS THE ENGINE'S. Nothing here releases anything: an answer that must wait for its record
//! is held by its owner, which does not give the transport the piece that completes it
//! ([`crate::hold::Hold`]). The transport is never called about delivery.
//!
//! NOTHING IS MADE AHEAD (owner's allocation ruling): an empty ledger holds no array and no cell; an
//! entry is made when the transport announces a stream, a cell when its request is admitted, the wake
//! cell with the first of those.
//!
//! NO ANSWER BYTE IS HELD HERE (OPEN-3 16, money): the session already holds each answer's bytes in
//! its own output buffer, charged to the connection's storage account. The ledger checks the answer
//! and places its run ([`Wire::check`]) without copying a byte; the connection is given
//! [`DeliveryLedger::give`] straight from the session's buffer, which is cleared only after the write.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::response_delivery::{
    CarrierProgress, DeliverySnapshot, DeliveryTerminal, ResponseKey, ResponseStop,
};
use busbar_plugin_abi::transport as abi;
use futures::task::AtomicWaker;

use crate::outbound::delivery::{Delivery as Verdict, Reason, Role, State as Sent};
use crate::outbound::records::Out;
use crate::outbound::wire::{Checked, Fault, Wire};

#[cfg(test)]
#[path = "response_delivery_tests.rs"]
mod tests;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE DELIVERY RECORD OF ONE ANSWER, in the words its audit record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// `whole`, `part` or `none`.
    pub state: &'static str,
    /// Only when not `whole`: `caller_gone`, `deadline`, `cancelled`, `protocol`, `transport_fault` or
    /// `shutdown`.
    pub reason: Option<&'static str>,
    /// Bytes of class payload the transport made for the answer. When `state` is `whole` all of them
    /// were accepted.
    pub body_bytes: u64,
}

impl DeliveryRecord {
    fn of(verdict: Verdict) -> Self {
        Self {
            state: verdict.state.as_str(),
            reason: verdict.reason.map(Reason::as_str),
            body_bytes: verdict.body_bytes,
        }
    }
}

struct Cell {
    key: ResponseKey,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
    owner_wake: Arc<AtomicWaker>,
}

struct State {
    snapshot: DeliverySnapshot,
    record: Option<DeliveryRecord>,
    ordinal: Option<u64>,
    published: bool,
    cancel: Option<ResponseStop>,
    cancel_taken: bool,
    producer_ended: bool,
    reader_eof: bool,
    input_retired: bool,
}

/// Read/watch access only; a clone keeps the answer's cell alive until it is dropped.
#[derive(Clone)]
pub struct DeliveryWatch(Arc<Cell>);

impl DeliveryWatch {
    /// The immutable admitted identity of this answer.
    pub fn key(&self) -> ResponseKey {
        self.0.key
    }

    /// The facts as the root's settlement reads them today: whether a body byte was accepted, and the
    /// terminal once the verdict is final (`whole` is Complete; `part` and `none` are Failed).
    pub fn snapshot(&self) -> DeliverySnapshot {
        lock(&self.0.state).snapshot
    }

    /// THE DELIVERY RECORD, once the verdict is final: `whole` / `part` / `none`, the reason, the body
    /// bytes. `None` while a byte of the answer can still be written.
    pub fn record(&self) -> Option<DeliveryRecord> {
        lock(&self.0.state).record
    }

    /// The root's finalizer stated that this answer's record is in.
    pub fn published(&self) -> bool {
        lock(&self.0.state).published
    }

    /// The owner's stop request, as it was asked (before the connection has settled the answer).
    pub fn cancellation(&self) -> Option<ResponseStop> {
        lock(&self.0.state).cancel
    }

    /// Await the one frozen verdict; cancelling this waiter changes no delivery fact.
    pub async fn terminal(&self) -> DeliverySnapshot {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let snapshot = self.snapshot();
            if snapshot.terminal.is_some() {
                return snapshot;
            }
            changed.await;
        }
    }
}

/// The admission-bound stop request. It asks the connection to stop the answer (`emit(E_RESET)`); it
/// never makes a verdict: that is still what the socket took.
#[derive(Clone)]
pub struct DeliveryCancel(Arc<Cell>);

impl DeliveryCancel {
    /// Ask once; the first reason wins. Nothing after the verdict is final.
    pub fn cancel(&self, reason: ResponseStop) {
        let mut state = lock(&self.0.state);
        if state.snapshot.terminal.is_none() {
            state.cancel.get_or_insert(reason);
        }
        drop(state);
        self.0.owner_wake.wake();
    }
}

/// What the root's own producer and reader observed. Recorded beside the verdict; none of them is
/// delivery, and none of them can make an answer `whole`: only the socket's progress does.
#[derive(Clone)]
pub struct DeliveryInput(Arc<Cell>);

impl DeliveryInput {
    /// The owner gave the connection its last piece.
    pub fn producer_ended(&self) {
        lock(&self.0.state).producer_ended = true;
    }

    /// The answer's reader observed its end.
    pub fn reader_eof(&self) {
        lock(&self.0.state).reader_eof = true;
    }

    /// The answer's producer and reader were stopped and joined; not a successful end.
    pub fn retired(&self) {
        lock(&self.0.state).input_retired = true;
    }

    /// What was observed so far: (producer ended, reader saw its end, input retired).
    pub fn observed(&self) -> (bool, bool, bool) {
        let state = lock(&self.0.state);
        (state.producer_ended, state.reader_eof, state.input_retired)
    }
}

/// The root's confirmed-intent finalizer binds its final publication ordinal here and states when the
/// record is in. THE HOLD IS THE ENGINE'S: publishing releases nothing in the connection, because the
/// connection holds nothing: the owner withholds the completing piece itself until this returns.
pub struct ReleasePublisher(Arc<Cell>);

impl ReleasePublisher {
    /// Bind the immutable final publication ordinal before starting intent confirmation.
    pub fn freeze(&self, key: ResponseKey, ordinal: u64) -> Result<(), ResponseStop> {
        let mut state = lock(&self.0.state);
        if key != self.0.key || ordinal == 0 || state.snapshot.terminal.is_some() {
            return Err(ResponseStop::Integrity);
        }
        match state.ordinal {
            Some(old) if old != ordinal => Err(ResponseStop::Integrity),
            _ => {
                state.ordinal = Some(ordinal);
                Ok(())
            }
        }
    }

    /// State that the record of exactly this ordinal is in.
    pub fn publish(&self, key: ResponseKey, ordinal: u64) -> Result<(), ResponseStop> {
        let mut state = lock(&self.0.state);
        if key != self.0.key || state.ordinal != Some(ordinal) {
            return Err(ResponseStop::Integrity);
        }
        if let Some(reason) = state.cancel {
            return Err(reason);
        }
        if state.snapshot.terminal.is_some() {
            return Err(ResponseStop::Integrity);
        }
        state.published = true;
        Ok(())
    }
}

/// Separately scoped handles installed before exposing the admitted request.
pub struct ResponseHandles {
    /// Read-only: the verdict and its record; clones keep the cell alive until dropped.
    pub watch: DeliveryWatch,
    /// Only the root's intent finalizer receives this.
    pub release: ReleasePublisher,
    /// A request to stop the answer.
    pub cancel: DeliveryCancel,
    /// Only the root's producer and reader observers publish these.
    pub input: DeliveryInput,
}

/// What an owner asks of the connection, taken before feeds and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryControl {
    /// Stop the answer on `stream` for `reason`.
    Cancel { stream: u64, reason: ResponseStop },
}

/// The reason a stopped answer's record carries, from the owner's stop request.
const fn reason_of(stop: ResponseStop) -> Reason {
    match stop {
        ResponseStop::Deadline => Reason::Deadline,
        ResponseStop::Protocol => Reason::Protocol,
        ResponseStop::Carrier(_) | ResponseStop::CarrierRetired => Reason::CallerGone,
        // The owner's own stops (cancelled, an integrity or capacity refusal of the engine's): the
        // transport did nothing wrong, so the word is never `transport_fault`.
        ResponseStop::Cancelled | ResponseStop::Integrity | ResponseStop::Capacity => {
            Reason::Cancelled
        }
    }
}

/// One stream the transport announced whose verdict has not been read yet.
struct Answer {
    /// The transport's stream (1 after the hand-over of an upgrade).
    on: u64,
    /// Its owner, once the request is admitted.
    cell: Option<Arc<Cell>>,
    /// A dialled session's stream (`STREAM_OPENED`): it never has an owner here.
    opened: bool,
    /// The transport sent the stream's end mark.
    ended: bool,
    /// The engine cut the owner's answer short itself (its feed went away): how much of it the socket
    /// had taken then.
    cut: Option<Sent>,
    /// `emit(E_RESET)` went at this time: the transport owes the stream's end mark.
    reset_at: Option<Instant>,
    /// The owner was told a body byte of the answer is out.
    body_told: bool,
}

/// THE ACCEPTED CONNECTION'S OUTPUT, DRIVEN: the delivery driver in the answering role, the
/// connection's counts of the bytes the transport made, and each answer's owner. It holds no byte of
/// an answer: those stay in the session's own charged buffer until the connection took them.
///
/// It moves whole across the hand-over of an UPGRADE, counters and all ([`Self::adopt`]). However it
/// goes, every answer still open has its verdict frozen as the socket's progress stands and handed to
/// its owner, which then holds only that small value.
pub struct DeliveryLedger {
    wire: Wire,
    /// Bytes of the placed runs the connection has ever taken.
    written: u64,
    /// Bytes ever placed for the connection: every checked run, byte for byte (an accepted
    /// connection has no layer below its session here; its TLS is beneath the writer it is given).
    queued: u64,
    /// A write failed: the rest of its run is not given, and nothing more is placed.
    lost: bool,
    answers: Vec<Answer>,
    /// CREDIT OWED to the transport, one entry a stream: (stream, bytes). Two things put a credit
    /// here and nothing else does: a stream that is over still held or owed bytes ([`Wire::over`]),
    /// and the transport handed up body of a stream the engine has left ([`Outcome::left`], every
    /// byte owed at once). The session gives each as `emit(stream, E_CONSUMED)` and it is taken
    /// from here as it is given: no credit is given twice.
    owed: Vec<(u64, u64)>,
    wake: Option<Arc<AtomicWaker>>,
    last_stream: u64,
    identity: Option<(u64, u64, u64)>,
    retired: bool,
}

impl fmt::Debug for DeliveryLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryLedger")
            .field("answers", &self.answers.len())
            .field("queued", &self.queued)
            .field("written", &self.written)
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

/// An empty ledger: no array, no cell, nothing allocated.
impl Default for DeliveryLedger {
    fn default() -> Self {
        Self {
            wire: Wire::new(Role::Answer),
            written: 0,
            queued: 0,
            lost: false,
            answers: Vec::new(),
            owed: Vec::new(),
            wake: None,
            last_stream: 0,
            identity: None,
            retired: false,
        }
    }
}

/// The connection's task ended, however it ended: nothing can be written any more, so every answer
/// still open has its verdict now.
impl Drop for DeliveryLedger {
    fn drop(&mut self) {
        self.gone(Reason::CallerGone);
    }
}

impl DeliveryLedger {
    fn at(&self, stream: u64) -> Option<usize> {
        self.answers.iter().position(|answer| answer.on == stream)
    }

    /// The transport announced `stream` (`STREAM_HEAD`): its delivery entry is made now, before the
    /// request is admitted, so an end mark that arrives first is valid and is remembered.
    ///
    /// # Errors
    /// L2 for stream 0 or a stream already open.
    pub(crate) fn announced(&mut self, stream: u64) -> Result<(), Fault> {
        self.wire.announced(stream)?;
        self.answers.push(Answer {
            on: stream,
            cell: None,
            opened: false,
            ended: false,
            cut: None,
            reset_at: None,
            body_told: false,
        });
        Ok(())
    }

    /// `count` bytes of credit are owed to the transport for `stream`: one entry a stream.
    fn owe(&mut self, stream: u64, count: u64) {
        if count == 0 {
            return;
        }
        match self.owed.iter_mut().find(|(owed, _)| *owed == stream) {
            Some((_, owed)) => *owed = owed.saturating_add(count),
            None => self.owed.push((stream, count)),
        }
    }

    /// Make the answer's cell before its request is exposed. Ids are never reused. For a ledger no
    /// session drives yet: a stream nobody announced is entered here.
    pub fn admit(&mut self, key: ResponseKey) -> Result<ResponseHandles, ResponseStop> {
        self.admit_on(key, false)
    }

    /// As [`Self::admit`], on a driven connection: the request must be one the transport announced
    /// and nobody answers yet. An answer on a stream the transport never opened is refused.
    pub(crate) fn admit_announced(
        &mut self,
        key: ResponseKey,
    ) -> Result<ResponseHandles, ResponseStop> {
        self.admit_on(key, true)
    }

    fn admit_on(
        &mut self,
        key: ResponseKey,
        announced_only: bool,
    ) -> Result<ResponseHandles, ResponseStop> {
        let identity = (key.node, key.incarnation, key.connection_generation);
        if self.retired
            || key.stream <= self.last_stream
            || key.connection_generation == 0
            || self.identity.is_some_and(|old| old != identity)
        {
            return Err(ResponseStop::Integrity);
        }
        let at = match self.at(key.stream) {
            Some(at) if self.answers[at].cell.is_none() && !self.answers[at].opened => at,
            Some(_) => return Err(ResponseStop::Integrity),
            None if announced_only => return Err(ResponseStop::Integrity),
            None => {
                self.announced(key.stream)
                    .map_err(|_| ResponseStop::Integrity)?;
                self.answers.len() - 1
            }
        };
        // The owner's wake cell is made with the first answer: before it no cell can ask anything.
        let owner_wake = Arc::clone(
            self.wake
                .get_or_insert_with(|| Arc::new(AtomicWaker::new())),
        );
        let cell = Arc::new(Cell {
            key,
            state: Mutex::new(State {
                snapshot: DeliverySnapshot {
                    first_payload_written: false,
                    terminal: None,
                },
                record: None,
                ordinal: None,
                published: false,
                cancel: None,
                cancel_taken: false,
                producer_ended: false,
                reader_eof: false,
                input_retired: false,
            }),
            changed: tokio::sync::Notify::new(),
            owner_wake,
        });
        self.last_stream = key.stream;
        self.identity = Some(identity);
        self.answers[at].cell = Some(Arc::clone(&cell));
        // A stream that ended before its request was admitted (the caller reset it at once) has its
        // verdict already: admission finds it ended. Streams below this one can no longer be
        // admitted: theirs are let go.
        self.settle();
        Ok(ResponseHandles {
            watch: DeliveryWatch(Arc::clone(&cell)),
            release: ReleasePublisher(Arc::clone(&cell)),
            cancel: DeliveryCancel(Arc::clone(&cell)),
            input: DeliveryInput(cell),
        })
    }

    /// Hand-over on UPGRADE: the upgraded request's answer becomes stream 1 of the adopting session.
    /// The connection's counters are not reset and the owner keeps its handles.
    pub fn adopt(&mut self, stream: u64) {
        self.wire.adopt(stream);
        if let Some(at) = self.at(stream) {
            self.answers[at].on = 1;
        }
    }

    /// Register before checking the cells, so a concurrent request wakes the connection's task. With
    /// no answer admitted yet there is no cell to ask, so nothing to register with.
    pub(crate) fn register_control_waker(&self, waker: &Waker) {
        if let Some(wake) = &self.wake {
            wake.register(waker);
        }
    }

    /// Park the connection's one task without losing a concurrent stop request.
    pub(crate) fn poll_control(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryControl> {
        self.register_control_waker(cx.waker());
        self.next_control().map_or(Poll::Pending, Poll::Ready)
    }

    /// One stop request not yet acted on.
    pub(crate) fn next_control(&mut self) -> Option<DeliveryControl> {
        for answer in &self.answers {
            let Some(cell) = &answer.cell else {
                continue;
            };
            let mut state = lock(&cell.state);
            if let Some(reason) = state.cancel {
                if !state.cancel_taken && state.snapshot.terminal.is_none() {
                    state.cancel_taken = true;
                    return Some(DeliveryControl::Cancel {
                        stream: answer.on,
                        reason,
                    });
                }
            }
        }
        None
    }

    /// Whether an admitted answer's verdict is still open.
    pub(crate) fn has_responses(&self) -> bool {
        self.answers.iter().any(|answer| answer.cell.is_some())
    }

    /// Whether the engine may still emit a piece on `stream`: the transport announced (or opened) it,
    /// has not ended it, and the engine has not reset it.
    pub(crate) fn takes_pieces(&self, stream: u64) -> bool {
        self.at(stream).is_some_and(|at| {
            let answer = &self.answers[at];
            !answer.ended && answer.reset_at.is_none()
        })
    }

    /// The engine is about to `emit` `piece` on `stream` (`len` = the bytes of an `E_BODY`): the
    /// driver learns what the engine asked, which is what L5 and L6 are judged against.
    pub(crate) fn emitting(&mut self, stream: u64, piece: u32, len: u64) {
        match piece {
            abi::E_BODY => self.wire.emitting_body(stream, len),
            abi::E_END => self.wire.emitting_end(stream),
            abi::E_REFUSE => self.wire.emitting_refuse(stream),
            abi::E_RESET => self.wire.stopping(stream, Reason::Cancelled),
            _ => {}
        }
    }

    /// The owner asked to stop the answer on `stream`. `true` = the engine emits `E_RESET` now (the
    /// transport then owes the stream's end mark); `false` = the transport already ended the stream,
    /// or was already told: nothing is emitted on it again.
    pub(crate) fn stop(&mut self, stream: u64, reason: ResponseStop, now: Instant) -> bool {
        let Some(at) = self.at(stream) else {
            return false;
        };
        self.wire.stopping(stream, reason_of(reason));
        let answer = &mut self.answers[at];
        if answer.ended || answer.reset_at.is_some() {
            return false;
        }
        answer.reset_at = Some(now);
        true
    }

    /// The engine reset `stream` itself at its stall deadline (`emit(E_RESET, RESET_STALLED)`).
    pub(crate) fn stalled(&mut self, stream: u64, now: Instant) {
        self.wire.stopping(stream, Reason::Deadline);
        if let Some(at) = self.at(stream) {
            let answer = &mut self.answers[at];
            if !answer.ended {
                answer.reset_at.get_or_insert(now);
            }
        }
    }

    /// The caller reset `stream` (`STREAM_RESET`): whatever of its answer is not out is not whole, and
    /// the reason is the caller's.
    pub(crate) fn caller_reset(&mut self, stream: u64) {
        self.wire.stopping(stream, Reason::CallerGone);
    }

    /// The engine is ending the owner's answer itself with its own refusal (the answer's feed went
    /// away before its end). What the transport then completes is the engine's refusal, not the
    /// owner's answer: the answer's record is what stood when it was cut, never `whole`.
    pub(crate) fn cut(&mut self, stream: u64) {
        if let Some(at) = self.at(stream) {
            let stood = self.wire.state_of(stream);
            self.answers[at].cut.get_or_insert(stood);
        }
    }

    /// The soonest time a stream the engine reset is overdue: the transport has `limit` to end it.
    pub(crate) fn next_overdue(&self, limit: Duration) -> Option<Instant> {
        self.answers
            .iter()
            .filter(|answer| !answer.ended)
            .filter_map(|answer| answer.reset_at)
            .min()
            .map(|at| at + limit)
    }

    /// Whether a stream the engine reset `limit` ago still has no end mark: the engine then closes the
    /// connection, which is the one way left to make its verdict final.
    pub(crate) fn overdue(&self, now: Instant, limit: Duration) -> bool {
        self.next_overdue(limit).is_some_and(|due| due <= now)
    }

    /// ONE ANSWER of the transport, as the driver reads it: checked whole, then its parts placed for
    /// the connection as one run, after every run before it. `tail(i)` = the bytes of the
    /// `WIRE_PART` at index `i`, where the session holds them. Nothing is copied: the caller gives
    /// the connection [`Self::give`] of the returned [`Checked`] from those same bytes, in order,
    /// before it answers again, and keeps them (charged) until the connection took them.
    ///
    /// # Errors
    /// The [`Fault`]: nothing of the answer was placed. The caller ends the session and calls
    /// [`Self::faulted`] (or [`Self::gone`] for [`Fault::Queue`]). [`Fault::Queue`] also when the
    /// run before was not all given: a run placed after bytes that never went out would stand at
    /// the wrong place.
    pub(crate) fn answer<'a>(
        &mut self,
        items: &[Out],
        tail: impl Fn(usize) -> &'a [u8],
    ) -> Result<Checked, Fault> {
        if self.retired || self.lost || self.written != self.queued {
            return Err(Fault::Queue);
        }
        let mut checked = self.wire.check(items, tail, self.queued)?;
        self.queued += checked.bytes();
        let outcome = &mut checked.outcome;
        for item in items {
            if let Out::End(end) = *item {
                if let Some(at) = self.at(end.stream) {
                    self.answers[at].ended = true;
                }
            }
        }
        // ONE MECHANISM, BOTH ROLES: the answer carried body of streams the engine has left (the
        // caller's upload for an answer that was reset, refused or already complete). Nobody will
        // hold those bytes against a window, and a session that multiplexes reopens a window by
        // the engine's credit alone: every such byte is owed now, exactly as the dial gives it
        // (`native_dial` `credit_left`). The entries are TAKEN from the outcome into the one list
        // the session gives credit from, so the outcome's reader finds none and cannot give them a
        // second time.
        for (stream, count) in outcome.left.drain(..) {
            self.owe(stream, count);
        }
        if let Some(stream) = outcome.opened {
            self.answers.push(Answer {
                on: stream,
                cell: None,
                opened: true,
                ended: false,
                cut: None,
                reset_at: None,
                body_told: false,
            });
        }
        // An end mark whose bytes were all out already is final now.
        self.settle();
        Ok(checked)
    }

    /// The bytes of a [`Checked`] answer to give the connection, in order, read where the session
    /// holds them (`tail`, the same as given to [`Self::answer`]): no byte is copied. The writer
    /// counts each write the connection took into the returned [`Giving`] as it goes, so the count
    /// stands however the write ends.
    pub(crate) fn give<'s, 'a: 's>(
        &'s mut self,
        checked: &Checked,
        tail: impl Fn(usize) -> &'a [u8],
    ) -> Giving<'s> {
        Giving {
            pieces: self.wire.written(checked, tail),
            written: &mut self.written,
            queued: self.queued,
        }
    }

    /// A write to the connection failed (or ran out of time): the rest of its run is not given, and
    /// nothing more is placed. The session wipes its buffer; the verdicts come with
    /// [`Self::retire`].
    pub(crate) fn discard(&mut self) {
        self.lost = true;
    }

    /// The flush after the last write succeeded, and `progress` is what the connection's own carrier
    /// then reports: the driver learns how far the operating system accepted the placed runs, as whole
    /// encrypted records under TLS. Answers whose bytes are all out get their verdicts.
    ///
    /// # Errors
    /// The carrier's own sticky fault, or a reading that is not this connection's (it claims more than
    /// was ever written): nothing is counted, and the caller fails the connection.
    pub(crate) fn flushed(&mut self, progress: CarrierProgress) -> Result<(), ResponseStop> {
        if let Some(fault) = progress.fault {
            return Err(ResponseStop::Carrier(fault));
        }
        if progress.accepted_plaintext > self.queued
            || progress.complete_records_plaintext > progress.accepted_plaintext
        {
            return Err(ResponseStop::Integrity);
        }
        self.wire.accepted(progress.complete_records_plaintext);
        // A body byte of an answer is out (the delivery ledger knows where each answer's first one
        // stands): its owner may read that fact before the verdict. `whole` is told by the verdict
        // itself, which knows whether the answer had a body.
        for answer in &mut self.answers {
            if answer.body_told || self.wire.state_of(answer.on) != Sent::Part {
                continue;
            }
            answer.body_told = true;
            if let Some(cell) = &answer.cell {
                lock(&cell.state).snapshot.first_payload_written = true;
            }
        }
        self.settle();
        Ok(())
    }

    /// The shutdown an `END_SHUTDOWN` (or a graceful `CLOSE`) asked for succeeded.
    pub(crate) fn shut_down(&mut self) {
        self.wire.shut_down();
        self.settle();
    }

    /// The reader of `stream` took `len` inbound body bytes. `Some(n)` = `emit(stream, E_CONSUMED)`
    /// with `n` in `credit` (a session that multiplexes reopens a window by nothing else).
    pub(crate) fn taken(&mut self, stream: u64, len: u64) -> Option<u64> {
        self.wire.taken(stream, len)
    }

    /// Whether the engine reads the connection now, by what the session stated.
    pub(crate) fn reads_socket(&self) -> bool {
        self.wire.reads_socket()
    }

    /// Credit owed for a stream that is over, to give the transport: (stream, bytes).
    pub(crate) fn take_owed(&mut self) -> Option<(u64, u64)> {
        self.owed.pop()
    }

    /// How much of `stream`'s answer the operating system accepted, as it stands.
    pub(crate) fn state_of(&self, stream: u64) -> Sent {
        self.wire.state_of(stream)
    }

    /// The connection is gone (failed, closed, dropped): every answer still open has its verdict
    /// frozen as the socket's progress stands and handed to its owner; nothing is held after it.
    pub(crate) fn gone(&mut self, reason: Reason) {
        if self.retired {
            return;
        }
        self.retired = true;
        self.wire.gone(reason);
        self.settle();
        self.owed.clear();
    }

    /// The connection's writer is gone and `last` is its carrier's final reading: as [`Self::gone`].
    /// A write that failed part-way is not a flush, so nothing becomes `whole` by this reading; it
    /// only tells an answer whose first body byte did leave (`part`) from one of which none did.
    pub(crate) fn retire(&mut self, last: CarrierProgress, reason: Reason) {
        // A write that failed may have put bytes on the carrier that the writer never reported back.
        let sound = last.accepted_plaintext <= self.queued
            && last.complete_records_plaintext <= last.accepted_plaintext;
        if sound && !self.retired {
            // The delivery ledger's own second count: it tells `part` from `none` per answer, by
            // where each answer's first body byte stands, and makes nothing `whole`.
            self.wire.reached(last.complete_records_plaintext);
        }
        self.gone(reason);
    }

    /// The transport broke a rule of its output: as [`Self::gone`], every open answer recorded
    /// `transport_fault`.
    pub(crate) fn faulted(&mut self) {
        if self.retired {
            return;
        }
        self.retired = true;
        self.wire.faulted();
        self.settle();
        self.owed.clear();
    }

    /// Hand every final verdict to its owner and release its entry. An announced stream nobody was
    /// admitted for is kept only while its request can still be admitted.
    fn settle(&mut self) {
        let mut at = 0;
        while at < self.answers.len() {
            let answer = &self.answers[at];
            let waits_for_admission = answer.cell.is_none()
                && !answer.opened
                && answer.on > self.last_stream
                && !self.retired;
            if waits_for_admission {
                at += 1;
                continue;
            }
            let on = answer.on;
            let Some(verdict) = self.wire.take_verdict(on) else {
                at += 1;
                continue;
            };
            let answer = self.answers.swap_remove(at);
            let (_, credit) = self.wire.over(on, false);
            if let Some(count) = credit {
                self.owe(on, count);
            }
            if let Some(cell) = answer.cell {
                freeze(&cell, verdict, answer.cut);
            }
        }
    }
}

/// One checked answer being given to the connection ([`DeliveryLedger::give`]): its pieces, borrowed
/// from the session's charged buffer (and a sealed value's slot), and the ledger's count of what the
/// connection took, kept as each write returns.
pub(crate) struct Giving<'s> {
    /// The run's bytes, in order.
    pub(crate) pieces: smallvec::SmallVec<[&'s [u8]; 16]>,
    written: &'s mut u64,
    queued: u64,
}

impl Giving<'_> {
    /// The connection took `count` more bytes of the run (never counted past what was placed).
    pub(crate) fn took(&mut self, count: usize) {
        *self.written = self.written.saturating_add(count as u64).min(self.queued);
    }
}

/// The verdict is final: the owner's cell is frozen with it, once.
fn freeze(cell: &Cell, verdict: Verdict, cut: Option<Sent>) {
    let mut state = lock(&cell.state);
    if state.snapshot.terminal.is_some() {
        return;
    }
    let verdict = match cut {
        Some(stood) if verdict.state == Sent::Whole => Verdict {
            state: stood,
            reason: Some(Reason::Cancelled),
            body_bytes: verdict.body_bytes,
        },
        _ => verdict,
    };
    let mut snapshot = verdict.snapshot();
    // What the owner was already told stays told.
    snapshot.first_payload_written |= state.snapshot.first_payload_written;
    // The owner's own stop keeps the word the owner gave it (its settlement matches on it).
    if let (Some(DeliveryTerminal::Failed(_)), Some(asked)) = (snapshot.terminal, state.cancel) {
        snapshot.terminal = Some(DeliveryTerminal::Failed(asked));
    }
    state.snapshot = snapshot;
    state.record = Some(DeliveryRecord::of(verdict));
    drop(state);
    cell.changed.notify_waiters();
}
