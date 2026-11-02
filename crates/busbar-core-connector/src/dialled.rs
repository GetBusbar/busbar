// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM LEG OF A HELD SESSION: the connection

use std::future::Future as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use busbar_contract::conn::{ConnError, Piece, PieceKind};
use busbar_contract::ids::StreamId;

use crate::datagram::{
    Across, DatagramFraming, Leg, LegSink, LineStep, Pairing, SessionBatch, SubmitError,
};
use crate::framer::{Refused, Yielded};
use crate::publication::{Custody, Message};
use crate::udp::{ReadyPort, MAX_DATAGRAM};

#[cfg(test)]
thread_local! {
    static AFTER_WRITE_TAKE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn after_next_write_take(hook: impl FnOnce() + 'static) {
    AFTER_WRITE_TAKE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// The most datagrams one drive reads before it yields.
const READS_PER_DRIVE: usize = 256;
/// The channel messages a leg holds for a reader that has not read them, at which it stops

const MAX_READY: usize = 1024;
/// The most bytes of the far end's description the open buffers before its end.
const MAX_DESCRIPTION: usize = 64 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Take the next channel message a reader has not read into `buf`: how many bytes, and whether

pub(crate) fn take_ready(ready: &Mutex<Messages>, buf: &mut [u8]) -> Option<(usize, bool)> {
    let mut queue = lock(ready);
    let message = &mut queue.first.as_mut()?.message;
    let transfer = message.custody.copying();
    #[cfg(test)]
    tests::after_ready_pop();
    let n = (message.bytes.len() - message.consumed).min(buf.len());
    buf[..n].copy_from_slice(&message.bytes[message.consumed..message.consumed + n]);
    message.consumed += n;
    let complete = message.consumed == message.bytes.len();
    let end = message.end && complete;
    let retired = if complete { queue.pop_front() } else { None };
    drop(queue);

    drop(retired);
    drop(transfer);
    Some((n, end))
}

/// Each node is covered by its message's batch reservation. Popping frees node storage too;
/// no spare container allocation survives after its last reservation has been retired.
#[derive(Default)]
pub(crate) struct Messages {
    first: Option<Box<MessageNode>>,
    len: usize,
}

struct MessageNode {
    message: Message,
    next: Option<Box<MessageNode>>,
}

impl Messages {
    fn push_back(&mut self, message: Message) {
        let mut tail = &mut self.first;
        while let Some(node) = tail {
            tail = &mut node.next;
        }
        *tail = Some(Box::new(MessageNode {
            message,
            next: None,
        }));
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<Message> {
        let node = self.first.take()?;
        let MessageNode { message, next } = *node;
        self.first = next;
        self.len -= 1;
        Some(message)
    }

    fn len(&self) -> usize {
        self.len
    }
    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Messages {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

/// Where the composed open stands.
#[derive(Debug)]
enum Phase {
    /// The exchange is in flight: `ok` once its head said whether it succeeded; the body so far.
    Exchanging { ok: Option<bool>, answer: Vec<u8> },
    /// The completed description is crossing the framer; readers wait for its result.
    Settling(Option<Waker>),
    /// The far end answered and the leg is attached: reads are its channel messages.
    Running,
    /// A consumed drive failure remains the reader's answer.
    Failed(ConnError),
    /// The leg is over.
    Over,
}

/// Where the leg's association is. IT IS CROSSED WITH NO LOCK HELD (`BUSBAR-1.6.0.md` §11: no
/// plugin code runs under a host lock): a drive, a write or a line frame takes the association out,
/// crosses its framer with nothing held, and puts it back. One that finds it out does not wait: a
/// drive is woken when it is back, a write answers PENDING (re-offered after the next read or
/// wait), and a LINE producer waits in the pairing actor. A close never waits:
/// an association at home is taken and finished with no lock held; one that is out is finished by
/// its holder as it brings it back.
#[derive(Default)]
struct Held {
    /// The association while nobody has it out; `None` while one does, and once it is closed.
    framing: Option<DatagramFraming>,
    /// A drive, write or line frame has it out.
    out: bool,
    /// The leg is closed: the association is finished, or will be as it is brought back.
    closing: bool,
    /// The keying-material item had been presented when it was last at home.
    presented: bool,
    /// The drives that found it out, woken when it is back.
    missed: Option<Waker>,
    /// An ordinary read owes another drive once exclusive and continuation custody return.
    drive_waiting: bool,
    /// A completed producer batch must reach the FIFO before another ordinary crossing.
    publishing: bool,
    /// Latest interest in this held connection's channel output, as with the line's per-stream
    /// registration and the port's read direction. Re-polling replaces the previous context.
    reader: Option<Waker>,
}

/// An association out of its slot. Only an unwind drops it still holding the association: the

struct Taken<'l> {
    leg: &'l UpstreamLeg,
    framing: Option<DatagramFraming>,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.framing.take() {
            let waiting = {
                let mut held = lock(&self.leg.framing);
                held.closing = true;
                held.out = false;
                (held.missed.take(), held.reader.take())
            };
            drop(f);
            wake(waiting.0.into_iter().chain(waiting.1));
        }
    }
}

/// The upstream association and its own port: the [`LegSink`] the caller's line frames cross into.
pub(crate) struct UpstreamLeg {
    framing: Mutex<Held>,
    /// The pairing owns its attached leg; the return route must not own the pairing back.
    pairing: Weak<Pairing>,
    port: ReadyPort,
    /// Channel messages for the reader: the bytes and whether they end the message.
    ready: Mutex<Messages>,
    /// The channel stream a write goes to: the first channel the leg named.
    channel: Mutex<Option<u64>>,
    /// The read buffer one drive reads datagrams into.
    recv: Mutex<Vec<u8>>,
    timer: Mutex<Option<Pin<Box<tokio::time::Sleep>>>>,
}

impl UpstreamLeg {
    /// THE HAND-OFF: take the association out, `run` it on `arg` with no lock held, and bring it

    fn turn<A, R>(
        &self,
        arg: A,
        out: impl FnOnce(A) -> R,
        closed: impl FnOnce(A) -> R,
        run: impl FnOnce(&mut DatagramFraming, A) -> R,
    ) -> R {
        self.turn_mode(None, arg, out, closed, run)
    }

    fn turn_mode<A, R>(
        &self,
        mut waiter: Option<Waker>,
        arg: A,
        out: impl FnOnce(A) -> R,
        closed: impl FnOnce(A) -> R,
        run: impl FnOnce(&mut DatagramFraming, A) -> R,
    ) -> R {
        let producer = waiter.is_some();
        let f = {
            let mut held = lock(&self.framing);
            if held.closing {
                drop(held);
                return closed(arg);
            }
            if held.publishing
                || (!producer
                    && held
                        .framing
                        .as_ref()
                        .is_some_and(DatagramFraming::continuing))
            {
                held.drive_waiting |= !producer;
                let displaced = waiter.take().and_then(|waiter| held.missed.replace(waiter));
                drop(held);
                drop(displaced);
                return out(arg);
            }
            match held.framing.take() {
                Some(f) => {
                    held.out = true;
                    f
                }
                None if held.out => {
                    if !producer {
                        held.drive_waiting = true;
                    }
                    let displaced = waiter.take().and_then(|waiter| held.missed.replace(waiter));
                    drop(held);
                    drop(displaced);
                    return out(arg);
                }
                None => {
                    drop(held);
                    return closed(arg);
                }
            }
        };
        let mut taken = Taken {
            leg: self,
            framing: Some(f),
        };
        let r = run(taken.framing.as_mut().expect("the association is out"), arg);
        self.bring_back(&mut taken);
        r
    }

    /// Return exclusive association custody before the actor publishes or recalls its output.
    fn bring_back(&self, taken: &mut Taken<'_>) {
        let mut held = lock(&self.framing);
        held.out = false;
        let missed = held.missed.take();
        let reader = if held.drive_waiting
            && !held.publishing
            && taken.framing.as_ref().is_none_or(|f| !f.continuing())
        {
            held.drive_waiting = false;
            held.reader.take()
        } else {
            None
        };
        if held.closing {
            drop(held);
            drop(taken.framing.take());
        } else {
            let f = taken.framing.take().expect("the association is out");
            held.presented = f.presented();
            held.framing = Some(f);
            drop(held);
        }
        wake(missed.into_iter().chain(reader));
    }

    /// Register this connection's latest read context before checking the ready queue, matching

    fn wait_ready(&self, waker: &Waker) {
        let incoming = waker.clone();
        let displaced = {
            let mut held = lock(&self.framing);
            if held.closing || held.reader.as_ref().is_some_and(|w| w.will_wake(&incoming)) {
                Some(incoming)
            } else {
                held.reader.replace(incoming)
            }
        };

        drop(displaced);
    }

    /// Whether the association has presented its keying-material item (`false` once closed).
    fn presented(&self) -> bool {
        let held = lock(&self.framing);
        !held.closing
            && held
                .framing
                .as_ref()
                .map_or(held.out && held.presented, DatagramFraming::presented)
    }

    /// Send what the association owes the port; a send that would block drops the datagram.
    fn flush(&self, f: &mut DatagramFraming) {
        while let Some((to, d)) = f.poll_send() {
            let _ = self.port.send_to(&d, to);
        }
    }

    /// Take what the leg's association yielded through the pairing: line frames go across, the

    fn take(
        &self,
        pairing: &Arc<Pairing>,
        yielded: Yielded,
        now: Instant,
    ) -> Result<(), ConnError> {
        let batch = pairing.publish(Leg::Upstream, yielded, now);
        self.channels(batch, now).map_err(|_| ConnError::Fault)
    }

    fn take_channels(&self, batch: SessionBatch) -> Result<(), ConnError> {
        let SessionBatch {
            pieces,
            custody,
            owners,
            producer,
        } = batch;
        let activity = custody.publishing();
        let _publication = ChannelPublication {
            leg: self,
            producer: Some(producer),
            custody: Some(custody),
            activity: Some(activity),
        };
        let fallback = _publication
            .custody
            .as_ref()
            .expect("publication owns its container")
            .clone();
        let mut owners = owners.into_iter();
        if lock(&self.framing).closing {
            drop(pieces);
            drop(owners);
            drop(fallback);
            return Err(ConnError::Closed);
        }
        let mut queued = false;
        for g in pieces {
            let owner = owners.next().unwrap_or_else(|| fallback.clone());

            let held = lock(&self.framing);
            if held.closing {
                drop(held);
                drop(g);
                drop(owner);
                return Err(ConnError::Closed);
            }
            if g.fields {
                lock(&self.channel).get_or_insert(g.stream);
                drop(held);
                drop(g);
                drop(owner);
                continue;
            }
            if g.failed && g.stream != 0 {
                drop(held);
                drop(g);
                drop(owner);
                return Err(ConnError::Fault);
            }
            if g.stream == 0 || g.ends_stream() {
                drop(held);
                drop(g);
                drop(owner);
                continue;
            }
            drop(g.reason);
            lock(&self.ready).push_back(Message {
                bytes: g.bytes,
                end: g.end_of_frame,
                consumed: 0,
                custody: owner.reader_on(Leg::Upstream),
            });
            queued = true;
        }
        drop(owners);
        drop(fallback);
        if queued {
            let waiting = lock(&self.framing).reader.take();
            if let Some(waker) = waiting {
                waker.wake();
            }
        }
        Ok(())
    }

    /// Read every datagram waiting on the port, keep the association's clock, flush, and arm the

    fn drive(
        &self,
        pairing: &Arc<Pairing>,
        cx: &mut Context<'_>,
        due: Option<Instant>,
    ) -> Result<(), ConnError> {
        let now = Instant::now();

        let room = MAX_READY.saturating_sub(lock(&self.ready).len());
        let yielded = self.turn(
            (),
            |()| Ok(None),
            |()| Err(ConnError::Closed),
            |f, ()| {
                let mut buf = std::mem::take(&mut *lock(&self.recv));
                let read = self.read_port(pairing, f, cx, &mut buf, room, now);
                *lock(&self.recv) = buf;
                let mut yielded = read?;
                if yielded.is_none() && f.deadline().is_some_and(|d| d <= now) {
                    let generation = pairing.storage_generation();
                    yielded = match f.timeout_step(now).map_err(|_| ConnError::Fault)? {
                        LineStep::Batch { yielded, .. } => Some(yielded),
                        LineStep::Complete => None,
                        LineStep::Credit => {
                            if !pairing.wait_storage(cx.waker(), generation) {
                                return Err(ConnError::Fault);
                            }
                            None
                        }
                    };
                }
                self.flush(f);
                let wake = [f.deadline(), due.filter(|_| !f.presented())]
                    .into_iter()
                    .flatten()
                    .min();
                let mut timer = lock(&self.timer).take();
                let mut elapsed = false;
                match wake {
                    Some(at) => {
                        let _entered = crate::io::enter_process_runtime();
                        if tokio::runtime::Handle::try_current().is_ok() {
                            let at = tokio::time::Instant::from_std(at);
                            let t =
                                timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
                            t.as_mut().reset(at);
                            elapsed = t.as_mut().poll(cx).is_ready();
                        }
                    }
                    None => timer = None,
                }
                let retired = {
                    let held = lock(&self.framing);
                    if held.closing {
                        timer
                    } else {
                        std::mem::replace(&mut *lock(&self.timer), timer)
                    }
                };
                drop(retired);
                if elapsed {
                    cx.waker().wake_by_ref();
                }
                if yielded.is_some() {
                    let mut held = lock(&self.framing);
                    held.publishing = true;

                    held.drive_waiting = true;
                }
                Ok(yielded)
            },
        )?;
        if let Some(yielded) = yielded {
            self.take(pairing, yielded, now)?;
        }
        Ok(())
    }
}

impl UpstreamLeg {
    /// Read until the first checked batch. Reserve before the port relinquishes a datagram;

    fn read_port(
        &self,
        pairing: &Pairing,
        f: &mut DatagramFraming,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        room: usize,
        now: Instant,
    ) -> Result<Option<Yielded>, ConnError> {
        for _ in 0..READS_PER_DRIVE {
            if room == 0 {
                return Ok(None);
            }
            let generation = pairing.storage_generation();
            if !f.prepare_output() {
                if !pairing.wait_storage(cx.waker(), generation) {
                    return Err(ConnError::Fault);
                }
                return Ok(None);
            }
            match self.port.poll_recv_from(cx, buf) {
                Poll::Ready(Ok((n, from))) => {
                    match f
                        .datagram_step(from, &buf[..n], now)
                        .map_err(|_| ConnError::Fault)?
                    {
                        LineStep::Batch { yielded, .. } => return Ok(Some(yielded)),
                        LineStep::Complete => {}

                        LineStep::Credit => return Err(ConnError::Fault),
                    }
                }

                Poll::Ready(Err(_)) => f.release_output_reservation(),
                Poll::Pending => {
                    f.release_output_reservation();
                    return Ok(None);
                }
            }
        }

        lock(&self.framing).drive_waiting = true;
        Ok(None)
    }
}

/// Wake every drive in `missed`.
fn wake(missed: impl IntoIterator<Item = Waker>) {
    for w in missed {
        w.wake();
    }
}

impl LegSink for UpstreamLeg {
    fn line(&self, across: Across, now: Instant) {
        let _ = now;

        let Some(pairing) = self.pairing.upgrade() else {
            return;
        };
        let custody = match pairing.reserve_input_for(Leg::Upstream, across.bytes.capacity()) {
            Ok(custody) => custody,
            Err(_) => {
                pairing.close();
                return;
            }
        };
        let _ = pairing.submit_owned(Leg::Upstream, across, false, custody);
    }

    fn poll_line(
        &self,
        cx: &mut Context<'_>,
        input: Option<&Across>,
        text: bool,
        now: Instant,
    ) -> Poll<Result<LineStep, Refused>> {
        self.turn_mode(
            Some(cx.waker().clone()),
            (),
            |()| Poll::Pending,
            |()| {
                Poll::Ready(Err(Refused {
                    outcome: busbar_contract::abi::mechanism::call::Outcome::Fault,
                    error: "the upstream association is closed".into(),
                }))
            },
            |f, ()| {
                let result = f.line_step(input, text, now);
                self.flush(f);
                if matches!(result, Ok(LineStep::Batch { .. })) {
                    lock(&self.framing).publishing = true;
                }
                Poll::Ready(result)
            },
        )
    }

    fn pairing(&self) -> Option<Arc<Pairing>> {
        self.pairing.upgrade()
    }

    fn channels(&self, batch: SessionBatch, _: Instant) -> Result<(), String> {
        self.take_channels(batch)
            .map_err(|error| format!("upstream channel publication failed: {error:?}"))
    }

    fn close(&self) {
        let (framing, waiting) = {
            let mut held = lock(&self.framing);
            held.closing = true;
            let waiting = (held.missed.take(), held.reader.take());
            (held.framing.take(), waiting)
        };
        drop(framing);
        let ready = std::mem::take(&mut *lock(&self.ready));
        drop(ready);
        let timer = lock(&self.timer).take();
        drop(timer);
        wake(waiting.0.into_iter().chain(waiting.1));
    }
}

/// A pending batch remains ordered while exclusive framer custody has already returned home.

struct ChannelPublication<'a> {
    leg: &'a UpstreamLeg,
    producer: Option<crate::publication::ProducerCustody>,
    custody: Option<Custody>,
    activity: Option<crate::publication::Transfer>,
}

impl Drop for ChannelPublication<'_> {
    fn drop(&mut self) {
        drop(self.producer.take());
        drop(self.custody.take());
        drop(self.activity.take());
        let (scheduler, reader) = {
            let mut held = lock(&self.leg.framing);
            held.publishing = false;
            let reader = if held.drive_waiting
                && !held.out
                && held.framing.as_ref().is_none_or(|f| !f.continuing())
            {
                held.drive_waiting = false;
                held.reader.take()
            } else {
                None
            };
            (held.missed.take(), reader)
        };
        wake(scheduler.into_iter().chain(reader));
    }
}

#[derive(Default)]
struct Gather {
    bytes: Vec<u8>,
    custody: Custody,
    /// The gathered allocation already reserved its future admission guard too.
    reserved: bool,
    /// A final write owns the message outside this mutex, until it is emitted or restored.
    writing: bool,
}

struct Writing {
    gather: Arc<Mutex<Gather>>,
    leg: Weak<UpstreamLeg>,
    /// Only accepted queued admission wakes a writer; preaccept Pending must not self-wake.
    notify: bool,
}

impl Drop for Writing {
    fn drop(&mut self) {
        let leg = self.leg.upgrade();
        let closed = leg.as_ref().is_none_or(|leg| lock(&leg.framing).closing);
        let discarded = {
            let mut gather = lock(&self.gather);
            gather.writing = false;
            closed.then(|| {
                gather.reserved = false;
                (
                    std::mem::take(&mut gather.bytes),
                    std::mem::take(&mut gather.custody),
                )
            })
        };
        drop(discarded);
        if let Some(leg) = leg.filter(|_| self.notify) {
            let waiting = lock(&leg.framing).reader.take();
            if let Some(waiting) = waiting {
                waiting.wake();
            }
        }
    }
}

/// A held session's upstream leg, as the connection table holds it.
pub(crate) struct Dialled {
    leg: Arc<UpstreamLeg>,
    pairing: Arc<Pairing>,
    phase: Mutex<Phase>,
    /// The composed open's bound: the association must be keyed by then.
    due: Option<Instant>,
    /// A message being written, gathered until its end.
    gather: Arc<Mutex<Gather>>,
}

impl Dialled {
    /// The leg over `framing` (begun, its description sent as the exchange's body) on `port`, for

    pub(crate) fn new(
        mut framing: DatagramFraming,
        port: ReadyPort,
        pairing: Arc<Pairing>,
        due: Option<Instant>,
    ) -> Self {
        framing.memory(pairing.memory_account());
        Dialled {
            leg: Arc::new(UpstreamLeg {
                framing: Mutex::new(Held {
                    framing: Some(framing),
                    ..Held::default()
                }),
                pairing: Arc::downgrade(&pairing),
                port,
                ready: Mutex::new(Messages::default()),
                channel: Mutex::new(None),
                recv: Mutex::new(vec![0_u8; MAX_DATAGRAM]),
                timer: Mutex::new(None),
            }),
            pairing,
            phase: Mutex::new(Phase::Exchanging {
                ok: None,
                answer: Vec::new(),
            }),
            due,
            gather: Arc::new(Mutex::new(Gather::default())),
        }
    }

    /// Whether the exchange is still in flight (its pieces are read off the exchange's line).
    pub(crate) fn exchanging(&self) -> bool {
        matches!(*lock(&self.phase), Phase::Exchanging { .. })
    }

    /// One piece the exchange answered, judged: `Some(piece)` for the reader, `None` when the

    pub(crate) fn exchanged(&self, piece: Piece, bytes: &[u8]) -> Result<Option<Piece>, ConnError> {
        let mut phase = lock(&self.phase);
        let Phase::Exchanging { ok, answer } = &mut *phase else {
            return Ok(Some(piece));
        };
        match (piece.kind, *ok) {
            (PieceKind::Fields, None) => {
                if piece.status.is_some() || piece.end {
                    *ok = Some(
                        piece.status
                            == Some(busbar_contract::transport::wire::WireStatusClass::Success),
                    );
                }
                Ok(Some(piece))
            }

            (_, Some(false)) => {
                if piece.kind == PieceKind::Completion {
                    *phase = Phase::Over;
                    drop(phase);
                    self.pairing.close();
                }
                Ok(Some(piece))
            }
            (PieceKind::Body, Some(true)) => {
                if answer.len().saturating_add(bytes.len()) > MAX_DESCRIPTION {
                    *phase = Phase::Over;
                    drop(phase);
                    self.pairing.close();
                    self.leg.close();
                    return Err(ConnError::Refused);
                }
                answer.extend_from_slice(bytes);
                Ok(None)
            }
            (PieceKind::Completion, Some(true)) => {
                let description = std::mem::take(answer);
                *phase = Phase::Settling(None);
                drop(phase);
                if let Err(error) = self.settle(&description) {
                    return Err(self.fail(error));
                }
                let missed = {
                    let mut phase = lock(&self.phase);
                    match &mut *phase {
                        Phase::Settling(missed) => {
                            let missed = std::mem::take(missed);
                            *phase = Phase::Running;
                            missed
                        }
                        Phase::Failed(error) => return Err(*error),
                        _ => return Err(ConnError::Closed),
                    }
                };
                wake(missed);
                Ok(None)
            }
            _ => Ok(Some(piece)),
        }
    }

    /// The far end's description settles the association; its lines must mirror the caller's.
    fn settle(&self, description: &[u8]) -> Result<(), ConnError> {
        let now = Instant::now();
        let yielded = self.leg.turn(
            (),
            |()| Err(ConnError::Pending),
            |()| Err(ConnError::Closed),
            |f, ()| {
                let y = f
                    .rendezvous(description, now)
                    .map_err(|_| ConnError::Fault)?;
                self.leg.flush(f);
                lock(&self.leg.framing).publishing = true;
                Ok(y)
            },
        )?;

        let admission = (yielded.producer.clone(), yielded.custody.clone());
        self.leg.take(&self.pairing, yielded, now)?;
        let leg: Arc<dyn LegSink> = Arc::clone(&self.leg) as Arc<dyn LegSink>;
        if self.pairing.attach(leg).is_err() {
            self.leg.close();
            self.pairing.close();
            return Err(ConnError::Refused);
        }
        drop(admission);
        Ok(())
    }

    /// A read once the leg runs: the next channel message, or Pending with `waker` woken when the

    pub(crate) fn read(&self, waker: &Waker, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.running(waker)?;
        self.leg.wait_ready(waker);
        let mut cx = Context::from_waker(waker);
        loop {
            if let Some((n, end)) = take_ready(&self.leg.ready, buf) {
                return Ok(Piece {
                    kind: PieceKind::Body,
                    stream: StreamId(0),
                    len: n,
                    end,
                    status: None,
                    status_code: None,
                    status_namespace: None,
                    retry_after_secs: None,
                    fault: None,
                    reason: None,
                    declared_len: None,
                });
            }
            let keyed = self.leg.presented();
            if !keyed && self.due.is_some_and(|d| Instant::now() >= d) {
                return Err(ConnError::Timeout);
            }
            if let Err(e) = self.leg.drive(&self.pairing, &mut cx, self.due) {
                return Err(self.fail(e));
            }
            if lock(&self.leg.ready).is_empty() {
                return Err(ConnError::Pending);
            }
        }
    }

    /// A write once the leg runs: gathered until `end`, then accepted as one bounded queued

    pub(crate) fn write(&self, bytes: &[u8], end: bool, text: bool) -> Result<usize, ConnError> {
        match &*lock(&self.phase) {
            Phase::Running => {}
            Phase::Exchanging { .. } | Phase::Settling(_) => return Err(ConnError::Pending),
            Phase::Failed(error) => return Err(*error),
            Phase::Over => return Err(ConnError::Closed),
        }
        let mut gather = lock(&self.gather);
        if gather.writing {
            return Err(ConnError::Pending);
        }

        if gather.bytes.len().saturating_add(bytes.len()) > crate::compose::WRITE_BUFFER_BYTES {
            let old = std::mem::take(&mut gather.bytes);
            let custody = std::mem::take(&mut gather.custody);
            gather.reserved = false;
            drop(gather);
            self.pairing.cancel_retained_input(old.len());
            drop(old);
            drop(custody);
            return Err(ConnError::Refused);
        }

        let stream = if end {
            Some((*lock(&self.leg.channel)).ok_or(ConnError::Pending)?)
        } else {
            None
        };
        gather.writing = true;
        let prefix = std::mem::take(&mut gather.bytes);
        let old_custody = std::mem::take(&mut gather.custody);
        let reserved = std::mem::take(&mut gather.reserved);
        drop(gather);
        let writing = Writing {
            gather: Arc::clone(&self.gather),
            leg: Arc::downgrade(&self.leg),
            notify: false,
        };

        let total = prefix.len() + bytes.len();
        let preaccepted = prefix.len();
        let reuse = reserved && prefix.capacity() >= total;
        let (mut message, custody) = if reuse {
            (prefix, old_custody)
        } else {
            let requested = total + std::mem::size_of::<Writing>();
            let custody = match self.pairing.reserve_input_for(Leg::Upstream, requested) {
                Ok(custody) => custody,
                Err(error) => {
                    let mut gather = lock(&self.gather);
                    gather.bytes = prefix;
                    gather.custody = old_custody;
                    gather.reserved = reserved;
                    drop(gather);
                    drop(writing);
                    return Err(match error {
                        SubmitError::Pending => ConnError::Pending,
                        SubmitError::Exhausted => self.fail(ConnError::Fault),
                        SubmitError::Closed => ConnError::Closed,
                    });
                }
            };
            let mut message = Vec::with_capacity(total);
            message.extend_from_slice(&prefix);
            drop(prefix);
            drop(old_custody);
            (message, custody)
        };
        message.extend_from_slice(bytes);
        if !end {
            if !self.pairing.retain_input(bytes.len()) {
                self.pairing.cancel_retained_input(preaccepted);
                drop(message);
                drop(custody);
                drop(writing);
                return Err(ConnError::Closed);
            }
            let mut gather = lock(&self.gather);
            gather.bytes = message;
            gather.custody = custody;
            gather.reserved = true;
            drop(gather);
            drop(writing);
            if self.pairing.closed() {
                return Err(ConnError::Closed);
            }
            return Ok(bytes.len());
        }
        #[cfg(test)]
        {
            let hook = AFTER_WRITE_TAKE.with(|slot| slot.borrow_mut().take());
            if let Some(hook) = hook {
                hook();
            }
        }
        let stream = stream.expect("an ending write checked its channel");
        self.leg.turn(
            (message, custody, writing),
            |(mut message, custody, writing)| {
                message.truncate(message.len() - bytes.len());
                let mut gather = lock(&self.gather);
                gather.bytes = message;
                gather.custody = custody;
                gather.reserved = true;
                drop(gather);
                drop(writing);
                Err(ConnError::Pending)
            },
            |_| {
                self.pairing.cancel_retained_input(preaccepted);
                Err(ConnError::Closed)
            },
            |_, (message, custody, mut writing)| {
                writing.notify = true;
                self.pairing
                    .submit_preaccepted_owned(
                        Leg::Upstream,
                        Across {
                            stream,
                            bytes: message,
                            end_of_frame: true,
                        },
                        text,
                        custody,
                        preaccepted,
                        Some(Box::new(writing)),
                    )
                    .map_err(|error| match error {
                        SubmitError::Pending | SubmitError::Exhausted => {
                            self.fail(ConnError::Fault)
                        }
                        SubmitError::Closed => ConnError::Closed,
                    })
            },
        )?;
        Ok(bytes.len())
    }

    /// Whether a read would answer now (a message waits, the keying bound passed, or the leg is over).
    pub(crate) fn ready(&self, waker: &Waker) -> bool {
        match self.running(waker) {
            Err(ConnError::Pending) => return false,
            Err(_) => return true,
            Ok(()) => {}
        }
        if !lock(&self.leg.ready).is_empty() {
            return true;
        }
        self.leg.wait_ready(waker);
        if !lock(&self.leg.ready).is_empty() {
            return true;
        }
        if !self.leg.presented() && self.due.is_some_and(|d| Instant::now() >= d) {
            return true;
        }
        let mut cx = Context::from_waker(waker);
        if let Err(error) = self.leg.drive(&self.pairing, &mut cx, self.due) {
            self.fail(error);
            return true;
        }
        !lock(&self.leg.ready).is_empty()
    }

    /// A settling crossing owns progress; its completion or close wakes every waiting reader.
    fn running(&self, waker: &Waker) -> Result<(), ConnError> {
        if self.pairing.publication_outcome().failure.is_some() {
            return Err(self.fail(ConnError::Fault));
        }
        let incoming = waker.clone();
        let mut phase = lock(&self.phase);
        match &mut *phase {
            Phase::Running => Ok(()),
            Phase::Settling(missed) => {
                let displaced = missed.replace(incoming);
                drop(phase);
                drop(displaced);
                Err(ConnError::Pending)
            }
            Phase::Exchanging { .. } => Err(ConnError::Pending),
            Phase::Failed(error) => Err(*error),
            Phase::Over => Err(ConnError::Closed),
        }
    }

    /// Retain a consumed failure before closing either leg, with no phase lock held at a crossing.
    fn fail(&self, error: ConnError) -> ConnError {
        let (error, missed) = {
            let mut phase = lock(&self.phase);
            match &*phase {
                Phase::Over => return ConnError::Closed,
                Phase::Failed(error) => return *error,
                _ => {}
            }
            let old = std::mem::replace(&mut *phase, Phase::Failed(error));
            let missed = match old {
                Phase::Settling(missed) => missed,
                _ => None,
            };
            (error, missed)
        };
        self.pairing.close();
        self.leg.close();
        self.discard_gather();
        wake(missed);
        error
    }

    /// The session's connection closed: the pairing closes, and with it both legs, once.
    pub(crate) fn close(&self) {
        let missed = match std::mem::replace(&mut *lock(&self.phase), Phase::Over) {
            Phase::Settling(missed) => missed,
            _ => None,
        };
        self.pairing.close();
        self.leg.close();
        self.discard_gather();
        wake(missed);
    }

    fn discard_gather(&self) {
        let discarded = {
            let mut gather = lock(&self.gather);
            gather.reserved = false;
            (
                std::mem::take(&mut gather.bytes),
                std::mem::take(&mut gather.custody),
            )
        };
        self.pairing.cancel_retained_input(discarded.0.len());
        drop(discarded);
    }
}

/// THE EXCHANGE BODY OF A COMPOSED OPEN: what goes

pub(crate) fn composed_body(
    fields: &[(&str, &[u8])],
    body: &[u8],
    description: &[u8],
) -> Result<Vec<u8>, ConnError> {
    if body.is_empty() {
        return Ok(description.to_vec());
    }
    let boundary = fields
        .iter()
        .filter(|(name, _)| !busbar_contract::conn::is_sealed_fields_field(name.as_bytes()))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .and_then(form_boundary)
        .ok_or(ConnError::Refused)?;
    let delimiter = [b"\r\n--", boundary.as_bytes()].concat();
    if description
        .windows(delimiter.len())
        .any(|w| w == delimiter.as_slice())
    {
        return Err(ConnError::Refused);
    }
    Ok([body, description, &delimiter, b"--\r\n"].concat())
}

/// The `boundary` of a `multipart/form-data` content type (RFC 7578, RFC 2046 section 5.1.1),

fn form_boundary(content_type: &str) -> Option<String> {
    let mut params = content_type.split(';');
    if !params
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    let boundary = params.find_map(|p| {
        let (name, value) = p.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_string())
    })?;

    let fits = (1..=70).contains(&boundary.len())
        && boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b));
    fits.then_some(boundary)
}

#[cfg(test)]
#[path = "tests/dialled_compose_tests.rs"]
mod compose_tests;

#[cfg(test)]
#[path = "tests/dialled_tests.rs"]
mod tests;
