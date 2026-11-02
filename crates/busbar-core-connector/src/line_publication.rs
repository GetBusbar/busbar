// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIFO publication is independent of exclusive association custody. A producer returns its

use super::*;
use std::future::Future;
use std::pin::Pin;

/// What host publication completed before an episode stopped. Handed-on bytes cannot be unsent.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicationOutcome {
    /// Original application bytes accepted into the host publication queue.
    pub original_bytes: u64,
    /// Accepted application bytes actually taken by the framer.
    pub original_handed_bytes: u64,
    /// Accepted application bytes cancelled without a confirmed taking result.
    pub original_cancelled_bytes: u64,
    /// Subset of cancelled application bytes whose crossing outcome became unknown.
    pub original_uncertain_bytes: u64,
    /// LINE frames retained for publication.
    pub accepted_frames: u64,
    /// Payload bytes in those frames.
    pub accepted_bytes: u64,
    /// Frames taken by the destination framer.
    pub handed_frames: u64,
    /// Bytes taken by the destination framer, rather than acknowledged by its remote peer.
    pub handed_bytes: u64,
    /// Retained frames explicitly cancelled by a terminal outcome.
    pub cancelled_frames: u64,
    /// Retained bytes explicitly cancelled by a terminal outcome.
    pub cancelled_bytes: u64,
    /// Subset of cancelled LINE frames whose crossing outcome became unknown.
    pub uncertain_frames: u64,
    /// Subset of cancelled LINE bytes whose crossing outcome became unknown.
    pub uncertain_bytes: u64,
    /// A terminal failure, including configured resource exhaustion or cancellation.
    pub failure: Option<String>,
}

#[derive(Default)]
pub(super) struct PublicationState {
    queue: Queue,
    inputs: Queue,
    recall: [bool; 2],
    running: bool,
    pub(super) waiting_attachment: bool,
    outcome: PublicationOutcome,
    retained_input: usize,
}

impl PublicationState {
    pub(super) fn stop(&mut self) -> (Queue, Queue) {
        if self.running
            || self.recall.iter().any(|recall| *recall)
            || !self.queue.is_empty()
            || !self.inputs.is_empty()
            || self.retained_input != 0
        {
            self.outcome
                .failure
                .get_or_insert_with(|| "datagram publication was closed".into());
        }
        self.running = false;
        self.outcome.cancelled_frames = self.outcome.accepted_frames - self.outcome.handed_frames;
        self.outcome.cancelled_bytes = self.outcome.accepted_bytes - self.outcome.handed_bytes;
        self.outcome.original_cancelled_bytes =
            self.outcome.original_bytes - self.outcome.original_handed_bytes;
        (
            std::mem::take(&mut self.queue),
            std::mem::take(&mut self.inputs),
        )
    }
}

#[derive(Default)]
pub(super) struct Queue {
    front: Option<Box<Node>>,

    back: Option<Box<Node>>,
}

struct Node {
    job: Job,
    next: Option<Box<Node>>,
}

struct Job {
    to: Leg,
    across: Across,
    now: Instant,
    text: bool,
    original: bool,
    unpaired: Option<(Leg, u64)>,
    _custody: Custody,
    _admission: Option<Box<dyn Send + 'static>>,
}

impl Queue {
    fn is_empty(&self) -> bool {
        self.front.is_none() && self.back.is_none()
    }

    fn push_front(&mut self, job: Job) {
        let next = self.front.take();
        self.front = Some(Box::new(Node { job, next }));
    }

    fn push(&mut self, job: Job) {
        let next = self.back.take();
        self.back = Some(Box::new(Node { job, next }));
    }

    fn pop(&mut self) -> Option<Job> {
        if self.front.is_none() {
            while let Some(mut node) = self.back.take() {
                self.back = node.next.take();
                node.next = self.front.take();
                self.front = Some(node);
            }
        }
        let node = self.front.take()?;
        let Node { job, next } = *node;
        self.front = next;
        Some(job)
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

fn index(leg: Leg) -> usize {
    match leg {
        Leg::Caller => 0,
        Leg::Upstream => 1,
    }
}

fn other(leg: Leg) -> Leg {
    match leg {
        Leg::Caller => Leg::Upstream,
        Leg::Upstream => Leg::Caller,
    }
}

/// Reservation and channel output returned to the actual reader owner.
pub struct SessionBatch {
    /// Channel pieces, in crossing order.
    pub pieces: Vec<crate::framer::Got>,
    /// Per-piece reservations, parallel to `pieces`. Old uncharged/manual batches may omit them.
    pub owners: Vec<Custody>,
    /// Retain this custody alongside every queued or partially consumed payload.
    pub custody: Custody,
    /// Keep the producer active until all channel handoffs complete too.
    pub producer: crate::publication::ProducerCustody,
}

/// Fresh input has not been accepted when reservation is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// Existing publication or a real reader can release storage; retry after a wake.
    Pending,
    /// No transfer can make the required reservation fit; this connection is failed explicitly.
    Exhausted,
    /// The pairing has already ended.
    Closed,
}

struct Driving {
    pairing: Arc<Pairing>,
    armed: bool,
}

struct Crossing<'a> {
    pairing: &'a Pairing,
    original: bool,
    bytes: u64,
    armed: bool,
}

impl Crossing<'_> {
    fn uncertain(&mut self) {
        if !std::mem::take(&mut self.armed) {
            return;
        }
        let mut state = self.pairing.lock();
        if self.original {
            state.publications.outcome.original_uncertain_bytes += self.bytes;
        } else {
            state.publications.outcome.uncertain_frames += 1;
            state.publications.outcome.uncertain_bytes += self.bytes;
        }
    }
}

impl Drop for Crossing<'_> {
    fn drop(&mut self) {
        self.uncertain();
    }
}

impl Drop for Driving {
    fn drop(&mut self) {
        if self.armed && self.pairing.lock().publications.running {
            self.pairing
                .publication_failed("datagram publication was cancelled".into());
        }
    }
}

impl Pairing {
    /// A storage-retirement generation captured before a reservation attempt.
    #[must_use]
    pub fn storage_generation(&self) -> u64 {
        self.memory.generation()
    }
    /// Record accepted early/gathered bytes before they have a destination producer job.
    pub fn retain_input(&self, bytes: usize) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.publications.retained_input += bytes;
        state.publications.outcome.original_bytes += bytes as u64;
        true
    }

    /// Retire a previously accepted prefix after an explicit refusal or teardown.
    pub fn cancel_retained_input(&self, bytes: usize) {
        let mut state = self.lock();
        state.publications.retained_input -= bytes;
        if !state.closed {
            state.publications.outcome.original_cancelled_bytes += bytes as u64;
        }
    }
    pub(crate) fn retire_metadata_if_closed(&self) {
        if !self.memory.retired() {
            return;
        }
        let retired = {
            let mut state = self.lock();
            if !state.closed {
                return;
            }
            let mut empty = Bridge::new();
            empty.stop();
            std::mem::replace(&mut state.bridge, empty)
        };
        drop(retired);
    }
    /// Register a synchronous reader/driver for genuine storage retirement. `false` explicitly
    pub fn wait_storage(&self, waker: &std::task::Waker, generation: u64) -> bool {
        self.memory.register(waker);
        let progress = {
            let mut state = self.lock();
            if state.closed {
                return false;
            }
            let progress = self.memory.progress(
                generation,
                state.publications.running && !state.publications.waiting_attachment,
            );
            if matches!(progress, crate::publication::Progress::Exhausted) {
                state.closed = true;
                state.bridge.stop();
            }
            progress
        };
        match progress {
            crate::publication::Progress::Changed => {
                waker.wake_by_ref();
                true
            }
            crate::publication::Progress::Pending => true,
            crate::publication::Progress::Closed => false,
            crate::publication::Progress::Exhausted => {
                self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
                false
            }
        }
    }
    /// Reserve before growing accepted input. `capacity` is requested capacity, rather than
    pub fn reserve_input(&self, capacity: usize) -> Result<Custody, SubmitError> {
        self.reserve_input_from(None, capacity)
    }

    /// Reserve a writer's input while excluding its own unread queue as a progress dependency.
    pub fn reserve_input_for(&self, leg: Leg, capacity: usize) -> Result<Custody, SubmitError> {
        self.reserve_input_from(Some(index(leg)), capacity)
    }

    fn reserve_input_from(
        &self,
        source_leg: Option<usize>,
        capacity: usize,
    ) -> Result<Custody, SubmitError> {
        let bytes = capacity.checked_add(
            std::mem::size_of::<Node>()
                + std::mem::size_of::<Across>()
                + 8 * std::mem::size_of::<usize>(),
        );
        let Some(bytes) = bytes else {
            self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
            return Err(SubmitError::Exhausted);
        };
        let attempt = {
            let mut state = self.lock();
            if state.closed {
                return Err(SubmitError::Closed);
            }
            let attempt = self.memory.input(
                bytes,
                state.publications.running && !state.publications.waiting_attachment,
                source_leg,
            );
            if matches!(
                attempt,
                Err(crate::publication::ReservationError::Exhausted)
            ) {
                state.closed = true;
                state.bridge.stop();
            }
            attempt
        };
        match attempt {
            Ok(custody) => Ok(custody),
            Err(crate::publication::ReservationError::Pending) => Err(SubmitError::Pending),
            Err(crate::publication::ReservationError::Closed) => Err(SubmitError::Closed),
            Err(crate::publication::ReservationError::Exhausted) => {
                self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
                Err(SubmitError::Exhausted)
            }
        }
    }

    /// Queue already charged application input without copying or claiming delivery. The
    pub fn submit_owned(
        self: &Arc<Self>,
        leg: Leg,
        across: Across,
        text: bool,
        custody: Custody,
    ) -> Result<(), SubmitError> {
        self.submit_owned_guarded(leg, across, text, custody, None)
    }

    /// As [`Self::submit_owned`], retaining the source's bounded admission guard until actual
    pub fn submit_owned_guarded(
        self: &Arc<Self>,
        leg: Leg,
        across: Across,
        text: bool,
        custody: Custody,
        admission: Option<Box<dyn Send + 'static>>,
    ) -> Result<(), SubmitError> {
        self.submit_preaccepted_owned(leg, across, text, custody, 0, admission)
    }

    /// Transfer early/gathered bytes into their producer job. `preaccepted` has already been
    pub fn submit_preaccepted_owned(
        self: &Arc<Self>,
        leg: Leg,
        across: Across,
        text: bool,
        custody: Custody,
        preaccepted: usize,
        admission: Option<Box<dyn Send + 'static>>,
    ) -> Result<(), SubmitError> {
        let job = Job {
            to: leg,
            across,
            now: Instant::now(),
            text,
            original: true,
            unpaired: None,
            _custody: custody,
            _admission: admission,
        };
        let (schedule, caller) = {
            let mut state = self.lock();
            state.publications.retained_input -= preaccepted;
            if state.closed {
                drop(state);
                drop(job);
                return Err(SubmitError::Closed);
            }
            state.publications.outcome.original_bytes +=
                (job.across.bytes.len() - preaccepted) as u64;
            state.publications.inputs.push(job);
            let schedule = !state.publications.running;
            state.publications.running = true;
            (schedule, state.caller.clone())
        };
        if schedule {
            self.schedule_publication(caller);
        }
        Ok(())
    }

    /// Borrowed application write: wait before copying when live publication can free credit,
    pub async fn send(self: &Arc<Self>, leg: Leg, stream: u64, bytes: &[u8], text: bool) -> bool {
        let Ok(custody) = self.input_credit_for(leg, bytes.len()).await else {
            return false;
        };
        let across = Across {
            stream,
            bytes: bytes.to_vec(),
            end_of_frame: true,
        };
        if self.submit_owned(leg, across, text, custody).is_err() {
            return false;
        }
        struct Accepted(Arc<Pairing>, bool);
        impl Drop for Accepted {
            fn drop(&mut self) {
                if !self.1 {
                    self.0
                        .publication_failed("accepted datagram write was cancelled".into());
                }
            }
        }
        let mut accepted = Accepted(Arc::clone(self), false);
        let outcome = self.published().await;
        accepted.1 = true;
        outcome.failure.is_none() && !self.closed()
    }

    /// Wait for fresh input credit without copying or accepting its bytes. Cancellation while
    pub async fn input_credit(&self, capacity: usize) -> Result<Custody, SubmitError> {
        self.input_credit_from(None, capacity).await
    }

    /// Wait for capacity that can be retired independently of this writer's own reader task.
    pub async fn input_credit_for(
        &self,
        leg: Leg,
        capacity: usize,
    ) -> Result<Custody, SubmitError> {
        self.input_credit_from(Some(index(leg)), capacity).await
    }

    async fn input_credit_from(
        &self,
        source_leg: Option<usize>,
        capacity: usize,
    ) -> Result<Custody, SubmitError> {
        loop {
            let changed = self.memory.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.reserve_input_from(source_leg, capacity) {
                Ok(custody) => return Ok(custody),
                Err(SubmitError::Pending) => changed.await,
                Err(error) => return Err(error),
            }
        }
    }

    fn schedule_publication(self: &Arc<Self>, caller: Option<Arc<dyn LegSink>>) {
        let driving = Driving {
            pairing: Arc::clone(self),
            armed: true,
        };
        let future = Box::pin(async move {
            let mut guard = driving;
            guard.pairing.drive_publication().await;

            guard.armed = false;
        });
        if !caller.is_some_and(|caller| caller.schedule(future)) {
            self.publication_failed("no reactor for datagram publication".into());
        }
    }

    /// The one memory account shared by both legs, accepted inputs and channel readers.
    #[must_use]
    pub fn memory_account(&self) -> Arc<Memory> {
        Arc::clone(&self.memory)
    }

    /// Queue checked output in FIFO order. No framer callback runs before this method returns;
    pub fn publish(self: &Arc<Self>, leg: Leg, mut yielded: Yielded, now: Instant) -> SessionBatch {
        let owns_storage = yielded.pieces.capacity() != 0
            || yielded.heads.capacity() != 0
            || yielded.wire.capacity() != 0
            || yielded.interim.capacity() != 0
            || yielded.flow.capacity() != 0;
        if self.memory.limit().is_some() && !yielded.custody.tracked() && owns_storage {
            let credit = yielded
                .adoption_bound()
                .and_then(|bytes| self.memory.reserve(bytes));
            let Some(credit) = credit else {
                self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
                return SessionBatch {
                    pieces: Vec::new(),
                    custody: Custody::default(),
                    owners: Vec::new(),
                    producer: crate::publication::ProducerCustody::default(),
                };
            };
            yielded.custody = credit;
            yielded.producer = self.memory.producer().unwrap_or_default();
            yielded.split_piece_custody();
            let retained = yielded.retained_capacity();
            yielded.custody.reduce(retained);
        }
        let pieces = std::mem::take(&mut yielded.pieces);
        let custody = std::mem::take(&mut yielded.custody);
        let continuing = yielded.continuing;
        let piece_custody = std::mem::take(&mut yielded.piece_custody);
        let producer = std::mem::take(&mut yielded.producer);

        drop(yielded);
        let mut retired = Vec::new();
        let (pieces, owners, schedule, caller) = {
            let mut state = self.lock();
            let mut session = Vec::new();
            let mut owners = Vec::new();
            let mut piece_custody = piece_custody.into_iter();
            for piece in pieces {
                let owner = piece_custody.next().unwrap_or_else(|| custody.clone());

                let line = state
                    .bridge
                    .lines(leg)
                    .iter()
                    .any(|(stream, _)| *stream == piece.stream)
                    && is_line_payload(&piece);
                let bytes = piece.bytes.len() as u64;
                if line {
                    state.publications.outcome.accepted_frames += 1;
                    state.publications.outcome.accepted_bytes += bytes;
                    if state.closed {
                        state.publications.outcome.cancelled_frames += 1;
                        state.publications.outcome.cancelled_bytes += bytes;
                        retired.push(owner);
                    } else {
                        let stream = state.bridge.across(leg, piece.stream);
                        state.publications.queue.push(Job {
                            to: other(leg),
                            unpaired: stream.is_none().then_some((leg, piece.stream)),
                            across: Across {
                                stream: stream.unwrap_or(piece.stream),
                                bytes: piece.bytes,
                                end_of_frame: piece.end_of_frame,
                            },
                            now,
                            text: false,
                            original: false,
                            _admission: None,
                            _custody: owner,
                        });
                    }
                    continue;
                }
                let heads = state.bridge.caller.len()
                    + state.bridge.upstream.len()
                    + state.bridge.channels.len();
                let (mut channel, across) = state.bridge.sort(leg, vec![piece]);
                let new_heads = state.bridge.caller.len()
                    + state.bridge.upstream.len()
                    + state.bridge.channels.len();
                if new_heads != heads {
                    state.bridge.custody.push(owner.clone());
                }
                if state.closed {
                    retired.push(owner);
                    continue;
                }
                for across in across {
                    state.publications.queue.push(Job {
                        to: other(leg),
                        across,
                        now,
                        text: false,
                        original: false,
                        unpaired: None,
                        _admission: None,
                        _custody: owner.clone(),
                    });
                }
                for piece in channel.drain(..) {
                    session.push(piece);
                    owners.push(owner.clone());
                }
                retired.push(owner);
            }
            retired.extend(piece_custody);
            if !state.closed {
                state.publications.recall[index(leg)] |= continuing;
            }
            let schedule = !state.publications.running
                && !state.closed
                && (!state.publications.queue.is_empty()
                    || state.publications.recall.iter().any(|recall| *recall));
            if schedule {
                state.publications.running = true;
            }
            (session, owners, schedule, state.caller.clone())
        };
        drop(retired);
        if schedule {
            self.schedule_publication(caller);
        }
        SessionBatch {
            pieces,
            custody,
            owners,
            producer,
        }
    }

    /// Completed or partial publication counters for this connection. A successful ABI Emit
    #[must_use]
    pub fn publication_outcome(&self) -> PublicationOutcome {
        self.lock().publications.outcome.clone()
    }

    /// Await actual publication quiescence, or explicit terminal failure. Channel ownership
    pub async fn published(&self) -> PublicationOutcome {
        loop {
            let changed = self.published.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.lock();
                if !state.publications.running || state.closed {
                    return state.publications.outcome.clone();
                }
            }
            changed.await;
        }
    }

    pub(super) fn publication_failed(&self, failure: String) {
        let (abandoned, exhausted) = {
            let mut state = self.lock();
            let publications = &mut state.publications;
            let exhausted =
                publications.outcome.failure.is_none() && failure == LINE_MEMORY_EXHAUSTED;
            publications.outcome.failure.get_or_insert(failure);
            (publications.stop(), exhausted)
        };
        drop(abandoned);
        if exhausted {
            tracing::warn!(local = %self.local, reason = "resource_exhausted",
                "the configured datagram LINE memory limit is exhausted; the affected connection is closed");
        }
        self.published.notify_waiters();
        self.close();
    }

    fn cancelled(&self, _job: &Job) {
        let mut state = self.lock();
        let outcome = &mut state.publications.outcome;
        outcome.cancelled_frames = outcome.accepted_frames - outcome.handed_frames;
        outcome.cancelled_bytes = outcome.accepted_bytes - outcome.handed_bytes;
        outcome.original_cancelled_bytes = outcome.original_bytes - outcome.original_handed_bytes;
    }

    fn awaiting_attachment(&self) -> bool {
        let mut state = self.lock();
        if state.closed || state.upstream.is_some() {
            return false;
        }
        state.publications.waiting_attachment = true;
        true
    }

    async fn drive_publication(self: &Arc<Self>) {
        let mut current: Option<Job> = None;
        loop {
            let attached = self.published.notified();
            tokio::pin!(attached);
            attached.as_mut().enable();
            let (leg, sink, now) = {
                let mut state = self.lock();
                if state.closed {
                    state.publications.running = false;
                    drop(state);
                    if let Some(job) = current.take() {
                        self.cancelled(&job);
                    }
                    self.published.notify_waiters();
                    return;
                }

                if current.is_none() {
                    current = state
                        .publications
                        .queue
                        .pop()
                        .or_else(|| state.publications.inputs.pop());
                }
                if let Some(job) = &mut current {
                    if let Some((from, stream)) = job.unpaired {
                        if let Some(stream) = state.bridge.across(from, stream) {
                            job.across.stream = stream;
                            job.unpaired = None;
                        }
                    }
                }
                let leg = match current.as_ref() {
                    Some(job) => job.to,
                    None if state.publications.recall[0] => Leg::Caller,
                    None if state.publications.recall[1] => Leg::Upstream,
                    None => {
                        state.publications.running = false;
                        drop(state);
                        self.published.notify_waiters();
                        return;
                    }
                };
                let sink = match leg {
                    Leg::Caller => state.caller.clone(),
                    Leg::Upstream => state.upstream.clone(),
                };
                (
                    leg,
                    sink,
                    current.as_ref().map_or_else(Instant::now, |job| job.now),
                )
            };
            let Some(sink) = sink else {
                if leg == Leg::Upstream {
                    if self.awaiting_attachment() {
                        self.memory.progress_changed();
                        attached.await;
                    }
                    continue;
                }
                if let Some(job) = current.take() {
                    self.cancelled(&job);
                }
                self.publication_failed("LINE output has no attached destination".into());
                return;
            };
            if current.as_ref().is_some_and(|job| job.unpaired.is_some()) {
                if self.awaiting_attachment() {
                    self.memory.progress_changed();
                    attached.await;
                    continue;
                }
                self.publication_failed(
                    "LINE output could not be paired after upstream admission".into(),
                );
                return;
            }
            let input = current.as_ref().map(|job| &job.across);

            let owed = {
                let mut state = self.lock();
                state.publications.waiting_attachment = false;
                std::mem::take(&mut state.publications.recall[index(leg)])
            };
            let text = current.as_ref().is_some_and(|job| job.text);
            let mut crossing = Crossing {
                pairing: self,
                original: current.as_ref().is_some_and(|job| job.original),
                bytes: input.map_or(0, |input| input.bytes.len() as u64),
                armed: input.is_some(),
            };
            let generation = self.storage_generation();
            let result = std::future::poll_fn(|cx| sink.poll_line(cx, input, text, now)).await;
            if result
                .as_ref()
                .is_err_and(|error| error.outcome != Outcome::Refused)
            {
                crossing.uncertain();
            } else {
                crossing.armed = false;
            }
            match result {
                Ok(LineStep::Credit) => {
                    if owed {
                        let mut state = self.lock();
                        if !state.closed {
                            state.publications.recall[index(leg)] = true;
                        }
                    }
                    if self.memory.reader_progress(generation).await {
                        continue;
                    }
                    if let Some(job) = current.take() {
                        self.cancelled(&job);
                    }
                    self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
                    return;
                }
                Ok(LineStep::Batch { yielded, accepted }) => {
                    {
                        let mut state = self.lock();
                        if !state.closed {
                            state.publications.recall[index(leg)] = true;
                        }
                    }
                    if accepted {
                        if let Some(job) = current.take() {
                            let mut state = self.lock();
                            if !job.original {
                                state.publications.outcome.handed_frames += 1;
                                state.publications.outcome.handed_bytes +=
                                    job.across.bytes.len() as u64;
                            } else {
                                state.publications.outcome.original_handed_bytes +=
                                    job.across.bytes.len() as u64;
                            }
                            if state.closed {
                                let outcome = &mut state.publications.outcome;
                                outcome.cancelled_frames =
                                    outcome.accepted_frames - outcome.handed_frames;
                                outcome.cancelled_bytes =
                                    outcome.accepted_bytes - outcome.handed_bytes;
                                outcome.original_cancelled_bytes =
                                    outcome.original_bytes - outcome.original_handed_bytes;
                            }
                            drop(state);
                            drop(job);
                        }
                    }

                    let session = self.publish(leg, yielded, now);
                    if let Err(error) = sink.channels(session, now) {
                        self.publication_failed(error);
                        return;
                    }
                    if current.as_ref().is_some_and(|job| job.original) {
                        let job = current.take().expect("the held source input");

                        let retired = {
                            let mut state = self.lock();
                            if state.closed {
                                Some(job)
                            } else {
                                state.publications.inputs.push_front(job);
                                None
                            }
                        };
                        if let Some(job) = retired {
                            self.cancelled(&job);
                            drop(job);
                        }
                    }
                }

                Ok(LineStep::Complete) => {}
                Err(error) => {
                    if let Some(job) = current.take() {
                        self.cancelled(&job);
                    }
                    self.publication_failed(error.error);
                    return;
                }
            }
        }
    }
}

/// An owned scheduling future, captured before it is handed to the reactor.
pub type PublicationTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[cfg(test)]
#[path = "tests/line_publication_driver_tests.rs"]
mod driver_tests;

#[cfg(test)]
#[path = "tests/line_publication_queue_tests.rs"]
mod queue_tests;
