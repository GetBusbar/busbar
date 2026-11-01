// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIFO publication is independent of exclusive association custody. A producer returns its
//! association after each checked batch; callbacks enqueue feedback and never await one another.

use super::*;
use std::future::Future;
use std::pin::Pin;

/// What host publication completed before an episode stopped. Handed-on bytes cannot be unsent.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicationOutcome {
    /// Original application bytes accepted into the host publication queue.
    pub original_bytes: u64,
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
    /// A terminal failure, including configured resource exhaustion or cancellation.
    pub failure: Option<String>,
}

#[derive(Default)]
pub(super) struct PublicationState {
    queue: Queue,
    recall: [bool; 2],
    running: bool,
    outcome: PublicationOutcome,
}

#[derive(Default)]
struct Queue(Option<Box<Node>>);

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
    _custody: Custody,
}

impl Queue {
    fn push(&mut self, job: Job) {
        let mut tail = &mut self.0;
        while let Some(node) = tail {
            tail = &mut node.next;
        }
        *tail = Some(Box::new(Node { job, next: None }));
    }

    fn pop(&mut self) -> Option<Job> {
        let node = self.0.take()?;
        let Node { job, next } = *node;
        self.0 = next;
        Some(job)
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

fn index(leg: Leg) -> usize {
    match leg { Leg::Caller => 0, Leg::Upstream => 1 }
}

fn other(leg: Leg) -> Leg {
    match leg { Leg::Caller => Leg::Upstream, Leg::Upstream => Leg::Caller }
}

/// Reservation and channel output returned to the actual reader owner.
pub struct SessionBatch {
    /// Channel pieces, in crossing order.
    pub pieces: Vec<crate::framer::Got>,
    /// Retain this custody alongside every queued or partially consumed payload.
    pub custody: Custody,
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

struct Driving(Arc<Pairing>);

impl Drop for Driving {
    fn drop(&mut self) {
        if self.0.lock().publications.running {
            self.0.publication_failed("datagram publication was cancelled".into());
        }
    }
}

impl Pairing {
    /// Reserve before growing accepted input. `capacity` is requested capacity, rather than
    /// payload length. Include the old live capacity when a growth temporarily retains both.
    pub fn reserve_input(&self, capacity: usize) -> Result<Custody, SubmitError> {
        let bytes = capacity.checked_add(std::mem::size_of::<Node>()
            + std::mem::size_of::<Across>() + 8 * std::mem::size_of::<usize>());
        let Some(bytes) = bytes else {
            self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
            return Err(SubmitError::Exhausted);
        };
        if self.closed() { return Err(SubmitError::Closed); }
        if let Some(custody) = self.memory.reserve(bytes) { return Ok(custody); }
        if self.memory.can_fit(bytes)
            && (self.lock().publications.running || self.memory.readers()) {
            return Err(SubmitError::Pending);
        }
        self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
        Err(SubmitError::Exhausted)
    }

    /// Queue already charged application input without copying or claiming delivery. The
    /// reservation remains with this input until the destination framer actually takes it.
    pub fn submit_owned(
        self: &Arc<Self>, leg: Leg, across: Across, text: bool, custody: Custody,
    ) -> Result<(), SubmitError> {
        let (schedule, caller) = {
            let mut state = self.lock();
            if state.closed { return Err(SubmitError::Closed); }
            state.publications.outcome.original_bytes += across.bytes.len() as u64;
            state.publications.queue.push(Job {
                to: leg, across, now: Instant::now(), text, original: true, _custody: custody,
            });
            let schedule = !state.publications.running;
            state.publications.running = true;
            (schedule, state.caller.clone())
        };
        if schedule { self.schedule_publication(caller); }
        Ok(())
    }

    /// Borrowed application write: wait before copying when live publication can free credit,
    /// then await the honest output result. Cancellation after acceptance ends the pairing.
    pub async fn send(
        self: &Arc<Self>, leg: Leg, stream: u64, bytes: &[u8], text: bool,
    ) -> bool {
        let custody = loop {
            let changed = self.memory.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.reserve_input(bytes.len()) {
                Ok(custody) => break custody,
                Err(SubmitError::Pending) => changed.await,
                Err(_) => return false,
            }
        };
        let across = Across { stream, bytes: bytes.to_vec(), end_of_frame: true };
        if self.submit_owned(leg, across, text, custody).is_err() { return false; }
        struct Accepted(Arc<Pairing>, bool);
        impl Drop for Accepted {
            fn drop(&mut self) {
                if !self.1 { self.0.publication_failed("accepted datagram write was cancelled".into()); }
            }
        }
        let mut accepted = Accepted(Arc::clone(self), false);
        let outcome = self.published().await;
        accepted.1 = true;
        outcome.failure.is_none() && !self.closed()
    }

    fn schedule_publication(self: &Arc<Self>, caller: Option<Arc<dyn LegSink>>) {
        let driving = Driving(Arc::clone(self));
        let future = Box::pin(async move {
            let guard = driving;
            guard.0.drive_publication().await;
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
    /// the scheduler crosses one producer batch at a time after its association is returned.
    pub fn publish(self: &Arc<Self>, leg: Leg, yielded: Yielded, now: Instant) -> SessionBatch {
        let Yielded { pieces, custody, .. } = yielded;
        let (pieces, schedule, caller) = {
            let mut state = self.lock();
            if state.closed {
                return SessionBatch { pieces: Vec::new(), custody };
            }
            let (pieces, across) = state.bridge.sort(leg, pieces);
            for across in across {
                state.publications.outcome.accepted_frames += 1;
                state.publications.outcome.accepted_bytes += across.bytes.len() as u64;
                state.publications.queue.push(Job {
                    to: other(leg), across, now, text: false, original: false, _custody: custody.clone(),
                });
            }
            let schedule = !state.publications.running && state.publications.queue.0.is_some();
            if schedule {
                state.publications.running = true;
            }
            (pieces, schedule, state.caller.clone())
        };
        if schedule {
            // Construct the guard before spawn, so cancellation before first poll closes the
            // accepted episode too. The real caller schedules on its captured reactor/tracker.
            self.schedule_publication(caller);
        }
        SessionBatch { pieces, custody }
    }

    /// Completed or partial publication counters for this connection. A successful ABI Emit
    /// means its original bytes were taken; these counters separately describe its output.
    #[must_use]
    pub fn publication_outcome(&self) -> PublicationOutcome {
        self.lock().publications.outcome.clone()
    }

    /// Await actual publication quiescence, or explicit terminal failure. Channel ownership
    /// may remain with readers after success and continues to count against the memory limit.
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
        let abandoned = {
            let mut state = self.lock();
            let publications = &mut state.publications;
            publications.outcome.failure.get_or_insert(failure);
            publications.running = false;
            std::mem::take(&mut publications.queue)
        };
        let mut abandoned = abandoned;
        while let Some(job) = abandoned.pop() {
            self.cancelled(&job);
        }
        self.published.notify_waiters();
        self.close();
    }

    fn cancelled(&self, job: &Job) {
        if job.original { return; }
        let mut state = self.lock();
        state.publications.outcome.cancelled_frames += 1;
        state.publications.outcome.cancelled_bytes += job.across.bytes.len() as u64;
    }

    async fn drive_publication(&self) {
        let mut current: Option<Job> = None;
        loop {
            let (leg, sink, now) = {
                let mut state = self.lock();
                if state.closed {
                    state.publications.running = false;
                    drop(state);
                    if let Some(job) = current.take() { self.cancelled(&job); }
                    self.published.notify_waiters();
                    return;
                }
                if current.is_none() { current = state.publications.queue.pop(); }
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
                (leg, sink, current.as_ref().map_or_else(Instant::now, |job| job.now))
            };
            let Some(sink) = sink else {
                if let Some(job) = current.take() { self.cancelled(&job); }
                self.publication_failed("LINE output has no attached destination".into());
                return;
            };
            let result = std::future::poll_fn(|cx| {
                sink.poll_line(cx, current.as_ref().map(|job| &job.across),
                    current.as_ref().is_some_and(|job| job.text), now)
            }).await;
            match result {
                Ok(LineStep::Credit) => {
                    if self.memory.reader_progress().await { continue; }
                    if let Some(job) = current.take() { self.cancelled(&job); }
                    self.publication_failed(LINE_MEMORY_EXHAUSTED.into());
                    return;
                }
                Ok(LineStep::Batch { yielded, accepted }) => {
                    self.lock().publications.recall[index(leg)] = true;
                    if accepted {
                        if let Some(job) = current.take() {
                            let mut state = self.lock();
                            if !job.original {
                                state.publications.outcome.handed_frames += 1;
                                state.publications.outcome.handed_bytes += job.across.bytes.len() as u64;
                            }
                            drop(state);
                            drop(job);
                        }
                    }
                    // This enqueues feedback only. It cannot await this producer or cross a
                    // destination while the source's exclusive association is still out.
                    let pair = sink.pairing();
                    let Some(pair) = pair else {
                        self.publication_failed("publication lost its pairing".into());
                        return;
                    };
                    let session = pair.publish(leg, yielded, now);
                    if let Err(error) = sink.channels(session, now) {
                        self.publication_failed(error);
                        return;
                    }
                }
                Ok(LineStep::Complete) => {
                    self.lock().publications.recall[index(leg)] = false;
                }
                Err(error) => {
                    if let Some(job) = current.take() { self.cancelled(&job); }
                    self.publication_failed(error.error);
                    return;
                }
            }
        }
    }
}

/// An owned scheduling future, captured before it is handed to the reactor.
pub type PublicationTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
