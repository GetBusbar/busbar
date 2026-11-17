// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned response write attribution and bounded lifecycle controls.

use std::collections::VecDeque;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use busbar_contract::response_delivery::{
    CarrierProgress, CompletionRequirement, DeliveryReader, DeliverySnapshot, DeliveryTerminal,
    ResponseKey, ResponseStop, WireClass,
};
use busbar_contract::storage::{StorageCredit, StorageSource};
use futures::task::AtomicWaker;

#[cfg(test)]
#[path = "response_delivery_tests.rs"]
mod tests;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Cell {
    key: ResponseKey,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
    owner_wake: Arc<AtomicWaker>,
    slots: Arc<AtomicUsize>,
}

impl Drop for Cell {
    fn drop(&mut self) {
        self.slots.fetch_sub(1, Ordering::AcqRel);
    }
}

struct State {
    snapshot: DeliverySnapshot,
    ordinal: Option<u64>,
    release_pending: bool,
    released: bool,
    cancel: Option<ResponseStop>,
    cancel_taken: bool,
    producer_ended: bool,
    reader_eof: bool,
    input_retired: bool,
    pending_producer_end: bool,
    pending_reader_eof: bool,
    pending_input_retired: bool,
    quiescent: bool,
    settled_pending: bool,
    settled_sent: bool,
    settled_ack: bool,
}

/// Read/watch access only; retaining a clone retains its admitted response-cell capacity.
#[derive(Clone)]
pub struct DeliveryWatch(Arc<Cell>);

impl DeliveryWatch {
    /// Borrow the immutable admitted identity from this watch's actual private cell.
    pub fn key(&self) -> ResponseKey {
        self.0.key
    }
    /// Read the monotone facts without acquiring write authority.
    pub fn snapshot(&self) -> DeliverySnapshot {
        lock(&self.0.state).snapshot
    }

    /// Read the actual cancellation latch before the output owner has settled delivery.
    pub fn cancellation(&self) -> Option<ResponseStop> {
        lock(&self.0.state).cancel
    }

    /// Await the single frozen terminal; cancellation of this waiter changes no delivery fact.
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

impl DeliveryReader for DeliveryWatch {
    fn key(&self) -> ResponseKey {
        self.key()
    }
    fn snapshot(&self) -> DeliverySnapshot {
        self.snapshot()
    }
}

/// The admission-bound cancellation endpoint; this requests stop, never manufactures a receipt.
#[derive(Clone)]
pub struct DeliveryCancel(Arc<Cell>);

impl DeliveryCancel {
    /// Coalesce a cancellation request into the reserved cell; the first reason wins.
    pub fn cancel(&self, reason: ResponseStop) {
        let mut state = lock(&self.0.state);
        if state.snapshot.terminal.is_none() {
            state.cancel.get_or_insert(reason);
            state.release_pending = false;
        }
        drop(state);
        self.0.owner_wake.wake();
    }
}

/// The actual root input observers' scoped endpoint; it cannot publish a delivery receipt.
#[derive(Clone)]
pub struct DeliveryInput(Arc<Cell>);

impl DeliveryInput {
    /// Record the real ordered response-producing end, independently of transport feed disposal.
    pub fn producer_ended(&self) {
        lock(&self.0.state).pending_producer_end = true;
        self.0.owner_wake.wake();
    }

    /// Record EOF actually observed by the registered reader, never inferred from Body Drop.
    pub fn reader_eof(&self) {
        lock(&self.0.state).pending_reader_eof = true;
        self.0.owner_wake.wake();
    }

    /// Record that cancelled input producers/readers have been joined; this is not successful EOF.
    pub fn retired(&self) {
        lock(&self.0.state).pending_input_retired = true;
        self.0.owner_wake.wake();
    }
}

/// A non-Clone publication right given only to the root's actual confirmed-intent finalizer.
///
/// This endpoint does not confirm persistence or verify a signature. Production root retains it
/// privately and calls publish only after consuming its confirmed, response-bound ReleasePermit.
/// Historical decoders, request bodies and plugins must never receive this endpoint.
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

    /// Submit the exact confirmed ordinal without waiting on data credit or E_END acceptance.
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
        if !state.released {
            state.release_pending = true;
        }
        drop(state);
        self.0.owner_wake.wake();
        Ok(())
    }
}

/// Separately scoped handles installed before exposing the admitted request.
pub struct ResponseHandles {
    /// Read-only delivery observation; clones retain capacity until dropped.
    pub watch: DeliveryWatch,
    /// Only the root's actual intent finalizer receives this publication right.
    pub release: ReleasePublisher,
    /// A request to stop, independent of output-owner settlement.
    pub cancel: DeliveryCancel,
    /// Only actual root producer/reader observers publish these local input facts.
    pub input: DeliveryInput,
}

/// Native controls taken from reserved cells before normal feeds and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryControl {
    Release { stream: u64 },
    Cancel { stream: u64, reason: ResponseStop },
    Settled { stream: u64 },
}

/// Validated protocol metadata; the actual bytes remain in the runtime's charged SecureVec.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WireEvent {
    Part {
        stream: u64,
        class: WireClass,
        len: usize,
    },
    End {
        stream: u64,
        requirement: CompletionRequirement,
    },
    Abort {
        stream: u64,
    },
    Quiescent {
        stream: u64,
    },
}

struct Span {
    start: u64,
    end: u64,
    stream: u64,
    class: WireClass,
}

struct Fence {
    end: u64,
    requirement: CompletionRequirement,
    flushed: bool,
    ready: bool,
}

struct Entry {
    cell: Arc<Cell>,
    last_end: u64,
    fence: Option<Fence>,
    stop: Option<ResponseStop>,
}

struct Shadow {
    stream: u64,
    ended: bool,
    stopped: bool,
    quiescent: bool,
}

/// The sole connection output owner's bounded, non-Clone provenance ledger.
///
/// Runtime supervision retains this owner until the actual carrier operation is settled. Dropping
/// it while a writer may remain live deliberately creates no synthetic terminal receipt.
pub struct DeliveryLedger {
    spans: VecDeque<Span>,
    entries: Vec<Entry>,
    scratch: Vec<Shadow>,
    // Declaration order is intentional: all three backing arrays drop before their byte credit.
    // Fixed self-owning control/Arc layouts retain the explicitly named storage-contract exclusion.
    storage: StorageCredit,
    slots: Arc<AtomicUsize>,
    wake: Arc<AtomicWaker>,
    max_spans: usize,
    max_responses: usize,
    max_events: usize,
    last_stream: u64,
    identity: Option<(u64, u64, u64)>,
    adopted: u64,
    observed: CarrierProgress,
    retired: bool,
    poisoned: bool,
}

impl fmt::Debug for DeliveryLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryLedger")
            .field("pending_spans", &self.spans.len())
            .field("live_responses", &self.entries.len())
            .field("reserved_storage_bytes", &self.storage.len())
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

/// A linear reservation after whole-batch validation; no byte I/O may precede commit.
pub(crate) struct PreparedBatch<'a> {
    owner: &'a mut DeliveryLedger,
    events: &'a [WireEvent],
}

impl PreparedBatch<'_> {
    /// Adopt only the already validated descriptors. Dropping the reservation changes no state.
    pub(crate) fn commit(self) {
        self.owner.commit_batch(self.events);
    }
}

impl DeliveryLedger {
    /// Quote requested separately allocated backing using the actual private element layouts.
    ///
    /// This covers the retained span deque and entry/scratch vectors, including spare capacity.
    /// The admitted fixed control-cell count is separate. Self-owning Arc/control layouts and
    /// allocator overhead are outside the shared storage contract; this is not an RSS estimate.
    /// A quote alone reserves nothing: the actual StorageSource must fund it before allocation.
    pub fn required_storage(
        max_pending_spans: NonZeroUsize,
        max_live_responses: NonZeroUsize,
    ) -> Result<usize, ResponseStop> {
        let spans = max_pending_spans
            .get()
            .checked_mul(std::mem::size_of::<Span>());
        let responses = std::mem::size_of::<Entry>()
            .checked_add(std::mem::size_of::<Shadow>())
            .and_then(|bytes| bytes.checked_mul(max_live_responses.get()));
        spans
            .and_then(|bytes| responses.and_then(|other| bytes.checked_add(other)))
            .ok_or(ResponseStop::Capacity)
    }

    /// Allocate finite metadata storage from real admission allowances, without a default cap.
    ///
    /// The runtime separately reserves callback staging bytes/descriptors before copying callback
    /// output. Both staging and this ledger's simultaneous debt must fit its admitted allowance.
    pub fn new(
        source: &StorageSource,
        max_pending_spans: NonZeroUsize,
        max_live_responses: NonZeroUsize,
    ) -> Result<Self, ResponseStop> {
        let bytes = Self::required_storage(max_pending_spans, max_live_responses)?;
        let max_spans = max_pending_spans.get();
        let max_responses = max_live_responses.get();
        let max_events = max_responses
            .checked_mul(4)
            .and_then(|count| count.checked_add(max_spans))
            .ok_or(ResponseStop::Capacity)?;
        // This binding precedes every array: on any allocation error the allocated locals drop
        // first, then credit. Moving into Self preserves the same backing-before-credit order.
        let storage = source
            .try_reserve(bytes)
            .map_err(|_| ResponseStop::Capacity)?;
        let mut spans = VecDeque::new();
        spans
            .try_reserve_exact(max_spans)
            .map_err(|_| ResponseStop::Capacity)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(max_responses)
            .map_err(|_| ResponseStop::Capacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(max_responses)
            .map_err(|_| ResponseStop::Capacity)?;
        Ok(Self {
            spans,
            entries,
            scratch,
            storage,
            slots: Arc::new(AtomicUsize::new(0)),
            wake: Arc::new(AtomicWaker::new()),
            max_spans,
            max_responses,
            max_events,
            last_stream: 0,
            identity: None,
            adopted: 0,
            observed: CarrierProgress {
                accepted_plaintext: 0,
                written_plaintext: 0,
                complete_records_plaintext: 0,
                fault: None,
            },
            retired: false,
            poisoned: false,
        })
    }

    /// Reserve the fixed lifecycle cell before request exposure. IDs never get reused.
    pub fn admit(&mut self, key: ResponseKey) -> Result<ResponseHandles, ResponseStop> {
        let identity = (key.node, key.incarnation, key.connection_generation);
        if self.retired
            || self.poisoned
            || self.observed.fault.is_some()
            || key.stream <= self.last_stream
            || key.connection_generation == 0
            || self.identity.is_some_and(|old| old != identity)
        {
            return Err(ResponseStop::Integrity);
        }
        if self.slots.load(Ordering::Acquire) >= self.max_responses {
            return Err(ResponseStop::Capacity);
        }
        self.slots.fetch_add(1, Ordering::AcqRel);
        let cell = Arc::new(Cell {
            key,
            state: Mutex::new(State {
                snapshot: DeliverySnapshot {
                    first_payload_written: false,
                    terminal: None,
                },
                ordinal: None,
                release_pending: false,
                released: false,
                cancel: None,
                cancel_taken: false,
                producer_ended: false,
                reader_eof: false,
                input_retired: false,
                pending_producer_end: false,
                pending_reader_eof: false,
                pending_input_retired: false,
                quiescent: false,
                settled_pending: false,
                settled_sent: false,
                settled_ack: false,
            }),
            changed: tokio::sync::Notify::new(),
            owner_wake: Arc::clone(&self.wake),
            slots: Arc::clone(&self.slots),
        });
        self.last_stream = key.stream;
        self.identity = Some(identity);
        self.entries.push(Entry {
            cell: Arc::clone(&cell),
            last_end: 0,
            fence: None,
            stop: None,
        });
        Ok(ResponseHandles {
            watch: DeliveryWatch(Arc::clone(&cell)),
            release: ReleasePublisher(Arc::clone(&cell)),
            cancel: DeliveryCancel(Arc::clone(&cell)),
            input: DeliveryInput(cell),
        })
    }

    fn index(&self, stream: u64) -> Result<usize, ResponseStop> {
        self.entries
            .iter()
            .position(|entry| entry.cell.key.stream == stream)
            .ok_or(ResponseStop::Integrity)
    }

    /// Register before checking the reserved control cells, so concurrent publications wake the owner.
    pub(crate) fn register_control_waker(&self, waker: &Waker) {
        self.wake.register(waker);
    }

    /// Park the single connection owner without losing a concurrent reserved-cell publication.
    pub(crate) fn poll_control(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryControl> {
        self.register_control_waker(cx.waker());
        self.next_control().map_or(Poll::Pending, Poll::Ready)
    }

    /// Whether a response binding still needs an input/protocol/settlement join.
    pub(crate) fn has_responses(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Retry only the existing complete retirement predicate after actual input publications.
    /// Registration precedes the scan so a concurrent EOF or cancellation join cannot be lost.
    pub(crate) fn poll_idle(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.register_control_waker(cx.waker());
        self.drain_input();
        for index in (0..self.entries.len()).rev() {
            let stream = self.entries[index].cell.key.stream;
            let _ = self.retire_response(stream);
        }
        if self.entries.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Take one coalesced control; cancellation wins over an unconsumed release.
    pub(crate) fn next_control(&mut self) -> Option<DeliveryControl> {
        self.drain_input();
        for entry in &mut self.entries {
            let mut state = lock(&entry.cell.state);
            let stream = entry.cell.key.stream;
            if let Some(reason) = state.cancel {
                state.release_pending = false;
                if !state.cancel_taken && state.snapshot.terminal.is_none() {
                    state.cancel_taken = true;
                    entry.stop.get_or_insert(reason);
                    return Some(DeliveryControl::Cancel { stream, reason });
                }
            }
            if state.release_pending
                && state.snapshot.terminal.is_none()
                && !self.retired
                && !self.poisoned
                && self.observed.fault.is_none()
            {
                state.release_pending = false;
                state.released = true;
                return Some(DeliveryControl::Release { stream });
            }
            if state.settled_pending {
                state.settled_pending = false;
                state.settled_sent = true;
                return Some(DeliveryControl::Settled { stream });
            }
        }
        None
    }

    fn drain_input(&mut self) {
        for index in 0..self.entries.len() {
            let cell = &self.entries[index].cell;
            let stream = cell.key.stream;
            let mut state = lock(&cell.state);
            let ended = std::mem::take(&mut state.pending_producer_end);
            let eof = std::mem::take(&mut state.pending_reader_eof);
            let retired = std::mem::take(&mut state.pending_input_retired);
            drop(state);
            if ended {
                let _ = self.producer_ended(stream);
            }
            if eof {
                let _ = self.reader_eof(stream);
            }
            if retired {
                let _ = self.input_retired(stream);
            }
        }
    }

    /// Validate an entire bounded answer before adopting metadata or permitting any of its I/O.
    ///
    /// Callback staging must already own its separate admitted copy allowance. This reservation
    /// covers the ledger, not callback buffers; no borrowed callback slice is retained here.
    pub(crate) fn prepare_batch<'a>(
        &'a mut self,
        events: &'a [WireEvent],
    ) -> Result<PreparedBatch<'a>, ResponseStop> {
        if self.retired || self.poisoned || self.observed.fault.is_some() {
            return Err(ResponseStop::Integrity);
        }
        if events.len() > self.max_events {
            return Err(ResponseStop::Capacity);
        }
        self.scratch.clear();
        let mut descriptors = self.spans.len();
        for entry in &self.entries {
            let state = lock(&entry.cell.state);
            if entry.fence.as_ref().is_some_and(|fence| !fence.ready) {
                descriptors += 1;
            }
            self.scratch.push(Shadow {
                stream: entry.cell.key.stream,
                ended: entry.fence.is_some(),
                stopped: entry.stop.is_some()
                    || state.cancel.is_some()
                    || state.snapshot.terminal.is_some(),
                quiescent: state.quiescent,
            });
        }
        let mut end = self.adopted;
        for event in events {
            match *event {
                WireEvent::Part { stream, class, len } => {
                    if len == 0 || (stream == 0 && class != WireClass::Control) {
                        return Err(ResponseStop::Integrity);
                    }
                    if stream != 0 {
                        let state = self
                            .scratch
                            .iter()
                            .find(|state| state.stream == stream)
                            .ok_or(ResponseStop::Integrity)?;
                        if state.ended || state.stopped || state.quiescent {
                            return Err(ResponseStop::Integrity);
                        }
                    }
                    end = end
                        .checked_add(u64::try_from(len).map_err(|_| ResponseStop::Capacity)?)
                        .ok_or(ResponseStop::Capacity)?;
                    descriptors = descriptors.checked_add(1).ok_or(ResponseStop::Capacity)?;
                }
                WireEvent::End { stream, .. } => {
                    let index = self.index(stream)?;
                    let state = self
                        .scratch
                        .iter_mut()
                        .find(|state| state.stream == stream)
                        .ok_or(ResponseStop::Integrity)?;
                    if state.ended
                        || state.stopped
                        || state.quiescent
                        || !lock(&self.entries[index].cell.state).released
                    {
                        return Err(ResponseStop::Integrity);
                    }
                    state.ended = true;
                    descriptors = descriptors.checked_add(1).ok_or(ResponseStop::Capacity)?;
                }
                WireEvent::Abort { stream } => {
                    let state = self
                        .scratch
                        .iter_mut()
                        .find(|state| state.stream == stream)
                        .ok_or(ResponseStop::Integrity)?;
                    state.stopped = true;
                }
                WireEvent::Quiescent { stream } => {
                    let state = self
                        .scratch
                        .iter_mut()
                        .find(|state| state.stream == stream)
                        .ok_or(ResponseStop::Integrity)?;
                    if state.quiescent {
                        return Err(ResponseStop::Integrity);
                    }
                    state.quiescent = true;
                }
            }
            if descriptors > self.max_spans {
                return Err(ResponseStop::Capacity);
            }
        }
        Ok(PreparedBatch {
            owner: self,
            events,
        })
    }

    #[cfg(test)]
    fn adopt_batch(&mut self, events: &[WireEvent]) -> Result<(), ResponseStop> {
        self.prepare_batch(events)?.commit();
        Ok(())
    }

    fn commit_batch(&mut self, events: &[WireEvent]) {
        for event in events {
            match *event {
                WireEvent::Part { stream, class, len } => {
                    let end = self.adopted + len as u64;
                    self.spans.push_back(Span {
                        start: self.adopted,
                        end,
                        stream,
                        class,
                    });
                    self.adopted = end;
                    if stream != 0 {
                        if let Some(entry) = self
                            .entries
                            .iter_mut()
                            .find(|entry| entry.cell.key.stream == stream)
                        {
                            entry.last_end = end;
                        }
                    }
                }
                WireEvent::End {
                    stream,
                    requirement,
                } => {
                    if let Some(entry) = self
                        .entries
                        .iter_mut()
                        .find(|entry| entry.cell.key.stream == stream)
                    {
                        entry.fence = Some(Fence {
                            end: self.adopted,
                            requirement,
                            flushed: false,
                            ready: false,
                        });
                    }
                }
                WireEvent::Abort { stream } => {
                    let _ = self.stop(stream, ResponseStop::Protocol);
                }
                WireEvent::Quiescent { stream } => {
                    let _ = self.quiescent(stream);
                }
            }
        }
    }

    /// The end of all attributed protocol output adopted so far.
    pub(crate) fn adopted_prefix(&self) -> u64 {
        self.adopted
    }

    /// The earliest unresolved finite-prefix fence; later wire output must wait for its operation.
    pub(crate) fn next_fence(&self) -> Option<(u64, CompletionRequirement)> {
        self.entries
            .iter()
            .filter_map(|entry| entry.fence.as_ref())
            .filter(|fence| !fence.ready)
            .min_by_key(|fence| fence.end)
            .map(|fence| (fence.end, fence.requirement))
    }

    /// Consume real carrier progress before interpreting every outer poll result, even errors.
    pub(crate) fn observe(&mut self, next: CarrierProgress) -> Result<(), ResponseStop> {
        let old = self.observed;
        if self.retired
            || self.poisoned
            || next.complete_records_plaintext > next.written_plaintext
            || next.written_plaintext > next.accepted_plaintext
            || next.accepted_plaintext > self.adopted
            || next.accepted_plaintext < old.accepted_plaintext
            || next.written_plaintext < old.written_plaintext
            || next.complete_records_plaintext < old.complete_records_plaintext
            || (old.fault.is_some() && next != old)
        {
            self.poisoned = true;
            return Err(ResponseStop::Integrity);
        }
        self.observed = next;
        while let Some(span) = self.spans.front_mut() {
            if span.start >= next.written_plaintext {
                break;
            }
            if span.class == WireClass::Payload {
                let entry = self
                    .entries
                    .iter()
                    .find(|entry| entry.cell.key.stream == span.stream)
                    .ok_or(ResponseStop::Integrity)?;
                let mut state = lock(&entry.cell.state);
                if state.snapshot.terminal.is_some() {
                    return Err(ResponseStop::Integrity);
                }
                state.snapshot.first_payload_written = true;
            }
            if span.end <= next.written_plaintext {
                self.spans.pop_front();
            } else {
                span.start = next.written_plaintext;
                break;
            }
        }
        next.fault
            .map_or(Ok(()), |fault| Err(ResponseStop::Carrier(fault)))
    }

    fn join(entry: &mut Entry) {
        let mut state = lock(&entry.cell.state);
        if state.snapshot.terminal.is_none()
            && state.cancel.is_none()
            && entry.stop.is_none()
            && state.released
            && state.producer_ended
            && state.reader_eof
            && entry.fence.as_ref().is_some_and(|fence| fence.ready)
        {
            state.snapshot.terminal = Some(DeliveryTerminal::Complete);
            state.settled_pending = true;
            drop(state);
            entry.cell.changed.notify_waiters();
            entry.cell.owner_wake.wake();
        }
    }

    fn completion(&mut self, prefix: u64, shutdown: bool) -> Result<(), ResponseStop> {
        if self.retired
            || self.poisoned
            || self.observed.fault.is_some()
            || prefix > self.observed.complete_records_plaintext
        {
            return Err(ResponseStop::Integrity);
        }
        for entry in &mut self.entries {
            if let Some(fence) = &mut entry.fence {
                if fence.end <= prefix {
                    if !shutdown {
                        fence.flushed = true;
                    }
                    if fence.flushed
                        && (fence.requirement == CompletionRequirement::Flush || shutdown)
                    {
                        fence.ready = true;
                    }
                }
            }
            Self::join(entry);
        }
        Ok(())
    }

    /// Record an actual successful flush for this finite prefix, after sampling its progress.
    pub(crate) fn complete_flush(&mut self, prefix: u64) -> Result<(), ResponseStop> {
        self.completion(prefix, false)
    }

    /// Record an actual successful carrier shutdown, never MemIo shutdown or queued close_notify.
    pub(crate) fn complete_shutdown(&mut self, prefix: u64) -> Result<(), ResponseStop> {
        self.completion(prefix, true)
    }

    /// Retain ordered producer end independently of the runtime feed slot's lifetime.
    pub(crate) fn producer_ended(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        lock(&self.entries[index].cell.state).producer_ended = true;
        if !self.poisoned && self.observed.fault.is_none() {
            Self::join(&mut self.entries[index]);
        }
        Ok(())
    }

    /// Retain actual reader EOF; dropping a body or its Bytes clones does not supply this fact.
    pub(crate) fn reader_eof(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        lock(&self.entries[index].cell.state).reader_eof = true;
        if !self.poisoned && self.observed.fault.is_none() {
            Self::join(&mut self.entries[index]);
        }
        Ok(())
    }

    /// Record that failed-response input producers/readers were actually cancelled and joined.
    /// This permits retirement after failure, but can never satisfy successful producer end/EOF.
    pub(crate) fn input_retired(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        lock(&self.entries[index].cell.state).input_retired = true;
        Ok(())
    }

    /// Record protocol quiescence, which forbids future serialized spans but proves no writes.
    pub(crate) fn quiescent(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        lock(&self.entries[index].cell.state).quiescent = true;
        Ok(())
    }

    /// Suppress future publication while retaining every pending interval until actual settlement.
    pub(crate) fn stop(&mut self, stream: u64, reason: ResponseStop) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        let entry = &mut self.entries[index];
        let mut state = lock(&entry.cell.state);
        if state.snapshot.terminal.is_none() {
            entry.stop.get_or_insert(reason);
            state.cancel.get_or_insert(reason);
            state.release_pending = false;
        }
        drop(state);
        entry.cell.owner_wake.wake();
        Ok(())
    }

    fn fail(entry: &mut Entry, reason: ResponseStop) {
        let mut state = lock(&entry.cell.state);
        if state.snapshot.terminal.is_none() {
            state.snapshot.terminal = Some(DeliveryTerminal::Failed(reason));
            state.release_pending = false;
            state.settled_pending = true;
            entry.fence = None;
            drop(state);
            entry.cell.changed.notify_waiters();
            entry.cell.owner_wake.wake();
        }
    }

    /// Freeze a stopped response only after the owner has settled its active carrier operation.
    ///
    /// Remaining serialized bytes must have actually written through complete records. Otherwise
    /// the owner must finish the indivisible frame/record under its bound or retire the carrier.
    pub(crate) fn settle_stopped(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        let entry = &mut self.entries[index];
        let state = lock(&entry.cell.state);
        if state.snapshot.terminal.is_some() {
            return Ok(());
        }
        let reason = entry.stop.or(state.cancel).ok_or(ResponseStop::Integrity)?;
        if !state.quiescent
            || self.spans.iter().any(|span| span.stream == stream)
            || self.observed.complete_records_plaintext < entry.last_end
        {
            return Err(ResponseStop::Integrity);
        }
        drop(state);
        Self::fail(entry, reason);
        Ok(())
    }

    /// Sample after actual carrier retirement, then fail all unfinished responses exactly once.
    ///
    /// The runtime must already have cancelled/joined every operation capable of a later write.
    pub(crate) fn retire_carrier(&mut self, last: CarrierProgress, reason: ResponseStop) {
        if self.retired {
            return;
        }
        let observed = self.observe(last);
        let reason = match observed {
            Err(ResponseStop::Integrity) => ResponseStop::Integrity,
            _ => reason,
        };
        self.retired = true;
        self.spans.clear();
        for entry in &mut self.entries {
            let reason = entry.stop.unwrap_or(reason);
            Self::fail(entry, reason);
        }
    }

    /// Acknowledge actual successful E_DELIVERY_SETTLED consumption by the protocol owner.
    pub(crate) fn settled_ack(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        let mut state = lock(&self.entries[index].cell.state);
        if !state.settled_sent || state.snapshot.terminal.is_none() {
            return Err(ResponseStop::Integrity);
        }
        state.settled_ack = true;
        Ok(())
    }

    /// Remove live binding only after protocol, input and settlement joins; handles retain debt.
    pub(crate) fn retire_response(&mut self, stream: u64) -> Result<(), ResponseStop> {
        let index = self.index(stream)?;
        let state = lock(&self.entries[index].cell.state);
        let input_done = match state.snapshot.terminal {
            Some(DeliveryTerminal::Complete) => state.producer_ended && state.reader_eof,
            Some(DeliveryTerminal::Failed(_)) => {
                state.input_retired || (state.producer_ended && state.reader_eof)
            }
            None => false,
        };
        if !input_done
            || !state.quiescent
            || !state.settled_ack
            || self.spans.iter().any(|span| span.stream == stream)
        {
            return Err(ResponseStop::Integrity);
        }
        drop(state);
        self.entries.swap_remove(index);
        Ok(())
    }
}
