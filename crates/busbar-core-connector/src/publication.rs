// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Requested storage held by one datagram pairing, including storage handed to its readers.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A pair's optional limit. This accounts requested storage, not allocator retention or RSS.
#[derive(Debug)]
pub struct Memory {
    limit: Option<usize>,
    state: Mutex<State>,
    pub(crate) changed: tokio::sync::Notify,
    wake: futures::task::AtomicWaker,
    observer: Mutex<std::sync::Weak<crate::datagram::Pairing>>,
}

#[derive(Debug, Default)]
struct State {
    used: usize,
    readers: usize,
    readers_by_leg: [usize; 2],
    transfers: usize,
    closed: bool,
    producers: usize,
    generation: u64,
}

pub(crate) enum ReservationError {
    Pending,
    Exhausted,
    Closed,
}
pub(crate) enum Progress {
    Changed,
    Pending,
    Exhausted,
    Closed,
}

impl Memory {
    pub(crate) fn reservation_size(bytes: usize) -> Option<usize> {
        bytes.checked_add(std::mem::size_of::<Lease>() + 2 * std::mem::size_of::<usize>())
    }
    /// Capture the limit once for this pairing. `None` preserves unlimited custody.
    #[must_use]
    pub fn new(limit: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(State::default()),
            changed: tokio::sync::Notify::new(),
            wake: futures::task::AtomicWaker::new(),
            observer: Mutex::new(std::sync::Weak::new()),
        })
    }

    /// The captured configured limit.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Requested storage still in host custody.
    #[must_use]
    pub fn used(&self) -> usize {
        lock(&self.state).used
    }

    pub(crate) fn generation(&self) -> u64 {
        lock(&self.state).generation
    }

    pub(crate) fn progress(&self, generation: u64, pending: bool) -> Progress {
        let state = lock(&self.state);
        if state.closed {
            Progress::Closed
        } else if state.generation != generation {
            Progress::Changed
        } else if pending || state.transfers != 0 || state.producers != 0 {
            Progress::Pending
        } else {
            Progress::Exhausted
        }
    }

    pub(crate) fn input(
        self: &Arc<Self>,
        bytes: usize,
        pending: bool,
        source_leg: Option<usize>,
    ) -> Result<Custody, ReservationError> {
        let bytes = Self::reservation_size(bytes).ok_or(ReservationError::Exhausted)?;
        {
            let mut state = lock(&self.state);
            if state.closed {
                return Err(ReservationError::Closed);
            }
            if self.limit.is_none() {
                return Ok(Custody::default());
            }
            let limit = self.limit.expect("a configured limit");
            if state
                .used
                .checked_add(bytes)
                .is_none_or(|used| used > limit)
            {
                return Err(
                    if bytes <= limit
                        && (pending
                            || state.transfers != 0
                            || state.producers != 0
                            || source_leg.is_some_and(|leg| state.readers_by_leg[1 - leg] != 0))
                    {
                        ReservationError::Pending
                    } else {
                        ReservationError::Exhausted
                    },
                );
            }
            state.used += bytes;
        }
        Ok(Custody(Some(Arc::new(Lease {
            memory: Arc::clone(self),
            bytes,
            previous: Custody::default(),
        }))))
    }

    pub(crate) fn observe(&self, pairing: std::sync::Weak<crate::datagram::Pairing>) {
        *lock(&self.observer) = pairing;
    }

    pub(crate) fn retired(&self) -> bool {
        let state = lock(&self.state);
        state.closed && state.producers == 0
    }

    pub(crate) fn producer(self: &Arc<Self>) -> Option<ProducerCustody> {
        {
            let mut state = lock(&self.state);
            if state.closed {
                return None;
            }
            state.producers += 1;
        }
        Some(ProducerCustody(Some(Arc::new(Producer {
            memory: Some(Arc::clone(self)),
            previous: ProducerCustody::default(),
        }))))
    }

    pub(crate) fn register(&self, waker: &std::task::Waker) {
        self.wake.register(waker);
    }

    /// Reserve before allocating or crossing a framer. Failed reservations allocate nothing.
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Custody> {
        if self.limit.is_none() {
            return Some(Custody::default());
        }
        let bytes = Self::reservation_size(bytes)?;
        {
            let mut state = lock(&self.state);
            let used = state.used.checked_add(bytes)?;
            if state.closed || self.limit.is_some_and(|limit| used > limit) {
                return None;
            }
            state.used = used;
        }
        Some(Custody(Some(Arc::new(Lease {
            memory: Arc::clone(self),
            bytes,
            previous: Custody::default(),
        }))))
    }

    /// A reservation failure may wait only while an actual reader owns releasable storage.
    pub(crate) async fn reader_progress(&self, generation: u64) -> bool {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let state = lock(&self.state);
            if state.closed {
                return false;
            }
            if state.generation != generation {
                return true;
            }
            if state.transfers == 0 && state.producers == 0 {
                return false;
            }
        }
        changed.await;
        !lock(&self.state).closed
    }

    pub(crate) fn close(&self) {
        {
            let mut state = lock(&self.state);
            state.closed = true;
            state.generation = state.generation.wrapping_add(1);
        }
        self.changed.notify_waiters();
        self.wake.wake();
    }
}

#[derive(Debug)]
struct Producer {
    memory: Option<Arc<Memory>>,
    previous: ProducerCustody,
}

impl Drop for Producer {
    fn drop(&mut self) {
        let Some(memory) = self.memory.take() else {
            return;
        };
        let mut count = 1;
        let mut previous = std::mem::take(&mut self.previous).0;
        while let Some(producer) = previous {
            match Arc::try_unwrap(producer) {
                Ok(mut producer) => {
                    previous = std::mem::take(&mut producer.previous).0;
                    producer.memory = None;
                    count += 1;
                }
                Err(producer) => {
                    drop(producer);
                    break;
                }
            }
        }
        let retired = {
            let mut state = lock(&memory.state);
            state.producers -= count;
            state.generation = state.generation.wrapping_add(1);
            state.closed && state.producers == 0
        };
        memory.changed.notify_waiters();
        memory.wake.wake();
        if retired {
            let pairing = lock(&memory.observer).upgrade();
            if let Some(pairing) = pairing {
                pairing.retire_metadata_if_closed();
            }
        }
    }
}

/// A checked producer still owns either its crossing or output awaiting classification.
/// This preserves stream identity through a concurrent terminal close without keeping it forever.
#[derive(Debug, Default, Clone)]
pub struct ProducerCustody(Option<Arc<Producer>>);

impl PartialEq for ProducerCustody {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for ProducerCustody {}

impl ProducerCustody {
    pub(crate) fn prepend(&mut self, previous: Self) {
        if let Some(producer) = &mut self.0 {
            Arc::get_mut(producer)
                .expect("a fresh producer is not shared")
                .previous = previous;
        } else {
            *self = previous;
        }
    }
}

#[derive(Debug)]
struct Lease {
    memory: Arc<Memory>,
    bytes: usize,
    previous: Custody,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let mut released = self.bytes;
        let mut previous = std::mem::take(&mut self.previous).0;
        while let Some(lease) = previous {
            match Arc::try_unwrap(lease) {
                Ok(mut lease) if Arc::ptr_eq(&self.memory, &lease.memory) => {
                    previous = std::mem::take(&mut lease.previous).0;
                    released += lease.bytes;
                    lease.bytes = 0;
                }
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(lease) => {
                    drop(lease);
                    break;
                }
            }
        }
        {
            let mut state = lock(&self.memory.state);
            state.used -= released;
            state.generation = state.generation.wrapping_add(1);
        }
        self.memory.changed.notify_waiters();
        self.memory.wake.wake();
    }
}

/// A shared storage reservation. Moving bytes to another host owner retains this reservation.
/// Cloning custody adds a reference to the same allocation; it never copies payload storage.
#[derive(Debug, Default, Clone)]
pub struct Custody(Option<Arc<Lease>>);

// Storage identity is deliberately absent from semantic output equality.
impl PartialEq for Custody {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for Custody {}

impl Custody {
    pub(crate) fn tracked(&self) -> bool {
        self.0.is_some()
    }
    /// Split already reserved storage into an independent owner before the parent reservation
    /// is shared. The child allocation and its Arc header are paid from pre-crossing credit.
    pub(crate) fn split(&mut self, bytes: usize) -> Self {
        let Some(lease) = self.0.as_mut() else {
            return Self::default();
        };
        let lease =
            Arc::get_mut(lease).expect("a producer splits only exclusive pre-crossing credit");
        let bytes = bytes
            .checked_add(std::mem::size_of::<Lease>() + 2 * std::mem::size_of::<usize>())
            .expect("the checked pre-crossing reservation covers owner layout");
        assert!(
            bytes <= lease.bytes,
            "an owner exceeded the pre-crossing reservation"
        );
        lease.bytes -= bytes;
        Self(Some(Arc::new(Lease {
            memory: Arc::clone(&lease.memory),
            bytes,
            previous: Self::default(),
        })))
    }

    /// Return unused pre-crossing credit once every requested allocation is known. This is
    /// only valid before the fresh reservation is shared with publication or reader owners.
    pub(crate) fn reduce(&mut self, retained: usize) {
        let Some(lease) = self.0.as_mut() else {
            return;
        };
        let lease =
            Arc::get_mut(lease).expect("a producer releases unused credit before sharing it");
        let retained = retained
            .checked_add(std::mem::size_of::<Lease>() + 2 * std::mem::size_of::<usize>())
            .expect("retained storage was covered by the checked pre-crossing bound");
        assert!(
            retained <= lease.bytes,
            "the retained storage exceeded its pre-crossing reservation"
        );
        let released = lease.bytes - retained;
        lease.bytes = retained;
        {
            let mut state = lock(&lease.memory.state);
            state.used -= released;
            if released != 0 {
                state.generation = state.generation.wrapping_add(1);
            }
        }
        lease.memory.changed.notify_waiters();
        lease.memory.wake.wake();
    }

    /// Chain a fresh batch's reservation to older eager output without another allocation.
    pub fn prepend(&mut self, older: Self) {
        if let Some(lease) = self.0.as_mut() {
            Arc::get_mut(lease)
                .expect("a fresh batch has exclusive reservation custody")
                .previous = older;
        } else {
            *self = older;
        }
    }

    /// Transfer to a reader. The guard survives until actual payload consumption or teardown.
    #[must_use]
    pub fn reader(&self) -> ReaderCustody {
        self.reader_for(None)
    }

    /// Transfer storage to this leg's reader. Queued bytes on the writer's own leg cannot be
    /// assumed independently consumable while that writer is blocking its reader task.
    #[must_use]
    pub fn reader_on(&self, leg: crate::datagram::Leg) -> ReaderCustody {
        self.reader_for(Some(match leg {
            crate::datagram::Leg::Caller => 0,
            crate::datagram::Leg::Upstream => 1,
        }))
    }

    fn reader_for(&self, leg: Option<usize>) -> ReaderCustody {
        let memory = self.0.as_ref().map(|lease| Arc::clone(&lease.memory));
        if let Some(memory) = &memory {
            let mut state = lock(&memory.state);
            state.readers += 1;
            if let Some(leg) = leg {
                state.readers_by_leg[leg] += 1;
            }
        }
        ReaderCustody {
            custody: self.clone(),
            memory,
            transfer: None,
            leg,
        }
    }
}

/// Reader ownership of charged output. Release follows consumption, including partial reads.
#[derive(Debug)]
pub struct ReaderCustody {
    custody: Custody,
    memory: Option<Arc<Memory>>,
    transfer: Option<Transfer>,
    leg: Option<usize>,
}

/// An actual read/copy or receiver handoff which can retire charged storage without another
/// producer crossing. Queued ownership alone is not such a transfer.
#[derive(Debug, Default)]
pub struct Transfer(Option<Arc<Memory>>);

impl Transfer {
    fn new(memory: Option<&Arc<Memory>>) -> Self {
        if let Some(memory) = memory {
            lock(&memory.state).transfers += 1;
        }
        Self(memory.cloned())
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if let Some(memory) = &self.0 {
            {
                let mut state = lock(&memory.state);
                state.transfers -= 1;
                state.generation = state.generation.wrapping_add(1);
            }
            memory.changed.notify_waiters();
            memory.wake.wake();
        }
    }
}

impl ReaderCustody {
    /// Mark a synchronous copy as in flight. Drop its guard after the queue lock is released.
    #[must_use]
    pub fn copying(&self) -> Transfer {
        Transfer::new(self.memory.as_ref())
    }

    fn receiving(&mut self, transfer: Option<Transfer>) -> Option<Transfer> {
        if self.transfer.is_none() {
            self.transfer = Some(transfer.unwrap_or_else(|| self.copying()));
            None
        } else {
            transfer
        }
    }
}

impl Drop for ReaderCustody {
    fn drop(&mut self) {
        let custody = std::mem::take(&mut self.custody);
        drop(custody);
        if let Some(memory) = &self.memory {
            {
                let mut state = lock(&memory.state);
                state.readers -= 1;
                if let Some(leg) = self.leg {
                    state.readers_by_leg[leg] -= 1;
                }
                state.generation = state.generation.wrapping_add(1);
            }
            memory.changed.notify_waiters();
            memory.wake.wake();
        }
    }
}

/// One channel message and the reservation retained through the reader's last byte.
#[derive(Debug)]
pub struct Message {
    /// The copied opaque payload.
    pub bytes: Vec<u8>,
    /// Whether its last byte ends the message.
    pub end: bool,
    /// Bytes consumed without allocating a copied suffix.
    pub consumed: usize,
    /// Storage remains charged while this message is queued or partially read.
    pub custody: ReaderCustody,
}

impl<T: AsRef<[u8]>> PartialEq<T> for Message {
    fn eq(&self, other: &T) -> bool {
        self.bytes == other.as_ref()
    }
}

/// A bounded channel-reader queue with one charged allocation per live message. It retains
/// no spare descriptor capacity after a message is consumed.
#[derive(Debug)]
pub struct Messages {
    capacity: usize,
    state: Mutex<MessagesState>,
    ready: tokio::sync::Notify,
    wake: futures::task::AtomicWaker,
}

#[derive(Debug, Default)]
struct MessagesState {
    head: Option<Box<MessageNode>>,
    len: usize,
    closed: bool,
    waiters: usize,
    handoff: Option<Transfer>,
}

struct Receiving<'a>(&'a Messages);

impl Drop for Receiving<'_> {
    fn drop(&mut self) {
        let retired = {
            let mut state = lock(&self.0.state);
            state.waiters -= 1;
            if state.waiters == 0 {
                state.handoff.take()
            } else {
                None
            }
        };
        drop(retired);
    }
}

#[derive(Debug)]
struct MessageNode {
    message: Message,
    next: Option<Box<MessageNode>>,
}

impl Messages {
    /// Create the existing endpoint's descriptor-count bound without allocating its slots.
    #[must_use]
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            state: Mutex::new(MessagesState::default()),
            ready: tokio::sync::Notify::new(),
            wake: futures::task::AtomicWaker::new(),
        })
    }

    /// Transfer an already charged message; no payload copy is made.
    ///
    /// # Errors
    /// The endpoint closed or its existing descriptor bound is reached. The message is returned.
    pub fn send(&self, message: Message) -> Result<(), Message> {
        {
            let mut state = lock(&self.state);
            if state.closed || state.len == self.capacity {
                return Err(message);
            }
            if state.waiters != 0 && state.handoff.is_none() {
                state.handoff = Some(message.custody.copying());
            }
            let mut tail = &mut state.head;
            while let Some(node) = tail {
                tail = &mut node.next;
            }
            *tail = Some(Box::new(MessageNode {
                message,
                next: None,
            }));
            state.len += 1;
        }
        self.ready.notify_one();
        self.wake.wake();
        Ok(())
    }

    /// Wait for and take one message. Custody moves with it until actual reader retirement.
    pub async fn recv(&self) -> Option<Message> {
        lock(&self.state).waiters += 1;
        let _receiving = Receiving(self);
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = lock(&self.state);
                if let Some(node) = state.head.take() {
                    let MessageNode { mut message, next } = *node;
                    state.head = next;
                    state.len -= 1;
                    let retired = message.custody.receiving(state.handoff.take());
                    drop(state);
                    drop(retired);
                    return Some(message);
                }
                if state.closed {
                    return None;
                }
            }
            ready.await;
        }
    }

    /// Register a nonblocking reader. The actual wake runs after the queue lock is released.
    pub fn poll_recv(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Message>> {
        self.wake.register(cx.waker());
        let mut state = lock(&self.state);
        if let Some(node) = state.head.take() {
            let MessageNode { mut message, next } = *node;
            state.head = next;
            state.len -= 1;
            let retired = message.custody.receiving(state.handoff.take());
            drop(state);
            drop(retired);
            return std::task::Poll::Ready(Some(message));
        }
        if state.closed {
            std::task::Poll::Ready(None)
        } else {
            std::task::Poll::Pending
        }
    }

    /// Take an already queued message, for source controls and nonblocking readers.
    ///
    /// # Errors
    /// No message is queued.
    pub fn try_recv(&self) -> Result<Message, std::sync::mpsc::TryRecvError> {
        let mut state = lock(&self.state);
        let node = state
            .head
            .take()
            .ok_or(std::sync::mpsc::TryRecvError::Empty)?;
        let MessageNode { mut message, next } = *node;
        state.head = next;
        state.len -= 1;
        let retired = message.custody.receiving(state.handoff.take());
        drop(state);
        drop(retired);
        Ok(message)
    }

    /// Close the producer. Already accepted messages remain readable and charged until the
    /// reader consumes them or the endpoint itself is destroyed.
    pub fn close(&self) {
        lock(&self.state).closed = true;
        self.ready.notify_waiters();
        self.wake.wake();
    }
}

impl Drop for Messages {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        let mut head = state.head.take();
        while let Some(mut node) = head {
            head = node.next.take();
        }
    }
}

#[cfg(test)]
#[path = "tests/publication_tests.rs"]
mod tests;
