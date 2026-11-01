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
}

#[derive(Debug, Default)]
struct State {
    used: usize,
    readers: usize,
    closed: bool,
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

    pub(crate) fn readers(&self) -> bool {
        lock(&self.state).readers != 0
    }

    pub(crate) fn register(&self, waker: &std::task::Waker) {
        self.wake.register(waker);
    }

    pub(crate) fn can_fit(&self, bytes: usize) -> bool {
        Self::reservation_size(bytes)
            .is_some_and(|bytes| self.limit.is_none_or(|limit| bytes <= limit))
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
    pub(crate) async fn reader_progress(&self) -> bool {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let state = lock(&self.state);
            if state.closed || state.readers == 0 {
                return false;
            }
        }
        changed.await;
        !lock(&self.state).closed
    }

    pub(crate) fn close(&self) {
        lock(&self.state).closed = true;
        self.changed.notify_waiters();
        self.wake.wake();
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
        lock(&lease.memory.state).used -= released;
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
        let memory = self.0.as_ref().map(|lease| Arc::clone(&lease.memory));
        if let Some(memory) = &memory {
            lock(&memory.state).readers += 1;
        }
        ReaderCustody {
            custody: self.clone(),
            memory,
        }
    }
}

/// Reader ownership of charged output. Release follows consumption, including partial reads.
#[derive(Debug)]
pub struct ReaderCustody {
    custody: Custody,
    memory: Option<Arc<Memory>>,
}

impl Drop for ReaderCustody {
    fn drop(&mut self) {
        let custody = std::mem::take(&mut self.custody);
        drop(custody);
        if let Some(memory) = &self.memory {
            lock(&memory.state).readers -= 1;
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
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = lock(&self.state);
                if let Some(node) = state.head.take() {
                    let MessageNode { message, next } = *node;
                    state.head = next;
                    state.len -= 1;
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
            let MessageNode { message, next } = *node;
            state.head = next;
            state.len -= 1;
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
        let MessageNode { message, next } = *node;
        state.head = next;
        state.len -= 1;
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
