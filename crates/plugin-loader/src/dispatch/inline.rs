// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INLINE TICKETS: the ticket space of ops the host drives ON THE CALLING THREAD (`abi::transport`:
//! "PER-CONNECTION TOKEN SPACE", "TWO TICKETS PER CONNECTION"). A carrier's connection is driven by
//! the task that polls it, inline, with no thread handoff (#30): its two sides each hold one of
//! these. A PENDING op on one registers the task's waker; the host's wake for the ticket (from
//! `io.*`, or a plugin's own `wake`) wakes that task, which re-invokes the op with `FLAG_RESUME`.
//!
//! An inline ticket's slot names a worker no dispatcher runs ([`INLINE_WORKER`]), so the pool
//! routes its wakes here and never to a worker. Its generation is bumped when it is dropped: a late
//! wake for a recycled ticket names a generation that no longer exists and is dropped.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Wake, Waker};

use busbar_contract::abi::mechanism::ticket::Ticket;
use futures::task::AtomicWaker;

use super::ticket::{decode, encode, recycled_generation, MAX_INDEX, MAX_WORKERS};

/// The worker an inline ticket's slot names: past every worker a dispatcher runs.
pub(crate) const INLINE_WORKER: u32 = MAX_WORKERS - 1;

/// One inline ticket's slot: its generation and the waker of the task driving it.
#[derive(Debug, Default)]
pub(crate) struct Slot {
    generation: AtomicU32,
    waker: AtomicWaker,
}

impl Wake for Slot {
    fn wake(self: Arc<Self>) {
        self.waker.wake();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.waker.wake();
    }
}

/// The inline tickets of one dispatcher.
#[derive(Debug, Default)]
pub struct InlineTickets {
    slots: Mutex<(Vec<Arc<Slot>>, Vec<u32>)>,
}

impl InlineTickets {
    /// Mint a ticket; `None` when every slot is held.
    pub(crate) fn mint(self: &Arc<Self>) -> Option<InlineTicket> {
        let mut held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let index = match held.1.pop() {
            Some(i) => i,
            None => {
                let i = u32::try_from(held.0.len()).ok().filter(|i| *i <= MAX_INDEX)?;
                held.0.push(Arc::new(Slot {
                    generation: AtomicU32::new(1),
                    waker: AtomicWaker::new(),
                }));
                i
            }
        };
        let slot = Arc::clone(&held.0[index as usize]);
        let ticket = Ticket {
            slot: encode(INLINE_WORKER, index),
            generation: slot.generation.load(Ordering::Acquire),
        };
        Some(InlineTicket {
            ticket,
            slot,
            owner: Arc::clone(self),
        })
    }

    fn slot(&self, t: Ticket) -> Option<Arc<Slot>> {
        let (w, i) = decode(t.slot);
        if w != INLINE_WORKER {
            return None;
        }
        let held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        held.0
            .get(i as usize)
            .filter(|s| s.generation.load(Ordering::Acquire) == t.generation)
            .cloned()
    }

    /// The waker of `t`'s task; `None` for a stale or foreign ticket.
    pub(crate) fn waker_of(&self, t: Ticket) -> Option<Waker> {
        self.slot(t).map(Waker::from)
    }

    /// Wake `t`'s task; a stale ticket is dropped.
    pub(crate) fn wake(&self, t: Ticket) {
        if let Some(s) = self.slot(t) {
            s.waker.wake();
        }
    }

    fn recycle(&self, index: u32, slot: &Slot) {
        let g = slot.generation.load(Ordering::Acquire);
        slot.generation
            .store(recycled_generation(g), Ordering::Release);
        slot.waker.take();
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .push(index);
    }
}

/// Whether `t` is an inline ticket.
#[must_use]
pub(crate) fn is_inline(t: Ticket) -> bool {
    decode(t.slot).0 == INLINE_WORKER
}

/// ONE INLINE TICKET, held by the side of a connection that drives ops on it. Dropping it recycles
/// the ticket: a late wake for it is dropped.
#[derive(Debug)]
pub struct InlineTicket {
    ticket: Ticket,
    slot: Arc<Slot>,
    owner: Arc<InlineTickets>,
}

impl InlineTicket {
    /// The ticket.
    #[must_use]
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// Register `waker` as the task an op pending on this ticket wakes.
    pub fn register(&self, waker: &Waker) {
        self.slot.waker.register(waker);
    }
}

impl Drop for InlineTicket {
    fn drop(&mut self) {
        let (_, index) = decode(self.ticket.slot);
        self.owner.recycle(index, &self.slot);
    }
}
