// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INLINE TICKETS: the ticket space of ops the host drives ON THE CALLING THREAD (`abi::transport`:
//! "PER-CONNECTION TOKEN SPACE", "TWO TICKETS PER CONNECTION"). A carrier's connection is driven by
//! the task that polls it, inline, with no thread handoff (#30): its two sides each hold one of
//! these. A PENDING op on one registers the task's waker; the host's wake for the ticket (from
//! `io.*`, or a plugin's own `wake`) wakes that task, which re-invokes the op with `FLAG_RESUME`.
//!
//! An inline ticket's slot names a worker no dispatcher runs ([`INLINE_WORKER`]), so the pool
//! routes its wakes here and never to a worker. Its generation is a worker slot's (#74): the keyed
//! permutation of the slot's mint counter ([`super::handle::ticket_generation`] under
//! [`INLINE_WORKER`]), advanced when the ticket is dropped. A wake whose generation matches no held
//! ticket is judged by the permutation's inverse ([`Judged`]): one the slot minted is a late wake,
//! dropped; one it never minted is a FORGERY, blamed on the wake's supplier. A slot whose counter is
//! spent is RETIRED, never handed out again.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Wake, Waker};

use busbar_contract::abi::mechanism::ticket::Ticket;
use futures::task::AtomicWaker;

use super::handle::{ticket_count, ticket_generation, TicketKey};
use super::ticket::{decode, encode, MAX_INDEX, MAX_WORKERS};

/// The worker an inline ticket's slot names: past every worker a dispatcher runs.
pub(crate) const INLINE_WORKER: u32 = MAX_WORKERS - 1;

/// One inline ticket's slot: its mint counter, its generation (`0` once RETIRED: no ticket is
/// handed out on it again) and the waker of the task driving it.
#[derive(Debug, Default)]
pub(crate) struct Slot {
    count: AtomicU32,
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

/// What a wake for an inline ticket found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judged {
    /// A held ticket's task, woken.
    Woken,
    /// A generation the slot minted, no longer held: a late wake, dropped.
    Stale,
    /// A generation no slot ever minted (#74): the wake's supplier is to blame.
    Forged,
}

/// The inline tickets of one dispatcher.
pub struct InlineTickets {
    /// The dispatcher's ticket key: inline generations are permuted as a worker slot's.
    key: TicketKey,
    slots: Mutex<(Vec<Arc<Slot>>, Vec<u32>)>,
}

impl std::fmt::Debug for InlineTickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineTickets").finish_non_exhaustive()
    }
}

impl InlineTickets {
    /// The inline tickets of a dispatcher whose ticket key is `key`.
    pub(crate) fn new(key: TicketKey) -> Self {
        Self {
            key,
            slots: Mutex::default(),
        }
    }

    /// Mint a ticket; `None` when every slot is held.
    pub(crate) fn mint(self: &Arc<Self>) -> Option<InlineTicket> {
        let mut held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let index = match held.1.pop() {
            Some(i) => i,
            None => {
                let i = u32::try_from(held.0.len())
                    .ok()
                    .filter(|i| *i <= MAX_INDEX)?;
                held.0.push(Arc::new(Slot {
                    count: AtomicU32::new(1),
                    generation: AtomicU32::new(ticket_generation(self.key, INLINE_WORKER, i, 1)),
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

    /// The slot `t` names and whether `t` is its held ticket; `None` for no slot.
    fn lookup(&self, t: Ticket) -> Option<(Arc<Slot>, bool)> {
        let (w, i) = decode(t.slot);
        if w != INLINE_WORKER {
            return None;
        }
        let held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = Arc::clone(held.0.get(i as usize)?);
        drop(held);
        let g = slot.generation.load(Ordering::Acquire);
        let live = g != 0 && g == t.generation;
        Some((slot, live))
    }

    fn slot(&self, t: Ticket) -> Option<Arc<Slot>> {
        self.lookup(t).and_then(|(s, live)| live.then_some(s))
    }

    /// The waker of `t`'s task; `None` for a stale or foreign ticket.
    pub(crate) fn waker_of(&self, t: Ticket) -> Option<Waker> {
        self.slot(t).map(Waker::from)
    }

    /// Wake `t`'s task, judging a `t` that is not held (#74): a generation the slot minted is a late
    /// wake, dropped; anything else (no such slot, or a generation whose inverse names no count the
    /// slot reached; `NONE`, generation 0, is a late wake by rule) is [`Judged::Forged`]. No lock is
    /// held when this returns, so the caller blames the supplier lock-free.
    pub(crate) fn wake(&self, t: Ticket) -> Judged {
        if t.generation == 0 {
            return Judged::Stale;
        }
        let Some((slot, live)) = self.lookup(t) else {
            return Judged::Forged;
        };
        if live {
            slot.waker.wake();
            return Judged::Woken;
        }
        let (_, i) = decode(t.slot);
        let c = ticket_count(self.key, INLINE_WORKER, i, t.generation);
        if c >= 1 && c <= slot.count.load(Ordering::Acquire) {
            Judged::Stale
        } else {
            Judged::Forged
        }
    }

    /// The ticket on `index` is dropped: its counter advances and the slot goes back, or, its counter
    /// spent, the slot is RETIRED (generation `0`, never back on the free list), so no generation of
    /// it is ever minted twice.
    fn recycle(&self, index: u32, slot: &Slot) {
        let next = super::worker::next_count(slot.count.load(Ordering::Acquire));
        // The count first: a late wake for the generation being retired always inverts to a count
        // the slot has reached.
        if let Some(c) = next {
            slot.count.store(c, Ordering::Release);
        }
        let g = next.map_or(0, |c| ticket_generation(self.key, INLINE_WORKER, index, c));
        slot.generation.store(g, Ordering::Release);
        slot.waker.take();
        if next.is_some() {
            self.slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1
                .push(index);
        }
    }

    /// TEST ONLY: the ticket `t`'s slot as if handed out `count` times; its ticket at that count.
    #[cfg(test)]
    pub(crate) fn seed_count(&self, t: Ticket, count: u32) -> Ticket {
        let (_, i) = decode(t.slot);
        let slot = self.lookup(t).expect("an inline slot").0;
        let g = ticket_generation(self.key, INLINE_WORKER, i, count);
        slot.count.store(count, Ordering::Release);
        slot.generation.store(g, Ordering::Release);
        Ticket {
            slot: t.slot,
            generation: g,
        }
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
