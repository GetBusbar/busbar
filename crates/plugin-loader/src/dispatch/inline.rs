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
//!
//! THE RESULTS KEPT UNDER AN INLINE TICKET are an op's own, as a worker ticket's are (THE DESIGN
//! §11.12, "the host never runs a service twice"; §11.11 H2): the dispatcher's stored service
//! results and the connector's kept answers under the ticket are forgotten when a NEW op (not a
//! resume, and not the one re-call a short answer earns) starts on it ([`InlineTickets::starting`]),
//! and when the ticket is dropped. Kept, the next op, whose handles count from 0 again, would
//! redeem the last op's answer (the same random bytes, a stale verdict) and the entries would never
//! be freed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Wake, Waker};

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::InstanceId;

use super::services::ServiceStore;

use super::handle::{ticket_count, ticket_generation, TicketKey};
use super::ticket::{decode, encode, MAX_INDEX, MAX_WORKERS};

/// The worker an inline ticket's slot names: past every worker a dispatcher runs.
pub(crate) const INLINE_WORKER: u32 = MAX_WORKERS - 1;

/// One inline ticket's slot: its mint counter, and its generation with the waker of the task
/// driving it under ONE per-slot section ([`Held`]).
#[derive(Debug, Default)]
pub(crate) struct Slot {
    /// How many times the slot was handed out; only grows (read lock-free by the judgement).
    count: AtomicU32,
    held: Mutex<Held>,
}

/// THE SLOT'S SECTION: the generation it holds (`0` once RETIRED: no ticket is handed out on it
/// again) and the waker of the task driving that generation. A recycle bumps (or retires) the
/// generation and clears the waker in it; a wake checks the generation and takes the waker in it.
/// So a wake for one generation never takes the waker a later generation's task registered.
#[derive(Debug, Default)]
struct Held {
    generation: u32,
    waker: Option<Waker>,
    /// The instance whose ops this generation drove: its kept connector answers under the ticket
    /// are forgotten with the ticket.
    instance: Option<InstanceId>,
    /// The op whose last call answered short: the one re-call it earns reads the results it kept.
    short: Option<u32>,
}

impl Slot {
    fn section(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The generation the slot holds now.
    fn generation(&self) -> u32 {
        self.section().generation
    }

    /// Wake the task of `generation`, if the slot still holds it: the generation is checked and the
    /// waker taken in the section; it is woken once the section is let go (a `Waker::wake` only
    /// schedules, and the waker taken is that generation's task's, whatever happens after). `false`:
    /// the slot holds another generation, and nothing is woken.
    fn wake_generation(&self, generation: u32) -> bool {
        let taken = {
            let mut held = self.section();
            if generation == 0 || held.generation != generation {
                return false;
            }
            held.waker.take()
        };
        if let Some(w) = taken {
            w.wake();
        }
        true
    }
}

/// THE WAKER OF ONE GENERATION of an inline slot (what [`InlineTickets::waker_of`] hands the host's
/// I/O): it wakes the slot's task only while the slot still holds that generation. Fired after the
/// slot was recycled and re-minted, it is a late wake: nothing is woken and no one is blamed (the
/// host held it, not a forger).
struct GenerationWaker {
    slot: Arc<Slot>,
    generation: u32,
}

impl Wake for GenerationWaker {
    fn wake(self: Arc<Self>) {
        self.slot.wake_generation(self.generation);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.slot.wake_generation(self.generation);
    }
}

#[cfg(test)]
thread_local! {
    /// THE TEST HOOK between a wake's lookup and its section: what runs here (a recycle and a
    /// re-mint) races the wake as another thread would.
    pub(crate) static BETWEEN_LOOKUP_AND_WAKE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
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
    /// The dispatcher's service results, which keep what an op on an inline ticket was answered.
    services: Weak<ServiceStore>,
}

impl std::fmt::Debug for InlineTickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineTickets").finish_non_exhaustive()
    }
}

impl InlineTickets {
    /// The inline tickets of a dispatcher whose ticket key is `key` and whose service results
    /// `services` keeps.
    pub(crate) fn new(key: TicketKey, services: &Arc<ServiceStore>) -> Self {
        Self {
            key,
            slots: Mutex::default(),
            services: Arc::downgrade(services),
        }
    }

    /// An op of `instance`'s op `s` is about to cross on the inline ticket `t`. A NEW op (not a
    /// `resume`, and not the one re-call of an op whose last call answered short) starts with
    /// nothing kept: the last op's stored service results and kept connector answers under `t` go,
    /// ending their epoch, so a service of the last op still running completes into nothing.
    pub(crate) fn starting(&self, t: Ticket, instance: InstanceId, s: u32, resume: bool) {
        let Some(slot) = self.lookup(t) else {
            return;
        };
        let fresh = {
            let mut held = slot.section();
            if held.generation == 0 || held.generation != t.generation {
                return;
            }
            held.instance = Some(instance);
            !resume && held.short.take() != Some(s)
        };
        if fresh {
            if let Some(store) = self.services.upgrade() {
                store.forget(t);
            }
            // No lock is held here: the dials it left in flight close at once.
            drop(super::conn_services::forget(instance, t));
        }
    }

    /// The op `s` on the inline ticket `t` returned; `short`: it answered short, and its one
    /// re-call reads what it kept.
    pub(crate) fn ended(&self, t: Ticket, s: u32, short: bool) {
        let Some(slot) = self.lookup(t) else {
            return;
        };
        let mut held = slot.section();
        if held.generation != 0 && held.generation == t.generation {
            held.short = short.then_some(s);
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
                    held: Mutex::new(Held {
                        generation: ticket_generation(self.key, INLINE_WORKER, i, 1),
                        waker: None,
                        instance: None,
                        short: None,
                    }),
                }));
                i
            }
        };
        let slot = Arc::clone(&held.0[index as usize]);
        let ticket = Ticket {
            slot: encode(INLINE_WORKER, index),
            generation: slot.generation(),
        };
        Some(InlineTicket {
            ticket,
            slot,
            owner: Arc::clone(self),
        })
    }

    /// The slot `t` names; `None` for no slot.
    fn lookup(&self, t: Ticket) -> Option<Arc<Slot>> {
        let (w, i) = decode(t.slot);
        if w != INLINE_WORKER {
            return None;
        }
        let held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        held.0.get(i as usize).cloned()
    }

    /// The waker of `t`'s task, bound to `t`'s generation ([`GenerationWaker`]); `None` for a
    /// ticket the slot does not hold now, or a foreign one.
    pub(crate) fn waker_of(&self, t: Ticket) -> Option<Waker> {
        let slot = self.lookup(t)?;
        let generation = slot.generation();
        (generation != 0 && generation == t.generation)
            .then(|| Waker::from(Arc::new(GenerationWaker { slot, generation })))
    }

    /// Wake `t`'s task, judging a `t` that is not held (#74): a generation the slot minted is a late
    /// wake, dropped; anything else (no such slot, or a generation whose inverse names no count the
    /// slot reached; `NONE`, generation 0, is a late wake by rule) is [`Judged::Forged`]. No lock is
    /// held when this returns, so the caller blames the supplier lock-free.
    pub(crate) fn wake(&self, t: Ticket) -> Judged {
        if t.generation == 0 {
            return Judged::Stale;
        }
        let Some(slot) = self.lookup(t) else {
            return Judged::Forged;
        };
        #[cfg(test)]
        if let Some(between) = BETWEEN_LOOKUP_AND_WAKE.with(|h| h.borrow_mut().take()) {
            between();
        }
        // The generation checked and the waker taken in the slot's section: a recycle and re-mint
        // racing this wake cannot hand it the next generation's task.
        if slot.wake_generation(t.generation) {
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
        // The generation and the waker go together, in the section: no wake for the old
        // generation takes a waker from here on, and the next task registers on a clean slot.
        let (gone, instance, old) = {
            let mut held = slot.section();
            let old = held.generation;
            held.generation = g;
            held.short = None;
            (held.waker.take(), held.instance.take(), old)
        };
        drop(gone);
        // What the dropped ticket's last op kept goes with it, before its slot can be handed out.
        let dropped = Ticket {
            slot: encode(INLINE_WORKER, index),
            generation: old,
        };
        if old != 0 {
            if let Some(store) = self.services.upgrade() {
                store.forget(dropped);
            }
            if let Some(instance) = instance {
                // No lock is held here: the dials it left in flight close at once.
                drop(super::conn_services::forget(instance, dropped));
            }
        }
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
        let slot = self.lookup(t).expect("an inline slot");
        let g = ticket_generation(self.key, INLINE_WORKER, i, count);
        slot.count.store(count, Ordering::Release);
        slot.section().generation = g;
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

    /// Register `waker` as the task an op pending on this ticket wakes (in the slot's section: the
    /// ticket is held, so the slot holds its generation).
    pub fn register(&self, waker: &Waker) {
        let mut held = self.slot.section();
        if !held.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
            held.waker = Some(waker.clone());
        }
    }
}

impl Drop for InlineTicket {
    fn drop(&mut self) {
        let (_, index) = decode(self.ticket.slot);
        self.owner.recycle(index, &self.slot);
    }
}
