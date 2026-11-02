// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Wake, Waker};

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::InstanceId;

use super::services::ServiceStore;

use super::handle::{ticket_count, ticket_generation, TicketKey};
use super::ticket::{decode, encode, MAX_INDEX, MAX_WORKERS};

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
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
}

impl Slot {
    fn section(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn generation(&self) -> u32 {
        self.section().generation
    }

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

pub struct InlineTickets {
    key: TicketKey,
    slots: Mutex<(Vec<Arc<Slot>>, Vec<u32>)>,

    services: Weak<ServiceStore>,
}

impl std::fmt::Debug for InlineTickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineTickets").finish_non_exhaustive()
    }
}

impl InlineTickets {
    pub(crate) fn new(key: TicketKey, services: &Arc<ServiceStore>) -> Self {
        Self {
            key,
            slots: Mutex::default(),
            services: Arc::downgrade(services),
        }
    }

    pub(crate) fn starting(&self, t: Ticket, instance: InstanceId, s: u32, resume: bool) -> bool {
        let Some(slot) = self.lookup(t) else {
            return false;
        };
        let fresh = {
            let mut held = slot.section();
            if held.generation == 0 || held.generation != t.generation {
                return false;
            }
            let framing = super::framing_context::current();
            let fresh = !resume && held.short != Some(s);
            if !fresh
                && (held.instance != Some(instance)
                    || held.framing.as_ref().map(|f| f.leg()) != framing.as_ref().map(|f| f.leg()))
            {
                return false;
            }
            if fresh {
                held.framing = framing;
            }
            held.instance = Some(instance);
            if !resume {
                held.short = None;
            }
            fresh
        };
        if fresh {
            if let Some(store) = self.services.upgrade() {
                store.forget(t);
            }

            drop(super::conn_services::forget(instance, t));
        }
        true
    }

    pub(crate) fn ended(&self, t: Ticket, s: u32, short: bool) {
        let Some(slot) = self.lookup(t) else {
            return;
        };
        let mut held = slot.section();
        if held.generation != 0 && held.generation == t.generation {
            held.short = short.then_some(s);
        }
    }

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
                        framing: None,
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

    fn lookup(&self, t: Ticket) -> Option<Arc<Slot>> {
        let (w, i) = decode(t.slot);
        if w != INLINE_WORKER {
            return None;
        }
        let held = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        held.0.get(i as usize).cloned()
    }

    pub(crate) fn waker_of(&self, t: Ticket) -> Option<Waker> {
        let slot = self.lookup(t)?;
        let generation = slot.generation();
        (generation != 0 && generation == t.generation)
            .then(|| Waker::from(Arc::new(GenerationWaker { slot, generation })))
    }

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

    fn recycle(&self, index: u32, slot: &Slot) {
        let next = super::worker::next_count(slot.count.load(Ordering::Acquire));

        if let Some(c) = next {
            slot.count.store(c, Ordering::Release);
        }
        let g = next.map_or(0, |c| ticket_generation(self.key, INLINE_WORKER, index, c));

        let (gone, instance, old) = {
            let mut held = slot.section();
            let old = held.generation;
            held.generation = g;
            held.short = None;
            held.framing = None;
            (held.waker.take(), held.instance.take(), old)
        };
        drop(gone);

        let dropped = Ticket {
            slot: encode(INLINE_WORKER, index),
            generation: old,
        };
        if old != 0 {
            if let Some(store) = self.services.upgrade() {
                store.forget(dropped);
            }
            if let Some(instance) = instance {
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
    #[must_use]
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }

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
