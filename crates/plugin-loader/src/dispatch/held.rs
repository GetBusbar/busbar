// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::completion_retirement::{Domain, Handle};

use super::ticket::decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Issued {
    caller: usize,
    handle: Handle,
}

/// One driver ticket's handles in its current cycle.
#[derive(Debug, Default)]
struct Cycle {
    /// A `tick` crossing of a kept cycle is in progress: a handle in `issued` is refused.
    refusing: bool,
    /// Every handle issued in the cycle before the crossing in progress.
    issued: HashSet<Issued>,
    /// The handles the crossing in progress issued.
    fresh: HashSet<Issued>,
    /// The handles whose last call answered PENDING: one per held exchange.
    pending: HashSet<Issued>,
    /// One inspection per issuing instance, outside the completion-handle namespace.
    inspections: HashSet<usize>,
    conditionals: HashSet<usize>,
}

/// The driver tickets' cycles, by ticket.
#[derive(Debug, Default)]
pub(crate) struct Held {
    inner: Mutex<HashMap<Ticket, Cycle>>,
    /// The tickets `inner` tracks, read without its lock: a service call on any other ticket
    /// (every call but a driver ticket's) is told so here and takes no lock ([`Held::tracks`]).
    /// Replaced, under `inner`'s lock, whenever a ticket is tracked or stops being tracked.
    drivers: ArcSwap<HashSet<Ticket>>,
}

impl Held {
    fn lock(&self) -> MutexGuard<'_, HashMap<Ticket, Cycle>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn tracks(&self, ticket: Ticket) -> bool {
        let drivers = self.drivers.load();
        !drivers.is_empty() && drivers.contains(&ticket)
    }

    fn publish(&self, all: &HashMap<Ticket, Cycle>) {
        self.drivers.store(Arc::new(all.keys().copied().collect()));
    }

    pub(crate) fn track(&self, driver: Ticket) {
        let mut all = self.lock();
        all.insert(driver, Cycle::default());
        self.publish(&all);
    }

    pub(crate) fn untrack(&self, ticket: Ticket) {
        if !self.tracks(ticket) {
            return;
        }
        let mut all = self.lock();
        if all.remove(&ticket).is_some() {
            self.publish(&all);
        }
    }

    pub(crate) fn untrack_worker(&self, worker: u32) {
        let mut all = self.lock();
        let before = all.len();
        all.retain(|t, _| decode(t.slot).0 != worker);
        if all.len() != before {
            self.publish(&all);
        }
    }

    pub(crate) fn forget(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            *c = Cycle::default();
        }
    }

    pub(crate) fn enter(&self, driver: Ticket, refusing: bool) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.refusing = refusing;
            c.fresh.clear();
        }
    }

    pub(crate) fn leave(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.refusing = false;
            let fresh = std::mem::take(&mut c.fresh);
            c.issued.extend(fresh);
        }
    }

    pub(crate) fn drained(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.pending.clear();
            c.inspections.clear();
            c.conditionals.clear();
        }
    }

    pub(crate) fn held(&self, driver: Ticket) -> u32 {
        self.lock().get(&driver).map_or(0, |c| {
            u32::try_from(
                c.pending
                    .len()
                    .saturating_add(c.inspections.len())
                    .saturating_add(c.conditionals.len()),
            )
            .unwrap_or(u32::MAX)
        })
    }

    pub(crate) fn inspection(&self, ticket: Ticket, caller: usize, pending: bool) {
        if !self.tracks(ticket) {
            return;
        }
        if let Some(c) = self.lock().get_mut(&ticket) {
            if pending {
                c.inspections.insert(caller);
            } else {
                c.inspections.remove(&caller);
            }
        }
    }

    pub(crate) fn conditional(&self, ticket: Ticket, caller: usize, pending: bool) {
        if !self.tracks(ticket) {
            return;
        }
        if let Some(c) = self.lock().get_mut(&ticket) {
            if pending {
                c.conditionals.insert(caller);
            } else {
                c.conditionals.remove(&caller);
            }
        }
    }

    pub(crate) fn call(&self, caller: usize, domain: Domain, h: CompletionHandle) -> bool {
        if !self.tracks(h.ticket) {
            return true;
        }
        let mut all = self.lock();
        let Some(c) = all.get_mut(&h.ticket) else {
            return true;
        };
        let key = Issued {
            caller,
            handle: Handle { domain, seq: h.seq },
        };
        if (c.refusing && c.issued.contains(&key))
            || c.issued.iter().chain(c.fresh.iter()).any(|old| {
                old.caller == caller && old.handle.seq == h.seq && old.handle.domain != domain
            })
        {
            return false;
        }
        c.fresh.insert(key);
        true
    }

    pub(crate) fn answered(
        &self,
        caller: usize,
        domain: Domain,
        h: CompletionHandle,
        pending: bool,
    ) {
        if !self.tracks(h.ticket) {
            return;
        }
        if let Some(c) = self.lock().get_mut(&h.ticket) {
            let key = Issued {
                caller,
                handle: Handle { domain, seq: h.seq },
            };
            if pending {
                c.pending.insert(key);
            } else {
                c.pending.remove(&key);
            }
        }
    }

    pub(crate) fn retire(
        &self,
        ticket: Ticket,
        caller: usize,
        handles: &[Handle],
        detach: impl FnOnce(),
    ) -> Result<(), ()> {
        let mut all = self.lock();
        let cycle = all.get_mut(&ticket).ok_or(())?;
        for handle in handles {
            let key = Issued {
                caller,
                handle: *handle,
            };
            if cycle.pending.contains(&key)
                || !(cycle.issued.contains(&key) || cycle.fresh.contains(&key))
            {
                return Err(());
            }
        }
        detach();
        for handle in handles {
            let key = Issued {
                caller,
                handle: *handle,
            };
            cycle.issued.remove(&key);
            cycle.fresh.remove(&key);
        }
        Ok(())
    }
}
