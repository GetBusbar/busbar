// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HELD EXCHANGES OF A DRIVER TICKET (`dispatch::worker`, held work on a driver ticket): what
//! the host sees of the work a plugin holds PENDING side by side on one driver ticket, by
//! completion handle, through the two slots that keep answers by handle (the host services,
//! `super::services`, and the connector, `super::conn_services`).
//!
//! * ONE PENDING HANDLE PER HELD EXCHANGE. An exchange stops at its first call that answers PENDING
//!   (Ready|Pending(wake), the replay rule), so the handles whose last call answered PENDING are
//!   the held exchanges, one each. A handle leaves the set when a call on it answers anything else:
//!   its exchange moved on (and is held again under its next handle if that one pends) or is over.
//!   The worker bounds the set by the instance's `max_inflight`, and a slot frees as each held
//!   exchange ends, not only when a `drive` answers that nothing is held.
//! * NO HANDLE IS ISSUED TWICE IN A KEPT CYCLE. While a cycle is kept (something was held at its
//!   tick's start), a `tick` starts new work: a call it makes under a handle already issued in the
//!   cycle would be answered another exchange's kept answer. It is REFUSED as a fault instead (the
//!   one fault answer, `Outcome::Fault`, no text), and nothing runs.
//!
//! Only driver tickets are tracked ([`Held::track`]); a call on any other ticket passes untouched,
//! and takes no lock.

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

    /// Whether `ticket` is tracked, read without the lock. A driver ticket is tracked from before
    /// it is handed out until it is recycled, so no call on it races its tracking.
    pub(crate) fn tracks(&self, ticket: Ticket) -> bool {
        let drivers = self.drivers.load();
        !drivers.is_empty() && drivers.contains(&ticket)
    }

    /// `all`'s tickets, as the lock-free read sees them.
    fn publish(&self, all: &HashMap<Ticket, Cycle>) {
        self.drivers.store(Arc::new(all.keys().copied().collect()));
    }

    /// Track `driver`, a driver ticket just minted.
    pub(crate) fn track(&self, driver: Ticket) {
        let mut all = self.lock();
        all.insert(driver, Cycle::default());
        self.publish(&all);
    }

    /// Stop tracking `ticket` (it was recycled).
    pub(crate) fn untrack(&self, ticket: Ticket) {
        if !self.tracks(ticket) {
            return;
        }
        let mut all = self.lock();
        if all.remove(&ticket).is_some() {
            self.publish(&all);
        }
    }

    /// Stop tracking every ticket of worker `worker` (it was replaced).
    pub(crate) fn untrack_worker(&self, worker: u32) {
        let mut all = self.lock();
        let before = all.len();
        all.retain(|t, _| decode(t.slot).0 != worker);
        if all.len() != before {
            self.publish(&all);
        }
    }

    /// A new cycle on `driver`: nothing is held or issued.
    pub(crate) fn forget(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            *c = Cycle::default();
        }
    }

    /// A crossing on `driver` begins; `refusing` = it is a `tick` of a kept cycle.
    pub(crate) fn enter(&self, driver: Ticket, refusing: bool) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.refusing = refusing;
            c.fresh.clear();
        }
    }

    /// The crossing on `driver` returned: what it issued is the cycle's.
    pub(crate) fn leave(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.refusing = false;
            let fresh = std::mem::take(&mut c.fresh);
            c.issued.extend(fresh);
        }
    }

    /// A `drive` on `driver` answered anything but PENDING: nothing is held.
    pub(crate) fn drained(&self, driver: Ticket) {
        if let Some(c) = self.lock().get_mut(&driver) {
            c.pending.clear();
            c.inspections.clear();
            c.conditionals.clear();
        }
    }

    /// How many exchanges are held on `driver`.
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

    /// Count an inspection while its receipt awaits the driver's next crossing.
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

    /// A call under `h` is about to be served: `false` when it reuses a handle another exchange
    /// issued in a kept cycle (refused, as a fault, and nothing runs).
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

    /// The call under `h` answered: PENDING (`pending`) or anything else.
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

    /// The caller already holds the exact result-owner locks. Validate the complete batch
    /// before detaching any entry; no callback or payload destructor runs under these locks.
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
