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
//! Only driver tickets are tracked ([`Held::track`]); a call on any other ticket passes untouched.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};

use super::ticket::decode;

/// One driver ticket's handles in its current cycle.
#[derive(Debug, Default)]
struct Cycle {
    /// A `tick` crossing of a kept cycle is in progress: a handle in `issued` is refused.
    refusing: bool,
    /// Every handle issued in the cycle before the crossing in progress.
    issued: HashSet<u32>,
    /// The handles the crossing in progress issued.
    fresh: HashSet<u32>,
    /// The handles whose last call answered PENDING: one per held exchange.
    pending: HashSet<u32>,
}

/// The driver tickets' cycles, by ticket.
#[derive(Debug, Default)]
pub(crate) struct Held {
    inner: Mutex<HashMap<Ticket, Cycle>>,
}

impl Held {
    fn lock(&self) -> MutexGuard<'_, HashMap<Ticket, Cycle>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Track `driver`, a driver ticket just minted.
    pub(crate) fn track(&self, driver: Ticket) {
        self.lock().insert(driver, Cycle::default());
    }

    /// Stop tracking `ticket` (it was recycled).
    pub(crate) fn untrack(&self, ticket: Ticket) {
        self.lock().remove(&ticket);
    }

    /// Stop tracking every ticket of worker `worker` (it was replaced).
    pub(crate) fn untrack_worker(&self, worker: u32) {
        self.lock().retain(|t, _| decode(t.slot).0 != worker);
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
        }
    }

    /// How many exchanges are held on `driver`.
    pub(crate) fn held(&self, driver: Ticket) -> u32 {
        self.lock()
            .get(&driver)
            .map_or(0, |c| u32::try_from(c.pending.len()).unwrap_or(u32::MAX))
    }

    /// A call under `h` is about to be served: `false` when it reuses a handle another exchange
    /// issued in a kept cycle (refused, as a fault, and nothing runs).
    pub(crate) fn call(&self, h: CompletionHandle) -> bool {
        let mut all = self.lock();
        let Some(c) = all.get_mut(&h.ticket) else {
            return true;
        };
        if c.refusing && c.issued.contains(&h.seq) {
            return false;
        }
        c.fresh.insert(h.seq);
        true
    }

    /// The call under `h` answered: PENDING (`pending`) or anything else.
    pub(crate) fn answered(&self, h: CompletionHandle, pending: bool) {
        if let Some(c) = self.lock().get_mut(&h.ticket) {
            if pending {
                c.pending.insert(h.seq);
            } else {
                c.pending.remove(&h.seq);
            }
        }
    }
}
