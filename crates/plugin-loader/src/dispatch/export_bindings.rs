// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::{lifecycle::slot, ticket::Ticket};
use busbar_contract::conn::{DeclaredConns, InstanceId};
use busbar_contract::services::DiskDest;

use super::ticket::{InstanceWake, Waking};

pub(crate) struct Generation {
    pub(crate) conn: Option<(InstanceId, Arc<dyn DeclaredConns>)>,
    pub(crate) destinations: Vec<DiskDest>,
}

impl Drop for Generation {
    fn drop(&mut self) {
        if let Some((owner, table)) = &self.conn {
            table.forget(*owner);
        }
    }
}

#[derive(Default)]
pub(crate) struct Bindings(Mutex<State>);

#[derive(Default)]
struct State {
    current: Option<Arc<Generation>>,
    tickets: HashMap<Ticket, Arc<Generation>>,
    entering: usize,
    refreshing: Option<Ticket>,
    pending_refresh: bool,
    waiting: Vec<Ticket>,
}

pub(crate) struct Admission {
    wake: &'static InstanceWake,
    refresh: bool,
    ticket: Ticket,
}

/// Ticket cleanup may run while the worker owns its state lock. Retire the connection generation
/// and wake refresh waiters when the worker drops this value outside that lock.
pub(crate) struct Forgotten {
    binding: Option<Arc<Generation>>,
    waiting: Vec<Ticket>,
    wake: &'static InstanceWake,
}

impl Forgotten {
    pub(crate) fn binding(&self) -> Option<&Arc<Generation>> {
        self.binding.as_ref()
    }
}

impl Drop for Forgotten {
    fn drop(&mut self) {
        drop(self.binding.take());
        if let Some(waking) = Waking::of(self.wake) {
            for ticket in self.waiting.drain(..) {
                waking.wake(ticket);
            }
        }
    }
}

impl Bindings {
    pub(crate) fn admit(
        &self,
        wake: &'static InstanceWake,
        op: u32,
        ticket: Ticket,
    ) -> Option<Admission> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let refresh = op == slot::REFRESH;
        if refresh && state.refreshing.is_none() && state.entering == 0 {
            state.refreshing = Some(ticket);
        }
        let blocked = if refresh {
            state.entering != 0 || state.refreshing != Some(ticket)
        } else {
            state.refreshing.is_some()
        };
        if blocked {
            if !ticket.is_none() && !state.waiting.contains(&ticket) {
                state.waiting.push(ticket);
            }
            return None;
        }
        if !refresh {
            state.entering += 1;
        }
        Some(Admission {
            wake,
            refresh,
            ticket,
        })
    }

    pub(crate) fn pin(&self, ticket: Ticket) -> Option<Arc<Generation>> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if ticket.is_none() {
            return state.current.clone();
        }
        if let Some(generation) = state.tickets.get(&ticket) {
            return Some(generation.clone());
        }
        let generation = state.current.clone()?;
        state.tickets.insert(ticket, generation.clone());
        Some(generation)
    }

    /// A refresh owns its candidate for every crossing, including host-service results
    /// retained while Pending. Resuming must never redeclare it under a different owner.
    pub(crate) fn staged(&self, ticket: Ticket) -> Option<Arc<Generation>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tickets
            .get(&ticket)
            .cloned()
    }

    pub(crate) fn stage(&self, ticket: Ticket, generation: Arc<Generation>) {
        let prior = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tickets
            .insert(ticket, generation);
        drop(prior);
    }

    pub(crate) fn pending_refresh(&self, ticket: Ticket) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.refreshing == Some(ticket) {
            state.pending_refresh = true;
        }
    }

    pub(crate) fn finish_refresh(&self, wake: &'static InstanceWake, ticket: Ticket) {
        let waiting = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            if state.refreshing != Some(ticket) {
                return;
            }
            state.refreshing = None;
            state.pending_refresh = false;
            std::mem::take(&mut state.waiting)
        };
        if let Some(waking) = Waking::of(wake) {
            for ticket in waiting {
                waking.wake(ticket);
            }
        }
    }

    pub(crate) fn publish(&self, generation: Arc<Generation>) {
        let prior = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .replace(generation);
        drop(prior);
    }

    pub(crate) fn forget(&self, wake: &'static InstanceWake, ticket: Ticket) -> Forgotten {
        let (binding, waiting) = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let pending_refresh = state.pending_refresh && state.refreshing == Some(ticket);
            if pending_refresh {
                state.refreshing = None;
                state.pending_refresh = false;
            }
            let waiting = if pending_refresh {
                std::mem::take(&mut state.waiting)
            } else {
                Vec::new()
            };
            (state.tickets.remove(&ticket), waiting)
        };
        Forgotten {
            binding,
            waiting,
            wake,
        }
    }

    pub(crate) fn clear(&self) {
        let (current, tickets) = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            state.refreshing = None;
            state.pending_refresh = false;
            (state.current.take(), std::mem::take(&mut state.tickets))
        };
        drop((current, tickets));
    }

    pub(crate) fn wake_waiters(&self, wake: &'static InstanceWake) {
        let waiting = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut state.waiting)
        };
        if let Some(waking) = Waking::of(wake) {
            for ticket in waiting {
                waking.wake(ticket);
            }
        }
    }

    pub(crate) fn worker_pins(&self, worker: u32) -> Vec<(Ticket, Arc<Generation>)> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tickets
            .iter()
            .filter(|(ticket, _)| super::ticket::decode(ticket.slot).0 == worker)
            .map(|(ticket, binding)| (*ticket, binding.clone()))
            .collect()
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let waiting = {
            let mut state = self
                .wake
                .exports
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if self.refresh {
                // First-crossing admission transfers to the pending lifecycle. Its terminal
                // REFRESH, CANCEL, or ticket cleanup releases the barrier.
                if state.refreshing == Some(self.ticket) && !state.pending_refresh {
                    state.refreshing = None;
                }
            } else {
                state.entering -= 1;
            }
            if state.entering == 0 && state.refreshing.is_none() {
                std::mem::take(&mut state.waiting)
            } else {
                Vec::new()
            }
        };
        if let Some(waking) = Waking::of(self.wake) {
            for ticket in waiting {
                waking.wake(ticket);
            }
        }
    }
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<Arc<Generation>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn current() -> Option<Arc<Generation>> {
    CURRENT.with(|current| current.borrow().clone())
}

pub(crate) fn crossing<R>(generation: Option<Arc<Generation>>, call: impl FnOnce() -> R) -> R {
    struct Restore(Option<Arc<Generation>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let old = CURRENT.with(|current| current.replace(self.0.take()));
            drop(old);
        }
    }
    let _restore = Restore(CURRENT.with(|current| current.replace(generation)));
    call()
}
