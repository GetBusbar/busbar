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
            super::conn_services::forget_authority(*owner, table);
        }
    }
}

#[derive(Default)]
pub(crate) struct Bindings(Mutex<State>);

#[derive(Default)]
struct State {
    current: Option<Arc<Generation>>,
    // Root-installed member authentication remains bound to the original authority.
    root: Option<Arc<Generation>>,
    tickets: HashMap<Ticket, Arc<Generation>>,
    staged: HashMap<Ticket, Arc<Generation>>,
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

pub(crate) struct Forgotten {
    binding: Option<Arc<Generation>>,
    replaced: Option<Arc<Generation>>,
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
        drop(self.replaced.take());
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
        let another_refresh = refresh && state.staged.keys().any(|pending| *pending != ticket);
        if refresh && !another_refresh && state.refreshing.is_none() && state.entering == 0 {
            state.refreshing = Some(ticket);
        }
        let blocked = if refresh {
            another_refresh || state.entering != 0 || state.refreshing != Some(ticket)
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
        if let Some(generation) = state.staged.get(&ticket) {
            return Some(generation.clone());
        }
        if let Some(generation) = state.tickets.get(&ticket) {
            return Some(generation.clone());
        }
        let generation = state.current.clone()?;
        state.tickets.insert(ticket, generation.clone());
        Some(generation)
    }

    pub(crate) fn staged(&self, ticket: Ticket) -> Option<Arc<Generation>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .staged
            .get(&ticket)
            .cloned()
    }

    pub(crate) fn stage(
        &self,
        ticket: Ticket,
        generation: Arc<Generation>,
    ) -> Option<Arc<Generation>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .staged
            .insert(ticket, generation)
    }

    pub(crate) fn take_staged(&self, ticket: Ticket) -> Option<Arc<Generation>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .staged
            .remove(&ticket)
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
        let prior = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            if state.root.is_none() {
                state.root = Some(generation.clone());
            }
            state.current.replace(generation)
        };
        super::worker::drop_after_lock(Box::new(prior));
    }

    pub(crate) fn forget(&self, wake: &'static InstanceWake, ticket: Ticket) -> Forgotten {
        let (binding, replaced, waiting) = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let pending_refresh = state.pending_refresh && state.refreshing == Some(ticket);
            if pending_refresh {
                state.refreshing = None;
                state.pending_refresh = false;
            }
            let staged = state.staged.remove(&ticket);
            let waiting = if pending_refresh || (staged.is_some() && state.refreshing.is_none()) {
                std::mem::take(&mut state.waiting)
            } else {
                Vec::new()
            };
            let pinned = state.tickets.remove(&ticket);
            let (binding, replaced) = match staged {
                Some(staged) => (Some(staged), pinned),
                None => (pinned, None),
            };
            (binding, replaced, waiting)
        };
        Forgotten {
            binding,
            replaced,
            waiting,
            wake,
        }
    }

    pub(crate) fn clear(&self) {
        let (current, root, tickets, staged) = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            state.refreshing = None;
            state.pending_refresh = false;
            (
                state.current.take(),
                state.root.take(),
                std::mem::take(&mut state.tickets),
                std::mem::take(&mut state.staged),
            )
        };
        super::worker::drop_after_lock(Box::new((current, root, tickets, staged)));
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
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state
            .tickets
            .iter()
            .chain(state.staged.iter())
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
