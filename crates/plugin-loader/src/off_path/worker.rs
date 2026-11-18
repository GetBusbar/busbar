// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::worker`'s construction: a dispatcher's environment, worker pool, worker threads and
//! watchdog are built once, when the dispatcher is (`Dispatcher::build`/`new_unlent`); a worker's
//! slab once at that start (`cold::dispatch::runtime::start_workers`) and once more only when the
//! watchdog replaces a wedged worker (`dispatch::watchdog::replace`). The measurement listing is a
//! configuration check's. None of it runs per request.

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

use crate::dispatch::handle::TicketKey;
use crate::dispatch::services::{ServiceStore, ServicesSlot};
use crate::dispatch::ticket::MAX_WORKERS;
use crate::dispatch::worker::{
    spawn_worker, DispatchConfig, Dispatcher, Entry, Env, Msg, Pool, Worker, WorkerState,
};

impl Worker {
    pub(crate) fn new(
        index: u32,
        counts: Vec<Option<u32>>,
        key: TicketKey,
    ) -> (Arc<Self>, Receiver<Msg>) {
        let (tx, rx) = channel();

        // Built once, at dispatcher start or watchdog replacement.
        let free = crate::cold::dispatch::runtime::worker_free_slots(&counts);
        let entries =
            crate::cold::dispatch::runtime::worker_table(counts, |(count, idx)| match count {
                Some(count) => Entry::minted(
                    count,
                    crate::dispatch::handle::ticket_generation(key, index, idx, count),
                ),
                None => Entry::minted(u32::MAX, 0),
            });
        let state = WorkerState::fresh(entries, free);
        let w = Arc::new(Self {
            index,
            key,
            tx,
            state: Mutex::new(state),
            crossing_since: AtomicU64::new(0),
            crossing_budget: AtomicU64::new(0),
        });
        (w, rx)
    }
}

impl Dispatcher {
    /// Snapshot the immutable declarations of currently bound instances, including plugins
    /// declaring no classes. Used by the host to reject unknown configured namespaces.
    pub fn measurement_bindings(&self) -> Vec<crate::dispatch::measurement::Binding> {
        // Listed once per config check.
        crate::cold::dispatch::runtime::measurement_bindings(&self.pool.adopted)
    }

    pub(crate) fn build_unlent(
        config: DispatchConfig,
        provider: Option<Arc<ServicesSlot>>,
        ticket_key: TicketKey,
        callers: Arc<dyn busbar_contract::services::CallerBinding>,
    ) -> Self {
        let n = config.workers.clamp(1, MAX_WORKERS - 1);
        let services: Arc<ServiceStore> = Arc::default();
        let env = Arc::new(Env {
            measurements: Arc::default(),
            callers,
            budgets: config.budgets,
            quarantine_after: config.quarantine_after.max(1),
            stats: Arc::default(),
            inline: Arc::new(crate::dispatch::inline::InlineTickets::new(
                ticket_key, &services,
            )),
            services,
            provider,
            runtime: std::sync::OnceLock::new(),
            io: std::sync::OnceLock::new(),
            auth: std::sync::OnceLock::new(),
            observing: Arc::default(),
            ticket_key,
            latch: std::sync::OnceLock::new(),
            seal: std::sync::OnceLock::new(),
        });
        // A dispatcher's workers start once, when it is built.
        let (slots, started) = crate::cold::dispatch::runtime::start_workers(n, ticket_key);
        let pool = Arc::new(Pool {
            slots,
            env: env.clone(),
            stop: AtomicBool::new(false),
            adopted: Mutex::new(Vec::new()),
        });
        for (w, rx) in started {
            spawn_worker(w, rx, env.clone());
        }
        crate::dispatch::watchdog::spawn(
            Arc::downgrade(&pool),
            config.watchdog_period,
            config.budgets.min(),
        );
        Self { pool }
    }
}
