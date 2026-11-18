// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::export_bindings`' wedged-worker listing: read once per wedged worker, by its
//! replacement (`off_path::watchdog::replace` -> `dispatch::conn_services::forget_worker`), never
//! per request.

use std::sync::Arc;

use busbar_contract::abi::mechanism::ticket::Ticket;

use crate::dispatch::export_bindings::{Bindings, Generation};

impl Bindings {
    pub(crate) fn worker_pins(&self, worker: u32) -> Vec<(Ticket, Arc<Generation>)> {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        // A wedged worker's replacement forgets the export pins its tickets held.
        crate::cold::dispatch::runtime::worker_pins(
            state.tickets.iter().chain(state.staged.iter()),
            worker,
        )
    }
}
