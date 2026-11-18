// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::held`'s driver snapshot: republished only when a driver ticket starts
//! (`Held::track`, from `Dispatcher::driver`: a plane driver's construction or an instance's tick
//! loop start) or stops (`Held::untrack`, past its `tracks` check: only a driver ticket's recycle;
//! `Held::untrack_worker`: a wedged worker's replacement). No service call republishes it.

use std::sync::Arc;

use busbar_contract::abi::mechanism::ticket::Ticket;
use foldhash::HashMap;

use crate::dispatch::held::Held;

impl Held {
    pub(crate) fn publish<V>(&self, all: &HashMap<Ticket, V>) {
        // A driver ticket's start or stop republishes the lock-free snapshot; no service call does.
        let drivers = crate::cold::dispatch::runtime::driver_snapshot(all);
        self.drivers.store(Arc::new(drivers));
    }
}
